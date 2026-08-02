"""PNG 核心算法(纯标准库, 无需 Pillow)。

移植自 stego_solver.sh 的核心逻辑:
- chunk 解析
- build_png: 把含 filter 字节的原始像素数据重新封装成可查看 PNG
- guess_size: 根据解压数据量猜尺寸
- zlib 流边界检测(decompressobj + unused_data)
- 反过滤(unfilter): 从带 filter 的扫描行重建像素

这些是处理多 IDAT / 嵌套 zlib / IHDR 篡改 / 附加数据 的基础。
"""
from __future__ import annotations

import struct
import zlib
from typing import Optional

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

# PNG 颜色类型 -> 通道数
COLOR_TYPE_CHANNELS = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}
# 通道数 -> 颜色类型(反向, 用于 build_png)
CHANNELS_COLOR_TYPE = {1: 0, 2: 4, 3: 2, 4: 6}

# 正常 IEND 的 CRC
NORMAL_IEND_CRC = b"\xae\x42\x60\x82"


# --------------------------------------------------------------------------- #
#  chunk 解析
# --------------------------------------------------------------------------- #
class Chunk:
    __slots__ = ("ctype", "length", "offset", "data", "crc")

    def __init__(self, ctype: str, length: int, offset: int, data: bytes, crc: bytes):
        self.ctype = ctype
        self.length = length
        self.offset = offset
        self.data = data
        self.crc = crc

    @property
    def crc_ok(self) -> bool:
        calc = struct.pack(">I", zlib.crc32(self.ctype.encode("latin1") + self.data) & 0xFFFFFFFF)
        return calc == self.crc


class PNGInfo:
    """PNG 解析结果。"""

    def __init__(self) -> None:
        self.chunks: list[Chunk] = []
        self.idat_list: list[bytes] = []  # 各 IDAT 的 data
        self.idat_meta: list[tuple[int, int, int, str]] = []  # (idx, offset, length, head4hex)
        self.ihdr: Optional[tuple] = None  # (W,H,bd,ct_,cm,fm,im)
        self.post_iend: bytes = b""  # IEND 之后的数据
        self.iend_chunk: Optional[Chunk] = None
        self.is_png: bool = False


def parse_png(data: bytes) -> PNGInfo:
    """解析 PNG 字节, 返回 PNGInfo。非 PNG 返回 is_png=False。"""
    info = PNGInfo()
    if not data.startswith(PNG_SIGNATURE):
        return info
    info.is_png = True

    off = len(PNG_SIGNATURE)
    idat_idx = 0
    iend_seen = False
    while off + 8 <= len(data):
        length = struct.unpack(">I", data[off : off + 4])[0]
        ctype = data[off + 4 : off + 8].decode("latin1", "replace")
        cdata = data[off + 8 : off + 8 + length]
        crc = data[off + 8 + length : off + 12 + length] if off + 12 + length <= len(data) else b""
        chunk = Chunk(ctype, length, off, cdata, crc)
        info.chunks.append(chunk)

        if ctype == "IHDR" and len(cdata) >= 13:
            info.ihdr = struct.unpack(">IIBBBBB", cdata[:13])

        if ctype == "IDAT":
            info.idat_list.append(cdata)
            info.idat_meta.append((idat_idx, off, length, cdata[:4].hex()))
            idat_idx += 1

        if ctype == "IEND":
            info.iend_chunk = chunk
            iend_seen = True
            info.post_iend = data[off + 12 + length :]
            # 继续扫描(理论上 IEND 后不应有 chunk, 但有些文件会嵌第二个 PNG)

        off += 12 + length
        if iend_seen and ctype == "IEND":
            break  # IEND 后跳出主循环

    return info


def ihdr_dims(info: PNGInfo) -> tuple[int, int, int]:
    """返回 (W, H, channels), 默认 (0,0,3)。"""
    if info.ihdr:
        W, H, bd, ct_ = info.ihdr[:4]
        ch = COLOR_TYPE_CHANNELS.get(ct_, 3)
        return W, H, ch
    return 0, 0, 3


def expected_pixel_bytes(W: int, H: int, ch: int) -> int:
    """PNG 原始像素数据 = (1 + W*ch) * H(每行 1 个 filter 字节)。"""
    return (1 + W * ch) * H


def expected_pixel_bytes_ihdr(info: PNGInfo) -> int:
    """按 IHDR 计算 PNG 解压后 scanline 总长度。

    PNG 每行以 1 字节 filter type 开头，后面是压缩前像素字节。对 bit depth
    小于 8 的 grayscale/indexed PNG，单行像素字节需要按 bit 打包向上取整。
    """
    if not info.ihdr:
        return 0
    W, H, bd, ct_ = info.ihdr[:4]
    channels = COLOR_TYPE_CHANNELS.get(ct_, 3)
    bits_per_pixel = bd * channels
    row_bytes = (W * bits_per_pixel + 7) // 8
    return (1 + row_bytes) * H


# --------------------------------------------------------------------------- #
#  zlib 流边界
# --------------------------------------------------------------------------- #
def decompress_first_stream(data: bytes) -> tuple[bytes, bytes, bool]:
    """解压第一个完整 zlib 流。

    返回 (decoded, unused_data, success)。
    unused_data 是流结束后的剩余字节(隐藏 payload 的强信号)。
    """
    try:
        d = zlib.decompressobj()
        decoded = d.decompress(data)
        decoded += d.flush()
        return decoded, d.unused_data, True
    except zlib.error as e:
        return b"", data, False


def find_zlib_streams(data: bytes) -> list[tuple[int, bytes]]:
    """扫描所有 zlib 头(78 9c / 78 da / 78 01), 返回 [(offset, decompressed)]。"""
    results = []
    headers = (b"\x78\x9c", b"\x78\xda", b"\x78\x01")
    start = 0
    while True:
        pos = -1
        for h in headers:
            p = data.find(h, start)
            if p >= 0 and (pos < 0 or p < pos):
                pos = p
        if pos < 0:
            break
        try:
            d = zlib.decompressobj()
            dec = d.decompress(data[pos:]) + d.flush()
            results.append((pos, dec))
            start = pos + 2
        except zlib.error:
            start = pos + 1
    return results


# --------------------------------------------------------------------------- #
#  build_png: 像素数据 → 可查看 PNG
# --------------------------------------------------------------------------- #
def build_png(raw_pixels: bytes, W: int, H: int, channels: int) -> bytes:
    """把含 filter 字节的原始扫描行数据重新封装成合法 PNG 字节流。"""
    color_type = CHANNELS_COLOR_TYPE.get(channels, 2)

    def mkchunk(ctype: str, dd: bytes) -> bytes:
        ct = ctype.encode("latin1")
        crc = struct.pack(">I", zlib.crc32(ct + dd) & 0xFFFFFFFF)
        return struct.pack(">I", len(dd)) + ct + dd + crc

    ihdr = struct.pack(">IIBBBBB", W, H, 8, color_type, 0, 0, 0)
    compressed = zlib.compress(raw_pixels)
    return PNG_SIGNATURE + mkchunk("IHDR", ihdr) + mkchunk("IDAT", compressed) + mkchunk("IEND", b"")


# --------------------------------------------------------------------------- #
#  guess_size: 根据字节数猜尺寸
# --------------------------------------------------------------------------- #
def guess_size(nbytes: int) -> Optional[tuple[int, int, int]]:
    """根据原始像素字节数 (1+W*ch)*H 猜 (W,H,ch)。

    遍历通道数 (3,4,1) 与高度, 找合理比例的组合。
    """
    for ch in (3, 4, 1):
        body = nbytes / ch
        for h in range(10, 5001):
            if body % h != 0:
                continue
            w = int(body // h) - 1
            if w > 0:
                ratio = w / h if h else 0
                if 0.05 <= ratio <= 20:
                    return w, h, ch
    return None


# --------------------------------------------------------------------------- #
#  IHDR 篡改检测 + 尺寸爆破
# --------------------------------------------------------------------------- #
def ihdr_tampered(info: PNGInfo) -> bool:
    """IHDR 的 CRC 与实际数据是否不匹配(改宽高藏图)。"""
    for c in info.chunks:
        if c.ctype == "IHDR":
            return not c.crc_ok
    return False


def brute_force_dims(total_bytes: int, base_ch: int) -> list[tuple[int, int, int]]:
    """根据解压出的像素总数爆破真实尺寸, 返回候选 [(W,H,ch)]。

    优先返回「同通道数」的组合, 并按合理性排序。
    """
    candidates = []
    seen = set()
    for test_ch in (base_ch, 4, 1):
        for h in range(1, 5001):
            if total_bytes % h != 0:
                continue
            row = total_bytes // h
            if (row - 1) % test_ch != 0:
                continue
            w = (row - 1) // test_ch
            if 1 <= w <= 65535:
                ratio = w / h if h else 0
                if 0.05 <= ratio <= 20:
                    key = (w, h, test_ch)
                    if key not in seen:
                        seen.add(key)
                        candidates.append(key)
    # 排序: 通道数优先匹配 base_ch, 再按高度合理范围
    candidates.sort(key=lambda x: (0 if x[2] == base_ch else 1, abs(x[1] - 150)))
    return candidates


# --------------------------------------------------------------------------- #
#  反过滤 unfilter: 从带 filter 的扫描行重建像素(用于像素分析)
# --------------------------------------------------------------------------- #
def unfilter(raw: bytes, W: int, H: int, ch: int) -> bytes:
    """对 PNG 原始扫描行数据做反过滤, 返回纯像素字节(H*W*ch)。"""
    stride = 1 + W * ch
    out = bytearray()
    prev = bytearray(W * ch)
    pos = 0
    for _y in range(H):
        if pos + stride > len(raw):
            break
        ft = raw[pos]
        pos += 1
        line = bytearray(raw[pos : pos + W * ch])
        pos += W * ch
        if ft == 0:  # None
            pass
        elif ft == 1:  # Sub
            for i in range(ch, W * ch):
                line[i] = (line[i] + line[i - ch]) & 0xFF
        elif ft == 2:  # Up
            for i in range(W * ch):
                line[i] = (line[i] + prev[i]) & 0xFF
        elif ft == 3:  # Average
            for i in range(W * ch):
                a = line[i - ch] if i >= ch else 0
                line[i] = (line[i] + (a + prev[i]) // 2) & 0xFF
        elif ft == 4:  # Paeth
            for i in range(W * ch):
                a = line[i - ch] if i >= ch else 0
                b = prev[i]
                c = prev[i - ch] if i >= ch else 0
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                pr = a if pa <= pb and pa <= pc else (b if pb <= pc else c)
                line[i] = (line[i] + pr) & 0xFF
        out += line
        prev = line
    return bytes(out)
