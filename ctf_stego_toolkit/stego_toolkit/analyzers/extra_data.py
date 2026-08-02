"""通用附加数据处理: 对 IEND后/FFD9后/zlib-unused_data 做统一嗅探+解压+递归。

这是关键创新分析器。覆盖:
- misc5: IEND 后直接 ASCII flag
- misc8: IEND 后嵌套 PNG(需 OCR)
- misc16: zlib 流后 extra 是 LZMA(binwalk 也处理, 这里做补充)
- misc17: extra 是 bzip2 → 解压出隐藏 PNG
- 通用: gzip/zip 嵌套

策略:
1. 收集各种"附加数据"来源(PNG post_iend, PNG unused_data, JPG post_FFD9, GIF post_3B)
2. 对每段数据: 嗅探文件头 → 尝试解压 → 对解压结果递归处理 → 全程 flag 扫描
"""
from __future__ import annotations

import bz2
import gzip
import lzma
import os
import struct
import zipfile
import zlib
from io import BytesIO

from .base import Analyzer, AnalysisContext
from ..flags import find_flags_in_text
from .. import png_core


def sniff_format(data: bytes) -> str:
    """识别数据开头的格式。"""
    if not data:
        return "empty"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpg"
    if data.startswith(b"GIF8"):
        return "gif"
    if data.startswith(b"BM"):
        return "bmp"
    if data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        return "webp"
    if data.startswith(b"8BPS"):
        return "psd"
    if data.startswith(b"%PDF"):
        return "pdf"
    if data.startswith(b"\x7fELF"):
        return "elf"
    if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06"):
        return "zip"
    if data.startswith(b"\x1f\x8b"):
        return "gzip"
    if data.startswith(b"BZh"):
        return "bzip2"
    if data.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if data.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if len(data) > 262 and data[257:262] == b"ustar":
        return "tar"
    if data[:4] in (b"\x78\x9c", b"\x78\xda", b"\x78\x01", b"\x78\x5e"):
        return "zlib"
    # LZMA/xz magic
    if data[:6] == b"\xfd7zXZ\x00":
        return "xz"
    if data[:4] == b"\x5d\x00\x00":
        return "lzma_raw"  # 裸 LZMA(alone 格式)
    if len(data) >= 13 and data[0] == 0x5D:
        return "lzma_maybe"  # 可能是 LZMA
    # 纯文本?
    printable = sum(1 for b in data[:100] if 32 <= b < 127 or b in (9, 10, 13))
    if len(data) >= 4 and printable / min(len(data), 100) > 0.9:
        return "text"
    return "unknown"


def try_decompress(data: bytes, fmt_hint: str = "") -> tuple[bytes, str]:
    """尝试多种方式解压, 返回 (解压数据, 用的方法)。失败返回 (b"", "")。

    递归调用方应限制深度避免无限循环。
    """
    # 1. 按格式提示
    fmt = fmt_hint or sniff_format(data)

    if fmt == "zlib":
        try:
            return zlib.decompress(data), "zlib"
        except zlib.error:
            pass
    if fmt in ("zlib", "unknown"):
        for wbits in (-15, 31, 47):
            try:
                return zlib.decompress(data, wbits), f"zlib(wbits={wbits})"
            except zlib.error:
                continue
    if fmt == "gzip":
        try:
            return gzip.decompress(data), "gzip"
        except Exception:
            pass
    if fmt == "bzip2":
        try:
            return bz2.decompress(data), "bzip2"
        except Exception:
            pass
    if fmt in ("xz", "lzma_raw", "lzma_maybe", "unknown"):
        try:
            return lzma.decompress(data), "lzma"
        except lzma.LZMAError:
            pass
        # 尝试不同 filters
        try:
            dec = lzma.LZMADecompressor().decompress(data)
            if dec:
                return dec, "lzma(stream)"
        except Exception:
            pass
    if fmt == "zip":
        try:
            result = b""
            with zipfile.ZipFile(BytesIO(data)) as zf:
                for name in zf.namelist():
                    result += zf.read(name)
                    result += b"\n"
            return result, "zip"
        except Exception:
            pass

    # 2. 扫描内部找压缩流头再解压(适用于数据前面有杂质的情况)
    for magic, method in [
        (b"\x78\x9c", "zlib"), (b"\x78\xda", "zlib"), (b"\x78\x01", "zlib"),
        (b"\x1f\x8b", "gzip"), (b"BZh", "bzip2"),
    ]:
        pos = data.find(magic)
        if pos > 0 and pos < len(data) - 4:
            sub = data[pos:]
            dec, m = try_decompress(sub, method)
            if dec:
                return dec, f"{m}@offset{pos}"
    # LZMA 在数据中间(binwalk 场景)
    for pos in range(0, min(len(data), 2000)):
        if data[pos] == 0x5D and pos + 13 <= len(data):
            sub = data[pos:]
            try:
                dec = lzma.decompress(sub)
                if dec:
                    return dec, f"lzma@offset{pos}"
            except lzma.LZMAError:
                continue

    return b"", ""


def process_blob(ctx: AnalysisContext, blob: bytes, source: str, depth: int = 0,
                 max_depth: int = 4) -> None:
    """递归处理一段附加数据: 嗅探 → 解压 → flag 扫描 → 登记产物。

    depth 限制递归深度(防止嵌套炸弹)。
    """
    if depth > max_depth or not blob:
        return

    fmt = sniff_format(blob)
    ctx.add_finding("info", f"[extra depth={depth}] {source}: {len(blob)}B, 格式={fmt}")

    # 1. flag 直接扫描
    for f in find_flags_in_text(blob, source=f"extra({source})"):
        ctx.add_flag(f, confidence="high", source=f"extra {source}")
        ctx.add_finding("find", f"extra({source}) 发现 flag: {f}")

    # 2. 如果是文本, 保存
    if fmt == "text" and depth == 0:
        ctx.save_bytes(f"extra_{source}_text.txt", blob, f"附加文本数据({source})")

    # 3. 解压
    if fmt in ("png", "jpg", "gif", "bmp", "webp"):
        # 是图像: 保存并提示人工查看
        ext = {"png": ".png", "jpg": ".jpg", "gif": ".gif", "bmp": ".bmp", "webp": ".webp"}[fmt]
        fname = f"extra_{source}{ext}"
        ctx.save_bytes(fname, blob, f"附加图像({source}) — 可能含文字/二维码, 需人工查看",
                       needs_review=True)
        ctx.add_finding("find", f"extra({source}) 是一张 {fmt} 图像! 可能含 flag 文字",
                        source="extra_data")
        # PNG 图像也递归解 IDAT 看是否有嵌套
        if fmt == "png":
            self_info = png_core.parse_png(blob)
            if self_info.idat_list:
                all_idat = b"".join(self_info.idat_list)
                dec, unused, ok = png_core.decompress_first_stream(all_idat)
                if unused:
                    ctx.add_finding("find", f"extra({source}) 的嵌套 PNG 还有 {len(unused)}B unused",
                                    source="extra_data")
                    process_blob(ctx, unused, f"{source}_nested_unused", depth + 1, max_depth)
        return

    if fmt in ("pdf", "psd", "elf", "7z", "rar", "tar") and depth == 0:
        ext = {"pdf": ".pdf", "psd": ".psd", "elf": ".elf", "7z": ".7z", "rar": ".rar", "tar": ".tar"}[fmt]
        ctx.save_bytes(f"extra_{source}{ext}", blob, f"附加 {fmt.upper()} 文件({source})", needs_review=False)
        ctx.add_finding("find", f"extra({source}) 是 {fmt.upper()} 文件, 已保存供后续工具处理",
                        source="extra_data")

    if fmt in ("zlib", "gzip", "bzip2", "xz", "lzma_raw", "lzma_maybe", "zip", "unknown"):
        dec, method = try_decompress(blob, fmt)
        if dec:
            ctx.add_finding("find", f"extra({source}) 用 {method} 解压出 {len(dec)}B",
                            source="extra_data")
            # 保存解压结果
            sub_fmt = sniff_format(dec)
            if sub_fmt in ("png", "jpg", "gif", "bmp", "webp"):
                ext = {"png": ".png", "jpg": ".jpg", "gif": ".gif", "bmp": ".bmp", "webp": ".webp"}[sub_fmt]
                fname = f"extra_{source}_decompressed{ext}"
                ctx.save_bytes(fname, dec, f"{source} 解压出的 {sub_fmt} 图像", needs_review=True)
                ctx.add_finding("find", f"{source} 解压出一张 {sub_fmt} 图像! 可能含 flag",
                                source="extra_data")
            else:
                ctx.save_bytes(f"extra_{source}_decompressed.bin", dec,
                               f"{source} 解压数据({method})")
            # flag 扫描解压结果
            for f in find_flags_in_text(dec, source=f"extra({source})解压"):
                ctx.add_flag(f, confidence="high", source=f"extra {source}解压")
                ctx.add_finding("find", f"{source} 解压后含 flag: {f}")
            # 递归
            process_blob(ctx, dec, f"{source}_dec", depth + 1, max_depth)
        elif depth == 0:
            ctx.add_finding("info", f"extra({source}) 无法自动解压(可能需 binwalk 或人工)")


class ExtraDataAnalyzer(Analyzer):
    name = "阶段 5b: 附加数据分析"
    applies_to = None  # 所有类型都可能有附加数据
    requires = set()

    def run(self, ctx: AnalysisContext) -> None:
        data = ctx.data
        rtype = ctx.real_type

        # 1. PNG: post_iend + unused_data
        if rtype == "png":
            info = ctx.png_info.get("parsed")
            if info is None:
                info = png_core.parse_png(data)
            if info.post_iend:
                ctx.add_finding("find", f"IEND 之后附加 {len(info.post_iend)} 字节",
                                source=self.name)
                ctx.save_bytes("after_iend.bin", info.post_iend, "IEND 之后的数据")
                process_blob(ctx, info.post_iend, "after_iend")
            # unused_data 可能已被 png_deep 处理过(存在 ctx.png_info)
            unused = ctx.png_info.get("unused_data")
            if unused:
                process_blob(ctx, unused, "zlib_unused")

        # 2. JPG: FFD9 之后
        elif rtype == "jpg":
            pos = data.rfind(b"\xff\xd9")
            if pos >= 0:
                trailing = data[pos + 2 :]
                if trailing:
                    ctx.add_finding("find", f"FFD9 之后附加 {len(trailing)} 字节",
                                    source=self.name)
                    ctx.save_bytes("after_ffd9.bin", trailing, "FFD9 之后的数据")
                    process_blob(ctx, trailing, "after_ffd9")

        # 3. GIF: 0x3B 之后
        elif rtype == "gif":
            pos = data.rfind(b"\x3b")
            if pos >= 0:
                trailing = data[pos + 1 :]
                if trailing:
                    ctx.add_finding("find", f"GIF 结束标记后附加 {len(trailing)} 字节",
                                    source=self.name)
                    ctx.save_bytes("after_gif_trailer.bin", trailing, "GIF 结束后数据")
                    process_blob(ctx, trailing, "after_gif")

        # 4. BMP: 像素数据之后
        elif rtype == "bmp":
            # BMP 头: 前 2 字节 BM, 偏移 10 是像素数据偏移, 偏移 2-6 是文件大小
            if len(data) >= 14 and data[:2] == b"BM":
                file_size = struct.unpack("<I", data[2:6])[0]
                if file_size < len(data):
                    trailing = data[file_size:]
                    if trailing:
                        ctx.add_finding("find", f"BMP 声明大小后附加 {len(trailing)} 字节",
                                        source=self.name)
                        ctx.save_bytes("after_bmp.bin", trailing, "BMP 之后的数据")
                        process_blob(ctx, trailing, "after_bmp")

        # 5. TIFF: 简单检查文件末尾
        elif rtype == "tiff":
            # TIFF 没有明确结束标记, exiftool 会有 Trailer 提示
            # 这里检查是否有明显的附加文件头
            for magic, name in [(b"\x89PNG", "PNG"), (b"PK\x03\x04", "ZIP"), (b"\xff\xd8\xff", "JPEG")]:
                pos = data.find(magic, 8)  # 跳过开头
                if pos > 0:
                    ctx.add_finding("find", f"TIFF 中嵌套 {name} 数据 @offset {pos}",
                                    source=self.name)
