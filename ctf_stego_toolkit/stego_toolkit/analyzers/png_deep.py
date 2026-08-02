"""PNG 深度分析: chunk 结构 + zlib 流边界 + 隐藏数据提取。

覆盖手法:
- PNG tEXt/zTXt/iTXt chunk (misc9)
- 多 IDAT 独立 zlib 流 (misc11)
- 多 IDAT 切片 + 嵌套 zlib (misc12)
- 畸形 IEND (misc13)
- zlib 流后 extra data + stride/XOR 采样 (misc13)
- IHDR 篡改(改宽高藏图) + 尺寸爆破
- 第 2 个 IDAT 是独立 zlib 流 (misc10)
"""
from __future__ import annotations

import os
import re
import zlib

from .base import Analyzer, AnalysisContext
from ..flags import find_flags_in_text, prefix_alternation, scan_flags
from .. import png_core

FLAG_PAT = re.compile(
    rb"(?:" + prefix_alternation().encode("ascii") + rb")\{[ -~]{4,}\}",
    re.IGNORECASE,
)


class PNGDeepAnalyzer(Analyzer):
    name = "阶段 5: PNG 深度分析"
    applies_to = {"png"}
    requires = set()

    def run(self, ctx: AnalysisContext) -> None:
        data = ctx.data
        info = png_core.parse_png(data)
        if not info.is_png:
            ctx.add_finding("info", "非 PNG, 跳过")
            return

        # 存入 ctx 供其他分析器复用
        ctx.png_info["parsed"] = info

        W, H, ch = png_core.ihdr_dims(info)
        ctx.add_finding("info", f"chunk 结构: {self._chunk_summary(info)}")
        ctx.add_finding("info", f"IHDR: {W}x{H}, 通道数={ch} (颜色类型={info.ihdr[3] if info.ihdr else '?'})")

        # 5.1 IHDR 篡改检测
        self._check_ihdr_tamper(ctx, info)

        # 5.2 tEXt/zTXt/iTXt chunk 扫描
        self._scan_text_chunks(ctx, info)

        # 5.3 畸形 IEND 检测
        self._check_malformed_iend(ctx, info)

        # 5.4 zlib 流边界 + extra data
        self._analyze_zlib_streams(ctx, info, W, H, ch)

        # 5.5 多 IDAT 独立流检测
        self._check_multi_idat(ctx, info, W, H, ch)

    # ----------------------------------------------------------------------- #
    def _chunk_summary(self, info: png_core.PNGInfo) -> str:
        counts: dict[str, int] = {}
        for c in info.chunks:
            counts[c.ctype] = counts.get(c.ctype, 0) + 1
        return ", ".join(f"{k}×{v}" for k, v in counts.items())

    def _check_ihdr_tamper(self, ctx: AnalysisContext, info: png_core.PNGInfo) -> None:
        if png_core.ihdr_tampered(info):
            ctx.add_finding(
                "find",
                "IHDR CRC 不匹配 → IHDR 被篡改(可能改宽高藏图)",
                "出题人可能改小了高度, 图片下半部分(含 flag)被隐藏。\n"
                "        会尝试根据解压数据量爆破真实尺寸。",
                source=self.name,
            )

    def _scan_text_chunks(self, ctx: AnalysisContext, info: png_core.PNGInfo) -> None:
        """扫描 tEXt/zTXt/iTXt chunk(可能含明文 flag)。"""
        for c in info.chunks:
            if c.ctype in ("tEXt", "zTXt", "iTXt"):
                # tEXt: keyword\0text ; zTXt: keyword\0compression_method\0compressed_text
                if c.ctype == "tEXt":
                    parts = c.data.split(b"\x00", 1)
                    keyword = parts[0].decode("latin1", "replace")
                    text = parts[1] if len(parts) > 1 else b""
                elif c.ctype == "zTXt":
                    parts = c.data.split(b"\x00", 2)
                    keyword = parts[0].decode("latin1", "replace")
                    text = parts[2] if len(parts) > 2 else b""
                    try:
                        text = zlib.decompress(text)
                    except Exception:
                        pass
                else:  # iTXt
                    text = c.data
                    keyword = text.split(b"\x00", 1)[0].decode("latin1", "replace")

                ctx.add_finding("info", f"{c.ctype} chunk: keyword={keyword}, len={len(text)}")
                for f in find_flags_in_text(text, source=f"{self.name} {c.ctype}({keyword})"):
                    ctx.add_flag(f, confidence="high", source=f"{self.name} {c.ctype} chunk")
                    ctx.add_finding("find", f"{c.ctype} chunk({keyword}) 含 flag: {f}")
                # 可疑字段(如 Warning)
                if keyword.lower() in ("warning", "comment", "author", "description"):
                    ctx.add_finding("find", f"{c.ctype} 字段 {keyword}: {text[:100].decode('latin1','replace')}",
                                    source=self.name)

    def _check_malformed_iend(self, ctx: AnalysisContext, info: png_core.PNGInfo) -> None:
        """检测畸形 IEND(length≠0 或 CRC 异常)。"""
        if not info.iend_chunk:
            return
        c = info.iend_chunk
        is_normal = (c.length == 0 and c.data == b"" and c.crc == png_core.NORMAL_IEND_CRC)
        if not is_normal:
            detail = f"length={c.length} (正常 0), CRC={c.crc.hex()} (正常 ae426082)"
            if c.length > 0:
                detail += f"\n        IEND 携带数据: {c.data.hex()}"
                detail += "\n        → IEND 的 data 字段被用来藏数据(misc13 套路, 可能是密钥/标记)"
            crc_ok = c.crc_ok
            detail += f"\n        CRC 校验: {'通过(刻意构造)' if crc_ok else '不匹配'}"
            ctx.add_finding("find", f"畸形 IEND! {detail}", source=self.name)

    def _analyze_zlib_streams(self, ctx: AnalysisContext, info: png_core.PNGInfo,
                              W: int, H: int, ch: int) -> None:
        """分析 IDAT 拼接后的 zlib 流边界 + 处理 extra data。"""
        if not info.idat_list:
            return
        all_idat = b"".join(info.idat_list)
        decoded, unused, ok = png_core.decompress_first_stream(all_idat)
        if not ok:
            ctx.add_finding("warn", "IDAT zlib 流解压失败", source=self.name)
            return

        ctx.add_finding("info", f"zlib 流解压: {len(decoded)} 字节")
        expected = png_core.expected_pixel_bytes_ihdr(info) or png_core.expected_pixel_bytes(W, H, ch)
        if len(decoded) == expected:
            ctx.add_finding("info", f"长度匹配 PNG scanline 数据 = {expected} → 正常图像数据")
        else:
            ctx.add_finding("warn", f"长度 {len(decoded)} ≠ 预期 {expected} → 可能尺寸被篡改")
            if info.ihdr and info.ihdr[2] == 8:
                self._brute_force_size(ctx, decoded, ch, W, H)
            else:
                ctx.add_finding(
                    "info",
                    "非 8-bit PNG 暂不做尺寸爆破",
                    "低 bit-depth PNG 的 scanline 存在位打包，避免误重建。",
                    source=self.name,
                )

        # extra data 处理(关键! 多种手法)
        if unused:
            ctx.add_finding(
                "find",
                f"zlib 流后仍有 {len(unused)} 字节未使用(extra data) → 隐藏 payload 强信号",
                source=self.name,
            )
            ctx.save_bytes("idat_unused.bin", unused, "zlib 流后的 extra data")
            # 存入 ctx 供 ExtraDataAnalyzer 复用
            ctx.png_info["unused_data"] = unused
            # 这里只做基础 stride/XOR 扫描; 完整解压(嗅探 LZMA/bzip2)交给 ExtraDataAnalyzer
            self._stride_xor_scan(ctx, unused)

    def _stride_xor_scan(self, ctx: AnalysisContext, blob: bytes) -> None:
        """对 extra data 做 stride 间隔采样 + 单字节 XOR 暴力(misc13 套路)。"""
        found_any = False
        # stride 采样(偶数位/奇数位)
        for stride in (2, 3, 4):
            for start in range(stride):
                sampled = blob[start::stride]
                # 直接扫描
                for m in FLAG_PAT.finditer(sampled):
                    s = m.group().decode("ascii", "replace")
                    ctx.add_flag(s, confidence="medium",
                                 source=f"{self.name} stride={stride},start={start}")
                    ctx.add_finding("find", f"stride={stride},start={start} 采样发现 flag: {s}")
                    found_any = True
                # ASCII 过滤后扫描
                filtered = bytes(b if 32 <= b < 127 else 0 for b in sampled)
                for m in FLAG_PAT.finditer(filtered):
                    s = m.group().decode("ascii", "replace")
                    ctx.add_flag(s, confidence="medium",
                                 source=f"{self.name} stride={stride},start={start} ascii")
                    ctx.add_finding("find", f"stride={stride},start={start}(ascii) 发现 flag: {s}")
                    found_any = True

        # 单字节 XOR + stride
        for key in range(1, 256):
            xored = bytes(b ^ key for b in blob)
            for stride in (2, 3):
                for start in range(stride):
                    sampled = xored[start::stride]
                    filtered = bytes(b if 32 <= b < 127 else 0 for b in sampled)
                    for m in FLAG_PAT.finditer(filtered):
                        s = m.group().decode("ascii", "replace")
                        ctx.add_flag(s, confidence="low",
                                     source=f"{self.name} XOR(0x{key:02x})+stride={stride}")
                        ctx.add_finding("find", f"XOR(0x{key:02x})+stride={stride} 发现 flag: {s}")
                        found_any = True

        if found_any:
            ctx.add_finding("hint", "发现多个 stride/XOR 候选 → 第一个最可能是真 flag",
                            "其余可能是出题人放的干扰副本(改了几个字符)", source=self.name)

    def _brute_force_size(
        self,
        ctx: AnalysisContext,
        decoded: bytes,
        ch: int,
        original_w: int = 0,
        original_h: int = 0,
    ) -> None:
        """尺寸爆破: 根据解压数据量找真实尺寸, 自动重建图。"""
        candidates = png_core.brute_force_dims(len(decoded), ch)
        if not candidates:
            ctx.add_finding("info", "未找到合理尺寸(数据可能非完整图像)")
            return
        candidates.sort(
            key=lambda item: (
                0 if original_w and item[0] == original_w and item[1] != original_h else
                1 if original_h and item[1] == original_h and item[0] != original_w else
                2,
                abs(item[1] - original_h) if original_h else 0,
                abs(item[0] - original_w) if original_w else 0,
            )
        )
        ctx.add_finding("find", f"找到 {len(candidates)} 个候选真实尺寸(前 10 个):",
                        "\n        ".join(f"{w}x{h}x{c}ch" for w, h, c in candidates[:10]),
                        source=self.name)
        # 自动重建最可信的若干候选，避免第一个候选恰好是错误比例。
        chosen: list[tuple[int, int, int]] = []
        for cand in candidates:
            if cand not in chosen:
                chosen.append(cand)
            if len(chosen) >= 5:
                break
        for idx, (w, h, c) in enumerate(chosen):
            png_bytes = png_core.build_png(decoded, w, h, c)
            name = "reconstructed_real_size.png" if idx == 0 else f"reconstructed_real_size_{w}x{h}.png"
            path = ctx.save_bytes(name, png_bytes, f"真实尺寸重建图 {w}x{h}", needs_review=True)
            ctx.add_finding("find", f"自动重建 {w}x{h} → {os.path.basename(path)}",
                            "请人工查看是否露出隐藏的下半部分(flag 文字)", source=self.name)

    def _check_multi_idat(self, ctx: AnalysisContext, info: png_core.PNGInfo,
                          W: int, H: int, ch: int) -> None:
        """检测每个 IDAT 是否带独立 zlib 头(多 IDAT 隐写)。

        misc10: 第 2 个 IDAT 是独立 zlib 流(解压得 flag 文本)
        misc11: 双 IDAT 各自是独立隐藏图
        """
        # 带 zlib 头的 IDAT
        independent = [(idx, off, length, hd) for idx, off, length, hd in info.idat_meta
                       if hd[:4] in ("789c", "7801", "78da")]
        if len(independent) >= 2:
            ctx.add_finding("find", f"发现 {len(independent)} 个 IDAT 带独立 zlib 头(多 IDAT 隐写)",
                            source=self.name)
            for idx, off, length, hd in independent:
                self._process_independent_idat(ctx, info, idx, W, H, ch)

        # 即使只有 1 个带 zlib 头, 第 2 个 IDAT 也可能是独立流(misc10: 49 字节小流)
        if len(info.idat_list) >= 2 and len(independent) < 2:
            # 尝试解压每个 IDAT(非第一个)
            for idx in range(1, len(info.idat_list)):
                idat_data = info.idat_list[idx]
                dec, _unused, ok = png_core.decompress_first_stream(idat_data)
                if ok and dec:
                    for f in find_flags_in_text(dec, source=f"{self.name} IDAT[{idx}]独立流"):
                        ctx.add_flag(f, confidence="high", source=f"{self.name} IDAT[{idx}]")
                        ctx.add_finding("find", f"IDAT[{idx}] 独立 zlib 流含 flag: {f}")
                    if dec and not find_flags_in_text(dec):
                        # 可能是隐藏图
                        if len(dec) == (png_core.expected_pixel_bytes_ihdr(info) or png_core.expected_pixel_bytes(W, H, ch)):
                            png_bytes = png_core.build_png(dec, W, H, ch)
                            ctx.save_bytes(f"hidden_idat{idx}.png", png_bytes,
                                           f"IDAT[{idx}] 独立流隐藏图", needs_review=True)
                            ctx.add_finding("find", f"IDAT[{idx}] 独立流是隐藏图({W}x{H})",
                                            source=self.name)

    def _process_independent_idat(self, ctx: AnalysisContext, info: png_core.PNGInfo,
                                  idx: int, W: int, H: int, ch: int) -> None:
        """处理一个带独立 zlib 头的 IDAT。"""
        # 独立 zlib 流可能从某个 IDAT 开始并跨越后续多个 IDAT。
        # 只解单个 chunk 会把完整隐藏图误判为小尺寸残片(misc12)。
        idat_data = b"".join(info.idat_list[idx:])
        dec, _unused, ok = png_core.decompress_first_stream(idat_data)
        if not ok:
            return
        # 是否含 flag 文本
        flags = find_flags_in_text(dec, source=f"{self.name} IDAT[{idx}]")
        for f in flags:
            ctx.add_flag(f, confidence="high", source=f"{self.name} IDAT[{idx}]")
            ctx.add_finding("find", f"IDAT[{idx}] 独立流含 flag: {f}")
        if flags:
            return
        # 是否是隐藏图
        if len(dec) == (png_core.expected_pixel_bytes_ihdr(info) or png_core.expected_pixel_bytes(W, H, ch)):
            png_bytes = png_core.build_png(dec, W, H, ch)
            ctx.save_bytes(f"hidden_idat{idx}.png", png_bytes,
                           f"IDAT[{idx}] 独立流隐藏图 {W}x{H}", needs_review=True)
            ctx.add_finding("find", f"IDAT[{idx}] 独立流是隐藏图({W}x{H})", source=self.name)
        else:
            # 猜尺寸
            guess = png_core.guess_size(len(dec))
            if guess:
                gw, gh, gch = guess
                png_bytes = png_core.build_png(dec, gw, gh, gch)
                ctx.save_bytes(f"hidden_idat{idx}_guess.png", png_bytes,
                               f"IDAT[{idx}] 猜尺寸 {gw}x{gh}", needs_review=True)
            else:
                ctx.save_bytes(f"idat{idx}_raw.bin", dec, f"IDAT[{idx}] 解压数据")
