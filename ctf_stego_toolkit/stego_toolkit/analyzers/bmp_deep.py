"""BMP 专项: 头部 gap 区扫描 + 像素 LSB。

misc15: flag 在 BMP 头部 gap 区(palette 与像素数据之间)
"""
from __future__ import annotations

import struct

from .base import Analyzer, AnalysisContext
from ..flags import find_flags_in_text


class BMPDeepAnalyzer(Analyzer):
    name = "阶段 5d: BMP 专项分析"
    applies_to = {"bmp"}
    requires = set()

    def run(self, ctx: AnalysisContext) -> None:
        data = ctx.data
        if len(data) < 54 or data[:2] != b"BM":
            return

        # BMP 头解析
        file_size = struct.unpack("<I", data[2:6])[0]
        pixel_offset = struct.unpack("<I", data[10:14])[0]
        header_size = struct.unpack("<I", data[14:18])[0]
        width = struct.unpack("<i", data[18:22])[0]
        height = struct.unpack("<i", data[22:26])[0]
        bpp = struct.unpack("<H", data[28:30])[0]

        ctx.add_finding(
            "info",
            f"BMP: {width}x{height}, {bpp}bpp, header={header_size}B, pixel_offset={pixel_offset}",
        )

        # 1. 头部 gap 区(palette 结束 到 像素数据开始): 常藏 flag
        # BMP V3 头部 40B + 调色板(若 bpp<=8)
        gap_start = 14 + header_size
        if bpp <= 8:
            palette_size = (2 ** bpp) * 4
            gap_start += palette_size
        gap_end = pixel_offset
        if gap_end > gap_start and gap_end <= len(data):
            gap = data[gap_start:gap_end]
            for f in find_flags_in_text(gap, source=f"{self.name} 头部gap"):
                ctx.add_flag(f, confidence="high", source=f"{self.name} BMP头部gap")
                ctx.add_finding("find", f"BMP 头部 gap 区({gap_start}-{gap_end}) 含 flag: {f}")
            if gap and not find_flags_in_text(gap):
                # 可疑的非零 gap
                non_zero = sum(1 for b in gap if b != 0)
                if non_zero > 4:
                    ctx.add_finding("hint", f"BMP 头部 gap 区有 {non_zero}B 非零数据, 可能有线索",
                                    gap[:60].hex(), source=self.name)

        # 2. 扫描整个文件(兜底)
        for f in find_flags_in_text(data, source=f"{self.name} 全文件"):
            ctx.add_flag(f, confidence="high", source=f"{self.name} 全文件")
