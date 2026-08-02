"""TIFF 专项: EXIF 字段扫描 + 附加数据。

misc19: flag 分割在 DocumentName + HostComputer (由 metadata 处理, 这里兜底扫描)
"""
from __future__ import annotations

from .base import Analyzer, AnalysisContext
from ..flags import find_flags_in_text


class TIFFDeepAnalyzer(Analyzer):
    name = "阶段 5f: TIFF 专项分析"
    applies_to = {"tiff"}
    requires = set()

    def run(self, ctx: AnalysisContext) -> None:
        data = ctx.data
        # TIFF 的 EXIF 由 exiftool(metadata 分析器)覆盖
        # 这里做兜底: 全文件 flag 扫描 + 检查附加数据
        for f in find_flags_in_text(data, source=f"{self.name} 全文件"):
            ctx.add_flag(f, confidence="high", source=f"{self.name} TIFF全文件")
            ctx.add_finding("find", f"TIFF 中发现 flag: {f}")

        ctx.add_finding("info", "TIFF 主要依赖 exiftool(见阶段 2); 帧分割/附加数据已兜底扫描")
