"""二维码/条码识别。

CTF 图片题常把 flag 放进 QR Code、DataMatrix、Code128 等图形码中。
该分析器使用 zbarimg 扫描原图以及前面分析器产出的图像 artifact，包括
位平面重建图、EXIF 缩略图、binwalk 提取图等。
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

from .base import Analyzer, AnalysisContext
from ..flags import scan_flags


class BarcodeAnalyzer(Analyzer):
    name = "阶段 6d: 二维码/条码识别(zbarimg)"
    applies_to = None
    requires = {"zbarimg"}

    IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".tif", ".tiff", ".webp"}

    def run(self, ctx: AnalysisContext) -> None:
        candidates: list[str] = []
        if ctx.real_type in {"png", "jpg", "gif", "bmp", "tiff", "webp"}:
            candidates.append(ctx.target)
        for artifact in ctx.artifacts:
            if artifact.needs_review and os.path.isfile(artifact.path):
                if Path(artifact.path).suffix.lower() in self.IMAGE_EXTS:
                    candidates.append(artifact.path)
        # 去重 + 限制，避免动画拆出大量帧时 zbarimg 变慢。
        seen: set[str] = set()
        unique = []
        for item in candidates:
            if item not in seen:
                seen.add(item)
                unique.append(item)
        if len(unique) > 80:
            ctx.add_finding("hint", f"图像候选过多({len(unique)}), zbarimg 仅扫描前 80 个", source=self.name)
            unique = unique[:80]

        decoded_records: list[str] = []
        for path in unique:
            decoded = self._scan_one(path)
            if not decoded:
                continue
            rel = os.path.basename(path)
            for value in decoded:
                decoded_records.append(f"{rel}: {value}")
                ctx.add_finding("find", f"zbarimg({rel}) 解码: {value[:120]}", source=self.name)
                for flag in scan_flags(value.encode("utf-8", "replace"), source=f"{self.name} {rel}"):
                    ctx.add_flag(flag.value, confidence=flag.confidence, source=flag.source)
                    ctx.add_finding("find", f"条码内容包含 flag: {flag.value}", source=self.name)

        if decoded_records:
            ctx.save_bytes(
                "barcode_zbarimg_results.txt",
                ("\n".join(decoded_records) + "\n").encode("utf-8", "replace"),
                "zbarimg 解码结果",
            )
        else:
            ctx.add_finding("info", "zbarimg 未识别到二维码/条码", source=self.name)

    def _scan_one(self, path: str) -> list[str]:
        outputs: list[str] = []
        for cmd in (["zbarimg", "--raw", "-q", path], ["zbarimg", "-q", path]):
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            except Exception:
                continue
            text = proc.stdout.strip()
            if not text:
                continue
            for line in text.splitlines():
                value = line.strip()
                if not value:
                    continue
                if ":" in value and not cmd[1:2] == ["--raw"]:
                    value = value.split(":", 1)[1]
                if value not in outputs:
                    outputs.append(value)
        return outputs
