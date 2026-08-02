"""binwalk 扫描与提取: 检测嵌入的压缩文件(LZMA/bzip2/gzip/ZIP/PNG)并提取。

misc16: zlib 流后的 extra data 含 LZMA 流
misc17: extra data 含 bzip2 → 解压出隐藏 PNG
"""
from __future__ import annotations

import os
import subprocess

from .base import Analyzer, AnalysisContext
from ..flags import find_flags_in_text, scan_flags


class BinwalkAnalyzer(Analyzer):
    name = "阶段 4: binwalk 结构分析"
    applies_to = None
    requires = {"binwalk"}

    def run(self, ctx: AnalysisContext) -> None:
        out = subprocess.run(
            ["binwalk", ctx.target], capture_output=True, text=True, timeout=60
        ).stdout
        # 统计识别出的签名数
        sig_lines = [l for l in out.splitlines() if l and l[0].isdigit()]
        ctx.save_bytes("binwalk_scan.txt", out.encode("utf-8", "replace"), "binwalk 扫描结果")

        if len(sig_lines) <= 1:
            ctx.add_finding("info", "binwalk 仅识别出主文件, 无附加结构")
            return

        ctx.add_finding("find", f"binwalk 识别出 {len(sig_lines)} 个结构(可能有附加文件)",
                        "\n".join(sig_lines[:10]), source=self.name)

        # 提取
        extract_dir = os.path.join(ctx.outdir, "binwalk_extract")
        os.makedirs(extract_dir, exist_ok=True)
        try:
            subprocess.run(
                ["binwalk", "-e", "-C", extract_dir, ctx.target],
                capture_output=True, timeout=120,
            )
        except Exception as e:
            ctx.add_finding("warn", f"binwalk -e 提取失败: {e}")
            return

        # 扫描提取出的所有文件
        extracted_files = []
        for root, _dirs, files in os.walk(extract_dir):
            for fn in files:
                extracted_files.append(os.path.join(root, fn))

        if extracted_files:
            ctx.add_finding("find", f"binwalk 提取出 {len(extracted_files)} 个文件",
                            "扫描每个文件的 flag + 文件头...", source=self.name)
            for ef in extracted_files:
                try:
                    with open(ef, "rb") as f:
                        edata = f.read()
                except Exception:
                    continue
                # flag 扫描
                for fl in scan_flags(edata, source=f"{self.name} 提取:{os.path.basename(ef)}"):
                    ctx.add_flag(fl.value, confidence=fl.confidence, source=fl.source)
                    ctx.add_finding("find", f"提取文件 {os.path.basename(ef)} 含 flag: {fl.value}")
                # 登记为 artifact(若是图像则需人工)
                from .filetype import MAGIC_MAP
                is_image = any(edata.startswith(m) for m, _, _ in MAGIC_MAP)
                ctx.add_artifact(
                    ef,
                    f"binwalk 提取: {os.path.basename(ef)}",
                    needs_review=is_image,
                )
