"""LSB 隐写分析: zsteg 封装。

zsteg 是 PNG/BMP LSB 隐写最强工具。
"""
from __future__ import annotations

import subprocess

from .base import Analyzer, AnalysisContext
from ..flags import find_flags_in_text


class LSBAnalyzer(Analyzer):
    name = "阶段 6: LSB 隐写分析(zsteg)"
    applies_to = {"png", "bmp"}
    requires = {"zsteg"}

    def run(self, ctx: AnalysisContext) -> None:
        out = subprocess.run(
            ["zsteg", ctx.target], capture_output=True, text=True, timeout=60
        ).stdout
        ctx.save_bytes("zsteg_full.txt", out.encode("utf-8", "replace"), "完整 zsteg 输出")

        # 1. 附加数据信号
        for line in out.splitlines():
            if any(k in line.lower() for k in ("extra data", "extra bytes", "appended", "trailer")):
                ctx.add_finding("find", f"zsteg: {line.strip()}", source=self.name)

        # 2. 各通道的明文输出(不以 .. 结尾的行)
        for line in out.splitlines():
            line = line.strip()
            if not line or line.startswith("Meta") or line.startswith("[+] file"):
                continue
            # zsteg 输出格式: "b1 bgr lsb  .. text: ..." 或 "b1 r msb .. ..."
            if ":" in line:
                channel, content = line.split(":", 1)
                content = content.strip()
                # 提取 text: 后的内容
                if "text:" in content:
                    text = content.split("text:", 1)[1].strip().strip('"')
                elif "file:" in content:
                    text = content.split("file:", 1)[1].strip().strip('"')
                else:
                    text = content
                # 扫 flag
                for f in find_flags_in_text(text, source=f"{self.name} {channel.strip()}"):
                    ctx.add_flag(f, confidence="high", source=f"{self.name} {channel.strip()}")
                    ctx.add_finding("find", f"zsteg 通道 {channel.strip()} 发现 flag: {f}")
                # 有内容的通道(非 .. 纯噪声)
                if text and text != ".." and not text.startswith(".."):
                    if len(text) > 3 and any(c.isprintable() for c in text[:10]):
                        ctx.add_finding("hint", f"zsteg 通道有内容: {channel.strip()} = {text[:60]}",
                                        source=self.name)

        if not any("extra" in l.lower() for l in out.splitlines()):
            ctx.add_finding("info", "zsteg 无附加数据信号")

        # 3. zsteg 的 extradata 通道需要真正提取后递归分析。
        try:
            extracted = subprocess.run(
                ["zsteg", "-E", "extradata:0", ctx.target],
                capture_output=True, timeout=60,
            ).stdout
        except Exception:
            extracted = b""
        if extracted and extracted != ctx.data:
            path = ctx.save_bytes("zsteg_extradata0.bin", extracted, "zsteg -E extradata:0 提取数据")
            ctx.add_finding("find", f"zsteg extradata:0 提取 {len(extracted)}B → {path}",
                            source=self.name)
            from .extra_data import process_blob

            process_blob(ctx, extracted, "zsteg_extradata0")
