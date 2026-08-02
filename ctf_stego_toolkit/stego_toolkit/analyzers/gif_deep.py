"""GIF 专项: 拆帧 + 注释扩展块 + 末尾数据。

帧动画隐写极常见: 某一帧含文字/二维码。
"""
from __future__ import annotations

import os
import subprocess

from .base import Analyzer, AnalysisContext
from ..flags import find_flags_in_text


class GIFDeepAnalyzer(Analyzer):
    name = "阶段 5e: GIF 专项分析"
    applies_to = {"gif"}
    requires = set()

    def run(self, ctx: AnalysisContext) -> None:
        data = ctx.data

        # 1. 拆帧(ImageMagick convert)
        if ctx.tools.have("convert"):
            frames_dir = os.path.join(ctx.outdir, "gif_frames")
            os.makedirs(frames_dir, exist_ok=True)
            try:
                subprocess.run(
                    ["convert", ctx.target, "-coalesce", os.path.join(frames_dir, "frame_%03d.png")],
                    capture_output=True, timeout=60,
                )
                frames = sorted(
                    f for f in os.listdir(frames_dir) if f.endswith(".png")
                )
                if len(frames) > 1:
                    ctx.add_finding("find", f"GIF 有 {len(frames)} 帧, 已拆分 → gif_frames/",
                                    "逐帧查看找异常帧(含文字/二维码)", source=self.name)
                    for fn in frames:
                        ctx.add_artifact(os.path.join(frames_dir, fn),
                                         f"GIF 帧 {fn}", needs_review=True)
                elif frames:
                    ctx.add_finding("info", "GIF 仅 1 帧(静态)")
            except Exception as e:
                ctx.add_finding("warn", f"convert 拆帧失败: {e}")
        else:
            ctx.add_finding("warn", "convert(ImageMagick) 缺失, 无法拆 GIF 帧",
                            "apt install imagemagick | dnf install ImageMagick")

        # 2. 扫描注释扩展块(0x21 0xFE)
        pos = 0
        while pos < len(data) - 2:
            if data[pos] == 0x21 and data[pos + 1] == 0xFE:
                # 注释扩展: 后续是子块(1字节长度+数据, 0x00 结束)
                pos += 2
                comment = bytearray()
                while pos < len(data):
                    block_size = data[pos]
                    pos += 1
                    if block_size == 0:
                        break
                    comment += data[pos : pos + block_size]
                    pos += block_size
                ctx.add_finding("info", f"GIF 注释扩展块: {len(comment)}B")
                for f in find_flags_in_text(comment, source=f"{self.name} 注释块"):
                    ctx.add_flag(f, confidence="high", source=f"{self.name} GIF注释块")
                    ctx.add_finding("find", f"GIF 注释块含 flag: {f}")
            else:
                pos += 1

        # 3. 整体扫描(兜底)
        for f in find_flags_in_text(data, source=f"{self.name} 全文件"):
            ctx.add_flag(f, confidence="high", source=f"{self.name} GIF全文件")
