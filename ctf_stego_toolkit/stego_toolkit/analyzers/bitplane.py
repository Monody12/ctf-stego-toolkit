"""通用位平面可视化。

这类题不一定会在 zsteg 中直接出现明文；常见做法是把二维码、文字或
另一张图画在 R/G/B/A 的低位。该分析器不猜答案，只产出少量高价值图像
artifact，供后续 Barcode/OCR 自动扫描，也便于人工查看。
"""
from __future__ import annotations

import os
from pathlib import Path

from .base import Analyzer, AnalysisContext


class BitPlaneAnalyzer(Analyzer):
    name = "阶段 6c: 通用位平面可视化"
    applies_to = {"png", "jpg", "gif", "bmp", "tiff", "webp"}
    requires = set()

    def run(self, ctx: AnalysisContext) -> None:
        if any(flag.confidence == "high" for flag in ctx.flags):
            ctx.add_finding("info", "已有高置信 flag, 跳过位平面产物生成", source=self.name)
            return
        try:
            from PIL import Image, ImageDraw
        except Exception:
            ctx.add_finding("warn", "Pillow 缺失, 无法生成位平面图", source=self.name)
            return

        try:
            im = Image.open(ctx.target)
            # GIF/APNG/TIFF 多帧题另有专项分析器，这里只取当前帧做通用位平面。
            im.seek(0)
            rgba = im.convert("RGBA")
        except Exception as exc:
            ctx.add_finding("warn", f"图像无法用 Pillow 打开, 跳过位平面: {exc}", source=self.name)
            return

        width, height = rgba.size
        if width * height > 6_000_000:
            ctx.add_finding("hint", "图像过大, 跳过位平面可视化", f"{width}x{height}", source=self.name)
            return

        basename = Path(ctx.target).stem
        pixels = list(rgba.getdata())
        channels = ("R", "G", "B", "A")

        # 1-bit RGB 重建图: 常见于把一张黑白图/二维码藏在 RGB LSB。
        for bit in (0, 1):
            out_img = Image.new("RGB", (width, height))
            out_img.putdata([
                tuple(255 if ((px[idx] >> bit) & 1) else 0 for idx in range(3))
                for px in pixels
            ])
            if self._is_nontrivial(out_img):
                out = os.path.join(ctx.outdir, f"{basename}_rgb_bit{bit}.png")
                out_img.save(out)
                ctx.add_artifact(out, f"RGB 第 {bit} 位重建图", needs_review=True)

        # 每通道低 4 位接触图。单张接触图比 12 个散图更易维护。
        planes: list[tuple[str, object]] = []
        for idx, ch_name in enumerate(channels):
            if ch_name == "A" and all(px[3] == 255 for px in pixels):
                continue
            for bit in range(4):
                plane = Image.new("L", (width, height))
                plane.putdata([255 if ((px[idx] >> bit) & 1) else 0 for px in pixels])
                if self._is_nontrivial(plane):
                    planes.append((f"{ch_name}{bit}", plane))

        if planes:
            sheet = self._contact_sheet(planes, ImageDraw)
            out = os.path.join(ctx.outdir, f"{basename}_bitplanes_low_contact.png")
            sheet.save(out)
            ctx.add_artifact(out, "R/G/B/A 低 4 位位平面接触图", needs_review=True)
            ctx.add_finding(
                "hint",
                f"已生成 {len(planes)} 个低位位平面接触图",
                "若 flag 是二维码/文字，后续 Barcode/OCR 阶段会继续扫描该 artifact。",
                source=self.name,
            )

    def _is_nontrivial(self, image: object) -> bool:
        try:
            hist = image.convert("L").histogram()  # type: ignore[attr-defined]
        except Exception:
            return False
        total = sum(hist)
        if total <= 0:
            return False
        black = sum(hist[:16])
        white = sum(hist[240:])
        # 全白/全黑或几乎全单色没有复核价值。
        return not (black / total > 0.995 or white / total > 0.995)

    def _contact_sheet(self, planes: list[tuple[str, object]], ImageDraw: object) -> object:
        from PIL import Image

        thumb_w = 260
        label_h = 18
        margin = 8
        cols = min(4, max(1, len(planes)))
        thumbs = []
        for label, plane in planes:
            im = plane.convert("L")  # type: ignore[attr-defined]
            scale = min(thumb_w / im.width, 180 / im.height, 1.0)
            new_size = (max(1, int(im.width * scale)), max(1, int(im.height * scale)))
            thumb = im.resize(new_size)
            canvas = Image.new("RGB", (thumb_w, new_size[1] + label_h), "white")
            canvas.paste(thumb.convert("RGB"), ((thumb_w - thumb.width) // 2, label_h))
            draw = ImageDraw.Draw(canvas)
            draw.text((3, 2), label, fill=(0, 0, 0))
            thumbs.append(canvas)
        rows = (len(thumbs) + cols - 1) // cols
        cell_h = max(t.height for t in thumbs)
        sheet = Image.new("RGB", (cols * (thumb_w + margin) + margin, rows * (cell_h + margin) + margin), "white")
        for idx, thumb in enumerate(thumbs):
            x = margin + (idx % cols) * (thumb_w + margin)
            y = margin + (idx // cols) * (cell_h + margin)
            sheet.paste(thumb, (x, y))
        return sheet
