"""视觉文本分析: 保存图像 + 可插拔 OCR(tesseract)。

misc1, misc4: 像素里画的文字
misc8: IEND 后嵌套 PNG(由 extra_data 提取, 这里做 OCR)
misc14: 隐藏缩略图里的文字

tesseract 缺失时: 保存增强图, 提示人工/AI 查看。
"""
from __future__ import annotations

import os
import re
import subprocess

from .base import Analyzer, AnalysisContext
from ..flags import find_loose_visual_flags, find_normalized_flags, normalize_hexish_body, prefix_alternation


# OCR 字符白名单：hex 字符 + 大括号 + ctfshow 平台前缀字母（解题时常见平台）。
HEX_OCR_WHITELIST = "0123456789abcdefABCDEFctfshow{}"
_PREFIX_FRAGMENT_RE = re.compile(
    rf"({prefix_alternation()})\s*\{{\s*([^}}\r\n]{{0,80}})",
    re.IGNORECASE,
)
_HEXISH_FRAGMENT_RE = re.compile(r"[0-9A-Fa-fOQlI|/\\?BSsg]{4,80}\}?")


def try_ocr(image_path: str, use_gocr: bool = False) -> str:
    """用 tesseract 对图像做 OCR, 返回识别文本。"""
    commands = [
        ["tesseract", image_path, "stdout", "-l", "eng", "--psm", "6"],
        ["tesseract", image_path, "stdout", "-l", "eng", "--psm", "7"],
        [
            "tesseract", image_path, "stdout", "-l", "eng", "--psm", "6",
            "-c", f"tessedit_char_whitelist={HEX_OCR_WHITELIST}",
        ],
        [
            "tesseract", image_path, "stdout", "-l", "eng", "--psm", "7",
            "-c", f"tessedit_char_whitelist={HEX_OCR_WHITELIST}",
        ],
    ]
    texts: list[str] = []
    if use_gocr:
        try:
            out = subprocess.run(["gocr", image_path], capture_output=True, text=True, timeout=10).stdout.strip()
            if out and out not in texts:
                texts.append(out)
        except Exception:
            pass
    try:
        for cmd in commands:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout.strip()
            if out and out not in texts:
                texts.append(out)
    except Exception:
        pass
    return "\n".join(texts)


def enhance_and_save(ctx: AnalysisContext, src_path: str, prefix: str) -> None:
    """用 ImageMagick 对图像做放大/增强对比度, 保存为 OCR 友好版本。"""
    if not ctx.tools.have("convert"):
        return
    enhanced = os.path.join(ctx.outdir, f"{prefix}_enhanced.png")
    try:
        subprocess.run(
            ["convert", src_path, "-resize", "400%", "-colorspace", "gray",
             "-normalize", "-sharpen", "0x1", enhanced],
            capture_output=True, timeout=30,
        )
        if os.path.exists(enhanced):
            ctx.add_artifact(enhanced, f"{prefix} 增强版(放大+灰度+锐化, 利于 OCR)", needs_review=True)
    except Exception:
        pass


def color_text_mask(ctx: AnalysisContext, src_path: str, prefix: str) -> str:
    """提取彩色文字掩码。

    有些题把真 flag 用黄色/彩色小字放在白底上；灰度化会极大降低对比度。
    这里保留高饱和、非白色像素为黑色，其余置白。
    """
    try:
        from PIL import Image
    except Exception:
        return ""
    try:
        im = Image.open(src_path).convert("RGB")
        pixels = []
        for r, g, b in im.getdata():
            mx = max(r, g, b)
            mn = min(r, g, b)
            bright = (r + g + b) / 3
            if mx - mn >= 45 and 40 <= bright <= 245:
                pixels.append(0)
            else:
                pixels.append(255)
        mask = Image.new("L", im.size)
        mask.putdata(pixels)
        black_rows = []
        width, height = mask.size
        mask_pixels = list(mask.getdata())
        for y in range(height):
            count = sum(1 for x in range(width) if mask_pixels[y * width + x] == 0)
            if count >= max(3, width // 80):
                black_rows.append(y)
        if black_rows:
            top = max(0, min(black_rows) - 2)
            bottom = min(height, max(black_rows) + 3)
            # If there are sparse colored speckles above the real text, keep the
            # densest lower band as an extra-friendly OCR target.
            if bottom - top > height // 2:
                row_counts = [
                    (sum(1 for x in range(width) if mask_pixels[y * width + x] == 0), y)
                    for y in range(height)
                ]
                dense_rows = [y for count, y in row_counts if count >= sorted(row_counts, reverse=True)[0][0] * 0.35]
                if dense_rows:
                    top = max(0, min(dense_rows) - 2)
                    bottom = min(height, max(dense_rows) + 3)
            mask = mask.crop((0, top, width, bottom))
        if pixels.count(0) < max(6, im.size[0] // 20):
            return ""
        out = os.path.join(ctx.outdir, f"{prefix}_color_text_mask.png")
        mask = mask.resize((mask.width * 6, mask.height * 6))
        mask.save(out)
        ctx.add_artifact(out, f"{prefix} 彩色文字掩码", needs_review=True)
        return out
    except Exception:
        return ""


class VisualAnalyzer(Analyzer):
    name = "阶段 7: 视觉文本分析(OCR)"
    applies_to = None  # 处理原图 + 所有提取出的图像 artifact
    requires = set()

    def run(self, ctx: AnalysisContext) -> None:
        if any(flag.confidence == "high" for flag in ctx.flags):
            ctx.add_finding(
                "info",
                "已有高置信 flag, 跳过耗时 OCR",
                "如需人工复核, 可直接查看已保存的图像 artifact。",
                source=self.name,
            )
            return

        # 收集所有"可能是图像且需 OCR"的文件
        image_files: list[tuple[str, str]] = []  # (path, description)

        # 原图(若是图像)
        if ctx.real_type in ("png", "jpg", "gif", "bmp", "tiff", "webp"):
            image_files.append((ctx.target, "原图"))

        # 之前分析器产出的 needs_review 图像 artifact
        for a in ctx.artifacts:
            if a.needs_review and os.path.isfile(a.path):
                ext = os.path.splitext(a.path)[1].lower()
                if ext in (".png", ".jpg", ".jpeg", ".bmp", ".gif", ".tif", ".tiff", ".webp"):
                    image_files.append((a.path, a.description))

        if not image_files:
            return

        has_tesseract = ctx.tools.have("tesseract")
        has_gocr = ctx.tools.have("gocr")
        ocr_results: list[tuple[str, str]] = []

        if has_tesseract and len(image_files) > 50:
            ctx.add_finding(
                "hint",
                f"OCR 图像候选过多({len(image_files)}), 仅自动识别前 50 个",
                "其余帧已保存为 artifact, 可人工查看；动画延迟/结构编码由其他分析器处理。",
                source=self.name,
            )
            image_files = image_files[:50]

        for img_path, desc in image_files:
            base = os.path.splitext(os.path.basename(img_path))[0]

            if has_tesseract or has_gocr:
                # 先增强(若是小图)
                enhance_and_save(ctx, img_path, base)
                enhanced = os.path.join(ctx.outdir, f"{base}_enhanced.png")
                target_ocr_paths = [enhanced if os.path.exists(enhanced) else img_path]
                mask = color_text_mask(ctx, img_path, base)
                if mask:
                    target_ocr_paths.append(mask)

                texts: list[str] = []
                for target_ocr in target_ocr_paths:
                    text = try_ocr(target_ocr, use_gocr=has_gocr)
                    if text and text not in texts:
                        texts.append(text)
                text = "\n".join(texts)
                if text:
                    ocr_results.append((base, text))
                    ctx.save_bytes(f"{base}_ocr.txt", text.encode("utf-8", "replace"),
                                   f"{desc} OCR 结果")
                    # 在 OCR 结果里找 flag
                    for f in find_normalized_flags(text):
                        ctx.add_flag(f, confidence="medium", source=f"{self.name} OCR {base}")
                        ctx.add_finding("find", f"OCR({base}) 识别出 flag: {f}")
                    for f in find_loose_visual_flags(text):
                        ctx.add_flag(f, confidence="medium", source=f"{self.name} loose OCR {base}")
                        ctx.add_finding("find", f"OCR({base}) 宽松重建出 flag: {f}")
                    if text and len(text) > 3:
                        ctx.add_finding(
                            "hint", f"OCR({base}) 文本: {text[:80]}",
                            "OCR 对艺术字体可能不准, 请人工复核图像", source=self.name,
                        )
            else:
                # 无 tesseract: 只提示
                ctx.add_finding(
                    "hint",
                    f"{desc} 可能含文字, 但 tesseract 缺失, 无法自动 OCR",
                    f"图像: {img_path}\n"
                    "        请用图像查看器/AI 视觉人工查看, 或安装 tesseract:\n"
                    "        apt install tesseract-ocr | dnf install tesseract",
                    source=self.name,
                )

        if not (has_tesseract or has_gocr):
            ctx.add_finding(
                "warn",
                "OCR 工具缺失 — 视觉类题目(像素文字)无法自动识别",
                "apt install tesseract-ocr gocr | dnf install tesseract gocr",
            )
        elif ocr_results:
            self._assemble_frame_fragments(ctx, ocr_results)

    def _assemble_frame_fragments(
        self,
        ctx: AnalysisContext,
        ocr_results: list[tuple[str, str]],
    ) -> None:
        """按 OCR 顺序拼接多帧/多图碎片。

        CTFShow 的 GIF/APNG 题常把 ``ctfshow{...}`` 切成几帧。单帧不是完整
        flag, 但按帧序拼接 hex 片段后能恢复。
        """
        fragments: list[tuple[str, str, bool, str]] = []
        for base, text in ocr_results:
            compact = re.sub(r"\s+", "", text)
            matched_prefix = False
            for match in _PREFIX_FRAGMENT_RE.finditer(compact):
                prefix = match.group(1).lower()
                body = normalize_hexish_body(match.group(2))
                if body:
                    fragments.append((prefix, body, "}" in match.group(0), base))
                    matched_prefix = True
            if matched_prefix:
                continue
            # 无前缀的帧只收 hex-ish 片段，供前一帧的前缀继续拼接。
            pieces = []
            has_tail = False
            for match in _HEXISH_FRAGMENT_RE.finditer(compact):
                raw = match.group(0)
                has_tail = has_tail or raw.endswith("}")
                body = normalize_hexish_body(raw)
                if body:
                    pieces.append(body)
            if pieces:
                fragments.append(("", "".join(pieces), has_tail, base))

        for i, (prefix, body, has_tail, base) in enumerate(fragments):
            if not prefix:
                continue
            acc = body
            involved = [base]
            for _next_prefix, next_body, next_tail, next_base in fragments[i + 1 : i + 12]:
                if _next_prefix:
                    break
                acc += next_body
                involved.append(next_base)
                if len(acc) >= 32:
                    candidate = f"{prefix}{{{acc[:32]}}}"
                    if re.fullmatch(rf"(?:{prefix_alternation()})\{{[0-9a-f]{{32}}\}}", candidate, re.I):
                        ctx.add_flag(candidate, confidence="medium", source=f"{self.name} 多帧OCR拼接")
                        ctx.add_finding(
                            "find",
                            f"多帧 OCR 片段拼接得到: {candidate}",
                            f"涉及图像: {', '.join(involved)}",
                            source=self.name,
                        )
                        break
                if next_tail:
                    break
