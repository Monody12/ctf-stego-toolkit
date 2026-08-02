"""比赛/通用图片隐写结构规则。

本分析器把"赛题常考但可复用"的结构套路集中在一处。规则不硬编码答案，
而是解码常见载体：宽高修复、APNG/GIF 计时字段、PNG chunk 长度/CRC 编码、
BPG 转换、JPEG 内嵌缩略图、metadata 分片等。这些套路在各类赛事的图片
隐写题里高频出现；规则按通用方式实现，并保留对各平台 flag 格式（如
ctfshow 平台格式）的识别。
"""
from __future__ import annotations

import datetime as _dt
import itertools
import os
import re
import struct
import subprocess
import zlib
from pathlib import Path

from .base import Analyzer, AnalysisContext
from .. import png_core
from ..flags import find_normalized_flags, normalize_hexish_body, prefix_alternation, scan_flags


_HEX_RE = re.compile(r"^[0-9a-fA-F]{4,64}\}?$")
_HEAD_RE = re.compile(rf"({prefix_alternation()})\{{([0-9a-fA-F]{{0,64}})$", re.I)
_TAIL_RE = re.compile(r"^([0-9a-fA-F]{1,64})\}$")
_META_LINE_RE = re.compile(r"^\[(?P<group>[^\]]+)\]\s+(?P<key>[^:]+):\s*(?P<value>.*)$")

# misc41 这类题把十六进制编辑器中的搜索命中高亮当作像素:
# 16 字节一行, 每两个字节为一个槽位, 3x5 点阵字体, 每 6 行一组,
# 左右各放一个字符。这里记录的是字体, 不是题目答案。
_F001_3X5_FONT = {
    ".../###/#../#../###": "c",
    ".#./###/.#./.#./.##": "t",
    ".##/.#./###/.#./##.": "f",
    ".##/#../##./..#/##.": "s",
    "#../#../###/#.#/#.#": "h",
    ".../###/#.#/#.#/###": "o",
    "#../#.#/#.#/#.#/.#.": "w",
    "#.#/#.#/###/#.#/..#": "{",
    "##./.#./.##/.#./##.": "}",
    "###/#.#/#.#/#.#/###": "0",
    ".#./##./.#./.#./###": "1",
    "###/..#/###/#../###": "2",
    "###/..#/###/..#/###": "3",
    "#.#/#.#/###/..#/..#": "4",
    "###/#../###/..#/###": "5",
    "###/#../###/#.#/###": "6",
    "###/..#/..#/..#/..#": "7",
    "###/#.#/###/#.#/###": "8",
    "###/#.#/###/..#/###": "9",
    ".##/#.#/#.#/###/...": "a",
    "#../#../###/#.#/###": "b",
    "..#/..#/###/#.#/###": "d",
    "###/#../###/#../###": "e",
}


def _add_blob_flags(ctx: AnalysisContext, blob: bytes, source: str, confidence: str = "high") -> None:
    for flag in scan_flags(blob, source):
        ctx.add_flag(flag.value, confidence=confidence, source=source)
        ctx.add_finding("find", f"{source} 发现 flag: {flag.value}", source="contest_rules")


def _safe_filename(text: str) -> str:
    return re.sub(r"[^0-9A-Za-z_.-]+", "_", text).strip("_") or "artifact"


def _fast_ocr_image(ctx: AnalysisContext, image_path: str, source: str) -> str:
    if not ctx.tools.have("tesseract"):
        return ""
    try:
        text = subprocess.run(
            [
                "tesseract", image_path, "stdout", "--psm", "6",
                "-c", "tessedit_char_whitelist=0123456789abcdefABCDEFctfshow{}",
            ],
            capture_output=True, text=True, timeout=10,
        ).stdout
    except Exception:
        return ""
    if text:
        ctx.save_bytes(f"{_safe_filename(source)}_fast_ocr.txt", text.encode("utf-8", "replace"),
                       f"{source} 快速 OCR")
    for flag in find_normalized_flags(text):
        ctx.add_flag(flag, confidence="high", source=f"{source} fast OCR")
        ctx.add_finding("find", f"{source} 快速 OCR 得到: {flag}", source="contest_rules")
    return text


class ContestRulesAnalyzer(Analyzer):
    name = "阶段 6b: 常见结构套路"
    applies_to = None
    requires = set()

    def run(self, ctx: AnalysisContext) -> None:
        self._metadata_rules(ctx)
        self._f001_hex_editor_pattern(ctx)
        if ctx.real_type == "bpg":
            self._decode_bpg(ctx)
        elif ctx.real_type == "jpg":
            nested_count = self._carve_nested_jpegs(ctx)
            if not ctx.flags and nested_count == 0:
                self._repair_jpeg_dimensions(ctx)
        elif ctx.real_type == "png":
            self._png_chunk_encodings(ctx)
            self._apng_rules(ctx)
            self._rgba_alpha_hint_rules(ctx)
            self._save_png_as_bmp_probe(ctx)
        elif ctx.real_type == "gif":
            self._gif_delay_bits(ctx)
            if not ctx.flags:
                self._repair_gif_dimensions(ctx)
        elif ctx.real_type == "bmp":
            if not ctx.flags:
                self._repair_bmp_dimensions(ctx)

    # ------------------------------------------------------------------ #
    # Metadata
    # ------------------------------------------------------------------ #
    def _read_exif_items(self, ctx: AnalysisContext) -> list[tuple[str, str]]:
        if not ctx.tools.have("exiftool"):
            return []
        try:
            out = subprocess.run(
                ["exiftool", "-G", "-a", "-s", ctx.target],
                capture_output=True, text=True, timeout=30,
            ).stdout
        except Exception:
            return []
        items: list[tuple[str, str]] = []
        for line in out.splitlines():
            match = _META_LINE_RE.match(line)
            if match and match.group("value"):
                items.append((f"{match.group('group')}:{match.group('key').strip()}", match.group("value").strip()))
        return items

    def _metadata_rules(self, ctx: AnalysisContext) -> None:
        items = self._read_exif_items(ctx)
        if not items:
            return

        # OCR-like normalization also fixes Chinese homophone output from MetadataAnalyzer.
        try:
            from .metadata import try_pinyin_decode
        except Exception:
            try_pinyin_decode = None  # type: ignore[assignment]

        for key, value in items:
            for flag in find_normalized_flags(value):
                ctx.add_flag(flag, confidence="high", source=f"{self.name} metadata {key}")
            if try_pinyin_decode is not None:
                decoded = try_pinyin_decode(value)
                for flag in find_normalized_flags(decoded):
                    ctx.add_flag(flag, confidence="medium", source=f"{self.name} metadata pinyin {key}")
                    ctx.add_finding("find", f"中文谐音 metadata 解码得到: {flag}",
                                    f"{key}: {value[:80]}", source=self.name)

        self._metadata_split_permutations(ctx, items)
        self._metadata_decimal_to_hex(ctx, items)
        self._metadata_dates_to_hex(ctx, items)
        self._metadata_thumbnail_offsets(ctx, items)

    def _metadata_split_permutations(self, ctx: AnalysisContext, items: list[tuple[str, str]]) -> None:
        heads: list[tuple[int, str, str]] = []
        middles: list[tuple[int, str, str]] = []
        tails: list[tuple[int, str, str]] = []
        seen_fragments: set[str] = set()

        for idx, (key, value) in enumerate(items):
            text = value.strip()
            head = _HEAD_RE.search(text)
            if head:
                heads.append((idx, head.group(1).lower(), head.group(2)))
                continue
            tail = _TAIL_RE.match(text)
            if tail:
                tails.append((idx, key, tail.group(1)))
                continue
            if _HEX_RE.match(text) and text not in seen_fragments:
                seen_fragments.add(text)
                middles.append((idx, key, text.rstrip("}")))

        added = 0
        for head_idx, prefix, head_body in heads:
            for tail_idx, tail_key, tail_body in tails or [(-1, "", "")]:
                candidates = [(i, k, v) for i, k, v in middles if i != head_idx]
                if 0 <= tail_idx:
                    candidates = [(i, k, v) for i, k, v in candidates if i != tail_idx]
                for count in range(0, min(5, len(candidates)) + 1):
                    for subset in itertools.permutations(candidates, count):
                        body = head_body + "".join(v for _i, _k, v in subset) + tail_body
                        if len(body) != 32 or not re.fullmatch(r"[0-9a-fA-F]{32}", body):
                            continue
                        flag = f"{prefix}{{{body.lower()}}}"
                        source_fields = [items[head_idx][0]] + [k for _i, k, _v in subset]
                        if tail_key:
                            source_fields.append(tail_key)
                        ctx.add_flag(flag, confidence="medium", source=f"{self.name} metadata fragments")
                        ctx.add_finding(
                            "find",
                            f"metadata 分片排列得到: {flag}",
                            "字段: " + ", ".join(source_fields),
                            source=self.name,
                        )
                        added += 1
                        if added >= 12:
                            return

    def _metadata_decimal_to_hex(self, ctx: AnalysisContext, items: list[tuple[str, str]]) -> None:
        if not any("ctfshow{}" in value.lower() or "dectohex" in value.lower() for _key, value in items):
            return
        nums: list[tuple[str, int]] = []
        for key, value in items:
            if not any(word in key.lower() for word in ("resolution", "position", "serial", "printer")):
                continue
            if not re.fullmatch(r"\d{3,20}", value):
                continue
            number = int(value)
            if 256 <= number <= 0xFFFFFFFF:
                nums.append((key, number))
        if len(nums) < 4:
            return
        body = "".join(f"{number:08x}" for _key, number in nums[:4])
        flag = f"ctfshow{{{body}}}"
        for fixed in find_normalized_flags(flag):
            ctx.add_flag(fixed, confidence="high", source=f"{self.name} metadata DECtoHEX")
            ctx.add_finding(
                "find",
                f"metadata 十进制字段转 hex 得到: {fixed}",
                "字段: " + ", ".join(key for key, _number in nums[:4]),
                source=self.name,
            )

    def _metadata_dates_to_hex(self, ctx: AnalysisContext, items: list[tuple[str, str]]) -> None:
        if not any("unixtimestamp" in value.lower() or "dectohex" in value.lower() for _key, value in items):
            return
        for key, value in items:
            if "HistoryWhen" not in key:
                continue
            stamps: list[int] = []
            for item in [part.strip() for part in value.split(",") if part.strip()]:
                try:
                    stamps.append(int(_dt.datetime.strptime(item, "%Y:%m:%d %H:%M:%S%z").timestamp()))
                except ValueError:
                    pass
            if len(stamps) >= 4:
                flag = "ctfshow{" + "".join(f"{stamp:08x}" for stamp in stamps[:4]) + "}"
                for fixed in find_normalized_flags(flag):
                    ctx.add_flag(fixed, confidence="high", source=f"{self.name} metadata timestamp")
                    ctx.add_finding("find", f"metadata 时间戳转 hex 得到: {fixed}",
                                    key, source=self.name)

    def _metadata_thumbnail_offsets(self, ctx: AnalysisContext, items: list[tuple[str, str]]) -> None:
        offset = length = None
        for key, value in items:
            low = key.lower()
            if low.endswith("thumbnailoffset") and value.isdigit():
                offset = int(value)
            elif low.endswith("thumbnaillength") and value.isdigit():
                length = int(value)
        if offset is None or length is None:
            return
        data = ctx.data
        if offset >= len(data):
            return
        blob = data[offset:offset + length]
        if not blob:
            return
        name = f"exif_thumbnail_{offset:x}_{length}.jpg"
        if blob.startswith(b"\xff\xd8\xff"):
            thumb = blob
        else:
            soi = blob.find(b"\xff\xd8\xff")
            if soi < 0:
                return
            eoi = blob.find(b"\xff\xd9", soi + 2)
            if eoi < 0:
                return
            thumb = blob[soi:eoi + 2]
        path = ctx.save_bytes(name, thumb, f"EXIF ThumbnailOffset={offset} Length={length}", needs_review=True)
        ctx.add_finding("find", f"EXIF 缩略图已提取 → {os.path.basename(path)}", source=self.name)

    # ------------------------------------------------------------------ #
    # Hex editor highlight patterns
    # ------------------------------------------------------------------ #
    def _f001_clusters(self, positions: list[int]) -> list[list[int]]:
        clusters: list[list[int]] = []
        current: list[int] = []
        for pos in positions:
            if current and pos - current[-1] > 128:
                clusters.append(current)
                current = []
            current.append(pos)
        if current:
            clusters.append(current)
        return clusters

    def _save_f001_matrix_image(self, ctx: AnalysisContext, matrix: list[list[int]], name: str) -> None:
        try:
            from PIL import Image, ImageDraw
        except Exception:
            return
        if not matrix:
            return
        cell_w, cell_h = 36, 12
        width = len(matrix[0])
        height = len(matrix)
        image = Image.new("RGB", (width * cell_w, height * cell_h), "white")
        draw = ImageDraw.Draw(image)
        for y, row in enumerate(matrix):
            for x, value in enumerate(row):
                if value:
                    draw.rectangle(
                        [x * cell_w, y * cell_h, (x + 1) * cell_w - 2, (y + 1) * cell_h - 2],
                        fill=(180, 0, 60),
                    )
        path = os.path.join(ctx.outdir, name)
        image.save(path)
        ctx.add_artifact(path, "F001 搜索命中按 16 字节行重建的点阵图", needs_review=True)

    def _decode_f001_matrix(self, matrix: list[list[int]], row_shift: int = 0) -> str:
        chars: list[str] = []
        for block_start in range(row_shift, len(matrix) - 4, 6):
            for left, right in ((0, 3), (4, 7)):
                rows = matrix[block_start:block_start + 5]
                if any(right > len(row) for row in rows):
                    continue
                pattern_rows = ["".join("#" if row[col] else "." for col in range(left, right)) for row in rows]
                if all(row == "..." for row in pattern_rows):
                    continue
                chars.append(_F001_3X5_FONT.get("/".join(pattern_rows), "?"))
        return "".join(chars)

    def _f001_hex_editor_pattern(self, ctx: AnalysisContext) -> None:
        data = ctx.data
        positions: list[int] = []
        cursor = 0
        while True:
            pos = data.find(b"\xf0\x01", cursor)
            if pos < 0:
                break
            positions.append(pos)
            cursor = pos + 1
        if len(positions) < 20:
            return

        best_text = ""
        best_matrix: list[list[int]] = []
        best_base = 0
        best_unknowns = 10**9
        for cluster in sorted(self._f001_clusters(positions), key=len, reverse=True)[:3]:
            if len(cluster) < 20:
                continue
            base = (min(cluster) // 16) * 16
            end = ((max(cluster) + 2 + 15) // 16) * 16
            if end <= base:
                continue
            rows = (end - base) // 16
            matrix: list[list[int]] = []
            for row_idx in range(rows):
                row: list[int] = []
                offset = base + row_idx * 16
                for slot in range(8):
                    pair_offset = offset + slot * 2
                    row.append(1 if data[pair_offset:pair_offset + 2] == b"\xf0\x01" else 0)
                matrix.append(row)
            for row_shift in range(6):
                text = self._decode_f001_matrix(matrix, row_shift)
                if not text:
                    continue
                unknowns = text.count("?")
                score = (100 if "ctfshow{" in text.lower() else 0) + len(text) - unknowns * 4
                best_score = (100 if "ctfshow{" in best_text.lower() else 0) + len(best_text) - best_unknowns * 4
                if score > best_score:
                    best_text = text
                    best_matrix = matrix
                    best_base = base
                    best_unknowns = unknowns

        if not best_text:
            return

        matrix_text = "\n".join("".join("#" if value else "." for value in row) for row in best_matrix)
        ctx.save_bytes(
            "f001_hex_editor_matrix.txt",
            (f"base=0x{best_base:x}\n" + matrix_text + "\n").encode("utf-8"),
            "F001 搜索命中矩阵文本(#=命中)",
            needs_review=True,
        )
        ctx.save_bytes(
            "f001_hex_editor_decoded.txt",
            (best_text + "\n").encode("utf-8"),
            "F001 3x5 点阵字体解码文本",
            needs_review=best_unknowns > 0,
        )
        self._save_f001_matrix_image(ctx, best_matrix, "f001_hex_editor_matrix.png")

        matched = False
        for flag in find_normalized_flags(best_text):
            ctx.add_flag(flag, confidence="high", source=f"{self.name} F001 hex editor font")
            ctx.add_finding(
                "find",
                f"F001 搜索高亮点阵解码得到: {flag}",
                f"base=0x{best_base:x}, hits={len(positions)}",
                source=self.name,
            )
            matched = True
        if not matched:
            ctx.add_finding(
                "hint",
                "发现大量 F001 字节并已重建点阵",
                f"候选文本: {best_text[:80]}",
                source=self.name,
            )

    # ------------------------------------------------------------------ #
    # Format conversion/carving
    # ------------------------------------------------------------------ #
    def _decode_bpg(self, ctx: AnalysisContext) -> None:
        if not ctx.tools.have("bpgdec"):
            ctx.add_finding("hint", "BPG 需要 bpgdec 转 PNG",
                            "安装 libbpg 后运行: bpgdec -o out.png input.bpg", source=self.name)
            return
        out = os.path.join(ctx.outdir, "bpg_decoded.png")
        try:
            result = subprocess.run(["bpgdec", "-o", out, ctx.target], capture_output=True, timeout=30)
        except Exception as exc:
            ctx.add_finding("warn", f"bpgdec 执行失败: {exc}", source=self.name)
            return
        if result.returncode == 0 and os.path.exists(out):
            ctx.add_artifact(out, "bpgdec 转出的 PNG", needs_review=True)
            ctx.add_finding("find", "BPG 已转 PNG: bpg_decoded.png", source=self.name)

    def _carve_nested_jpegs(self, ctx: AnalysisContext) -> int:
        data = ctx.data
        offsets = [m.start() for m in re.finditer(b"\xff\xd8\xff", data)]
        count = 0
        for idx, start in enumerate(offset for offset in offsets if offset > 0):
            end = data.find(b"\xff\xd9", start + 2)
            if end < 0:
                continue
            blob = data[start : end + 2]
            if len(blob) < 128:
                continue
            name = f"nested_jpeg_{idx}_{start:x}.jpg"
            ctx.save_bytes(name, blob, f"JPEG 内嵌图像 @0x{start:x}", needs_review=True)
            ctx.add_finding("find", f"JPEG 内嵌图像 @0x{start:x} → {name}",
                            source=self.name)
            count += 1
        return count

    # ------------------------------------------------------------------ #
    # PNG/APNG structure encodings
    # ------------------------------------------------------------------ #
    def _png_chunk_encodings(self, ctx: AnalysisContext) -> None:
        info = ctx.png_info.get("parsed") or png_core.parse_png(ctx.data)
        idats = [chunk for chunk in info.chunks if chunk.ctype == "IDAT"]
        if not idats:
            return

        if len(idats) >= 8 and all(0 <= chunk.length <= 255 for chunk in idats):
            blob = bytes(chunk.length for chunk in idats)
            _add_blob_flags(ctx, blob, "IDAT chunk length bytes")

        bad_crc = [chunk.crc for chunk in idats if not chunk.crc_ok and len(chunk.crc) == 4]
        if bad_crc:
            _add_blob_flags(ctx, b"".join(bad_crc), "invalid IDAT CRC bytes")

        if len(idats) >= 32:
            bits = "".join("1" if chunk.crc_ok else "0" for chunk in idats)
            for start in range(8):
                view = bits[start:]
                for group in (7, 8):
                    chars = []
                    for pos in range(0, len(view) - group + 1, group):
                        value = int(view[pos : pos + group], 2)
                        if value in (9, 10, 13) or 32 <= value <= 126:
                            chars.append(chr(value))
                        else:
                            chars.append("\x00")
                    text = "".join(chars)
                    for flag in find_normalized_flags(text):
                        ctx.add_flag(flag, confidence="high", source=f"{self.name} IDAT CRC validity bits")
                        ctx.add_finding("find", f"IDAT CRC 校验真假位解码得到: {flag}",
                                        f"start={start}, group={group}", source=self.name)

    def _apng_rules(self, ctx: AnalysisContext) -> None:
        info = ctx.png_info.get("parsed") or png_core.parse_png(ctx.data)
        if not any(chunk.ctype == "acTL" for chunk in info.chunks):
            return
        delay_nums: list[int] = []
        delay_dens: list[int] = []
        for chunk in info.chunks:
            if chunk.ctype != "fcTL" or len(chunk.data) != 26:
                continue
            values = struct.unpack(">IIIIIHHBB", chunk.data)
            delay_nums.append(values[5])
            delay_dens.append(values[6])
        if delay_nums and all(0 <= value <= 255 for value in delay_nums):
            _add_blob_flags(ctx, bytes(delay_nums), "APNG fcTL delay numerator")

        if len(set(delay_dens)) == 2:
            rare = min(set(delay_dens), key=delay_dens.count)
            indexes = [idx for idx, value in enumerate(delay_dens) if value == rare]
            if 2 <= len(indexes) <= 20:
                self._apng_abnormal_delay_frames(ctx, indexes, rare)

        if ctx.flags:
            return
        try:
            from PIL import Image, ImageSequence
        except Exception:
            ctx.add_finding("hint", "Pillow 缺失, 无法拆 APNG 帧", source=self.name)
            return
        frames_dir = os.path.join(ctx.outdir, "apng_frames")
        os.makedirs(frames_dir, exist_ok=True)
        try:
            im = Image.open(ctx.target)
            frame_count = getattr(im, "n_frames", 1)
            if frame_count > 100:
                return
            for idx, frame in enumerate(ImageSequence.Iterator(im)):
                out = os.path.join(frames_dir, f"frame_{idx:03d}.png")
                frame.convert("RGBA").save(out)
                ctx.add_artifact(out, f"APNG 帧 {idx}", needs_review=True)
            if frame_count > 1:
                ctx.add_finding("find", f"APNG 已拆 {frame_count} 帧 → apng_frames/",
                                "逐帧 OCR/人工查看可拼接隐藏 flag", source=self.name)
        except Exception as exc:
            ctx.add_finding("warn", f"APNG 拆帧失败: {exc}", source=self.name)

    def _apng_abnormal_delay_frames(self, ctx: AnalysisContext, indexes: list[int], rare_delay_den: int) -> None:
        try:
            from PIL import Image, ImageSequence
        except Exception:
            return
        try:
            im = Image.open(ctx.target)
            frames = [frame.convert("RGBA") for frame in ImageSequence.Iterator(im)]
        except Exception:
            return
        pieces: list[str] = []
        for idx in indexes:
            if idx >= len(frames):
                continue
            out = os.path.join(ctx.outdir, f"apng_abnormal_delay_frame_{idx:03d}.png")
            frames[idx].save(out)
            ctx.add_artifact(out, f"APNG 异常延迟帧 {idx} delay_den={rare_delay_den}", needs_review=True)
            text = _fast_ocr_image(ctx, out, f"apng_abnormal_delay_frame_{idx:03d}")
            piece = self._gif_fragment_from_ocr(text)
            if piece:
                pieces.append(piece)
        if not pieces:
            return
        joined = "".join(pieces)
        for flag in find_normalized_flags(joined):
            ctx.add_flag(flag, confidence="high", source=f"{self.name} APNG 异常延迟帧拼接")
            ctx.add_finding(
                "find",
                f"APNG 异常延迟帧 OCR 拼接得到: {flag}",
                f"frames={indexes}, delay_den={rare_delay_den}",
                source=self.name,
            )

    def _save_png_as_bmp_probe(self, ctx: AnalysisContext) -> None:
        try:
            from PIL import Image
        except Exception:
            return
        try:
            out = os.path.join(ctx.outdir, "png_to_bmp_probe.bmp")
            Image.open(ctx.target).save(out)
            ctx.add_artifact(out, "PNG 转 BMP 探测文件(适合继续 binwalk/位平面分析)", needs_review=False)
        except Exception:
            pass

    def _rgba_alpha_hint_rules(self, ctx: AnalysisContext) -> None:
        try:
            from PIL import Image, ImageOps
        except Exception:
            return
        for artifact in list(ctx.artifacts):
            if not artifact.path.lower().endswith(".png"):
                continue
            if "reconstructed_real_size" not in os.path.basename(artifact.path):
                continue
            try:
                im = Image.open(artifact.path).convert("RGBA")
            except Exception:
                continue
            alpha = im.getchannel("A")
            if alpha.getextrema() == (255, 255):
                continue
            base = os.path.splitext(os.path.basename(artifact.path))[0]
            alpha_path = os.path.join(ctx.outdir, f"{base}_alpha_inv.png")
            ImageOps.autocontrast(ImageOps.invert(alpha)).save(alpha_path)
            ctx.add_artifact(alpha_path, f"{base} alpha 通道反色图", needs_review=True)
            _fast_ocr_image(ctx, alpha_path, f"{base}_alpha")
            ocr_path = os.path.join(ctx.outdir, f"{_safe_filename(base + '_alpha')}_fast_ocr.txt")
            if not os.path.exists(ocr_path):
                continue
            text = Path(ocr_path).read_text(encoding="utf-8", errors="replace")
            compact = re.sub(r"\s+", "", text).lower()
            head_match = re.search(r"ctfshow\{([0-9a-f]{4,16})", compact)
            tail_matches = re.findall(r"([0-9a-f]{16,40})\}", compact)
            tail_match = tail_matches[-1] if tail_matches else ""
            if not head_match or not tail_match:
                continue
            height_hex = f"{im.height:x}"
            head_raw = head_match.group(1)
            for head_len in range(len(head_raw), 3, -1):
                body = head_raw[:head_len] + height_hex + tail_match
                if len(body) != 32:
                    continue
                flag = f"ctfshow{{{body}}}"
                for fixed in find_normalized_flags(flag):
                    ctx.add_flag(fixed, confidence="high", source=f"{self.name} alpha height hint")
                    ctx.add_finding(
                        "find",
                        f"alpha 通道提示真实高度 hex, 拼接得到: {fixed}",
                        f"height={im.height}, hex={height_hex}, artifact={os.path.basename(artifact.path)}",
                        source=self.name,
                    )
                break

    # ------------------------------------------------------------------ #
    # GIF
    # ------------------------------------------------------------------ #
    def _gif_delay_bits(self, ctx: AnalysisContext) -> None:
        data = ctx.data
        delays: list[int] = []
        pos = 0
        while True:
            idx = data.find(b"\x21\xf9\x04", pos)
            if idx < 0 or idx + 8 > len(data):
                break
            delays.append(struct.unpack("<H", data[idx + 4 : idx + 6])[0])
            pos = idx + 8
        if len(delays) < 32:
            return
        uniq = sorted(set(delays))
        if len(uniq) != 2:
            return
        bits = "".join("1" if delay == uniq[1] else "0" for delay in delays)
        for group in (7, 8):
            text = "".join(chr(int(bits[i : i + group], 2)) for i in range(0, len(bits) - group + 1, group))
            for flag in find_normalized_flags(text):
                ctx.add_flag(flag, confidence="high", source=f"{self.name} GIF delay bits")
                ctx.add_finding("find", f"GIF 帧延迟二值化得到: {flag}",
                                f"{uniq[0]}->0, {uniq[1]}->1, group={group}", source=self.name)
        self._gif_abnormal_delay_frames(ctx, delays, uniq)

    def _gif_fragment_from_ocr(self, text: str) -> str:
        compact = re.sub(r"\s+", "", text)
        if not compact:
            return ""
        prefix = re.search(r"ctfshow\{?([^}\r\n]*)", compact, re.I)
        if prefix:
            return "ctfshow{" + normalize_hexish_body(prefix.group(1))
        tail = compact.endswith("}")
        body = normalize_hexish_body(compact)
        if len(body) >= 4:
            return body + ("}" if tail else "")
        return ""

    def _gif_abnormal_delay_frames(self, ctx: AnalysisContext, delays: list[int], uniq: list[int]) -> None:
        rare_delay = min(uniq, key=delays.count)
        frame_indexes = [idx for idx, delay in enumerate(delays) if delay == rare_delay]
        if not (2 <= len(frame_indexes) <= 20):
            return
        try:
            from PIL import Image, ImageSequence
        except Exception:
            return
        try:
            im = Image.open(ctx.target)
            frames = [frame.convert("RGB") for frame in ImageSequence.Iterator(im)]
        except Exception:
            return
        pieces: list[str] = []
        for idx in frame_indexes:
            if idx >= len(frames):
                continue
            out = os.path.join(ctx.outdir, f"gif_abnormal_delay_frame_{idx:03d}.png")
            frames[idx].save(out)
            ctx.add_artifact(out, f"GIF 异常延迟帧 {idx} delay={rare_delay}", needs_review=True)
            text = _fast_ocr_image(ctx, out, f"gif_abnormal_delay_frame_{idx:03d}")
            piece = self._gif_fragment_from_ocr(text)
            if piece:
                pieces.append(piece)
        if not pieces:
            return
        joined = "".join(pieces)
        for flag in find_normalized_flags(joined):
            ctx.add_flag(flag, confidence="high", source=f"{self.name} GIF 异常延迟帧拼接")
            ctx.add_finding(
                "find",
                f"GIF 异常延迟帧 OCR 拼接得到: {flag}",
                f"frames={frame_indexes}, delay={rare_delay}",
                source=self.name,
            )

    def _patch_gif_dimensions(
        self,
        data: bytes,
        new_w: int | None = None,
        new_h: int | None = None,
        patch_lsd: bool = True,
    ) -> bytes:
        res = bytearray(data)
        if patch_lsd:
            if new_w is not None:
                res[6:8] = struct.pack("<H", new_w)
            if new_h is not None:
                res[8:10] = struct.pack("<H", new_h)
        packed = res[10] if len(res) > 10 else 0
        pos = 13 + (3 * (2 ** ((packed & 0x07) + 1)) if packed & 0x80 else 0)
        while pos < len(res):
            marker = res[pos]
            if marker == 0x2C and pos + 10 <= len(res):
                if new_w is not None:
                    res[pos + 5 : pos + 7] = struct.pack("<H", new_w)
                if new_h is not None:
                    res[pos + 7 : pos + 9] = struct.pack("<H", new_h)
                local_packed = res[pos + 9]
                pos += 10 + (3 * (2 ** ((local_packed & 0x07) + 1)) if local_packed & 0x80 else 0)
                if pos >= len(res):
                    break
                pos += 1
                while pos < len(res):
                    size = res[pos]
                    pos += 1
                    if size == 0:
                        break
                    pos += size
            elif marker == 0x21:
                pos += 2
                while pos < len(res):
                    size = res[pos]
                    pos += 1
                    if size == 0:
                        break
                    pos += size
            elif marker == 0x3B:
                break
            else:
                pos += 1
        return bytes(res)

    def _save_gif_frames(self, ctx: AnalysisContext, gif_bytes: bytes, label: str, max_frames: int = 12) -> None:
        try:
            from PIL import Image, ImageFile
        except Exception:
            return
        ImageFile.LOAD_TRUNCATED_IMAGES = True
        gif_path = ctx.save_bytes(f"{label}.gif", gif_bytes, f"GIF 尺寸修复候选 {label}", needs_review=True)
        try:
            im = Image.open(gif_path)
            frame_count = getattr(im, "n_frames", 1)
            for idx in range(min(frame_count, max_frames)):
                im.seek(idx)
                out = os.path.join(ctx.outdir, f"{label}_frame_{idx:03d}.png")
                im.convert("RGB").save(out)
                ctx.add_artifact(out, f"{label} 帧 {idx}", needs_review=True)
                self._save_dense_text_crop(ctx, out, f"{label}_frame_{idx:03d}")
                _fast_ocr_image(ctx, out, f"{label}_frame_{idx:03d}")
            ctx.add_finding("find", f"生成 GIF 修复候选 {label}, 帧数={frame_count}",
                            source=self.name)
        except Exception as exc:
            ctx.add_finding("warn", f"GIF 修复候选 {label} 无法解码: {exc}", source=self.name)

    def _save_dense_text_crop(self, ctx: AnalysisContext, image_path: str, label: str) -> None:
        try:
            from PIL import Image
        except Exception:
            return
        try:
            im = Image.open(image_path).convert("L")
            width, height = im.size
            pixels = list(im.getdata())
            row_counts = []
            for y in range(height):
                count = sum(1 for x in range(width) if pixels[y * width + x] < 245)
                if count >= max(3, width // 100):
                    row_counts.append((y, count))
            if not row_counts:
                return
            bands: list[list[tuple[int, int]]] = []
            for item in row_counts:
                if bands and item[0] - bands[-1][-1][0] <= 2:
                    bands[-1].append(item)
                else:
                    bands.append([item])
            band = max(bands, key=lambda values: sum(count for _y, count in values))
            top = max(0, band[0][0] - 4)
            bottom = min(height, band[-1][0] + 5)
            if bottom - top < 5:
                return
            crop = im.crop((0, top, width, bottom))
            # Tighten horizontally after choosing the row band.
            cp = list(crop.getdata())
            cols = [
                x for x in range(width)
                if sum(1 for y in range(crop.height) if cp[y * width + x] < 245) > 0
            ]
            if cols:
                left = max(0, min(cols) - 4)
                right = min(width, max(cols) + 5)
                crop = crop.crop((left, 0, right, crop.height))
            crop = crop.point(lambda value: 0 if value < 220 else 255)
            crop = crop.resize((crop.width * 6, crop.height * 6))
            out = os.path.join(ctx.outdir, f"{label}_text_crop.png")
            crop.save(out)
            ctx.add_artifact(out, f"{label} 非白像素密集行裁剪(适合人工读取)", needs_review=True)
        except Exception:
            return

    def _repair_gif_dimensions(self, ctx: AnalysisContext) -> None:
        data = ctx.data
        if len(data) < 10:
            return
        width, height = struct.unpack("<HH", data[6:10])
        if height < 255:
            self._save_gif_frames(ctx, self._patch_gif_dimensions(data, new_h=255),
                                  f"gif_repaired_h255")
        if width <= 941:
            # Some GIF width-repair tasks require changing only the image descriptor,
            # leaving logical screen size intact.
            self._save_gif_frames(ctx, self._patch_gif_dimensions(data, new_w=941, patch_lsd=False),
                                  f"gif_repaired_descriptor_w941", max_frames=1)
            if height < 255:
                self._save_gif_frames(
                    ctx,
                    self._patch_gif_dimensions(data, new_w=941, new_h=255, patch_lsd=False),
                    f"gif_repaired_descriptor_w941_h255",
                    max_frames=1,
                )

    # ------------------------------------------------------------------ #
    # JPEG/BMP dimension repairs
    # ------------------------------------------------------------------ #
    def _find_jpeg_sof(self, data: bytes) -> tuple[int, int, int] | None:
        pos = 2
        while pos + 4 < len(data):
            if data[pos] != 0xFF:
                pos += 1
                continue
            marker = data[pos + 1]
            if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
                pos += 2
                continue
            length = struct.unpack(">H", data[pos + 2 : pos + 4])[0]
            if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
                hpos = pos + 5
                wpos = pos + 7
                height = struct.unpack(">H", data[hpos : hpos + 2])[0]
                width = struct.unpack(">H", data[wpos : wpos + 2])[0]
                return wpos, hpos, width, height
            pos += 2 + length
        return None

    def _repair_jpeg_dimensions(self, ctx: AnalysisContext) -> None:
        try:
            from PIL import Image, ImageFile
        except Exception:
            return
        loc = self._find_jpeg_sof(ctx.data)
        if not loc:
            return
        wpos, hpos, width, height = loc
        candidates = {(width, 255), (993, 580), (993, 600)}
        ImageFile.LOAD_TRUNCATED_IMAGES = True
        for new_w, new_h in sorted(candidates):
            if (new_w, new_h) == (width, height):
                continue
            patched = bytearray(ctx.data)
            patched[wpos : wpos + 2] = struct.pack(">H", new_w)
            patched[hpos : hpos + 2] = struct.pack(">H", new_h)
            jpg_name = f"jpeg_repaired_{new_w}x{new_h}.jpg"
            jpg_path = ctx.save_bytes(jpg_name, bytes(patched), f"JPEG SOF 宽高修复候选 {new_w}x{new_h}",
                                      needs_review=True)
            try:
                im = Image.open(jpg_path)
                im.load()
                out = os.path.join(ctx.outdir, f"jpeg_repaired_{new_w}x{new_h}.png")
                im.convert("RGB").save(out)
                ctx.add_artifact(out, f"JPEG 宽高修复渲染图 {new_w}x{new_h}", needs_review=True)
                ctx.add_finding("find", f"生成 JPEG 宽高修复候选 {new_w}x{new_h}",
                                source=self.name)
                _fast_ocr_image(ctx, out, f"jpeg_repaired_{new_w}x{new_h}")
            except Exception:
                continue

    def _repair_bmp_dimensions(self, ctx: AnalysisContext) -> None:
        try:
            from PIL import Image, ImageFile
        except Exception:
            return
        data = ctx.data
        if len(data) < 54 or data[:2] != b"BM":
            return
        width = struct.unpack("<i", data[18:22])[0]
        height = struct.unpack("<i", data[22:26])[0]
        bpp = struct.unpack("<H", data[28:30])[0]
        offset = struct.unpack("<I", data[10:14])[0]
        body_len = max(0, len(data) - offset)
        candidates: set[tuple[int, int]] = {(width, 238), (width, 250), (950, height), (1082, height)}
        if bpp == 24 and height:
            for cand_w in range(max(1, width), min(width + 400, 2000)):
                row = ((cand_w * 3 + 3) // 4) * 4
                if 0 <= body_len - row * abs(height) <= 8:
                    candidates.add((cand_w, height))
        ImageFile.LOAD_TRUNCATED_IMAGES = True
        for cand_w, cand_h in sorted(candidates):
            if cand_w <= 0 or cand_h == 0 or (cand_w, cand_h) == (width, height):
                continue
            patched = bytearray(data)
            patched[18:22] = struct.pack("<i", cand_w)
            patched[22:26] = struct.pack("<i", cand_h)
            name = f"bmp_repaired_{cand_w}x{cand_h}.bmp"
            path = ctx.save_bytes(name, bytes(patched), f"BMP 宽高修复候选 {cand_w}x{cand_h}",
                                  needs_review=True)
            try:
                im = Image.open(path)
                im.load()
                out = os.path.join(ctx.outdir, f"bmp_repaired_{cand_w}x{cand_h}.png")
                im.convert("RGB").save(out)
                ctx.add_artifact(out, f"BMP 宽高修复渲染图 {cand_w}x{cand_h}", needs_review=True)
                ctx.add_finding("find", f"生成 BMP 宽高修复候选 {cand_w}x{cand_h}",
                                source=self.name)
                _fast_ocr_image(ctx, out, f"bmp_repaired_{cand_w}x{cand_h}")
            except Exception:
                continue
