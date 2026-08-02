"""文件类型识别: file + 魔数检测(含格式欺骗)。

misc2: .txt 实为 PNG
misc3: BPG 格式
"""
from __future__ import annotations

import subprocess

from .base import Analyzer, AnalysisContext

# 魔数 -> (类型, 描述)
MAGIC_MAP = [
    (b"\x89PNG\r\n\x1a\n", "png", "PNG image"),
    (b"\xff\xd8\xff", "jpg", "JPEG image"),
    (b"GIF87a", "gif", "GIF image (87a)"),
    (b"GIF89a", "gif", "GIF image (89a)"),
    (b"BM", "bmp", "BMP image"),
    (b"II*\x00", "tiff", "TIFF image (little-endian)"),
    (b"MM\x00*", "tiff", "TIFF image (big-endian)"),
    (b"RIFF", "webp", "RIFF/WebP (可能含图像)"),
    (b"BPG\xfb", "bpg", "BPG (Better Portable Graphics)"),
    (b"8BPS", "psd", "Adobe Photoshop PSD"),
    (b"PK\x03\x04", "zip", "ZIP archive"),
    (b"\x1f\x8b", "gzip", "GZIP"),
]

# 扩展名 -> 期望类型(用于检测格式欺骗)
EXT_EXPECT = {
    ".png": "png", ".jpg": "jpg", ".jpeg": "jpg", ".gif": "gif",
    ".bmp": "bmp", ".tif": "tiff", ".tiff": "tiff", ".webp": "webp",
    ".bpg": "bpg", ".psd": "psd",
}


class FileTypeAnalyzer(Analyzer):
    name = "阶段 1: 文件类型识别"
    applies_to = None
    requires = set()

    def run(self, ctx: AnalysisContext) -> None:
        data = ctx.data
        ext = ""
        if "." in ctx.target:
            ext = "." + ctx.target.rsplit(".", 1)[-1].lower()

        # 1. file 命令(最准)
        file_desc = ""
        if ctx.tools.have("file"):
            try:
                out = subprocess.run(
                    ["file", "-b", ctx.target], capture_output=True, text=True, timeout=10
                ).stdout.strip()
                file_desc = out
                ctx.magic_desc = out
                ctx.add_finding("info", f"file: {out}")
            except Exception:
                pass

        # 2. 魔数检测(核心, 不依赖 file)
        real_type = "unknown"
        magic_desc = "未知"
        for magic, t, desc in MAGIC_MAP:
            if data.startswith(magic):
                real_type = t
                magic_desc = desc
                break

        # 特殊: WebP 的 RIFF 后面是 WEBP
        if real_type == "webp" and data[8:12] == b"WEBP":
            magic_desc = "WebP image"

        # 3. 格式欺骗检测
        expected = EXT_EXPECT.get(ext)
        if expected and real_type != "unknown" and expected != real_type:
            ctx.add_finding(
                "find",
                f"文件格式欺骗! 扩展名={ext}({expected}) 实际={real_type}",
                f"实际内容: {magic_desc}\n        这是常见隐写手法: 改扩展名让人误判文件类型。",
                source=self.name,
            )
        elif real_type == "unknown" and ext in EXT_EXPECT:
            ctx.add_finding(
                "warn",
                f"扩展名 {ext} 但魔数不匹配已知图像格式",
                f"file 说: {file_desc}\n        可能是特殊格式(BPG/WEBP 等)或损坏文件。",
                source=self.name,
            )

        # 4. 特殊格式提示
        if real_type == "bpg":
            ctx.add_finding(
                "find",
                "BPG 格式(Better Portable Graphics) — 罕见格式",
                "BPG 是一种高效图像格式, 多数查看器不支持。\n"
                "        需用 bpgview / ffmpeg / libbpg 转换为 PNG 后再分析。\n"
                "        转换: bpgdec -o out.png input.bpg",
                source=self.name,
            )

        ctx.real_type = real_type
        ctx.add_finding("info", f"真实类型: {real_type} ({magic_desc})")
