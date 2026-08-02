"""JPEG 专项: APP13 Photoshop 资源 / 隐藏 Exif 缩略图 / steghide。

misc6: APP13 中 Photoshop 8BIM 资源(PrintInfo2) 含 flag
misc14: APP13 里藏了第二个 Exif 目录 + 隐藏缩略图(需 OCR)
通用: steghide 空密码提取
"""
from __future__ import annotations

import os
import re
import struct
import subprocess

from .base import Analyzer, AnalysisContext
from ..flags import find_flags_in_text


def parse_jpeg_segments(data: bytes) -> list[tuple[int, int, bytes]]:
    """解析 JPEG 段(marker), 返回 [(marker_code, offset, content)]。

    marker: 0xFFD8(SOI), 0xFFE0-FFEF(APPn), 0xFFDB(DQT), 0xFFC0(SOF), 0xFFDA(SOS) 等
    APPn 和大部分段有 2 字节长度(含自身)。
    """
    segments = []
    i = 0
    while i < len(data) - 1:
        if data[i] != 0xFF:
            i += 1
            continue
        marker = data[i + 1]
        if marker == 0xD8:  # SOI, 无长度
            segments.append((0xFFD8, i, b""))
            i += 2
            continue
        if marker == 0xD9:  # EOI
            segments.append((0xFFD9, i, b""))
            i += 2
            continue
        if 0xD0 <= marker <= 0xD7:  # RSTn, 无长度
            i += 2
            continue
        if marker in (0x00, 0xFF):
            i += 1
            continue
        # 有长度的段
        if i + 4 > len(data):
            break
        length = struct.unpack(">H", data[i + 2 : i + 4])[0]
        content = data[i + 4 : i + 2 + length]
        segments.append((0xFF00 | marker, i, content))
        i += 2 + length
        # SOS 后是熵编码数据(到下一个 marker), 跳过
        if marker == 0xDA:
            # 找下一个 marker(0xFF 后非 0x00)
            while i < len(data) - 1:
                if data[i] == 0xFF and data[i + 1] != 0x00 and data[i + 1] != 0xFF:
                    break
                i += 1
    return segments


def extract_app13_resources(app13_data: bytes) -> list[tuple[int, bytes]]:
    """解析 APP13(Photoshop 8BIM) 资源, 返回 [(resource_id, data)]。

    8BIM 资源结构: "8BIM" + 2字节id + Pascal字符串 + 2字节长度 + 数据
    """
    resources = []
    pos = 0
    while pos < len(app13_data) - 8:
        # 找 "8BIM" 标记
        idx = app13_data.find(b"8BIM", pos)
        if idx < 0:
            break
        pos = idx + 4
        if pos + 3 > len(app13_data):
            break
        res_id = struct.unpack(">H", app13_data[pos : pos + 2])[0]
        pos += 2
        # Pascal 字符串(1 字节长度 + 内容, 偶对齐)
        name_len = app13_data[pos] if pos < len(app13_data) else 0
        pos += 1 + name_len
        if name_len % 2 == 0:
            pos += 1  # 偶对齐填充
        if pos + 2 > len(app13_data):
            break
        data_len = struct.unpack(">H", app13_data[pos : pos + 2])[0]
        pos += 2
        res_data = app13_data[pos : pos + data_len]
        resources.append((res_id, res_data))
        pos += data_len
        if data_len % 2 == 1:
            pos += 1  # 奇数长度填充
    return resources


class JPGDeepAnalyzer(Analyzer):
    name = "阶段 5c: JPEG 专项分析"
    applies_to = {"jpg"}
    requires = set()

    def run(self, ctx: AnalysisContext) -> None:
        data = ctx.data

        # 1. 解析 JPEG 段, 找 APP13
        segments = parse_jpeg_segments(data)
        app13_segments = [(off, content) for code, off, content in segments
                          if 0xFFE0 <= code <= 0xFFEF and content.startswith(b"Photoshop")]
        # 也找名为 "Exif" 的 APPn(misc14: APP13 里藏第二个 Exif)
        exif_in_app13 = []

        for off, content in app13_segments:
            ctx.add_finding("info", f"APP13(Photoshop) @0x{off:x}, {len(content)}B")
            # 解析 8BIM 资源
            resources = extract_app13_resources(content)
            for res_id, res_data in resources:
                # 扫描每个资源的 flag
                for f in find_flags_in_text(res_data, source=f"{self.name} APP13 8BIM(0x{res_id:04x})"):
                    ctx.add_flag(f, confidence="high", source=f"{self.name} APP13 资源 0x{res_id:04x}")
                    ctx.add_finding("find", f"APP13 8BIM 资源 0x{res_id:04x} 含 flag: {f}")
                # PrintInfo2 (0x043a) 等
                if res_id == 0x043A and res_data:
                    ctx.add_finding("info", f"8BIM 0x043a (PrintInfo2): {len(res_data)}B")

            # 检查 APP13 是否藏了 Exif(misc14)
            exif_pos = content.find(b"Exif\x00\x00")
            if exif_pos >= 0:
                ctx.add_finding("find", f"APP13 中藏了第二个 Exif 目录 @+{exif_pos}",
                                "这是 misc14 套路: 可能有隐藏缩略图", source=self.name)
                self._extract_hidden_thumbnail(ctx, content[exif_pos:])

        # 2. steghide 空密码
        if ctx.tools.have("steghide"):
            out_path = os.path.join(ctx.outdir, "steghide_output.txt")
            try:
                r = subprocess.run(
                    ["steghide", "extract", "-sf", ctx.target, "-p", "", "-f",
                     "-xf", out_path],
                    capture_output=True, timeout=30,
                )
                if r.returncode == 0 and os.path.exists(out_path):
                    with open(out_path, "rb") as f:
                        steg_data = f.read()
                    ctx.add_artifact(out_path, "steghide 空密码提取结果")
                    for f in find_flags_in_text(steg_data, source=f"{self.name} steghide"):
                        ctx.add_flag(f, confidence="high", source=f"{self.name} steghide空密码")
                        ctx.add_finding("find", f"steghide 空密码提取出 flag: {f}")
                else:
                    ctx.add_finding("info", "steghide 空密码无果(可能需要密码或非 steghide)")
            except Exception as e:
                ctx.add_finding("warn", f"steghide 执行失败: {e}")
        else:
            ctx.add_finding("warn", "steghide 缺失, 无法检测 JPEG steghide 隐写",
                            "apt install steghide | CentOS 需源码编译")

        missing_password_tools = [
            name for name in ("outguess", "jphide", "openstego", "stegseek")
            if not ctx.tools.have(name)
        ]
        if missing_password_tools:
            ctx.add_finding(
                "hint",
                "JPEG 密码型隐写工具未全部安装",
                "未安装: " + ", ".join(missing_password_tools)
                + "\n        若题目给了密码/字典, 可手动尝试 steghide/outguess/jphide/openstego；"
                "本工具默认不做长时间密码爆破。",
                source=self.name,
            )

    def _extract_hidden_thumbnail(self, ctx: AnalysisContext, exif_data: bytes) -> None:
        """从隐藏的 Exif 数据中提取缩略图(JPEG FFD8...FFD9)。"""
        # 找 FFD8 开头的 JPEG
        start = exif_data.find(b"\xff\xd8\xff")
        if start < 0:
            return
        end = exif_data.rfind(b"\xff\xd9")
        if end < 0 or end <= start:
            return
        thumb = exif_data[start : end + 2]
        ctx.save_bytes("hidden_thumbnail.jpg", thumb,
                       "从 APP13 隐藏 Exif 提取的缩略图 — 可能含 flag 文字, 需人工查看",
                       needs_review=True)
        ctx.add_finding("find", f"提取隐藏缩略图 {len(thumb)}B → hidden_thumbnail.jpg",
                        source=self.name)
        # 扫描缩略图的 EXIF(可能 flag 在字段里)
        for f in find_flags_in_text(thumb, source=f"{self.name} 隐藏缩略图"):
            ctx.add_flag(f, confidence="medium", source=f"{self.name} 隐藏缩略图")
