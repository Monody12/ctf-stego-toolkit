"""字符串扫描: 用 strings 或内置实现扫描可见字符串, 找明文 flag。

misc7: flag 在 JPEG scan data 内(strings 能找到)

除明文外，这里对 strings 输出做深度扫描（base64/hex/压缩/HTML 实体/
URL/\\uXXXX 等文本编码），因此像 ``&#107;&#101;...`` 这类 HTML 数字实体
编码的 flag 也能自动解出。
"""
from __future__ import annotations

import subprocess

from .base import Analyzer, AnalysisContext
from ..flags import find_flags_in_text, scan_flags


def _extract_strings(data: bytes, min_len: int = 4) -> list[str]:
    """内置 strings 实现: 提取连续 >=min_len 的可打印 ASCII 串。"""
    result = []
    cur = bytearray()
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                result.append(cur.decode("ascii"))
            cur = bytearray()
    if len(cur) >= min_len:
        result.append(cur.decode("ascii"))
    return result


class StringsAnalyzer(Analyzer):
    name = "阶段 3: 字符串扫描"
    applies_to = None
    requires = set()

    def run(self, ctx: AnalysisContext) -> None:
        data = ctx.data

        # 优先用系统 strings(更快, 支持 unicode)。-a 扫描整个文件而不仅
        # 是默认数据段，与题目经验一致（JPEG 等格式 flag 常在非默认段）。
        if ctx.tools.have("strings"):
            try:
                out = subprocess.run(
                    ["strings", "-a", "-n", "4", ctx.target], capture_output=True, text=True, timeout=30
                ).stdout
                # 保存完整输出
                ctx.save_bytes("strings_all.txt", out.encode("utf-8", "replace"), "完整 strings 输出")
                strings_list = out.splitlines()
            except Exception:
                strings_list = _extract_strings(data)
        else:
            strings_list = _extract_strings(data)
            ctx.save_bytes(
                "strings_all.txt",
                "\n".join(strings_list).encode("utf-8", "replace"),
                "完整 strings 输出(内置)",
            )

        # 明文 flag 扫描
        joined = "\n".join(strings_list)
        plaintext_flags = find_flags_in_text(joined, source=self.name)
        for flag in plaintext_flags:
            ctx.add_flag(flag, confidence="high", source=f"{self.name} 明文")
            ctx.add_finding("find", f"strings 发现明文 flag: {flag}", source=self.name)

        # 深度扫描：base64/hex/压缩/HTML 实体/URL/\\uXXXX 等。逐行扫描而非
        # 整体喂入，确保每行都是纯文本，文本编码守卫稳定通过；同时整体也
        # 扫一次以捕获跨行拼接的情况。
        deep_flags = []
        for line in strings_list:
            deep_flags.extend(scan_flags(line.encode("latin1", "ignore"), source=self.name))
        deep_flags.extend(scan_flags(joined.encode("latin1", "ignore"), source=self.name))

        for flag in deep_flags:
            if flag.value in plaintext_flags:
                continue
            ctx.add_flag(flag.value, confidence="high",
                         source=flag.source or self.name)
            ctx.add_finding("find", f"strings 深度扫描得到: {flag.value}",
                            flag.source, source=self.name)

        found_any = bool(plaintext_flags) or bool(deep_flags)

        # 扫描可疑关键词(可能是 flag 片段或编码)
        suspicious = []
        for s in strings_list:
            low = s.lower()
            if any(k in low for k in ("flag", "ctf", "key", "secret", "password")):
                if "{" in s and "}" in s:
                    suspicious.append(s)
        if suspicious and not found_any:
            for s in suspicious[:5]:
                ctx.add_finding("hint", f"可疑字符串(可能含 flag 片段): {s[:100]}", source=self.name)

        if not found_any and not suspicious:
            ctx.add_finding("info", "strings 未发现明文 flag", source=self.name)
