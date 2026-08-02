"""元数据分析: exiftool + EXIF 字段聚合(支持 flag 分割/非英文编码)。

misc6: APP13 Photoshop 资源(PrintInfo2)
misc9: PNG tEXt chunk (Warning 字段)  —— exiftool 也能读
misc18: flag 分割在 Title/Author/Model/LensModel
misc19: flag 分割在 TIFF DocumentName/HostComputer
misc20: 中文拼音谐音编码在 Comment 字段
"""
from __future__ import annotations

import re
import subprocess

from .base import Analyzer, AnalysisContext
from ..flags import find_flags_in_text, prefix_alternation

# 可能含 flag 的 EXIF 字段(关键字匹配)
SUSPICIOUS_FIELDS = (
    "Comment", "UserComment", "Author", "Artist", "Copyright", "Description",
    "ImageDescription", "Make", "Model", "Software", "History", "XMP", "ICC",
    "Warning", "Error", "GPS", "Manufacturer", "Title", "Subject", "Keywords",
    "DocumentName", "HostComputer", "LensModel", "CameraModel", "PageName",
    "Caption", "Credits", "Source", "By-line",
)

# 中文拼音/谐音表(misc20 类型): 把中文读音映射为 ASCII(hex 优先, 兼容字母)。
# 编码方式: 出题人常用数字读音 + 字母读音的中文谐音。多音节组合需长 key 优先。
# 关键约定:
#   - 多字组合优先(如 "爱抚"=f, "诶易"=ae), 再退到单字
#   - 数字 0-9 各有常见读音
#   - 同一汉字在不同上下文可能读法不同(如 "七"=7 或 "qi"), 这里数字优先(更常见)
PINYIN_MAP = {
    # 多音节组合(必须放前面, 贪婪匹配时长 key 优先)
    "爱抚": "f", "爱夫": "f", "艾服": "f", "唉赋": "f", "艾弗": "f",
    "诶易": "ae",  # 诶+易 组合读音 "ae"; 单独 诶 也 = "ae"(见下), 长key优先
    "大括号": "{",  # 第一个"大括号"通常表示开 {
    "左大括号": "{", "右大括号": "}",
    "埃克斯": "x", "艾克斯": "x",
    # 单字 — 数字优先
    "零": "0", "洞": "0", "〇": "0",
    "一": "1", "幺": "1",
    "二": "2", "两": "2",
    "三": "3", "仨": "3",
    "四": "4",
    "五": "5", "伍": "5",
    "六": "6", "陆": "6",
    "七": "7", "拐": "7",  # 数字七常见
    "八": "8", "捌": "8",
    "九": "9", "勾": "9",
    # 字母(谐音)
    "诶": "ae",  # 单独 诶 -> "ae"; (诶易 已上面处理为 "ae", 长 key 优先)
    "易": "e", "鹅": "e", "额": "e", "厄": "e", "亿": "e", "伊": "e",
    "必": "b", "逼": "b", "比": "b", "鼻": "b", "壁": "b",
    "西": "c", "希": "c", "细": "c", "洗": "c", "瑟": "c", "色": "c",
    "弟": "d", "迪": "d", "地": "d", "第": "d", "低": "d", "底": "d",
    "爱": "a", "艾": "a", "哎": "a", "安": "a",
    "佛": "f", "付": "f", "夫": "f", "福": "f",
    "哥": "g", "歌": "g", "个": "g", "格": "g", "戈": "g",
    "喝": "h", "赫": "h", "和": "h", "哈": "h", "河": "h",
    "衣": "i", "依": "i", "意": "i", "亦": "i",
    "鸡": "j", "吉": "j", "机": "j", "即": "j", "杰": "j",
    "克": "k", "科": "k", "可": "k", "柯": "k",
    "勒": "l", "了": "l", "拉": "l", "尔": "l", "李": "l",
    "谜": "m", "迷": "m", "米": "m", "木": "m",
    "呢": "n", "恩": "n", "纳": "n",
    "哦": "o", "欧": "o", "偶": "o",
    "披": "p", "批": "p", "皮": "p", "劈": "p",
    "欺": "q", "妻": "q", "奇": "q", "切": "q",
    "瑞": "r", "日": "r", "肉": "r", "啊": "r",
    "斯": "s", "丝": "s", "死": "s", "思": "s", "司": "s",
    "替": "t", "提": "t", "梯": "t", "踢": "t", "特": "t", "它": "t", "塔": "t",
    "油": "u", "有": "u", "尤": "u",
    "微": "v", "威": "v", "维": "v",
    "外": "w", "挖": "w", "瓦": "w", "为": "w",
    "洗": "x",  # 注: "西" 已映射 c
    "丫": "y", "歪": "y", "呀": "y", "亚": "y",
    "贼": "z", "则": "z", "子": "z",
    "秀": "show",
}


def try_pinyin_decode(text: str) -> str:
    """尝试把中文拼音谐音文本解码为 ASCII(尽力而为)。

    策略: 按映射表 key 长度降序贪婪匹配。
    "大括号" 在文中通常出现两次: 第一个是 { , 最后一个是 } 。
    """
    if not any("\u4e00" <= ch <= "\u9fff" for ch in text):
        return ""  # 无中文, 跳过

    # "大括号" 上下文: 文中第一次出现 = {, 最后一次 = } (CTF 常见写法)
    marker = "大括号"
    last_pos = text.rfind(marker)

    keys = sorted(PINYIN_MAP.keys(), key=len, reverse=True)
    result = []
    i = 0
    while i < len(text):
        # 先处理上下文相关的大括号
        if text.startswith(marker, i):
            result.append("}" if i == last_pos else "{")
            i += len(marker)
            continue
        matched = False
        for k in keys:
            if text.startswith(k, i):
                result.append(PINYIN_MAP[k])
                i += len(k)
                matched = True
                break
        if not matched:
            i += 1  # 跳过无法匹配的字符(标点/无关字)
    decoded = "".join(result)
    return decoded


def run_exiftool(target: str) -> str:
    """运行 exiftool, 返回完整输出。"""
    try:
        out = subprocess.run(
            ["exiftool", target], capture_output=True, text=True, timeout=30
        ).stdout
        return out
    except Exception:
        return ""


def parse_exif_fields(exif_out: str) -> dict[str, str]:
    """把 exiftool 输出解析为 {字段名: 值} 字典。"""
    fields = {}
    for line in exif_out.splitlines():
        if ":" in line:
            # 字段名: 值  (字段名可能含空格, 取第一个未被引号包裹的冒号)
            idx = line.find(":")
            if idx > 0:
                key = line[:idx].strip()
                val = line[idx + 1 :].strip()
                if val:
                    fields[key] = val
    return fields


class MetadataAnalyzer(Analyzer):
    name = "阶段 2: 元数据分析"
    applies_to = None
    requires = set()

    # flag 头: 字段值以某 flag 前缀 + 可选 {（前缀集合与 flags.py 默认集保持一致）
    _HEAD_RE = re.compile(
        rf"^(?:{prefix_alternation()})\s*\{{?",
        re.IGNORECASE,
    )
    # 尾: 以 } 结尾(可含前置 hex)
    _TAIL_RE = re.compile(r"[0-9a-fA-F]{1,64}\}$")
    # 纯 hex 片段(16-64 位常见 flag 哈希长度)
    _FRAG_RE = re.compile(r"^[0-9a-fA-F]{4,128}$")
    # head 的 hex 部分(前缀{hex...)
    _HEAD_HEX_RE = re.compile(
        rf"^({prefix_alternation()})\{{([0-9a-fA-F]{{0,128}})$",
        re.IGNORECASE,
    )

    def _detect_split_flag(self, ctx: AnalysisContext, fields: dict) -> list:
        """检测 flag 被分割在多个 EXIF 字段的情况。

        策略: 找到以 flag 前缀开头的"头"字段 + 以 } 结尾的"尾"字段,
        按字段在 exiftool 输出中的顺序, 把中间的 hex 片段拼接起来。
        关键: exiftool 常输出重复值(如 Title/Description/XP Title 同值), 需按值去重。
        """
        items = list(fields.items())  # 保持输出顺序
        # 找头(以 flag 前缀开头, 但自身不是完整 flag) — 按值去重
        head_idx, head_val = -1, None
        tail_idx, tail_val = -1, None
        for i, (name, val) in enumerate(items):
            if self._HEAD_RE.match(val) and not find_flags_in_text(val):
                if head_idx < 0:
                    head_idx, head_val = i, val
            # 尾: 以 } 结尾且无 { (单独的尾片)
            if (val.endswith("}") and "{" not in val
                    and not find_flags_in_text(val) and self._TAIL_RE.match(val)):
                if tail_idx < i:  # 取最后一个(可能在头之前, 此时跳过)
                    tail_idx, tail_val = i, val
        if head_idx < 0:  # 没有头, 无法拼
            return []

        # 头字段里 { 后面可能已有 hex
        m = self._HEAD_HEX_RE.match(head_val)
        if m:
            head_prefix = m.group(1) + "{"
            head_hex = m.group(2)
        else:
            head_prefix = head_val.rstrip()
            head_prefix += "" if head_prefix.endswith("{") else "{"
            head_hex = ""

        # 收集头尾之间的 hex 片段(顺序, 按值去重)
        seen_values = {head_hex} if head_hex else set()
        frags: list[str] = [head_hex] if head_hex else []
        involved = [items[head_idx][0]]
        hi = tail_idx if (tail_idx > head_idx) else len(items)
        for j in range(head_idx + 1, hi):
            name, val = items[j]
            if tail_idx == j:
                pre = val[:-1]  # 去掉 }
                if self._FRAG_RE.match(pre) and pre not in seen_values:
                    frags.append(pre)
                    seen_values.add(pre)
                    involved.append(name)
                break
            if self._FRAG_RE.match(val) and val not in seen_values:
                frags.append(val)
                seen_values.add(val)
                involved.append(name)

        body = "".join(frags)
        candidate = (head_prefix + body + "}") if tail_val and tail_idx > head_idx else head_prefix + body
        found = find_flags_in_text(candidate, source=f"{self.name} 字段拼接")
        if found:
            for f in found:
                ctx.add_flag(f, confidence="high", source=f"{self.name} EXIF字段拼接")
                ctx.add_finding(
                    "find",
                    f"flag 分割在多个 EXIF 字段, 拼接得到: {f}",
                    f"涉及字段(按顺序): {involved}",
                    source=self.name,
                )
            return found

        # 兜底: 头后所有短 hex 片段两两/多组合(最多 8 段), 按值去重
        if head_idx >= 0:
            seen: set[str] = set()
            short_frags = []
            for n, v in items[head_idx + 1:hi]:
                if self._FRAG_RE.match(v) and len(v) <= 64 and v not in seen:
                    seen.add(v)
                    short_frags.append((n, v))
            for n in range(1, min(9, len(short_frags) + 1)):
                combined = head_prefix + "".join(v for _, v in short_frags[:n]) + "}"
                found = find_flags_in_text(combined, source=f"{self.name} 字段拼接")
                if found:
                    for f in found:
                        ctx.add_flag(f, confidence="high", source=f"{self.name} EXIF字段拼接")
                        ctx.add_finding(
                            "find",
                            f"flag 分割在多个 EXIF 字段, 拼接得到: {f}",
                            f"涉及字段: {[items[head_idx][0]] + [nn for nn, _ in short_frags[:n]]}",
                            source=self.name,
                        )
                    return found
        return []

    def run(self, ctx: AnalysisContext) -> None:
        if not ctx.tools.have("exiftool"):
            ctx.add_finding("warn", "exiftool 缺失, 跳过元数据分析",
                            "apt install libimage-exiftool-perl | dnf install perl-Image-ExifTool")
            return

        out = run_exiftool(ctx.target)
        if not out:
            ctx.add_finding("info", "exiftool 无输出")
            return
        ctx.save_bytes("exiftool_full.txt", out.encode("utf-8", "replace"), "完整 exiftool 输出")

        fields = parse_exif_fields(out)

        # 1. 整体扫描 flag
        joined = out
        flags = find_flags_in_text(joined, source=self.name)
        for f in flags:
            ctx.add_flag(f, confidence="high", source=f"{self.name} EXIF")
            ctx.add_finding("find", f"EXIF 中发现 flag: {f}", source=self.name)

        # 2. 检查可疑字段(关键字命中)
        suspicious_values = []
        for fname, val in fields.items():
            low_field = fname.lower()
            low_val = val.lower()
            if any(k in low_field or k in low_val for k
                   in ("flag", "ctf", "comment", "warning", "secret", "key", "password")):
                suspicious_values.append((fname, val))
                if find_flags_in_text(val):
                    ctx.add_finding("find", f"字段 {fname} 含 flag: {val[:80]}", source=self.name)

        # 3. flag 分割检测: flag 可能被切碎分布在多个 EXIF 字段
        # misc18: Title=ctfshow{32 + Model/Artist(中间hex片) + LensModel=...}
        # misc19: DocumentName=ctfshow{...5 + HostComputer=...}
        # 关键: 只要某字段以 flag 前缀开头(或某字段以 } 结尾), 就把中间的
        #       hex/短片段按 exiftool 输出顺序拼接, 再扫描 flag。
        if not flags:
            split_found = self._detect_split_flag(ctx, fields)
            flags = split_found  # 已在 _detect_split_flag 中登记

        # 4. 非英文编码检测(中文拼音谐音)
        if not flags:
            for fname, val in fields.items():
                decoded = try_pinyin_decode(val)
                if decoded and ("ctfshow" in decoded.lower() or "flag" in decoded.lower()
                                or "ctf" in decoded.lower()):
                    ctx.add_flag(decoded, confidence="medium",
                                 source=f"{self.name} 字段{fname}中文谐音解码")
                    ctx.add_finding(
                        "find",
                        f"字段 {fname} 是中文拼音谐音编码, 解码: {decoded}",
                        f"原文: {val[:100]}",
                        source=self.name,
                    )

        # 5. 提示可疑字段(供人工)
        if suspicious_values and not flags:
            ctx.add_finding(
                "hint",
                f"发现 {len(suspicious_values)} 个可疑 EXIF 字段(可能含 flag 或线索)",
                "\n        ".join(f"{n}: {v[:60]}" for n, v in suspicious_values[:6]),
                source=self.name,
            )

        if not flags and not suspicious_values:
            ctx.add_finding("info", "EXIF 无可疑字段")
