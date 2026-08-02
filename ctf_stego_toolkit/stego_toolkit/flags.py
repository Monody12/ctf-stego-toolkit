"""统一 flag 扫描器。

扫描器刻意保持为纯标准库，供所有分析器复用。它处理常见 CTF 前缀、
UTF-16 文本、Base64/hex、常见压缩容器以及常见文本编码（HTML 实体 /
URL 编码 / \\uXXXX 转义）；每一层都有限制，避免把恶意压缩数据当作
无限大的输入处理。

flag 前缀默认覆盖常见 CTF 平台，并支持用户通过 ``flag_prefixes.json``
扩展自定义前缀（见 ``prefix_config.py`` 与 README）。模块导入时即合并
配置，因此各分析器引用 ``DEFAULT_PREFIXES`` 时自动获得最终生效集合。
"""
from __future__ import annotations

import base64
import binascii
import bz2
import html
import lzma
import os
import re
import urllib.parse
import zipfile
import zlib
from io import BytesIO
from itertools import product
from typing import Iterable, Iterator, Sequence, Union

from .analyzers.base import Flag


# --------------------------------------------------------------------------- #
#  内置 flag 前缀（常见 CTF 平台 / 通用关键字）
# --------------------------------------------------------------------------- #
# 正则以 ASCII 不区分大小写编译，因此不需要把 flag/FLAG/CTF 逐一列出。
# 用户自定义前缀通过 flag_prefixes.json 叠加（见下方 _load_prefixes）。
_BUILTIN_PREFIXES: tuple[str, ...] = (
    # 通用 / 经典
    "flag",
    "key",
    "ctf",
    # 国内常见平台
    "ctfshow",
    "ctfhub",
    "bugku",
    "ciscn",
    "cyberpeace",
    "dasctf",
    "d3ctf",
    "0ctf",
    "qwb",
    "rwctf",
    "r3ctf",
    "rctf",
    "hwb",
    "hgame",
    "moectf",
    "nctf",
    "nssctf",
    "swpuctf",
    "synctf",
    "suctf",
    "unctf",
    "vnctf",
    "wctf",
    "xctf",
    "tuctf",
    "uctf",
    "simplectf",
    "actf",
    "cctf",
    # 海外常见平台
    "picoctf",
    "dice",
    "corctf",
    "sekai",
    "uiuctf",
    "tjctf",
    "idek",
    "tcp1p",
    "hkcert",
    "xyctf",
    "litctf",
    "rakuctf",
    "syctf",
)


def _candidate_config_paths() -> list[str]:
    """按优先级返回用户配置文件的查找路径（前者优先）。

    顺序: 环境变量指定 → 当前工作目录 → 包目录 → 项目根（包目录的上两级）。
    """
    paths: list[str] = []
    env_path = os.environ.get("STEGO_FLAG_PREFIXES_FILE")
    if env_path:
        paths.append(os.path.abspath(env_path))
    paths.append(os.path.abspath("flag_prefixes.json"))
    here = os.path.dirname(os.path.abspath(__file__))
    paths.append(os.path.join(here, "flag_prefixes.json"))
    project_root = os.path.dirname(os.path.dirname(here))
    paths.append(os.path.join(project_root, "flag_prefixes.json"))
    return paths


def _load_user_prefixes() -> tuple[tuple[str, ...], bool]:
    """读取 flag_prefixes.json，返回 (自定义前缀元组, replace_default)。

    任一候选路径存在即采用（不再继续查找）。解析失败或文件不存在时返回
    空列表 + replace_default=False，即纯内置生效。
    """
    for path in _candidate_config_paths():
        if not os.path.isfile(path):
            continue
        try:
            import json

            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            return (), False
        if not isinstance(data, dict):
            return (), False
        raw = data.get("prefixes", [])
        replace = bool(data.get("replace_default", False))
        prefixes = [str(item).strip() for item in raw] if isinstance(raw, list) else []
        prefixes = [item for item in prefixes if item]
        return tuple(prefixes), replace
    return (), False


def _build_default_prefixes() -> tuple[str, ...]:
    """合并内置与用户配置，得到最终生效前缀集合（去重、按长度排序）。"""
    user, replace = _load_user_prefixes()
    if replace:
        combined = user if user else _BUILTIN_PREFIXES
    else:
        combined = (*_BUILTIN_PREFIXES, *user)
    # 去重（大小写不敏感）并按长度降序排序，保证长前缀优先匹配。
    seen: set[str] = set()
    unique: list[str] = []
    for item in combined:
        key = item.lower()
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return tuple(sorted(unique, key=lambda value: (-len(value), value.lower())))


# 最终生效的默认前缀集合（模块导入时一次性确定，供所有分析器复用）。
DEFAULT_PREFIXES: tuple[str, ...] = _build_default_prefixes()

# Flag 内容通常是可打印 ASCII。大括号必须排除，否则贪婪量词会把
# ``flag{one} ... ctf{two}`` 错并成一个候选。
MAX_FLAG_CONTENT_LENGTH = 1024
_FLAG_TPL = r"(?:__PREFIXES__)\{[\x20-\x7a\x7c\x7e]{1," + str(MAX_FLAG_CONTENT_LENGTH) + r"}\}"

# 深度扫描的资源上限。它们足以覆盖正常 CTF payload，同时避免压缩炸弹。
MAX_ENCODED_CANDIDATES = 64
MAX_ENCODED_CHARS = 16 * 1024
MAX_DECODED_BYTES = 4 * 1024 * 1024
MAX_SCAN_DEPTH = 2

_BASE64_RE = re.compile(
    rb"(?<![A-Za-z0-9+/=_-])([A-Za-z0-9+/_-]{8," + str(MAX_ENCODED_CHARS).encode() + rb"}={0,2})(?![A-Za-z0-9+/=_-])"
)
_HEX_RE = re.compile(
    rb"(?<![0-9a-fA-F])([0-9a-fA-F]{16," + str(MAX_ENCODED_CHARS).encode() + rb"})(?![0-9a-fA-F])"
)

# 纯 32 位 hex（可能是 flag 的 md5 部分）。
_HEX32_PAT = re.compile(rb"(?<![0-9a-fA-F])[0-9a-fA-F]{32}(?![0-9a-fA-F])")
# 默认的 hex-ish flag 正则（OCR 碎片修复用），按 DEFAULT_PREFIXES 构建。
_HEXISH_FLAG_RE = re.compile(
    r"(" + "|".join(re.escape(p) for p in DEFAULT_PREFIXES) + r")\s*\{\s*([^}\r\n]{8,96})\s*\}",
    re.IGNORECASE,
)


def prefix_alternation(prefixes: Union[Iterable[str], str, None] = None) -> str:
    """返回已 escape、按长度降序排列的前缀正则分支串。

    供需要把前缀写进自定义正则的分析器使用，避免重复维护写死的前缀列表。
    例如::

        pat = re.compile(rf"(?:{prefix_alternation()})\\{{[^}}]{{4,}}\\}}")
    """
    normalized = normalize_prefixes(prefixes)
    escaped = [re.escape(item) for item in normalized]
    # normalize_prefixes 已按长度降序，直接拼接即可。
    return "|".join(escaped) or "flag"

_HEX_CONFUSABLES = {
    "O": "0",
    "o": "0",
    "Q": "0",
    "I": "1",
    "l": "1",
    "|": "1",
    "Z": "2",
    "S": "5",
    "s": "5",
    "G": "6",
    "g": "6",
    "T": "f",
    "t": "f",
    "/": "7",
    "\\": "7",
    "?": "7",
    "B": "8",
}

_LOOSE_HEX_CHARS = set("0123456789abcdefABCDEFoOQIl|ZzSsGgTt/\\?B")
_LOOSE_HEX_ALTS = {
    "O": "0",
    "o": "0",
    "Q": "0",
    "I": "1",
    "l": "1",
    "|": "1",
    "Z": "2",
    "z": "2",
    "S": "58",
    "s": "58",
    "G": "6",
    "g": "6",
    "T": "f",
    "t": "f",
    "/": "7",
    "\\": "7",
    "?": "7",
    # Uppercase B is often an OCR rendering of 0/8 in pixel fonts. Lowercase
    # b is a normal hex digit and is kept exact below.
    "B": "08b",
    "C": "ce",
    "E": "ec",
}


def normalize_prefixes(prefixes: Union[Iterable[str], str, None] = None) -> tuple[str, ...]:
    """返回去空、去重且按长度排序的前缀元组。

    接受单个字符串是为了让 CLI/API 调用 ``prefixes="team"`` 时不会被
    误解释为 ``t/e/a/m`` 四个前缀。长度排序也能保证自定义前缀的匹配稳定。
    """
    if prefixes is None:
        return DEFAULT_PREFIXES
    values: Iterable[str]
    if isinstance(prefixes, str):
        values = (prefixes,)
    else:
        values = prefixes

    result: list[str] = []
    seen: set[str] = set()
    for prefix in values:
        value = str(prefix).strip()
        key = value.lower()
        if value and key not in seen:
            seen.add(key)
            result.append(value)
    return tuple(sorted(result, key=lambda item: (-len(item), item.lower())))


def _build_pattern(prefixes: Sequence[str]) -> re.Pattern[bytes]:
    """构建 bytes flag 正则。"""
    escaped = "|".join(re.escape(item) for item in prefixes) or "flag"
    return re.compile(_FLAG_TPL.replace("__PREFIXES__", escaped).encode("ascii"), re.IGNORECASE)


def _build_text_pattern(prefixes: Sequence[str]) -> re.Pattern[str]:
    """构建 str flag 正则。"""
    escaped = "|".join(re.escape(item) for item in prefixes) or "flag"
    return re.compile(_FLAG_TPL.replace("__PREFIXES__", escaped), re.IGNORECASE)


_BYTES_PAT = _build_pattern(DEFAULT_PREFIXES)
_TEXT_PAT = _build_text_pattern(DEFAULT_PREFIXES)


def _patterns(prefixes: Union[Iterable[str], str, None]) -> tuple[re.Pattern[str], re.Pattern[bytes], tuple[str, ...]]:
    normalized = normalize_prefixes(prefixes)
    if normalized == DEFAULT_PREFIXES:
        return _TEXT_PAT, _BYTES_PAT, normalized
    return _build_text_pattern(normalized), _build_pattern(normalized), normalized


def _append_matches(results: list[str], seen: set[str], matches: Iterable[Union[str, bytes]]) -> None:
    for match in matches:
        if isinstance(match, bytes):
            try:
                value = match.decode("ascii")
            except UnicodeDecodeError:
                continue
        else:
            value = match
        if value not in seen:
            seen.add(value)
            results.append(value)


def _utf16_ascii_views(blob: bytes) -> Iterator[bytes]:
    """产出明显 UTF-16 ASCII 文本的有效字节位。

    只在另一条字节位至少一半是 NUL 时启用，避免把普通像素的隔位数据当作
    文字。UTF-16 LE 与 BE 都可识别。
    """
    if len(blob) < 8:
        return
    for text_offset in (0, 1):
        text_bytes = blob[text_offset::2]
        padding = blob[1 - text_offset::2]
        if padding and padding.count(0) * 2 >= len(padding):
            yield text_bytes


def find_flags_in_text(
    text: Union[str, bytes, bytearray, memoryview],
    source: str = "",
    prefixes: Union[Iterable[str], str, None] = None,
) -> list[str]:
    """在 ``str`` 或 bytes 中查找明文 flag，按出现顺序去重。

    ``source`` 保留在函数签名中以兼容旧调用；来源由调用方在 ``Flag`` 对象
    中记录。bytes 输入额外尝试 UTF-16 LE/BE 的 ASCII 子集。
    """
    del source  # 保持向后兼容，结果类型本身不携带来源。
    text_pattern, bytes_pattern, _ = _patterns(prefixes)
    results: list[str] = []
    seen: set[str] = set()

    if isinstance(text, str):
        _append_matches(results, seen, (match.group() for match in text_pattern.finditer(text)))
        blob = text.encode("latin1", "ignore")
    else:
        blob = bytes(text)

    _append_matches(results, seen, (match.group() for match in bytes_pattern.finditer(blob)))
    for view in _utf16_ascii_views(blob):
        _append_matches(results, seen, (match.group() for match in bytes_pattern.finditer(view)))
    return results


def _decode_base64(chunk: bytes) -> bytes:
    """解码标准或 URL-safe Base64；无效输入返回空字节串。"""
    if not chunk or len(chunk) > MAX_ENCODED_CHARS or len(chunk) % 4 == 1:
        return b""
    padded = chunk + (b"=" * (-len(chunk) % 4))
    try:
        if b"-" in chunk or b"_" in chunk:
            return base64.b64decode(padded, altchars=b"-_", validate=True)
        return base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return b""


def _limited_zlib_decompress(data: bytes, wbits: int) -> bytes:
    try:
        decoder = zlib.decompressobj(wbits)
        result = decoder.decompress(data, MAX_DECODED_BYTES + 1)
        if len(result) > MAX_DECODED_BYTES or decoder.unconsumed_tail:
            return b""
        result += decoder.flush(MAX_DECODED_BYTES + 1 - len(result))
        if len(result) > MAX_DECODED_BYTES:
            return b""
        return result
    except zlib.error:
        return b""


def _decompress_payloads(blob: bytes) -> Iterator[tuple[str, bytes]]:
    """产出可安全解开的根容器 payload，不猜测任意偏移。"""
    if blob.startswith(b"\x1f\x8b"):
        result = _limited_zlib_decompress(blob, 31)
        if result:
            yield "gzip", result
    elif len(blob) >= 2 and blob[0] == 0x78 and ((blob[0] << 8) + blob[1]) % 31 == 0:
        result = _limited_zlib_decompress(blob, zlib.MAX_WBITS)
        if result:
            yield "zlib", result
    elif blob.startswith(b"BZh"):
        try:
            result = bz2.BZ2Decompressor().decompress(blob, MAX_DECODED_BYTES + 1)
            if len(result) <= MAX_DECODED_BYTES:
                yield "bzip2", result
        except (OSError, EOFError):
            pass
    elif blob.startswith(b"\xfd7zXZ\x00") or (len(blob) >= 13 and blob[0] == 0x5D):
        try:
            result = lzma.LZMADecompressor().decompress(blob, MAX_DECODED_BYTES + 1)
            if len(result) <= MAX_DECODED_BYTES:
                yield "lzma", result
        except lzma.LZMAError:
            pass
    elif blob.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        try:
            with zipfile.ZipFile(BytesIO(blob)) as archive:
                total = 0
                for entry in archive.infolist():
                    if entry.is_dir() or entry.flag_bits & 0x1 or entry.file_size > MAX_DECODED_BYTES:
                        continue
                    total += entry.file_size
                    if total > MAX_DECODED_BYTES:
                        break
                    with archive.open(entry) as member:
                        result = member.read(MAX_DECODED_BYTES + 1)
                    if len(result) <= MAX_DECODED_BYTES:
                        yield "zip:%s" % entry.filename, result
        except (OSError, RuntimeError, ValueError, zipfile.BadZipFile):
            pass


# 文本编码解码的资源上限：只对相对较小的 ASCII 文本运行，避免对大二进制
# 的热路径逐字节做 latin1 解码。
_MAX_TEXT_DECODE_BYTES = 64 * 1024
_MIN_PRINTABLE_RATIO = 0.75
# 命名实体/百分比/转义出现时才尝试对应解码，避免对普通文本做无谓转换。
_ENTITY_RE = re.compile(rb"&#x?[0-9A-Fa-f]+;|&[A-Za-z][A-Za-z0-9]+;")
_PERCENT_RE = re.compile(rb"%[0-9A-Fa-f]{2}")
# JS/C 风格的 \uXXXX 与 \xNN 转义（要求出现至少一处）。
_UESCAPE_RE = re.compile(rb"\\u[0-9A-Fa-f]{4}")
_XESCAPE_RE = re.compile(rb"\\x[0-9A-Fa-f]{2}")


def _is_mostly_ascii_text(blob: bytes) -> bool:
    """判断 blob 是否像 ASCII 文本（长度受限 + 可打印占比达标）。"""
    if not blob or len(blob) < 4 or len(blob) > _MAX_TEXT_DECODE_BYTES:
        return False
    printable = 0
    for b in blob:
        # 9=\t 10=\n 13=\r，其余 32..126 为可见 ASCII。
        if b in (9, 10, 13) or 32 <= b <= 126:
            printable += 1
    return printable * 4 >= len(blob) * 3  # >=75% 可打印


def _decode_text_payloads(blob: bytes) -> Iterator[tuple[str, bytes]]:
    """对 ASCII 文本产出常见文本编码的解码变体（仅当原文确实变化时）。

    覆盖: HTML 数字/命名实体（&#107; / &#x6b; / &amp;）、URL 百分号编码
    （%6b）、JS/C 风格的 \\uXXXX 与 \\xNN 转义。仅当原文里出现对应特征时
    才解码，避免把普通 ASCII 文本也走一遍。
    """
    if not _is_mostly_ascii_text(blob):
        return
    try:
        text = blob.decode("latin1")
    except Exception:
        return

    # HTML 实体（同时含数字实体 &#107; / &#x6b; 与命名实体 &amp;）。
    if _ENTITY_RE.search(blob):
        try:
            decoded = html.unescape(text)
        except Exception:
            decoded = ""
        if decoded and decoded != text:
            yield "HTML实体解码", decoded.encode("utf-8", "ignore")

    # URL 百分号编码（%6b 等）。
    if _PERCENT_RE.search(blob):
        try:
            decoded = urllib.parse.unquote(text, errors="replace")
        except Exception:
            decoded = ""
        if decoded and decoded != text:
            yield "URL解码", decoded.encode("utf-8", "ignore")

    # JS/C 风格的 \uXXXX 转义。
    if _UESCAPE_RE.search(blob):
        try:
            decoded = text.encode("latin1").decode("unicode_escape")
        except Exception:
            decoded = ""
        if decoded and decoded != text:
            yield "Unicode转义解码", decoded.encode("utf-8", "ignore")
    elif _XESCAPE_RE.search(blob):
        try:
            decoded = text.encode("latin1").decode("unicode_escape")
        except Exception:
            decoded = ""
        if decoded and decoded != text:
            yield "Hex转义解码", decoded.encode("utf-8", "ignore")


def _scan_flags(
    blob: bytes,
    source: str,
    prefixes: tuple[str, ...],
    depth: int,
) -> list[Flag]:
    flags: list[Flag] = []
    for value in find_flags_in_text(blob, prefixes=prefixes):
        flags.append(Flag(value, "high", source or "明文"))

    if depth >= MAX_SCAN_DEPTH:
        return flags

    # Base64: 使用 bytes 正则避免 Latin-1 字符串复制；支持无 padding 及 URL-safe 变体。
    for index, match in enumerate(_BASE64_RE.finditer(blob)):
        if index >= MAX_ENCODED_CANDIDATES:
            break
        decoded = _decode_base64(match.group(1))
        if decoded and len(decoded) <= MAX_DECODED_BYTES:
            flags.extend(_scan_flags(decoded, (source + " base64解码").strip(), prefixes, depth + 1))

    # Hex 不依赖固定前缀，故自定义 flag 前缀同样有效。
    for index, match in enumerate(_HEX_RE.finditer(blob)):
        if index >= MAX_ENCODED_CANDIDATES:
            break
        try:
            decoded = binascii.unhexlify(match.group(1))
        except (binascii.Error, ValueError):
            continue
        if decoded and len(decoded) <= MAX_DECODED_BYTES:
            flags.extend(_scan_flags(decoded, (source + " hex解码").strip(), prefixes, depth + 1))

    for method, decoded in _decompress_payloads(blob):
        flags.extend(_scan_flags(decoded, (source + " " + method + "解压").strip(), prefixes, depth + 1))

    # 文本编码层（HTML 实体 / URL / \uXXXX 等）：仅在 ASCII 文本上触发，
    # 解码后既做明文匹配，也递归（可叠加 base64/hex 等）。
    for method, decoded in _decode_text_payloads(blob):
        flags.extend(_scan_flags(decoded, (source + " " + method).strip(), prefixes, depth + 1))
    return flags


def scan_flags(
    blob: Union[bytes, bytearray, memoryview],
    source: str = "",
    prefixes: Union[Iterable[str], str, None] = None,
) -> list[Flag]:
    """深度扫描 bytes，返回去重后的候选 flag。

    除明文外，会递归扫描 Base64、hex、gzip/zlib/bzip2/LZMA/XZ/ZIP payload。
    解码深度、候选数量和每层输出大小均有上限，适合直接用于不可信题目文件。
    """
    raw = bytes(blob)
    if not raw:
        return []
    return _dedupe(_scan_flags(raw, source, normalize_prefixes(prefixes), 0))


def _dedupe(flags: Iterable[Flag]) -> list[Flag]:
    """按 value 去重，同值保留 high > medium > low。"""
    rank = {"high": 3, "medium": 2, "low": 1}
    best: dict[str, Flag] = {}
    for flag in flags:
        current = best.get(flag.value)
        if current is None or rank.get(flag.confidence, 0) > rank.get(current.confidence, 0):
            best[flag.value] = flag
    return list(best.values())


def find_hex32(blob: bytes) -> list[str]:
    """查找独立的 32 位 hex 串（可能是 flag 内容/MD5）。"""
    return [match.group().decode("ascii") for match in _HEX32_PAT.finditer(blob)]


def normalize_hexish_body(body: str) -> str:
    """把 OCR 常见误读清洗成 hex-ish 字符串。

    这个函数只用于已经识别到 flag 前缀的文本片段，不参与普通二进制扫描，
    因此可以比 ``find_flags_in_text`` 更积极地修正常见 OCR 错误。
    """
    chars: list[str] = []
    for ch in body:
        mapped = _HEX_CONFUSABLES.get(ch, ch)
        if mapped in "0123456789abcdefABCDEF":
            chars.append(mapped.lower())
    return "".join(chars)


def _trim_to_hex32(body: str, max_extra: int = 4) -> Iterator[str]:
    """产出长度为 32 的 hex body 变体。

    OCR 偶尔会多读 1-2 个字符，例如把中文谐音 ``诶`` 解成 ``ae`` 时
    真实语义只需要 ``a``。这里只在前缀已可信、且超长很短时尝试删除。
    """
    if len(body) == 32:
        yield body
        return
    extra = len(body) - 32
    if extra <= 0 or extra > max_extra:
        return
    if extra == 1:
        for i in range(len(body)):
            yield body[:i] + body[i + 1 :]
        return
    # 控制组合爆炸；CTF OCR 常见只多 1-2 个字符。
    if extra == 2:
        for i in range(len(body)):
            for j in range(i + 1, len(body)):
                yield body[:i] + body[i + 1 : j] + body[j + 1 :]


def find_normalized_flags(
    text: Union[str, bytes, bytearray, memoryview],
    prefixes: Union[Iterable[str], str, None] = None,
) -> list[str]:
    """查找 OCR/碎片拼接后的规范化 flag 候选。

    普通扫描由 ``find_flags_in_text`` 负责；本函数额外处理:
    - 前缀附近有空格；
    - 32 位 hex body 里有 OCR 混淆字符；
    - body 比 32 位略长，需要删除少量多读字符。
    """
    if isinstance(text, str):
        value = text
    else:
        value = bytes(text).decode("latin1", "ignore")

    allowed = {p.lower() for p in normalize_prefixes(prefixes)}
    results: list[str] = []
    seen: set[str] = set()

    for direct in find_flags_in_text(value, prefixes=prefixes):
        if direct not in seen:
            seen.add(direct)
            results.append(direct)

    for match in _HEXISH_FLAG_RE.finditer(value):
        prefix = match.group(1).lower()
        if prefix not in allowed:
            continue
        body = normalize_hexish_body(match.group(2))
        for fixed in _trim_to_hex32(body):
            candidate = f"{prefix}{{{fixed}}}"
            if candidate not in seen:
                seen.add(candidate)
                results.append(candidate)
    return results


def _loose_body_variants(raw: str, limit: int = 64) -> Iterator[str]:
    choices: list[str] = []
    for char in raw:
        if char in _LOOSE_HEX_ALTS:
            choices.append(_LOOSE_HEX_ALTS[char])
        elif char.lower() in "0123456789abcdef":
            choices.append(char.lower())
        else:
            choices.append("")
    yielded = 0
    for combo in product(*choices):
        value = "".join(combo)
        if not value:
            continue
        yield value
        yielded += 1
        if yielded >= limit:
            return


def find_loose_visual_flags(
    text: Union[str, bytes, bytearray, memoryview],
    prefixes: Union[Iterable[str], str, None] = None,
) -> list[str]:
    """Recover OCR flags where braces or a few hex glyphs were misread.

    This is deliberately stricter than ``find_normalized_flags`` in one way:
    it only returns 32-hex-body candidates following a known prefix. It exists
    for visual OCR outputs such as ``ctfshowCce52Bf...`` where ``C`` is a bad
    ``{`` and uppercase ``B`` may be ``0`` or ``8``.
    """
    if isinstance(text, str):
        value = text
    else:
        value = bytes(text).decode("latin1", "ignore")

    results: list[str] = []
    seen: set[str] = set()
    for direct in find_normalized_flags(value, prefixes=prefixes):
        if direct not in seen:
            seen.add(direct)
            results.append(direct)

    for prefix in normalize_prefixes(prefixes):
        prefix_re = re.compile(re.escape(prefix), re.IGNORECASE)
        for match in prefix_re.finditer(value):
            tail = value[match.end() : match.end() + 128]
            for skip in (1, 0, 2, 3):
                raw_chars: list[str] = []
                for char in tail[skip:]:
                    if char == "}":
                        break
                    if char in _LOOSE_HEX_CHARS:
                        raw_chars.append(char)
                        if len(raw_chars) >= 36:
                            break
                    elif char in "\r\n":
                        break
                    else:
                        # Spaces, underscores, bad braces, and punctuation are
                        # common OCR artifacts. Ignore them while the body is
                        # still plausibly being collected.
                        continue
                raw = "".join(raw_chars)
                if len(raw) < 28 or len(raw) > 36:
                    continue
                for variant in _loose_body_variants(raw):
                    for fixed in _trim_to_hex32(variant):
                        candidate = f"{prefix.lower()}{{{fixed}}}"
                        if candidate not in seen:
                            seen.add(candidate)
                            results.append(candidate)
                            if len(results) >= 16:
                                return results
    return results
