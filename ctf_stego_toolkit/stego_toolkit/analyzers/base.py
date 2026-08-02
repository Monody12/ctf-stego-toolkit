"""核心数据结构与分析器基类。

设计:
- Finding: 一次"发现"(级别/标题/内容/来源分析器名)
- Artifact: 一个产出文件(路径/描述/是否需人工查看)
- Flag: 候选 flag(值/置信度/来源)
- Analyzer: 分析器基类, 实现 run(ctx) 把结果写入 ctx
- AnalysisContext: 贯穿一次运行的全局上下文(文件/输出目录/工具表/结果)
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Optional


# --------------------------------------------------------------------------- #
#  结果数据结构
# --------------------------------------------------------------------------- #
@dataclass
class Flag:
    """候选 flag。"""

    value: str
    confidence: str = "medium"  # high / medium / low
    source: str = ""  # 来自哪个分析器/位置

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Flag) and self.value == other.value

    def __hash__(self) -> int:  # 便于去重
        return hash(self.value)


# 级别: info < hint < find < warn < error
LEVELS = ("info", "hint", "find", "warn", "error")
CONFIDENCE_RANK = {"low": 1, "medium": 2, "high": 3}


@dataclass
class Finding:
    """一次发现。level 越高越重要; level=find 计入可疑信号强度。"""

    level: str  # info/hint/find/warn/error
    title: str  # 简短标题
    detail: str = ""  # 详细内容(可多行)
    source: str = ""  # 来源分析器名

    def __post_init__(self) -> None:
        if self.level not in LEVELS:
            raise ValueError(f"未知 level: {self.level}, 应为 {LEVELS}")


@dataclass
class Artifact:
    """产出文件,供人工或后续步骤查看。"""

    path: str  # 绝对路径
    description: str = ""
    needs_review: bool = False  # 是否需人工查看(如含文字的图)


# --------------------------------------------------------------------------- #
#  运行上下文
# --------------------------------------------------------------------------- #
class AnalysisContext:
    """贯穿一次 solve() 调用的全局上下文。"""

    def __init__(
        self,
        target: str,
        outdir: str,
        tools: "ToolRegistry",
        verbose: bool = False,
    ) -> None:
        self.target = os.path.abspath(target)
        self.outdir = outdir
        self.tools = tools
        self.verbose = verbose

        # 原始字节缓存(lazy)
        self._data: Optional[bytes] = None
        # 文件类型(由 filetype 分析器填写): png/jpg/gif/bmp/tiff/webp/...
        self.real_type: str = "unknown"
        # 检测到的文件魔数描述
        self.magic_desc: str = ""

        # 结果收集
        self.findings: list[Finding] = []
        self.artifacts: list[Artifact] = []
        self.flags: list[Flag] = []

        # PNG 深度分析产物(供跨分析器复用): IHDR 信息、chunks、idat 数据等
        self.png_info: dict[str, Any] = {}

    # ---- 文件读取 ---- #
    @property
    def data(self) -> bytes:
        if self._data is None:
            with open(self.target, "rb") as f:
                self._data = f.read()
        return self._data

    # ---- 结果登记 ---- #
    def add_finding(self, level: str, title: str, detail: str = "", source: str = "") -> None:
        src = source or self._caller_name()
        self.findings.append(Finding(level, title, detail, src))

    def add_artifact(self, path: str, description: str = "", needs_review: bool = False) -> None:
        # 规范化为绝对路径
        if not os.path.isabs(path):
            path = os.path.join(self.outdir, path)
        path = os.path.abspath(path)
        for artifact in self.artifacts:
            if artifact.path == path:
                artifact.needs_review = artifact.needs_review or needs_review
                if not artifact.description and description:
                    artifact.description = description
                return
        self.artifacts.append(Artifact(path, description, needs_review))

    def add_flag(self, value: str, confidence: str = "medium", source: str = "") -> None:
        value = value.strip()
        if not value:
            return
        confidence = confidence.lower()
        if confidence not in CONFIDENCE_RANK:
            confidence = "medium"
        flag = Flag(value, confidence, source or self._caller_name())
        for index, existing in enumerate(self.flags):
            if existing.value != value:
                continue
            # 同一个 flag 后续若获得更可靠的证据，应升级而不是保留先前低置信度。
            if CONFIDENCE_RANK[flag.confidence] > CONFIDENCE_RANK[existing.confidence]:
                self.flags[index] = flag
            elif not existing.source and flag.source:
                self.flags[index] = flag
            return
        self.flags.append(flag)

    def save_bytes(self, name: str, data: bytes, description: str = "", needs_review: bool = False) -> str:
        """把字节保存到 outdir/<name>, 返回绝对路径并登记为 artifact。"""
        path = os.path.abspath(os.path.join(self.outdir, name))
        outdir = os.path.abspath(self.outdir)
        if os.path.commonpath((outdir, path)) != outdir:
            raise ValueError(f"产出文件必须位于输出目录内: {name}")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(data)
        self.add_artifact(path, description, needs_review)
        return path

    # ---- 统计 ---- #
    @property
    def suspicion_score(self) -> int:
        """可疑信号强度 = level=find 的发现数 + 找到的 flag 数。"""
        return sum(1 for x in self.findings if x.level == "find") + len(self.flags)

    # ---- 辅助 ---- #
    @staticmethod
    def _caller_name() -> str:
        import sys

        return sys._getframe(2).f_code.co_name


# --------------------------------------------------------------------------- #
#  分析器基类
# --------------------------------------------------------------------------- #
class Analyzer:
    """分析器基类。子类实现 run(ctx), 把结果写入 ctx。

    类属性:
        name: 分析器名(用于日志/来源标记)
        applies_to: 适用的文件类型集合(如 {"png","bmp"}); None = 所有类型
        requires: 依赖的外部工具名集合(如 {"zsteg"}); 缺失则跳过
    """

    name: str = "base"
    applies_to: Optional[set[str]] = None  # None 表示所有类型
    requires: set[str] = set()  # 外部工具依赖

    def run(self, ctx: AnalysisContext) -> None:
        raise NotImplementedError

    # 供 cli 调度: 判断是否适用
    def is_applicable(self, ctx: AnalysisContext) -> bool:
        if self.applies_to is not None and ctx.real_type not in self.applies_to:
            return False
        # 检查工具依赖
        missing = [t for t in self.requires if not ctx.tools.have(t)]
        if missing:
            ctx.add_finding(
                "warn",
                f"{self.name} 跳过",
                f"缺失工具: {', '.join(missing)}",
                source=self.name,
            )
            return False
        return True
