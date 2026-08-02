"""命令行入口: 解析参数, 调度分析器, 生成报告。

用法:
    python solve.py <图片路径> [--verbose] [--no-color]
    python solve.py              # 交互式
"""
from __future__ import annotations

import argparse
import os
import sys
from typing import Optional

from .analyzers.base import AnalysisContext
from .env import ToolRegistry

# ANSI 颜色
_COLORS = {
    "RED": "\033[31m", "GREEN": "\033[32m", "YELLOW": "\033[33m",
    "BLUE": "\033[34m", "MAGENTA": "\033[35m", "CYAN": "\033[36m",
    "BOLD": "\033[1m", "DIM": "\033[2m", "RST": "\033[0m",
}
_NO_COLOR = {k: "" for k in _COLORS}


def _c(name: str) -> str:
    return _COLORS.get(name, "")


# 日志函数
def log_title(msg: str) -> None:
    bar = "═" * 64
    print(f"\n{_c('BOLD')}{_c('CYAN')}{bar}\n{msg}\n{bar}{_c('RST')}")


def log_step(msg: str) -> None:
    print(f"\n{_c('BOLD')}{_c('BLUE')}▶ {msg}{_c('RST')}")


def log_info(msg: str) -> None:
    print(f"{_c('DIM')}  ℹ {msg}{_c('RST')}")


def log_ok(msg: str) -> None:
    print(f"{_c('GREEN')}  ✓ {msg}{_c('RST')}")


def log_warn(msg: str) -> None:
    print(f"{_c('YELLOW')}  ! {msg}{_c('RST')}", file=sys.stderr)


def log_hint(msg: str) -> None:
    print(f"{_c('MAGENTA')}  💡 {msg}{_c('RST')}")


def log_find(msg: str) -> None:
    print(f"{_c('GREEN')}  ★ {msg}{_c('RST')}")


def banner(version: str) -> None:
    print(
        f"""{_c('BOLD')}
   _____ _______   _____ _    _ _____  _      ____   ____ _   _
  / ____|__   __| |  __ \\ |  | |  __ \\| |    / __ \\ / __ \\ \\ / /
 | (___    | |    | |__) | |  | | |__) | |   | |  | | |  | \\ V /
  \\___ \\   | |    |  _  /| |  | |  ___/| |   | |  | | |  | |> <
  ____) |  | |    | | \\ \\| |__| | |    | |___| |__| | |__| / . \\
 |_____/   |_|    |_|  \\_\\\\____/|_|    |______\\____/ \\____/_/ \\_\\{_c('RST')}
{_c('DIM')}           CTF 图片隐写自动分析器 v{version}  |  Python {sys.version.split()[0]}{_c('RST')}

"""
    )


# --------------------------------------------------------------------------- #
#  分析器注册
# --------------------------------------------------------------------------- #
def get_all_analyzers():
    """延迟导入所有分析器, 返回有序列表。"""
    from .analyzers.filetype import FileTypeAnalyzer
    from .analyzers.metadata import MetadataAnalyzer
    from .analyzers.strings_scan import StringsAnalyzer
    from .analyzers.binwalk_scan import BinwalkAnalyzer
    from .analyzers.png_deep import PNGDeepAnalyzer
    from .analyzers.extra_data import ExtraDataAnalyzer
    from .analyzers.lsb import LSBAnalyzer
    from .analyzers.jpg_deep import JPGDeepAnalyzer
    from .analyzers.gif_deep import GIFDeepAnalyzer
    from .analyzers.bmp_deep import BMPDeepAnalyzer
    from .analyzers.tiff_deep import TIFFDeepAnalyzer
    from .analyzers.contest_rules import ContestRulesAnalyzer
    from .analyzers.bitplane import BitPlaneAnalyzer
    from .analyzers.barcode import BarcodeAnalyzer
    from .analyzers.visual import VisualAnalyzer

    # 顺序很重要: filetype 先跑(确定 real_type), 再跑其他
    return [
        FileTypeAnalyzer(),
        MetadataAnalyzer(),
        StringsAnalyzer(),
        BinwalkAnalyzer(),
        PNGDeepAnalyzer(),
        ExtraDataAnalyzer(),
        LSBAnalyzer(),
        JPGDeepAnalyzer(),
        GIFDeepAnalyzer(),
        BMPDeepAnalyzer(),
        TIFFDeepAnalyzer(),
        ContestRulesAnalyzer(),
        BitPlaneAnalyzer(),
        BarcodeAnalyzer(),
        VisualAnalyzer(),
    ]


# --------------------------------------------------------------------------- #
#  报告输出
# --------------------------------------------------------------------------- #
def print_findings(ctx: AnalysisContext) -> None:
    """实时打印分析器产生的 findings。"""
    for f in ctx.findings:
        if f.level == "info":
            log_info(f"{f.title}" + (f"\n{f.detail}" if f.detail and ctx.verbose else ""))
        elif f.level == "hint":
            log_hint(f"{f.title}" + (f"\n        {f.detail}" if f.detail else ""))
        elif f.level == "find":
            detail = f"\n        {f.detail}" if f.detail else ""
            log_find(f"{f.title}{detail}")
        elif f.level == "warn":
            log_warn(f"{f.title}" + (f"\n        {f.detail}" if f.detail else ""))
        elif f.level == "error":
            print(f"{_c('RED')}  ✗ {f.title}{_c('RST')}", file=sys.stderr)


def final_report(ctx: AnalysisContext, version: str) -> None:
    log_title("分析与提取总结")

    # flags
    if ctx.flags:
        print(f"{_c('BOLD')}{_c('GREEN')}  ★★★ 找到 {len(ctx.flags)} 个候选 flag:{_c('RST')}")
        for i, fl in enumerate(ctx.flags, 1):
            conf_tag = {"high": "🟢", "medium": "🟡", "low": "⚪"}.get(fl.confidence, "")
            print(f"     {i}. {conf_tag} {fl.value}")
            print(f"        (置信度: {fl.confidence}  来源: {fl.source})")
    else:
        log_info("未自动提取到 flag")

    print()
    print(f"{_c('DIM')}  可疑信号强度: {ctx.suspicion_score}{_c('RST')}")

    # artifacts
    review = [a for a in ctx.artifacts if a.needs_review]
    if ctx.artifacts:
        print(f"\n{_c('BOLD')}▶ 产出文件 ({len(ctx.artifacts)} 个):{_c('RST')}")
        for a in ctx.artifacts:
            mark = "🔍" if a.needs_review else "📁"
            print(f"  {mark} {a.path}")
            if a.description:
                print(f"     {_c('DIM')}{a.description}{_c('RST')}")

    # 人工介入建议
    print(f"\n{_c('BOLD')}▶ 人工介入建议:{_c('RST')}")
    if review:
        print(f"  {_c('YELLOW')}🔍 有 {len(review)} 个文件需人工查看(可能含文字/二维码):{_c('RST')}")
        for a in review[:8]:
            print(f"     - {os.path.basename(a.path)}: {a.description}")
    if not ctx.flags:
        print(f"  {_c('DIM')}- 未自动找到 flag, 尝试:{_c('RST')}")
        print(f"  {_c('DIM')}  1. 用图像查看器打开所有 .png 产出(含文字/二维码){_c('RST')}")
        print(f"  {_c('DIM')}  2. 用 xxd 查看 .bin 产出, 识别文件头{_c('RST')}")
        print(f"  {_c('DIM')}  3. 若是 JPEG 怀疑 steghide, 找密码后提取{_c('RST')}")
        print(f"  {_c('DIM')}  4. zsteg -a <file> (全模式 LSB){_c('RST')}")
    print(f"\n{_c('DIM')}  输出目录: {ctx.outdir}{_c('RST')}")


# --------------------------------------------------------------------------- #
#  主入口
# --------------------------------------------------------------------------- #
def solve(target: str, verbose: bool = False, color: bool = True) -> AnalysisContext:
    """对单个文件执行完整分析, 返回 context。"""
    from . import __version__

    if not color:
        global _COLORS
        _COLORS = _NO_COLOR

    target = os.path.abspath(target)
    if not os.path.isfile(target):
        print(f"{_c('RED')}✗ 文件不存在: {target}{_c('RST')}", file=sys.stderr)
        sys.exit(1)

    # 输出目录
    basedir = os.path.dirname(target) or "."
    basename = os.path.splitext(os.path.basename(target))[0]
    outdir = os.path.join(basedir, f"{basename}_out")
    os.makedirs(outdir, exist_ok=True)

    banner(__version__)
    print(f"{_c('DIM')}  目标: {target}{_c('RST')}")
    print(f"{_c('DIM')}  输出: {outdir}{_c('RST')}")

    # 环境检测
    log_title("阶段 0: 环境检测")
    tools = ToolRegistry()
    for t in tools.tools.values():
        if t.available:
            log_ok(f"{t.name} ({t.description})")
        elif t.required:
            print(f"{_c('RED')}  ✗ {t.name} 缺失 ({t.description}) — 必需工具!{_c('RST')}", file=sys.stderr)
        else:
            log_warn(f"{t.name} 缺失 ({t.description}) — {_c('DIM')}{t.install_hint}{_c('RST')}")
    if tools.has_pillow():
        log_ok("Pillow (图像像素操作)")
    else:
        log_warn("Pillow 缺失 — pip install Pillow")
    if tools.check_stdlib():
        log_ok("Python 标准库 (zlib/struct/base64/...) 就绪")
    if tools.missing():
        log_hint("缺失工具可在离线环境用 apt/dnf install <名> 或参考 docs/环境安装指南.md")

    ctx = AnalysisContext(target, outdir, tools, verbose=verbose)

    # 运行分析器
    analyzers = get_all_analyzers()
    for az in analyzers:
        log_step(f"{az.name}")
        # 记录此分析器运行前的 finding 数, 用于只打印新增
        prev_count = len(ctx.findings)
        try:
            if az.is_applicable(ctx):
                az.run(ctx)
        except Exception as e:
            ctx.add_finding("error", f"{az.name} 异常", str(e), source=az.name)
        # 打印此分析器新增的 findings
        for f in ctx.findings[prev_count:]:
            if f.level == "info":
                msg = f.title + (f"\n        {f.detail}" if f.detail and verbose else "")
                log_info(msg)
            elif f.level == "hint":
                log_hint(f.title + (f"\n        {f.detail}" if f.detail else ""))
            elif f.level == "find":
                log_find(f.title + (f"\n        {f.detail}" if f.detail else ""))
            elif f.level == "warn":
                log_warn(f.title + (f"\n        {f.detail}" if f.detail else ""))
            elif f.level == "error":
                print(f"{_c('RED')}  ✗ {f.title}{_c('RST')}", file=sys.stderr)

    # 打印找到的 flag(实时, 不等报告)
    if ctx.flags:
        log_title("★ 提取到的 flag")
        for fl in ctx.flags:
            conf = {"high": "🟢高", "medium": "🟡中", "low": "⚪低"}.get(fl.confidence, "")
            print(f"  {_c('BOLD')}{_c('GREEN')}{fl.value}{_c('RST')}  [{conf}置信度]")

    final_report(ctx, __version__)
    return ctx


def main(argv: Optional[list[str]] = None) -> None:
    parser = argparse.ArgumentParser(
        prog="solve.py",
        description="CTF 图片隐写自动分析器 — 支持 PNG/JPG/GIF/BMP/TIFF/WebP",
    )
    parser.add_argument("target", nargs="?", help="图片路径(不给则交互式询问)")
    parser.add_argument("-v", "--verbose", action="store_true", help="显示详细信息")
    parser.add_argument("--no-color", action="store_true", help="关闭彩色输出")
    parser.add_argument("--batch", action="store_true", help="按 misc 编号批量分析 questions 目录")
    parser.add_argument("--start", type=int, default=1, help="批量模式起始编号")
    parser.add_argument("--end", type=int, default=45, help="批量模式结束编号")
    parser.add_argument("--expected-file", help="可选 expected flag 文件, 用于批量验证")
    parser.add_argument("--report-dir", help="批量报告输出目录")
    parser.add_argument(
        "--list-prefixes", action="store_true",
        help="查看当前生效的 flag 前缀（内置 + 自定义），然后退出",
    )
    parser.add_argument(
        "--add-prefix", metavar="NAME", dest="add_prefix",
        help="新增一个自定义 flag 前缀（写入 flag_prefixes.json），然后退出",
    )
    parser.add_argument(
        "--remove-prefix", metavar="NAME", dest="remove_prefix",
        help="删除一个自定义 flag 前缀，然后退出",
    )
    parser.add_argument(
        "--reset-prefixes", action="store_true", dest="reset_prefixes",
        help="清空自定义前缀，恢复为内置列表，然后退出",
    )
    args = parser.parse_args(argv)

    if args.no_color:
        global _COLORS
        _COLORS = _NO_COLOR

    # 前缀管理子命令：在独立调用中完成，执行后直接退出（不与解题同进程，
    # 避免模块级正则与新配置不同步）。
    from . import prefix_config

    code = prefix_config.manage(
        list_=args.list_prefixes,
        add=args.add_prefix,
        remove=args.remove_prefix,
        reset=args.reset_prefixes,
    )
    if code is not None:
        sys.exit(code)

    target = args.target
    if not target:
        target = input("请输入图片路径: ").strip().strip('"').strip("'")
    if not target:
        print("未提供路径", file=sys.stderr)
        sys.exit(1)

    if args.batch:
        from .batch import run_batch

        run_batch(
            target,
            start=args.start,
            end=args.end,
            expected_file=args.expected_file,
            report_dir=args.report_dir,
            color=not args.no_color,
        )
        return

    solve(target, verbose=args.verbose, color=not args.no_color)


if __name__ == "__main__":
    main()
