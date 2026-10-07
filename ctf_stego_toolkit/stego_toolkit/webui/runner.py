"""分析子进程入口: 单独进程里调用 cli.solve(), 把结果序列化为 JSON。

由 webui.jobs 以 ``<python> -m stego_toolkit.webui.runner <图片> <结果json>`` 启动。
独立进程的意义:
- 崩溃/卡死隔离: 父进程按总超时强杀, 不影响 Web 服务;
- 配置新鲜: 前缀正则在 flags 模块 import 时编译, 子进程每次启动都会读到最新的
  STEGO_FLAG_PREFIXES_FILE 配置, WebUI 改前缀后下一题立即生效。

输出 JSON 结构:
    ok / error / elapsed / real_type / suspicion_score / outdir
    flags[{value,confidence,source}] / findings[{level,title,detail,source}]
    artifacts[{path,description,needs_review}] / log_text
退出码: 0 成功; 3 参数或分析失败(仍会尽量写出 JSON); 2 用法错误。
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import time


def _payload(image: str, result_path: str) -> dict:
    # 延迟导入: 确保父进程注入的环境变量(STEGO_FLAG_PREFIXES_FILE)在本进程
    # 导入 flags 模块前已生效。
    from ..cli import solve

    stdout, stderr = io.StringIO(), io.StringIO()
    error = ""
    ctx = None
    t0 = time.time()
    try:
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            ctx = solve(image, verbose=False, color=False)
    except SystemExit as exc:  # solve() 对文件不存在等直接 sys.exit
        error = f"分析进程退出 (code={exc.code})"
    except Exception as exc:  # 兜底: 任何异常都不应让 runner 无输出地死掉
        error = f"{type(exc).__name__}: {exc}"
    elapsed = time.time() - t0

    return {
        "ok": ctx is not None,
        "error": error,
        "elapsed": elapsed,
        "real_type": getattr(ctx, "real_type", "unknown") if ctx else "unknown",
        "suspicion_score": ctx.suspicion_score if ctx else 0,
        "outdir": ctx.outdir if ctx else "",
        "flags": [
            {"value": f.value, "confidence": f.confidence, "source": f.source}
            for f in (ctx.flags if ctx else [])
        ],
        "findings": [
            {"level": f.level, "title": f.title, "detail": f.detail, "source": f.source}
            for f in (ctx.findings if ctx else [])
        ],
        "artifacts": [
            {"path": a.path, "description": a.description, "needs_review": a.needs_review}
            for a in (ctx.artifacts if ctx else [])
        ],
        "log_text": stdout.getvalue() + stderr.getvalue(),
    }


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 2:
        print("用法: python -m stego_toolkit.webui.runner <图片路径> <结果json路径>", file=sys.stderr)
        return 2
    image, result_path = os.path.abspath(argv[0]), os.path.abspath(argv[1])
    os.makedirs(os.path.dirname(result_path) or ".", exist_ok=True)

    try:
        payload = _payload(image, result_path)
    except Exception as exc:  # 连延迟导入都失败的极端情况
        payload = {"ok": False, "error": f"{type(exc).__name__}: {exc}", "elapsed": 0,
                   "real_type": "unknown", "suspicion_score": 0, "outdir": "",
                   "flags": [], "findings": [], "artifacts": [], "log_text": ""}

    with open(result_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False)
    return 0 if payload.get("ok") else 3


if __name__ == "__main__":
    sys.exit(main())
