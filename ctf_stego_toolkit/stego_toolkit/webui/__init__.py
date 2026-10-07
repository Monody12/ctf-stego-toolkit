"""WebUI 子包：单机本地看板, 管理题目、触发分析与查看结果。

设计约束:
- CLI 零改动: WebUI 通过子进程 runner 复用 cli.solve(), 不侵入原代码路径;
- 离线可用: 前端零构建、无任何外链资源, 依赖全部为纯 Python;
- 单机定位: 默认只绑定 127.0.0.1, 无鉴权, SQLite 存储。

启动:
    ctf-stego-webui [--host H] [--port P] [--data-dir D] [--workers N] [--timeout SEC]
    python -m stego_toolkit.webui ...
"""
