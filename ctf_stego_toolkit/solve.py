#!/usr/bin/env python3
"""CTF 图片隐写自动分析器 — 一键入口。

用法:
    python3 solve.py <图片路径> [-v] [--no-color]
    python3 solve.py            # 交互式
"""
import os
import sys

# 确保能 import stego_toolkit 包(无论从哪里调用)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from stego_toolkit.cli import main

if __name__ == "__main__":
    main()
