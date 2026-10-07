#!/usr/bin/env python3
"""WebUI 冒烟测试: 不依赖 pytest, 直接用 Flask test client 走完整链路。

覆盖: 建库 -> 上传 PNG -> 后台子进程分析 -> 状态轮询 -> 详情页 -> 人工标注 ->
expected 上传与对答命中 -> 本地目录导入 -> 前缀增删。

用法(在装好 .[webui] 的环境、仓库根下执行):
    python3 scripts/webui_smoke.py
"""
from __future__ import annotations

import io
import json
import struct
import sys
import tempfile
import time
import zlib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "ctf_stego_toolkit"))

SMOKE_FLAG = "flag{webui_smoke_ok}"

PASS, FAIL = [], []


def check(name: str, cond: bool, detail: str = "") -> None:
    (PASS if cond else FAIL).append(name)
    mark = "PASS" if cond else "FAIL"
    print(f"  [{mark}] {name}" + (f" — {detail}" if detail and not cond else ""))


def make_png(text: str) -> bytes:
    """stdlib 生成一张 64x64 灰阶 PNG, 带 tEXt Comment=text(隐写内容)。"""
    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(
            ">I", zlib.crc32(tag + data) & 0xFFFFFFFF
        )

    width = height = 64
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0)
    raw = b"".join(b"\x00" + bytes([(x * 3 + y * 5) % 256 for x in range(width)])
                   for y in range(height))
    idat = zlib.compress(raw)
    text_data = b"Comment\x00" + text.encode("utf-8")
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
            + chunk(b"tEXt", text_data) + chunk(b"IDAT", idat) + chunk(b"IEND", b""))


def wait_status(client, qid: int, timeout: float = 180.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        data = client.get("/api/status").get_json()
        state = data["questions"].get(str(qid), {})
        if state.get("status") in ("done", "error"):
            return state
        time.sleep(1.0)
    return {"status": "timeout"}


def main() -> int:
    data_dir = tempfile.mkdtemp(prefix="stego_webui_smoke_")
    print(f"数据目录: {data_dir}\n")

    from stego_toolkit.webui.app import create_app

    app = create_app(data_dir=data_dir, workers=1, timeout=180)
    client = app.test_client()

    print("== 建库与页面 ==")
    check("首页 200", client.get("/").status_code == 200)
    check("前缀页 200", client.get("/prefixes").status_code == 200)
    check("expected 页 200", client.get("/expected").status_code == 200)

    print("== 上传与自动分析 ==")
    png = make_png(SMOKE_FLAG)
    resp = client.post("/api/upload",
                       data={"files": [(io.BytesIO(png), "misc1.png")]},
                       content_type="multipart/form-data")
    check("上传成功", resp.status_code in (200, 201), f"code={resp.status_code} {resp.get_json()}")
    created = (resp.get_json() or {}).get("created", [])
    check("建题 1 道", len(created) == 1)
    qid = created[0]["id"] if created else 0

    state = wait_status(client, qid)
    check("分析完成", state.get("status") == "done", f"状态={state.get('status')} err={state.get('error')}")
    check("识别 real_type=png", state.get("real_type") == "png", str(state.get("real_type")))
    check("找到 flag 候选", any(FLAG == SMOKE_FLAG for FLAG in [state.get("top_flag")]),
          f"top={state.get('top_flag')}")
    check("疑分 > 0", state.get("suspicion_score", 0) > 0)

    print("== 详情页与产物 ==")
    detail = client.get(f"/q/{qid}")
    check("详情页 200", detail.status_code == 200)
    html = detail.get_data(as_text=True)
    check("详情页含 flag", SMOKE_FLAG in html)
    check("详情页含产物", "_out" in html)

    print("== 人工标注 ==")
    resp = client.post(f"/api/questions/{qid}/annotate",
                       json={"confirmed_flag": SMOKE_FLAG, "notes": "冒烟测试笔记", "solved": True})
    check("标注保存", resp.status_code == 200 and resp.get_json().get("ok"))
    row = client.get("/api/status").get_json()["questions"][str(qid)]
    check("solved 状态生效", client.get("/api/status").get_json()["counts"]["solved"] == 1)
    check("confirmed_flag 入库", SMOKE_FLAG == row.get("top_flag") or SMOKE_FLAG in json.dumps(row))

    print("== expected 对答案 ==")
    expected_content = f"1. misc1: {SMOKE_FLAG}\n2. misc2: flag{{not_this_one}}\n".encode()
    resp = client.post("/api/expected/upload",
                       data={"file": (io.BytesIO(expected_content), "flags.md")},
                       content_type="multipart/form-data")
    report = resp.get_json() or {}
    check("expected 解析 2 条", report.get("entries") == 2, str(report))
    check("自动关联 1 题", report.get("linked") == 1, str(report))
    row = client.get("/api/status").get_json()["questions"][str(qid)]
    check("对答命中", row.get("expected_match") is True, str(row.get("expected_match")))

    print("== 本地目录导入 ==")
    seed_dir = Path(data_dir) / "tmp" / "seed"
    (seed_dir / "misc2").mkdir(parents=True, exist_ok=True)
    (seed_dir / "misc2" / "misc2.png").write_bytes(make_png("flag{dir_import_ok}"))
    (seed_dir / "misc3.png").write_bytes(make_png("flag{loose_file_ok}"))
    resp = client.post("/api/import_dir", json={"path": str(seed_dir)})
    report = resp.get_json() or {}
    check("目录导入 2 题", len(report.get("created", [])) == 2, str(report))
    check("重复上传被跳过",
          client.post("/api/upload",
                      data={"files": [(io.BytesIO(png), "misc1.png")]},
                      content_type="multipart/form-data").get_json().get("skipped"))

    print("== 前缀管理 ==")
    resp = client.post("/api/prefixes", json={"action": "add", "name": "smoketest"})
    state = resp.get_json() or {}
    check("添加前缀", "smoketest" in state.get("user", []), str(state.get("user")))
    check("写入配置文件", "smoketest" in (Path(data_dir) / "prefixes.json").read_text(encoding="utf-8"))
    resp = client.post("/api/prefixes", json={"action": "remove", "name": "smoketest"})
    check("移除前缀", "smoketest" not in (resp.get_json() or {}).get("user", []))

    print(f"\n结果: {len(PASS)} 通过, {len(FAIL)} 失败")
    if FAIL:
        print("失败项: " + ", ".join(FAIL))
        return 1
    print("冒烟测试全部通过 ✅")
    return 0


if __name__ == "__main__":
    sys.exit(main())
