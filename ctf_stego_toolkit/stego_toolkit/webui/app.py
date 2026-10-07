"""Flask 应用: 页面路由 + JSON API + 媒体服务 + 启动入口。

单机定位: 默认只绑 127.0.0.1, 无鉴权。数据目录(默认 <仓库根>/webui_data)内含:
    webui.db        SQLite 数据库(WAL)
    prefixes.json   flag 前缀配置(环境变量 STEGO_FLAG_PREFIXES_FILE 指向它,
                    runner 子进程与 prefix_config 读写共用同一个文件)
    uploads/q{id}/  每题一个目录: 原始文件 + solve() 生成的 *_out 产物
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
from pathlib import Path

from flask import Flask, abort, jsonify, render_template, request, send_from_directory

from . import importer
from .jobs import WorkerPool
from .models import CONFIDENCE_RANK, Artifact, Expected, Finding, Flag, Question, db

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8800
MAX_CONTENT_LENGTH = 512 * 1024 * 1024

_PREFIX_DOC = (
    "WebUI 前缀配置。replace_default=false 时与内置前缀合并; true 时完全覆盖。"
    "修改后下一次分析(子进程)立即生效。"
)


# --------------------------------------------------------------------------- #
#  工厂
# --------------------------------------------------------------------------- #
def _default_data_dir() -> str:
    env = os.environ.get("STEGO_WEBUI_DATA")
    if env:
        return os.path.abspath(env)
    root = Path(__file__).resolve().parents[3]
    if (root / "pyproject.toml").is_file():  # 源码/可编辑安装: 数据放仓库根
        return str(root / "webui_data")
    return os.path.join(os.path.expanduser("~"), ".stego_webui")


def create_app(data_dir: str | None = None, workers: int = 2, timeout: int = 300) -> Flask:
    data_dir = os.path.abspath(data_dir or _default_data_dir())
    for sub in ("uploads", "tmp"):
        os.makedirs(os.path.join(data_dir, sub), exist_ok=True)

    # 前缀配置固定到数据目录: STEGO_FLAG_PREFIXES_FILE 是 flags._candidate_config_paths
    # 的最高优先级路径, Web 服务进程与 runner 子进程因此共享同一份配置。
    prefixes_path = os.path.join(data_dir, "prefixes.json")
    os.environ["STEGO_FLAG_PREFIXES_FILE"] = prefixes_path
    if not os.path.isfile(prefixes_path):
        with open(prefixes_path, "w", encoding="utf-8") as handle:
            json.dump({"_comment": _PREFIX_DOC, "replace_default": False, "prefixes": []},
                      handle, ensure_ascii=False, indent=2)

    app = Flask(__name__)
    app.config.update(
        WEBUI_DATA_DIR=data_dir,
        WEBUI_WORKERS=max(1, int(workers)),
        WEBUI_TIMEOUT=max(10, int(timeout)),
        MAX_CONTENT_LENGTH=MAX_CONTENT_LENGTH,
        SQLALCHEMY_DATABASE_URI="sqlite:///" + os.path.join(data_dir, "webui.db"),
        SQLALCHEMY_ENGINE_OPTIONS={"connect_args": {"check_same_thread": False, "timeout": 30}},
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
    )
    db.init_app(app)

    from sqlalchemy import event

    with app.app_context():
        @event.listens_for(db.engine, "connect")
        def _sqlite_pragma(dbapi_conn, _record):  # noqa: ANN001
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA busy_timeout=30000")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.close()

        db.create_all()

        # 启动恢复: 上一进程退出时被 worker 认领成 running 的题目已成孤儿,
        # 新进程没有任何在跑的分析, 统一回退为 pending 重新排队。
        from .models import Question as _Question

        orphaned = _Question.query.filter_by(status="running").update({"status": "pending"})
        if orphaned:
            db.session.commit()

    if "webui_worker_pool" not in app.extensions:
        pool = WorkerPool(app, workers=workers, timeout=timeout)
        app.extensions["webui_worker_pool"] = pool
        pool.start()

    _register_routes(app)
    return app


# --------------------------------------------------------------------------- #
#  视图模型
# --------------------------------------------------------------------------- #
def _media(rel: str) -> str:
    return "/media/" + rel


def _question_row(question: Question) -> dict:
    top = question.top_flag
    match = question.expected_match()
    files = question.file_paths
    return {
        "id": question.id,
        "title": question.title,
        "status": question.status,
        "real_type": question.real_type or "",
        "suspicion_score": question.suspicion_score or 0,
        "thumb": _media(files[0]) if files else "",
        "file_count": len(files),
        "top_flag": top.value if top else "",
        "top_conf": top.confidence if top else "",
        "flag_count": len(question.flags),
        "expected_flag": question.expected_flag or "",
        "expected_match": match,
        "confirmed_flag": question.confirmed_flag or "",
        "solved": bool(question.solved),
        "has_notes": bool(question.notes),
        "error": question.error or "",
        "elapsed": question.elapsed or 0.0,
    }


def _stats() -> dict:
    questions = Question.query.all()
    counts = {"total": len(questions), "pending": 0, "running": 0, "done": 0, "error": 0,
              "solved": 0, "hit": 0}
    for question in questions:
        counts[question.status] = counts.get(question.status, 0) + 1
        if question.solved:
            counts["solved"] += 1
        if question.expected_match():
            counts["hit"] += 1
    return counts


def _artifact_group(artifacts: list[Artifact]) -> dict:
    review = [a for a in artifacts if a.needs_review and a.kind == "image"]
    images = [a for a in artifacts if not a.needs_review and a.kind == "image"]
    texts = [a for a in artifacts if a.kind == "text"]
    others = [a for a in artifacts if a.kind == "other"]
    return {
        "review": [(_a.path, _media(_a.path), _a.description) for _a in review],
        "images": [(_a.path, _media(_a.path), _a.description) for _a in images],
        "texts": [(_a.path, _media(_a.path), _a.description) for _a in texts],
        "others": [(_a.path, _media(_a.path), _a.description) for _a in others],
    }


def _prefix_state() -> dict:
    from ..flags import _BUILTIN_PREFIXES
    from ..prefix_config import _load_user_prefixes, get_config_path

    user, replace = _load_user_prefixes()
    if replace:
        effective = list(user) or list(_BUILTIN_PREFIXES)
    else:
        combined = list(_BUILTIN_PREFIXES) + list(user)
        seen: set[str] = set()
        effective = []
        for name in combined:
            if name.lower() not in seen:
                seen.add(name.lower())
                effective.append(name)
        effective.sort(key=lambda value: (-len(value), value.lower()))
    builtin_lower = {p.lower() for p in _BUILTIN_PREFIXES}
    return {
        "builtin": list(_BUILTIN_PREFIXES),
        "user": list(user),
        "effective": effective,
        "replace_default": replace,
        "config_path": get_config_path(),
        "user_tags": [p.lower() in builtin_lower for p in user],
    }


# --------------------------------------------------------------------------- #
#  路由
# --------------------------------------------------------------------------- #
def _register_routes(app: Flask) -> None:
    @app.context_processor
    def _inject_helpers():
        return {"CONF_RANK": CONFIDENCE_RANK}

    # ---- 页面 ---- #
    @app.get("/")
    def page_index():
        questions = Question.query.order_by(Question.id.desc()).all()
        return render_template("index.html", questions=[_question_row(q) for q in questions],
                               stats=_stats())

    @app.get("/q/<int:qid>")
    def page_detail(qid: int):
        question = db.session.get(Question, qid) or abort(404)
        files = question.file_paths
        review, images, texts, others = [], [], [], []
        for artifact in question.artifacts:
            item = {"rel": artifact.path, "url": _media(artifact.path),
                    "name": os.path.basename(artifact.path),
                    "description": artifact.description or ""}
            bucket = (review if artifact.needs_review and artifact.kind == "image"
                      else images if artifact.kind == "image"
                      else texts if artifact.kind == "text" else others)
            bucket.append(item)
        return render_template(
            "detail.html",
            q=question,
            files=[{"rel": f, "url": _media(f), "name": os.path.basename(f)} for f in files],
            main_url=_media(files[0]) if files else "",
            review=review, images=images, texts=texts, others=others,
        )

    @app.get("/prefixes")
    def page_prefixes():
        return render_template("prefixes.html", state=_prefix_state())

    @app.get("/expected")
    def page_expected():
        rows = Expected.query.order_by(Expected.number.asc()).all()
        return render_template("expected.html", rows=rows, stats=_stats())

    # ---- 导入 ---- #
    @app.post("/api/upload")
    def api_upload():
        files = [f for f in request.files.getlist("files") if f and f.filename]
        if not files:
            return jsonify({"errors": ["没有收到文件"]}), 400
        report = importer.import_uploaded_files(app.config["WEBUI_DATA_DIR"], files)
        code = 200 if not report["errors"] else 201  # 201: 部分成功
        return jsonify(report), code

    @app.post("/api/import_dir")
    def api_import_dir():
        payload = request.get_json(silent=True) or {}
        path = (payload.get("path") or "").strip()
        if not path:
            return jsonify({"errors": ["缺少 path"]}), 400
        return jsonify(importer.import_local_dir(app.config["WEBUI_DATA_DIR"], path))

    # ---- 题目操作 ---- #
    @app.post("/api/questions/<int:qid>/analyze")
    def api_analyze(qid: int):
        question = db.session.get(Question, qid) or abort(404)
        question.status = "pending"
        question.error = ""
        db.session.commit()
        return jsonify({"ok": True, "id": qid})

    @app.post("/api/questions/<int:qid>/annotate")
    def api_annotate(qid: int):
        question = db.session.get(Question, qid) or abort(404)
        payload = request.get_json(force=True, silent=True) or {}
        if "confirmed_flag" in payload:
            question.confirmed_flag = (payload["confirmed_flag"] or "").strip()
        if "notes" in payload:
            question.notes = payload["notes"] or ""
        if "solved" in payload:
            question.solved = bool(payload["solved"])
        if "expected_flag" in payload:
            question.expected_flag = (payload["expected_flag"] or "").strip()
        db.session.commit()
        return jsonify({"ok": True})

    @app.delete("/api/questions/<int:qid>")
    def api_delete(qid: int):
        question = db.session.get(Question, qid) or abort(404)
        if question.status == "running":
            return jsonify({"error": "分析进行中, 稍后再删"}), 409
        qdir = os.path.join(app.config["WEBUI_DATA_DIR"], "uploads", f"q{qid}")
        shutil.rmtree(qdir, ignore_errors=True)
        db.session.delete(question)
        db.session.commit()
        return jsonify({"ok": True})

    @app.get("/api/status")
    def api_status():
        questions = Question.query.all()
        counts = _stats()
        rows = {}
        for question in questions:
            top = question.top_flag
            rows[str(question.id)] = {
                "status": question.status,
                "suspicion_score": question.suspicion_score or 0,
                "top_flag": top.value if top else "",
                "top_conf": top.confidence if top else "",
                "flag_count": len(question.flags),
                "expected_match": question.expected_match(),
                "real_type": question.real_type or "",
                "elapsed": question.elapsed or 0.0,
            }
        return jsonify({
            "counts": counts,
            "any_running": counts["running"] > 0 or counts["pending"] > 0,
            "questions": rows,
        })

    # ---- expected ---- #
    @app.post("/api/expected/upload")
    def api_expected_upload():
        storage = request.files.get("file")
        if not storage or not storage.filename:
            return jsonify({"errors": ["没有收到文件"]}), 400
        data_dir = app.config["WEBUI_DATA_DIR"]
        staging = os.path.join(data_dir, "tmp", f"expected_{os.getpid()}_{os.urandom(4).hex()}")
        os.makedirs(os.path.dirname(staging), exist_ok=True)
        storage.save(staging)
        try:
            report = importer.import_expected_file(data_dir, staging)
        finally:
            os.unlink(staging)
        return jsonify(report)

    @app.post("/api/expected/apply")
    def api_expected_apply():
        linked = importer.auto_link_expected()
        db.session.commit()
        return jsonify({"linked": linked})

    # ---- 前缀 ---- #
    @app.get("/api/prefixes")
    def api_prefixes_get():
        return jsonify(_prefix_state())

    @app.post("/api/prefixes")
    def api_prefixes_post():
        from ..flags import _load_user_prefixes
        from ..prefix_config import save_config

        payload = request.get_json(force=True, silent=True) or {}
        action = payload.get("action")
        user, replace = _load_user_prefixes()
        if action == "add":
            name = (payload.get("name") or "").strip()
            if not name or "{" in name or "}" in name:
                return jsonify({"error": "前缀不能为空且不应包含花括号"}), 400
            if name.lower() not in {p.lower() for p in user}:
                user = list(user) + [name]
            save_config(user, replace)
        elif action == "remove":
            name = (payload.get("name") or "").strip().lower()
            user = [p for p in user if p.lower() != name]
            save_config(user, replace)
        elif action == "reset":
            save_config([], replace)
        elif action == "set_replace":
            save_config(user, bool(payload.get("replace_default")))
        else:
            return jsonify({"error": f"未知操作: {action}"}), 400
        return jsonify(_prefix_state())

    # ---- 媒体 ---- #
    @app.get("/media/<path:relpath>")
    def media(relpath: str):
        return send_from_directory(app.config["WEBUI_DATA_DIR"], relpath)


# --------------------------------------------------------------------------- #
#  入口
# --------------------------------------------------------------------------- #
def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="ctf-stego-webui",
        description="CTF 图片隐写自动分析器 — 本地 WebUI(看板/详情/前缀/对答案)",
    )
    parser.add_argument("--host", default=DEFAULT_HOST, help="监听地址(默认 127.0.0.1)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="监听端口(默认 8800)")
    parser.add_argument("--data-dir", default=None,
                        help="数据目录(默认 <仓库根>/webui_data, 可用环境变量 STEGO_WEBUI_DATA)")
    parser.add_argument("--workers", type=int, default=2, help="并行分析 worker 数(默认 2)")
    parser.add_argument("--timeout", type=int, default=300, help="单文件分析总超时秒数(默认 300)")
    args = parser.parse_args(argv)

    app = create_app(data_dir=args.data_dir, workers=args.workers, timeout=args.timeout)
    print(f"CTF Stego WebUI  ->  http://{args.host}:{args.port}")
    print(f"数据目录: {app.config['WEBUI_DATA_DIR']}  |  workers={args.workers}  "
          f"timeout={args.timeout}s")
    print("Ctrl+C 退出。仅本机访问; 对局域网开放请自行加 --host 0.0.0.0 并注意安全。")
    app.run(host=args.host, port=args.port, threaded=True, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
