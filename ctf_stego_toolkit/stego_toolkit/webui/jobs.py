"""后台分析 worker 池。

每个 worker 线程循环: 认领一条 pending 题目 -> 对每个文件启动 runner 子进程
(带总超时, 超时强杀) -> 合并结果入库 -> 置 done/error。

并发模型: Flask 开发服务器自带多线程; worker 是独立守护线程, 通过
``with app.app_context()`` 获取独立的 SQLAlchemy session; SQLite 开启 WAL +
busy_timeout 后多线程读写安全。认领动作用进程内锁串行化, 避免双领。
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading
import time

from .models import Artifact, Finding, Flag, Question, db

CONFIDENCE_RANK = {"low": 1, "medium": 2, "high": 3}


class WorkerPool:
    def __init__(self, app, workers: int = 2, timeout: int = 300) -> None:
        self.app = app
        self.workers = max(1, int(workers))
        self.timeout = max(10, int(timeout))
        self._claim_lock = threading.Lock()

    # ------------------------------------------------------------------ #
    def start(self) -> None:
        for index in range(self.workers):
            thread = threading.Thread(
                target=self._loop, name=f"stego-worker-{index}", daemon=True
            )
            thread.start()

    def _loop(self) -> None:
        while True:
            job = self._claim_next()
            if job is None:
                time.sleep(1.0)
                continue
            try:
                self._run_job(job)
            except Exception:  # worker 线程绝不能死
                self.app.logger.exception("worker 处理题目失败")

    # ------------------------------------------------------------------ #
    def _claim_next(self) -> dict | None:
        """认领最早的一条 pending 题目, 置为 running。"""
        with self.app.app_context():
            with self._claim_lock:
                question = (
                    Question.query.filter_by(status="pending")
                    .order_by(Question.id.asc())
                    .first()
                )
                if question is None:
                    return None
                question.status = "running"
                question.error = ""
                db.session.commit()
                return {
                    "id": question.id,
                    "files": list(question.file_paths),
                    "title": question.title,
                }

    # ------------------------------------------------------------------ #
    def _run_job(self, job: dict) -> None:
        data_dir = self.app.config["WEBUI_DATA_DIR"]
        merged = {
            "real_type": "", "suspicion_score": 0, "elapsed": 0.0,
            "flags": [], "findings": [], "artifacts": [], "logs": [],
        }
        errors: list[str] = []

        for index, rel_path in enumerate(job["files"]):
            image_abs = os.path.join(data_dir, *rel_path.split("/"))
            result_path = os.path.join(
                data_dir, "uploads", f"q{job['id']}", f".runner_result_{index}.json"
            )
            outcome = self._run_runner(image_abs, result_path)
            if outcome.get("timeout"):
                errors.append(f"{os.path.basename(image_abs)}: 分析超时(>{self.timeout}s), 已终止")
            elif not outcome.get("ok", False):
                errors.append(
                    f"{os.path.basename(image_abs)}: {outcome.get('error') or '分析失败'}"
                )
            self._merge(merged, outcome, data_dir)

        with self.app.app_context():
            question = db.session.get(Question, job["id"])
            if question is None:
                return
            question.real_type = merged["real_type"]
            question.suspicion_score = merged["suspicion_score"]
            question.elapsed = round(merged["elapsed"], 2)
            question.log_text = "\n\n".join(merged["logs"])

            Flag.query.filter_by(question_id=question.id).delete()
            for item in merged["flags"]:
                db.session.add(Flag(
                    question_id=question.id, value=item["value"],
                    confidence=item["confidence"], source=item["source"],
                ))
            Finding.query.filter_by(question_id=question.id).delete()
            for item in merged["findings"]:
                db.session.add(Finding(
                    question_id=question.id, level=item["level"],
                    title=item["title"], detail=item["detail"], source=item["source"],
                ))
            Artifact.query.filter_by(question_id=question.id).delete()
            for item in merged["artifacts"]:
                db.session.add(Artifact(
                    question_id=question.id, path=item["path"],
                    description=item["description"], needs_review=item["needs_review"],
                    kind=item["kind"],
                ))

            if not job["files"]:
                question.status = "error"
                question.error = "题目没有任何可分析文件"
            elif errors and not merged["flags"] and not merged["artifacts"]:
                question.status = "error"
                question.error = "\n".join(errors)
            else:
                # 部分文件失败但拿到了有效结果: 完成并在 error 字段留提示
                question.status = "done"
                question.error = "\n".join(errors)
            question.analyzed_at = time.strftime("%Y-%m-%d %H:%M:%S")
            db.session.commit()

    # ------------------------------------------------------------------ #
    def _run_runner(self, image_abs: str, result_path: str) -> dict:
        env = dict(os.environ)
        env.setdefault(
            "STEGO_FLAG_PREFIXES_FILE",
            os.path.join(self.app.config["WEBUI_DATA_DIR"], "prefixes.json"),
        )
        cmd = [sys.executable, "-m", "stego_toolkit.webui.runner", image_abs, result_path]
        popen_kwargs = {"env": env}
        if os.name == "posix":
            popen_kwargs["start_new_session"] = True  # 便于整组强杀
        # 关键: 不用 PIPE。runner 的结构化结果走 JSON 文件; 若用管道,
        # runner 的孤儿孙进程握住管道会导致 communicate() 永久阻塞(超时无法覆盖
        # "子进程已退出但管道未关闭"的阶段)。stderr 落盘仅供失败时取尾部。
        stderr_path = result_path + ".stderr"
        with open(stderr_path, "wb") as stderr_file:
            popen_kwargs.update(stdout=subprocess.DEVNULL, stderr=stderr_file)
            try:
                proc = subprocess.Popen(cmd, **popen_kwargs)
            except Exception as exc:
                return {"ok": False, "error": f"无法启动分析进程: {exc}"}

            timed_out = False
            try:
                proc.wait(timeout=self.timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                if os.name == "posix":
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except (ProcessLookupError, PermissionError):
                        proc.kill()
                else:
                    proc.kill()
                try:
                    proc.wait(timeout=10)
                except Exception:
                    pass

        payload = {}
        try:
            with open(result_path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, ValueError):
            payload = {}
        if timed_out:
            payload["timeout"] = True
            payload["ok"] = False
            payload.setdefault("error", "超时")
        elif proc.returncode != 0 and not payload.get("ok"):
            try:
                with open(stderr_path, "rb") as handle:
                    stderr_tail = handle.read()[-500:].decode("utf-8", "replace").strip()
            except OSError:
                stderr_tail = ""
            payload.setdefault("error", stderr_tail or f"分析进程退出 (code={proc.returncode})")
        return payload

    # ------------------------------------------------------------------ #
    @staticmethod
    def _merge(merged: dict, outcome: dict, data_dir: str) -> None:
        """把单个文件的分析结果并入题目级聚合。"""
        if not outcome:
            return
        if outcome.get("real_type") and outcome["real_type"] not in ("", "unknown"):
            merged["real_type"] = merged["real_type"] or outcome["real_type"]
        merged["suspicion_score"] = max(
            merged["suspicion_score"], int(outcome.get("suspicion_score") or 0)
        )
        merged["elapsed"] += float(outcome.get("elapsed") or 0.0)

        seen_values = {item["value"] for item in merged["flags"]}
        for item in outcome.get("flags", []):
            if item["value"] in seen_values:
                for existing in merged["flags"]:
                    if existing["value"] == item["value"] and \
                            CONFIDENCE_RANK.get(item["confidence"], 0) > \
                            CONFIDENCE_RANK.get(existing["confidence"], 0):
                        existing.update(item)
                        break
                continue
            seen_values.add(item["value"])
            merged["flags"].append(dict(item))

        merged["findings"].extend(dict(item) for item in outcome.get("findings", []))

        seen_paths = {item["path"] for item in merged["artifacts"]}
        for item in outcome.get("artifacts", []):
            abs_path = item.get("path", "")
            try:
                rel = os.path.relpath(abs_path, data_dir).replace(os.sep, "/")
            except ValueError:  # Windows 跨盘符
                rel = abs_path
            if rel in seen_paths:
                continue
            seen_paths.add(rel)
            from .models import artifact_kind

            merged["artifacts"].append({
                "path": rel,
                "description": item.get("description", ""),
                "needs_review": bool(item.get("needs_review")),
                "kind": artifact_kind(rel),
            })

        log_text = (outcome.get("log_text") or "").strip()
        if log_text:
            merged["logs"].append(log_text)
