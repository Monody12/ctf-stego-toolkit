"""SQLAlchemy 模型: 题目/flag 候选/发现/产物/expected 答案。

字段与 stego_toolkit.analyzers.base 的 Flag/Finding/Artifact dataclass 一一对应,
入库时只做 dataclass -> ORM 行的平移, 不改写语义。
"""
from __future__ import annotations

import json
import os

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

# 产物按扩展名分类, 前端据此决定内联图片 / 内联文本 / 列表展示。
IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tif", ".tiff"}
TEXT_EXTS = {".txt", ".log", ".json", ".md", ".csv"}

CONFIDENCE_RANK = {"low": 1, "medium": 2, "high": 3}


def artifact_kind(path: str) -> str:
    ext = os.path.splitext(path)[1].lower()
    if ext in IMAGE_EXTS:
        return "image"
    if ext in TEXT_EXTS:
        return "text"
    return "other"


class Question(db.Model):
    """一道题目。多文件题(如 misc{N}/ 目录)把文件列表存在 files_json。"""

    __tablename__ = "questions"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(300), nullable=False)
    status = db.Column(db.String(16), nullable=False, default="pending", index=True)
    # 数据目录内的相对路径列表(JSON 数组, 正斜杠), 第一个为主图(预览用)。
    files_json = db.Column(db.Text, nullable=False, default="[]")
    image_hash = db.Column(db.String(64), index=True)  # 主文件 sha256, 上传去重
    real_type = db.Column(db.String(32), default="")
    suspicion_score = db.Column(db.Integer, default=0)
    expected_flag = db.Column(db.String(300), default="")  # 从 expected 文件导入或手工填
    confirmed_flag = db.Column(db.String(300), default="")  # 人工确认的 flag
    solved = db.Column(db.Boolean, default=False)
    notes = db.Column(db.Text, default="")
    elapsed = db.Column(db.Float, default=0.0)
    log_text = db.Column(db.Text, default="")
    error = db.Column(db.Text, default="")
    created_at = db.Column(db.String(32), default="")
    analyzed_at = db.Column(db.String(32), default="")

    flags = db.relationship(
        "Flag", backref="question", cascade="all, delete-orphan",
        order_by="Flag.id", lazy="selectin",
    )
    findings = db.relationship(
        "Finding", backref="question", cascade="all, delete-orphan",
        order_by="Finding.id", lazy="selectin",
    )
    artifacts = db.relationship(
        "Artifact", backref="question", cascade="all, delete-orphan",
        order_by="Artifact.id", lazy="selectin",
    )

    # ---- files_json 便捷读写 ---- #
    @property
    def file_paths(self) -> list[str]:
        try:
            return json.loads(self.files_json or "[]")
        except ValueError:
            return []

    @file_paths.setter
    def file_paths(self, value: list[str]) -> None:
        self.files_json = json.dumps(value, ensure_ascii=False)

    @property
    def top_flag(self) -> "Flag | None":
        """置信度最高的候选(同分取先出现)。"""
        if not self.flags:
            return None
        return max(self.flags, key=lambda f: CONFIDENCE_RANK.get(f.confidence, 0))

    def expected_match(self) -> bool | None:
        """expected 对答案: True 命中 / False 未命中 / None 无 expected。"""
        if not self.expected_flag:
            return None
        values = {f.value for f in self.flags} | {self.confirmed_flag}
        return self.expected_flag in values


class Flag(db.Model):
    __tablename__ = "flags"

    id = db.Column(db.Integer, primary_key=True)
    question_id = db.Column(db.ForeignKey("questions.id"), nullable=False, index=True)
    value = db.Column(db.String(300), nullable=False)
    confidence = db.Column(db.String(16), default="medium")
    source = db.Column(db.String(300), default="")

    __table_args__ = (db.UniqueConstraint("question_id", "value", name="uq_flag_value"),)


class Finding(db.Model):
    __tablename__ = "findings"

    id = db.Column(db.Integer, primary_key=True)
    question_id = db.Column(db.ForeignKey("questions.id"), nullable=False, index=True)
    level = db.Column(db.String(16), nullable=False)  # info/hint/find/warn/error
    title = db.Column(db.String(500), default="")
    detail = db.Column(db.Text, default="")
    source = db.Column(db.String(300), default="")


class Artifact(db.Model):
    __tablename__ = "artifacts"

    id = db.Column(db.Integer, primary_key=True)
    question_id = db.Column(db.ForeignKey("questions.id"), nullable=False, index=True)
    path = db.Column(db.String(1000), nullable=False)  # 数据目录内相对路径(正斜杠)
    description = db.Column(db.String(500), default="")
    needs_review = db.Column(db.Boolean, default=False)
    kind = db.Column(db.String(16), default="other")


class Expected(db.Model):
    """expected 答案文件解析结果: 题号 -> 完整 flag。"""

    __tablename__ = "expected"

    number = db.Column(db.Integer, primary_key=True)
    flag = db.Column(db.String(300), nullable=False)
