"""题目导入: 上传文件 / zip 包 / 本地目录 -> 分组建题 + 去重。

分组规则(与 batch.py 的 misc{N}/ 工作流对齐):
- zip 内或目录下的每个顶层子目录 = 一道题(目录内全部文件入题);
- 散落的顶层图片文件 = 每张图一道题;
- 非图片文件跟随所在题目入库, 但分析时优先只跑图片扩展名(无图片则全跑)。

路径契约: Question.files_json 与 Artifact.path 一律存"数据目录内相对路径,
正斜杠"; 磁盘读写时再按本地分隔符拼装。
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import zipfile
from pathlib import Path

from .models import Expected, Question, artifact_kind, db

IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tif", ".tiff"}
ANALYZE_FIRST_EXTS = IMAGE_EXTS  # 多文件题先分析图片, 再跑其余文件
_MAX_UPLOAD_BYTES = 512 * 1024 * 1024


def _safe_name(name: str) -> str:
    """保留可读字符的保守文件名清洗(中文保留)。"""
    name = os.path.basename(name.replace("\\", "/")).strip()
    name = re.sub(r'[\\/:*?"<>|\x00-\x1f]', "_", name).strip(". ")
    return name or "file"


def _sha256(path: str | os.PathLike) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _rel(path: str | Path, data_dir: str) -> str:
    return os.path.relpath(os.path.abspath(path), data_dir).replace(os.sep, "/")


def _sort_for_analyze(paths: list[Path]) -> list[Path]:
    def key(path: Path) -> tuple[int, str]:
        return (0 if path.suffix.lower() in ANALYZE_FIRST_EXTS else 1, path.name)

    return sorted(paths, key=key)


# --------------------------------------------------------------------------- #
#  建题
# --------------------------------------------------------------------------- #
def _create_question(data_dir: str, title: str, files: list[Path], notes: str = "") -> dict:
    group_hash = hashlib.sha256(
        "\n".join(sorted(_sha256(f) for f in files)).encode("utf-8")
    ).hexdigest()[:64]
    existing = Question.query.filter_by(image_hash=group_hash).first()
    if existing is not None:
        return {"skipped": f"与已有题目 #{existing.id}「{existing.title}」重复"}

    question = Question(
        title=title or "untitled",
        status="pending",
        notes=notes or "",
        created_at=_now(),
        image_hash=group_hash,
    )
    db.session.add(question)
    db.session.flush()  # 拿 id

    qdir = Path(data_dir) / "uploads" / f"q{question.id}"
    qdir.mkdir(parents=True, exist_ok=True)
    stored: list[str] = []
    for src in files:
        dest = qdir / _safe_name(src.name)
        if dest.exists():  # 同题内重名: 追加序号
            stem, suffix = dest.stem, dest.suffix
            counter = 1
            while dest.exists():
                dest = qdir / f"{stem}_{counter}{suffix}"
                counter += 1
        shutil.copyfile(src, dest)
        stored.append(_rel(dest, data_dir))
    question.file_paths = stored
    db.session.commit()
    return {"id": question.id, "title": question.title, "files": len(stored)}


def _now() -> str:
    import time

    return time.strftime("%Y-%m-%d %H:%M:%S")


# --------------------------------------------------------------------------- #
#  分组
# --------------------------------------------------------------------------- #
def _group_files(root: Path) -> list[tuple[str, list[Path]]]:
    """把 root 下的内容按顶层子目录分组; 顶层散图各自成题。"""
    entries = sorted(root.iterdir(), key=lambda p: p.name)
    top_dirs = [p for p in entries if p.is_dir()]
    top_files = [p for p in entries if p.is_file()]

    groups: list[tuple[str, list[Path]]] = []
    if top_dirs:
        for directory in top_dirs:
            files = [p for p in directory.rglob("*") if p.is_file()]
            if files:
                groups.append((directory.name, _sort_for_analyze(files)))
    if not top_dirs or top_files:
        for path in _sort_for_analyze(top_files):
            groups.append((path.stem, [path]))
    return groups


def _collect_zip(zf: zipfile.ZipFile, target: Path) -> list[Path]:
    """安全解压(防 zip slip), 返回解出的普通文件列表。"""
    extracted: list[Path] = []
    for member in zf.infolist():
        name = member.filename
        if member.is_dir():
            continue
        relative = Path(*[part for part in Path(name).parts if part not in ("", ".", "..")])
        if not relative.parts:
            continue
        dest = target / relative
        if not str(dest.resolve()).startswith(str(target.resolve()) + os.sep) and \
                dest.parent != target:
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(member) as src, open(dest, "wb") as out:
            shutil.copyfileobj(src, out)
        extracted.append(dest)
    return extracted


def _ingest_groups(data_dir: str, groups: list[tuple[str, list[Path]]], notes: str = "") -> dict:
    report: dict = {"created": [], "skipped": [], "errors": []}
    try:
        for title, files in groups:
            if not files:
                continue
            result = _create_question(data_dir, title, files, notes=notes)
            if "id" in result:
                report["created"].append(result)
            else:
                report["skipped"].append(result.get("skipped", ""))
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        report["errors"].append(str(exc))
    return report


# --------------------------------------------------------------------------- #
#  三个入口
# --------------------------------------------------------------------------- #
def import_uploaded_files(data_dir: str, file_storages) -> dict:
    """处理 multipart 上传: 图片直接入题, zip 解压后按规则分组。"""
    report: dict = {"created": [], "skipped": [], "errors": []}
    for storage in file_storages:
        if not storage or not storage.filename:
            continue
        if storage.content_length and storage.content_length > _MAX_UPLOAD_BYTES:
            report["errors"].append(f"{storage.filename}: 超过大小限制")
            continue
        original = _safe_name(storage.filename)
        staging = Path(data_dir) / "tmp" / f"upload_{os.getpid()}_{original}"
        staging.parent.mkdir(parents=True, exist_ok=True)
        storage.save(str(staging))

        ext = staging.suffix.lower()
        try:
            if ext == ".zip":
                with zipfile.ZipFile(staging) as zf:
                    for member in zf.infolist():
                        if member.file_size > _MAX_UPLOAD_BYTES:
                            report["errors"].append(f"{original} 内 {member.filename} 过大")
                            staging.unlink(missing_ok=True)
                            return report
                    unpacked = Path(data_dir) / "tmp" / f"zip_{os.getpid()}_{staging.stem}"
                    if unpacked.exists():
                        shutil.rmtree(unpacked)
                    unpacked.mkdir(parents=True, exist_ok=True)
                    files = _collect_zip(zf, unpacked)
                groups = _group_files(unpacked) if any(p.is_dir() for p in unpacked.iterdir()) \
                    else [(p.stem, [p]) for p in _sort_for_analyze(files)]
                report = _merge_reports(report, _ingest_groups(data_dir, groups))
                shutil.rmtree(unpacked, ignore_errors=True)
            elif ext in IMAGE_EXTS:
                # 标题用原始文件名而不是临时暂存名
                report = _merge_reports(
                    report, _ingest_groups(data_dir, [(Path(original).stem, [staging])])
                )
            else:
                report["errors"].append(f"{original}: 不是支持的图片或 zip 包")
        except zipfile.BadZipFile:
            report["errors"].append(f"{original}: zip 文件损坏")
        finally:
            staging.unlink(missing_ok=True)
    return report


def import_local_dir(data_dir: str, path: str) -> dict:
    """导入 WSL 本地目录(或单文件)。目录含子目录时每个子目录一道题。"""
    target = Path(path).expanduser()
    if not target.exists():
        return {"created": [], "skipped": [], "errors": [f"路径不存在: {path}"]}
    if target.is_file():
        return _ingest_groups(data_dir, [(target.stem, [target])])
    groups = _group_files(target)
    if not groups:
        return {"created": [], "skipped": [], "errors": [f"目录为空: {path}"]}
    return _ingest_groups(data_dir, groups)


def import_expected_file(data_dir: str, path: str) -> dict:
    """解析 expected 文件(batch.load_expected 兼容格式), 全量替换并自动按题号关联。"""
    from ..batch import load_expected

    parsed = load_expected(path)
    Expected.query.delete()
    for number, flag in parsed.items():
        db.session.merge(Expected(number=number, flag=flag))
    linked = auto_link_expected()
    db.session.commit()
    return {"entries": len(parsed), "linked": linked}


def auto_link_expected() -> int:
    """按题号把 expected.flag 写到标题含 misc{N} 的题目上, 返回关联数。"""
    linked = 0
    for row in Expected.query.all():
        pattern = re.compile(rf"misc\s*{row.number}\b", re.I)
        matches = [q for q in Question.query.all() if pattern.search(q.title or "")]
        if len(matches) == 1:
            matches[0].expected_flag = row.flag
            linked += 1
    return linked


def _merge_reports(base: dict, extra: dict) -> dict:
    for key in ("created", "skipped", "errors"):
        base[key].extend(extra.get(key, []))
    return base


def human_size(num: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(num) < 1024:
            return f"{num:.0f}{unit}" if unit == "B" else f"{num:.1f}{unit}"
        num /= 1024
    return f"{num:.1f}TB"
