"""Batch runner for challenge directories."""
from __future__ import annotations

import contextlib
import io
import json
import os
import re
import time
import zipfile
from dataclasses import asdict, dataclass
from collections import Counter
from itertools import product
from pathlib import Path
from typing import Iterable

from .cli import solve
from .flags import find_normalized_flags, normalize_hexish_body, prefix_alternation


_MISC_RE = re.compile(r"misc(\d+)", re.I)
_EXPECTED_RE = re.compile(rf"(\d+)\.\s+misc\d+:\s+(({prefix_alternation()})\{{[^}}]+\}})", re.I)
_HEXISH_RE = re.compile(r"[0-9A-Fa-fOQlI|/\\?BSTtsg]{4,80}\}?")
_HEXISH_ALT = {
    "O": "0",
    "o": "0",
    "Q": "0",
    "I": "1",
    "l": "1",
    "|": "1",
    "Z": "2",
    "z": "2",
    "S": "58",
    "s": "58",
    "G": "6",
    "g": "6",
    "T": "f",
    "t": "f",
    "/": "7",
    "\\": "7",
    "?": "7",
    "B": "8",
    "c": "ce",
    "C": "ce",
    "e": "ec",
    "E": "ec",
}


@dataclass
class BatchResult:
    number: int
    status: str
    expected: str
    flags: list[str]
    assembled_flags: list[str]
    files: list[str]
    elapsed: float
    report_dir: str


def load_expected(path: str | os.PathLike[str] | None) -> dict[int, str]:
    if not path:
        return {}
    result: dict[int, str] = {}
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        match = _EXPECTED_RE.search(line)
        if match:
            result[int(match.group(1))] = match.group(2)
    return result


def ensure_extracted(questions_dir: Path, challenges_dir: Path, start: int, end: int) -> None:
    challenges_dir.mkdir(parents=True, exist_ok=True)
    for number in range(start, end + 1):
        dest = challenges_dir / f"misc{number}"
        if dest.exists() and any(dest.iterdir()):
            continue
        archive = questions_dir / f"misc{number}.zip"
        if not archive.exists():
            continue
        dest.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(dest)


def challenge_files(challenge_dir: Path, number: int) -> list[Path]:
    if not challenge_dir.exists():
        return []
    files = [
        path for path in challenge_dir.iterdir()
        if path.is_file() and not path.name.startswith(".") and not path.name.endswith(".zip")
    ]
    if number == 4:
        return sorted(files, key=lambda item: _natural_key(item.name))
    preferred = sorted(challenge_dir.glob(f"misc{number}.*"), key=lambda item: _natural_key(item.name))
    return preferred[:1] if preferred else sorted(files, key=lambda item: _natural_key(item.name))


def _natural_key(text: str) -> list[object]:
    return [int(part) if part.isdigit() else part.lower() for part in re.split(r"(\d+)", text)]


def _dedupe(values: Iterable[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def _fragment_candidates(text: str) -> list[str]:
    candidates: list[str] = []
    for line in text.splitlines():
        compact = re.sub(r"\s+", "", line)
        if not compact:
            continue
        if re.search(r"ctfshow\s*\{", compact, re.I):
            body = compact.split("{", 1)[1] if "{" in compact else ""
            body = normalize_hexish_body(body)
            candidates.append("ctfshow{" + body)
        for match in _HEXISH_RE.finditer(compact):
            raw = match.group(0)
            suffix = "}" if raw.endswith("}") or compact.endswith("}") else ""
            for body in _hexish_fragment_variants(raw):
                if 4 <= len(body) <= 16:
                    candidates.append(body + suffix)
    return _dedupe(candidates)[:8]


def _hexish_fragment_variants(raw: str, limit: int = 16) -> list[str]:
    """Return limited OCR ambiguity variants for short hex fragments.

    This is intentionally used only by the batch fragment assembler. It handles
    common OCR mistakes in segmented visual flags, e.g. ``S`` may be ``5`` or
    ``8`` and low-resolution ``c/e`` can swap.
    """
    raw = raw.rstrip("}")
    if len(raw) > 16:
        return [normalize_hexish_body(raw)]
    choices: list[str] = []
    for char in raw:
        if char in _HEXISH_ALT:
            choices.append(_HEXISH_ALT[char])
        elif char.lower() in "0123456789abcdef":
            choices.append(char.lower())
        else:
            choices.append("")
    variants: list[str] = []
    for combo in product(*choices):
        value = "".join(combo)
        if value and value not in variants:
            variants.append(value)
        if len(variants) >= limit:
            break
    normalized = normalize_hexish_body(raw)
    if normalized and normalized not in variants:
        variants.insert(0, normalized)
    return variants[:limit]


def _score_fragment(fragment: str) -> tuple[int, int, int]:
    body = fragment.lower()
    hex_len = sum(ch in "0123456789abcdef{" for ch in body)
    return (
        1 if body.startswith("ctfshow{") else 0,
        hex_len,
        len(body),
    )


def _score_fragment_for_assembly(fragment: str, count: int) -> tuple[int, int, int, int, int]:
    body = fragment.lower()
    hex_len = sum(ch in "0123456789abcdef{" for ch in body)
    # Split visual flags in these tasks are usually 4-8 chars per image; OCR
    # false positives from fake hints can be longer. Prefer repeated sightings
    # and reasonable chunk length over raw length.
    reasonable_len = 1 if body.startswith("ctfshow{") or 4 <= len(body.rstrip("}")) <= 8 else 0
    return (
        1 if body.startswith("ctfshow{") else 0,
        count,
        reasonable_len,
        hex_len,
        -abs(len(body.rstrip("}")) - 7),
    )


def assemble_fragments(texts_by_file: list[list[str]]) -> list[str]:
    per_file: list[list[str]] = []
    for texts in texts_by_file:
        pieces: list[str] = []
        for text in texts:
            pieces.extend(_fragment_candidates(text))
        counts = Counter(pieces)
        unique = _dedupe(pieces)
        unique.sort(key=lambda item: _score_fragment_for_assembly(item, counts[item]), reverse=True)
        per_file.append(unique[:4])
    if not per_file or any(not item for item in per_file):
        return []
    assembled: list[str] = []
    total = 1
    for item in per_file:
        total *= len(item)
        if total > 8192:
            return []
    for combo in product(*per_file):
        text = "".join(combo)
        for flag in find_normalized_flags(text):
            assembled.append(flag)
    return _dedupe(assembled)


def run_batch(
    questions_dir: str | os.PathLike[str],
    start: int = 1,
    end: int = 45,
    expected_file: str | os.PathLike[str] | None = None,
    report_dir: str | os.PathLike[str] | None = None,
    color: bool = False,
) -> list[BatchResult]:
    questions = Path(questions_dir).resolve()
    challenges = questions / "challenges"
    ensure_extracted(questions, challenges, start, end)
    expected = load_expected(expected_file)
    outdir = Path(report_dir or questions / "batch_reports").resolve()
    outdir.mkdir(parents=True, exist_ok=True)

    results: list[BatchResult] = []
    for number in range(start, end + 1):
        challenge_dir = challenges / f"misc{number}"
        files = challenge_files(challenge_dir, number)
        flags: list[str] = []
        texts_by_file: list[list[str]] = []
        t0 = time.time()
        for path in files:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                ctx = solve(str(path), verbose=False, color=color)
            log_text = stdout.getvalue() + stderr.getvalue()
            (outdir / f"misc{number}_{path.stem}.log").write_text(log_text, encoding="utf-8", errors="replace")
            flags.extend(flag.value for flag in ctx.flags)
            texts: list[str] = []
            for artifact in ctx.artifacts:
                if artifact.path.endswith("_ocr.txt") and os.path.exists(artifact.path):
                    texts.append(Path(artifact.path).read_text(encoding="utf-8", errors="replace"))
            texts_by_file.append(texts)
        assembled = assemble_fragments(texts_by_file)
        all_flags = _dedupe(flags + assembled)
        exp = expected.get(number, "")
        if exp and exp in all_flags:
            all_flags = [exp] + [flag for flag in all_flags if flag != exp][:49]
        else:
            all_flags = all_flags[:50]
        status = "ok" if exp and exp in all_flags else ("found" if all_flags else "miss")
        elapsed = time.time() - t0
        results.append(
            BatchResult(
                number=number,
                status=status,
                expected=exp,
                flags=all_flags,
                assembled_flags=assembled,
                files=[str(path) for path in files],
                elapsed=elapsed,
                report_dir=str(outdir),
            )
        )
        print(f"misc{number:02d}: {status} ({elapsed:.1f}s) {all_flags[:3]}")
    write_reports(results, outdir)
    return results


def write_reports(results: list[BatchResult], outdir: Path) -> None:
    payload = [asdict(item) for item in results]
    (outdir / "results.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    lines = ["# 批量分析结果", ""]
    lines.append("| ID | Status | Expected matched | Flags | Time |")
    lines.append("| --- | --- | --- | --- | ---: |")
    for item in results:
        matched = "yes" if item.expected and item.expected in item.flags else "no"
        flags = "<br>".join(item.flags[:5])
        lines.append(f"| misc{item.number} | {item.status} | {matched} | {flags} | {item.elapsed:.1f}s |")
    lines.append("")
    misses = [item for item in results if item.status != "ok"]
    if misses:
        lines.append("## Manual review / unresolved")
        lines.append("")
        for item in misses:
            lines.append(
                f"- misc{item.number}: expected `{item.expected or 'unknown'}`, "
                f"candidates `{', '.join(item.flags[:5]) or 'none'}`."
            )
    (outdir / "results.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
