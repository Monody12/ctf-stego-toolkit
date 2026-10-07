#!/usr/bin/env python3
"""从 Bugku 拉取热门 Misc 图像隐写题, 作为 WebUI 的练习/测试数据(一次性种子脚本)。

只访问: 题目列表页、题目详情页(含公开评论区)、免费附件下载。
绝不请求 writeup/WP 页面 —— 不消耗任何金币。
Cookie 只从本地文件读取(不进仓库); 拉取的题目文件只进 gitignore 的 webui_data/。

用法(在 WSL、仓库根下, 用 venv python 执行):
    .venv/bin/python scripts/fetch_bugku.py \
        --cookie-file ~/.bugku_cookies.json \
        [--count 10] [--pages 3] [--data-dir webui_data] [--seed 42]

选题逻辑: Misc 区按解题人数排序, 在前若干名中筛出"带附件且附件含图片"的题,
再随机抽取 --count 道; 题目描述/提示/公开评论写入题目的笔记字段作线索。
"""
from __future__ import annotations

import argparse
import html as html_mod
import json
import os
import random
import re
import shutil
import sys
import time
import urllib.request
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "ctf_stego_toolkit"))

BASE = "https://ctf.bugku.com"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "Chrome/126 Safari/537.36")
DELAY = 0.8  # 请求间隔, 做个有礼貌的爬虫

MAGIC_EXTS = [
    (b"\x89PNG\r\n\x1a\n", ".png"), (b"\xff\xd8\xff", ".jpg"),
    (b"GIF87a", ".gif"), (b"GIF89a", ".gif"), (b"BM", ".bmp"),
]
ARCHIVE_EXTS = [(b"Rar!", ".rar"), (b"7z\xbc\xaf", ".7z")]
IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tif", ".tiff"}

CARD_RE = re.compile(
    r'<a href="(/challenges/detail/id/(\d+)\.html)">.*?'
    r'title="([^"]*)".*?'
    r'<h4[^>]*>([^<]*)</h4>\s*<small>金币</small>.*?'
    r'<h4[^>]*>([^<]*)</h4>\s*<small>分数</small>.*?'
    r'<h4[^>]*>([^<]*)</h4>\s*<small>解决</small>',
    re.S,
)


def parse_count(text: str) -> int:
    text = text.strip().replace("+", "")
    for suffix, mul in (("K", 1000), ("W", 10000)):
        if text.endswith(suffix):
            return int(float(text[:-1]) * mul)
    try:
        return int(text)
    except ValueError:
        return 0


def strip_html(text: str) -> str:
    text = re.sub(r"<br\s*/?>", "\n", text, flags=re.I)
    text = re.sub(r"<[^>]+>", "", text)
    return html_mod.unescape(text).strip()


class BugkuClient:
    def __init__(self, cookie_file: str) -> None:
        raw = json.loads(Path(cookie_file).read_text(encoding="utf-8"))
        entries = raw if isinstance(raw, list) else [
            {"name": k, "value": v} for k, v in raw.items()
        ]
        self.cookie = "; ".join(f"{e['name']}={e['value']}" for e in entries)
        self.csrf = next((e["value"] for e in entries if e["name"] == "X-CSRF-TOKEN"), "")

    def get(self, url: str, referer: str = "") -> tuple[bytes, dict]:
        headers = {"User-Agent": UA, "Cookie": self.cookie,
                   "Accept-Language": "zh-CN,zh;q=0.9"}
        if self.csrf:
            headers["X-CSRF-TOKEN"] = self.csrf
        if referer:
            headers["Referer"] = referer
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=40) as resp:
            return resp.read(), dict(resp.headers)

    def get_text(self, url: str, referer: str = "") -> str:
        body, _ = self.get(url, referer)
        time.sleep(DELAY)
        return body.decode("utf-8", "replace")


def parse_list(client: BugkuClient, pages: int) -> list[dict]:
    items: dict[int, dict] = {}
    for page in range(1, pages + 1):
        body = client.get_text(f"{BASE}/challenges/index/gid/1/tid/4.html?page={page}")
        for path, cid, title, _coin, _score, solved in CARD_RE.findall(body):
            items[int(cid)] = {
                "id": int(cid), "title": html_mod.unescape(title.strip()),
                "solved": parse_count(solved),
            }
        print(f"  列表第 {page} 页: 累计 {len(items)} 题")
    return sorted(items.values(), key=lambda x: -x["solved"])


def parse_detail(client: BugkuClient, cid: int) -> dict:
    url = f"{BASE}/challenges/detail/id/{cid}.html"
    body = client.get_text(url)

    def field(label: str) -> str:
        m = re.search(rf'{label}:</span>\s*<(?:div|span)[^>]*>(.*?)</(?:div|span)>', body, re.S)
        return strip_html(m.group(1)) if m else ""

    attach = re.search(r'href="(/attachment/download/file/\d+\.html)"', body)
    comments = []
    blocks = re.split(r'id="comment-\d+', body)[1:]
    for block in blocks[:10]:
        user = re.search(r'class="link-1\s*">([^<]+)</a>', block)
        time_m = re.search(r'<small class="text-muted[^"]*">([^<]+)</small>', block)
        text = re.search(r"<p>(.*?)</p>", block, re.S)
        if text and strip_html(text.group(1)):
            comments.append({
                "user": strip_html(user.group(1)) if user else "?",
                "time": time_m.group(1).strip() if time_m else "",
                "text": strip_html(text.group(1))[:160],
            })
    return {
        "id": cid, "url": url,
        "desc": field(r"描　　述"), "hint": field(r"提　　示"),
        "attachment": (BASE + attach.group(1)) if attach else "",
        "comments": comments,
    }


def sniff_ext(data: bytes) -> str:
    for magic, ext in MAGIC_EXTS:
        if data.startswith(magic):
            return ext
    if data.startswith(b"PK\x03\x04"):
        return ".zip"
    for magic, ext in ARCHIVE_EXTS:
        if data.startswith(magic):
            return ext
    return ""


def paywall_amount(data: bytes) -> str:
    """识别付费附件页面, 返回金币数文本(免费/其他返回空)。"""
    if b"<!doctype html" not in data[:40].lower():
        return ""
    text = strip_html(data.decode("utf-8", "replace"))
    if "付费内容" not in text:
        return ""
    m = re.search(r"支付\s*(\d+)\s*金币", text)
    return m.group(1) if m else "若干"


def extract_archive(archive: Path, dest: Path) -> None:
    """zip 用标准库; rar/7z 用 7z(需 p7zip-full + p7zip-rar)。"""
    if archive.suffix.lower() == ".zip":
        with zipfile.ZipFile(archive) as zf:
            for member in zf.infolist():
                if member.is_dir():
                    continue
                rel = Path(*[p for p in Path(member.filename).parts
                             if p not in ("", ".", "..")])
                if not rel.parts:
                    continue
                target = dest / rel
                if not str(target.resolve()).startswith(str(dest.resolve())):
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(member) as src, open(target, "wb") as out:
                    shutil.copyfileobj(src, out)
        return
    import subprocess

    proc = subprocess.run(["7z", "x", "-y", f"-o{dest}", str(archive)],
                          capture_output=True, text=True, timeout=120)
    if proc.returncode not in (0, 1):  # 1 = 有警告但有产出
        raise RuntimeError(f"7z 解压失败: {proc.stderr.strip()[-200:]}")


def safe_filename(data: bytes, headers: dict, cid: int) -> str:
    disp = headers.get("Content-Disposition", "")
    m = re.search(r"filename\*=UTF-8''([^;]+)", disp) or re.search(r'filename="([^"]+)"', disp)
    if m:
        from urllib.parse import unquote

        name = os.path.basename(unquote(m.group(1)))
        if name and not name.endswith(".html"):
            return name
    ext = sniff_ext(data) or ".bin"
    return f"bugku_{cid}{ext}"


def collect_question_files(staging: Path) -> list[Path]:
    """从附件暂存目录里挑出要入库的文件: 图片优先, 其余(提示文本等)跟随。"""
    if not staging.exists():
        return []
    files = [p for p in staging.rglob("*") if p.is_file()]
    images = [p for p in files if p.suffix.lower() in IMAGE_EXTS]
    others = [p for p in files if p.suffix.lower() not in IMAGE_EXTS]
    return images + others


def main() -> int:
    parser = argparse.ArgumentParser(description="拉取 Bugku 热门 Misc 图像题入 WebUI")
    parser.add_argument("--cookie-file", required=True, help="Cookie JSON 文件路径(仓库外)")
    parser.add_argument("--count", type=int, default=10, help="抽取题数(默认 10)")
    parser.add_argument("--pages", type=int, default=3, help="列表页数(默认 3)")
    parser.add_argument("--data-dir", default=str(REPO_ROOT / "webui_data"))
    parser.add_argument("--seed", type=int, default=None, help="随机种子(便于复现)")
    parser.add_argument("--max-probe", type=int, default=28, help="最多探测详情页数")
    parser.add_argument("--only-ids", default="",
                        help="只处理这些题目 id(逗号分隔), 配合 --buy 精确购买")
    parser.add_argument("--buy", action="store_true",
                        help="允许支付金币购买付费附件(必须同时指定 --only-ids)")
    parser.add_argument("--budget", type=int, default=20,
                        help="本次运行的付费总额上限(默认 20 金币)")
    args = parser.parse_args()

    buy_ids = {int(x) for x in args.only_ids.split(",") if x.strip()}
    if args.buy and not buy_ids:
        parser.error("--buy 必须配合 --only-ids 使用, 避免误消费")

    from stego_toolkit.webui.app import create_app
    from stego_toolkit.webui.importer import _create_question

    client = BugkuClient(args.cookie_file)
    print(f"== 解析 Misc 列表({args.pages} 页) ==")
    ranked = parse_list(client, args.pages)
    print(f"共 {len(ranked)} 题, 解题人数 Top5: "
          + ", ".join(f"{i['title']}({i['solved']})" for i in ranked[:5]))

    print(f"\n== 按解题人数探测详情(最多 {args.max_probe} 题) ==")
    qualified: list[dict] = []
    skipped: list[str] = []
    for item in ranked:
        if len(qualified) >= args.max_probe:
            break
        detail = parse_detail(client, item["id"])
        entry = {**item, **detail}
        if detail["attachment"]:
            qualified.append(entry)
            print(f"  [有附件] {item['title']}  solved={item['solved']}  {detail['desc'][:40]}")
        else:
            skipped.append(item["title"])
    print(f"带附件 {len(qualified)} 道; 无附件跳过: {', '.join(skipped[:8])}"
          + ("…" if len(skipped) > 8 else ""))

    rng = random.Random(args.seed)
    pool = qualified[: args.max_probe]
    if buy_ids:
        pool = [e for e in pool if e["id"] in buy_ids]
    else:
        rng.shuffle(pool)  # 解题人数多的前若干名中随机抽取; 付费/无图题不占名额, 顺延补足
    print(f"\n== 处理 {len(pool)} 道(目标 {args.count}, 预算 {args.budget} 金币) ==")

    app = create_app(data_dir=args.data_dir, workers=2, timeout=300)
    staging_root = Path(args.data_dir) / "tmp" / "bugku_seed"
    staging_root.mkdir(parents=True, exist_ok=True)
    created, failed = [], []
    spent = 0

    with app.app_context():
        for entry in pool:
            if len(created) >= args.count:
                break
            cid, title = entry["id"], entry["title"]
            try:
                body, headers = client.get(entry["attachment"], referer=entry["url"])
                time.sleep(DELAY)
                paid = paywall_amount(body)
                if paid:
                    price = int(paid) if paid.isdigit() else 0
                    if not args.buy or cid not in buy_ids:
                        failed.append((title, f"附件收费 {paid} 金币 — 未授权购买, 跳过"))
                        continue
                    if spent + price > args.budget:
                        failed.append((title,
                                       f"超出预算: 需 {price} 币, 本次已花 {spent}/{args.budget}"))
                        continue
                    pay_body, _ = client.get(
                        f"{BASE}/attachment/pay/id/{cid}.html", referer=entry["url"])
                    time.sleep(DELAY)
                    body, headers = client.get(entry["attachment"], referer=entry["url"])
                    time.sleep(DELAY)
                    if paywall_amount(body):
                        failed.append((title,
                                       f"支付后仍为付费页(支付了 {price} 币, 请到平台核实)"))
                        continue
                    spent += price
                    print(f"  💰 {title}: 支付 {price} 金币 (本次累计 {spent})")
                ext = sniff_ext(body)
                if ext == "":
                    failed.append((title, "附件非文件/未知格式, 已跳过"))
                    continue
                staging = staging_root / str(cid)
                staging.mkdir(parents=True, exist_ok=True)
                archive = staging / safe_filename(body, headers, cid)
                archive.write_bytes(body)

                if ext in (".zip", ".rar", ".7z"):
                    extract_archive(archive, staging)
                    archive.unlink(missing_ok=True)
                files = collect_question_files(staging)
                if not any(p.suffix.lower() in IMAGE_EXTS for p in files) \
                        and cid not in buy_ids:
                    # 已付费的题无条件入库(钱不能白花), 未付费的才按图片题过滤
                    failed.append((title, f"附件内无图片文件({len(files)} 个其他文件), 已跳过"))
                    shutil.rmtree(staging, ignore_errors=True)
                    continue

                clues = "\n".join(f"- {c['user']}({c['time']}): {c['text']}"
                                  for c in entry["comments"][:8])
                notes = (f"【Bugku MISC】id={cid} · 解题 {entry['solved']}\n"
                         f"描述: {entry['desc'] or '-'}\n"
                         f"提示: {entry['hint'] or '-'}\n"
                         f"评论区公开线索(未购买 WP):\n{clues or '-'}")
                result = _create_question(args.data_dir, title, files, notes=notes)
                if "id" in result:
                    created.append(result)
                    print(f"  ✓ #{result['id']} {title} ({result['files']} 文件)")
                else:
                    failed.append((title, result.get("skipped", "")))
                shutil.rmtree(staging, ignore_errors=True)
            except Exception as exc:
                failed.append((title, f"{type(exc).__name__}: {exc}"))

    print(f"\n== 完成: 入库 {len(created)} 道, 本次消费 {spent} 金币 ==")
    for item in created:
        print(f"  #{item['id']:>3} {item['title']}")
    for title, reason in failed:
        print(f"  ✗ {title}: {reason}")
    shutil.rmtree(staging_root, ignore_errors=True)
    print("提示: worker 正在后台分析, 打开 WebUI 即可看到进度。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
