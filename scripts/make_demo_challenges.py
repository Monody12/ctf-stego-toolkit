#!/usr/bin/env python3
"""生成分7道合成隐写练习题入库(标题带【合成】标记), 用于体验 WebUI 与验证
各分析器产物的展示效果。需要 venv 里的 Pillow(.venv/bin/python 运行)。

用法:
    .venv/bin/python scripts/make_demo_challenges.py [--data-dir webui_data] [--count 7]
"""
from __future__ import annotations

import argparse
import shutil
import struct
import subprocess
import sys
import zlib
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "ctf_stego_toolkit"))

FONT_SIZE = 40


def font() -> ImageFont.FreeTypeFont:
    try:
        return ImageFont.load_default(size=FONT_SIZE)
    except TypeError:
        return ImageFont.load_default()


def text_image(text: str, size=(420, 140), invert=False) -> Image.Image:
    img = Image.new("L", size, 255 if not invert else 0)
    draw = ImageDraw.Draw(img)
    bbox = draw.textbbox((0, 0), text, font=font())
    w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
    draw.text(((size[0] - w) // 2, (size[1] - h) // 2), text,
              fill=0 if not invert else 255, font=font())
    return img


def canvas() -> Image.Image:
    return Image.new("RGB", (420, 140), (36, 41, 51))


# --------------------------------------------------------------------------- #
def make_lsb(staging: Path) -> Path:
    """flag 以 LSB 位平面方式藏在 R 通道 bit0 —— 位平面重建图可直接读出。"""
    flag = "flag{lsb_plane0_ok}"
    img = canvas()
    draw = ImageDraw.Draw(img)
    for y in range(0, 140, 12):
        draw.line([(0, y), (420, y)], fill=(60, 120, 200))
    arr = np.array(img)
    mask_img = np.array(text_image(flag)) > 128
    region = arr[: mask_img.shape[0], : mask_img.shape[1], 0]
    region[mask_img] = (region[mask_img] & 0xFE) | 1
    region[~mask_img] &= 0xFE
    out = staging / "lsb_hidden.png"
    Image.fromarray(arr).save(out)
    return out


def make_appended(staging: Path) -> Path:
    """IEND 之后追加明文 flag —— ExtraDataAnalyzer 的 after_iend.bin。"""
    img = canvas()
    ImageDraw.Draw(img).text((20, 50), "nothing to see here", fill=(200, 200, 200), font=font())
    out = staging / "appended.png"
    img.save(out)
    with open(out, "ab") as handle:
        handle.write(b"flag{after_iend_ok}")
    return out


def make_exif(staging: Path) -> Path:
    """EXIF Comment 藏 flag —— 元数据分析阶段提取。"""
    img = canvas()
    ImageDraw.Draw(img).text((20, 50), "check my metadata", fill=(230, 230, 230), font=font())
    out = staging / "with_exif.jpg"
    img.save(out, quality=92)
    subprocess.run(
        ["exiftool", "-overwrite_original", f"-Comment=flag{{exif_comment_ok}}", str(out)],
        check=True, capture_output=True,
    )
    return out


def make_steghide(staging: Path) -> Path:
    """steghide 嵌入(密码 123456, 见题面笔记) —— JPG 专项 + stegseek 爆破练习。"""
    # steghide 在 DCT 系数里嵌入需要足够容量(小图报 cover too short);
    # 且对非 ASCII 路径会 SIGABRT —— 在 ASCII 临时目录里完成嵌入再挪回。
    import tempfile

    img = Image.new("RGB", (1200, 800), (50, 50, 50))
    ImageDraw.Draw(img).text((400, 380), "knock knock...", fill=(220, 220, 220), font=font())
    out = staging / "knock.jpg"
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        cover = tmp / "knock.jpg"
        img.save(cover, quality=100, subsampling=0)
        secret = tmp / "secret.txt"
        secret.write_text("flag{steghide_123456}\n", encoding="utf-8")
        subprocess.run(
            ["steghide", "embed", "-cf", str(cover), "-ef", str(secret), "-p", "123456"],
            check=True, capture_output=True,
        )
        shutil.copyfile(cover, out)
    return out


def make_gif(staging: Path) -> Path:
    """flag 分成 3 帧的 GIF —— GIF 拆帧后逐帧查看。"""
    parts = ["flag{", "gif_frames_", "ok}"]
    frames = [text_image(part) for part in parts]
    out = staging / "blinking.gif"
    frames[0].convert("RGB").save(out, save_all=True, append_images=[
        f.convert("RGB") for f in frames[1:]], duration=600, loop=0)
    return out


def make_wrong_size(staging: Path) -> Path:
    """IHDR 宽高被改小(CRC 重算) —— 宽高修复候选练习。"""
    flag = "flag{fix_my_size_ok}"
    img = Image.new("RGB", (420, 140), (240, 240, 240))
    ImageDraw.Draw(img).text((30, 50), flag, fill=(10, 10, 10), font=font())
    tmp = staging / "_full.png"
    img.save(tmp)
    data = tmp.read_bytes()
    tmp.unlink()
    # IHDR 位于固定偏移: 8 签名 + 4 长度 + 4 类型, 宽高各 4 字节
    fake_w, fake_h = 300, 140
    ihdr = bytearray(data[16:29])
    ihdr[0:4] = struct.pack(">I", fake_w)
    crc = zlib.crc32(b"IHDR" + bytes(ihdr)) & 0xFFFFFFFF
    out = staging / "cropped.png"
    out.write_bytes(data[:16] + bytes(ihdr) + struct.pack(">I", crc) + data[33:])
    return out


def make_qr(staging: Path) -> Path:
    """flag 的二维码 —— zbarimg 直接扫描。"""
    out = staging / "qr.png"
    subprocess.run(["qrencode", "-o", str(out), "-s", "8", "flag{qr_scan_ok}"],
                   check=True, capture_output=True)
    return out


MAKERS = [
    ("【合成】LSB 位平面", "flag 藏在 R 通道 bit0, 用位平面重建图/zsteg 查看", make_lsb),
    ("【合成】IEND 尾部附加数据", "PNG 结束块后面跟了一段文本", make_appended),
    ("【合成】EXIF 注释", "元数据里藏着东西", make_exif),
    ("【合成】steghide 密码隐写", "JPEG 疑似 steghide; 密码是常见弱口令(123456)", make_steghide),
    ("【合成】闪动的 GIF", "flag 被拆到多帧里", make_gif),
    ("【合成】宽高修复", "图片显示不完整? 试试修复宽高", make_wrong_size),
    ("【合成】扫一扫", "图里有个码", make_qr),
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", default=str(REPO_ROOT / "webui_data"))
    parser.add_argument("--count", type=int, default=len(MAKERS))
    args = parser.parse_args()

    from stego_toolkit.webui.app import create_app
    from stego_toolkit.webui.importer import _create_question

    app = create_app(data_dir=args.data_dir)
    staging = Path(args.data_dir) / "tmp" / "demo_gen"
    staging.mkdir(parents=True, exist_ok=True)
    created = 0
    with app.app_context():
        for title, hint, maker in MAKERS[: args.count]:
            workdir = staging / title
            workdir.mkdir(parents=True, exist_ok=True)
            files = [maker(workdir)]
            notes = (f"【合成练习题】考点: {hint}\n生成方式见 scripts/make_demo_challenges.py,"
                     "非比赛真题, 仅用于体验 WebUI / 验证分析产物展示。")
            result = _create_question(args.data_dir, title, files, notes=notes)
            if "id" in result:
                print(f"  ✓ #{result['id']} {title}")
                created += 1
            else:
                print(f"  → {title}: {result.get('skipped', '')}")
    print(f"入库 {created} 道, worker 将自动开始分析。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
