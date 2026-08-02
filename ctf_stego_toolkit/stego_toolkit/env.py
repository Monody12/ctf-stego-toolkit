"""环境检测: 工具注册表 + 降级 + 安装指引。

检测每个外部工具是否存在; 提供各发行版的安装命令。
核心算法只用 Python 标准库, 外部工具都是增强项。
"""
from __future__ import annotations

import shutil
import sys
from dataclasses import dataclass


@dataclass
class ToolInfo:
    name: str
    description: str
    required: bool = False  # True=必需, False=增强项
    install_hint: str = ""  # 安装指引

    def __post_init__(self) -> None:
        self.available: bool = shutil.which(self.name) is not None


# 工具注册表(顺序即检测顺序)
TOOL_REGISTRY: list[ToolInfo] = [
    ToolInfo("file", "文件类型识别", required=True,
             install_hint="apt/dnf install file"),
    ToolInfo("python3", "核心算法处理", required=True,
             install_hint="apt/dnf install python3"),
    ToolInfo("strings", "可见字符串扫描",
             install_hint="apt/dnf install binutils  (coreutils)"),
    ToolInfo("xxd", "十六进制查看",
             install_hint="apt/dnf install vim-common"),
    ToolInfo("exiftool", "元数据分析(强烈推荐)",
             install_hint="apt install libimage-exiftool-perl | dnf install perl-Image-ExifTool"),
    ToolInfo("binwalk", "附加文件/结构扫描与提取",
             install_hint="pip install binwalk | apt install binwalk | dnf install binwalk"),
    ToolInfo("pngcheck", "PNG chunk 结构",
             install_hint="apt install pngcheck | dnf install pngcheck"),
    ToolInfo("zsteg", "PNG/BMP LSB 隐写",
             install_hint="gem install zsteg  (需 ruby: apt/dnf install ruby)"),
    ToolInfo("convert", "ImageMagick 图像处理(GIF拆帧等)",
             install_hint="apt install imagemagick | dnf install ImageMagick"),
    ToolInfo("identify", "ImageMagick 图像信息",
             install_hint="apt install imagemagick | dnf install ImageMagick"),
    ToolInfo("tesseract", "OCR 文字识别(视觉类题目)",
             install_hint="apt install tesseract-ocr | dnf install tesseract"),
    ToolInfo("gocr", "备用 OCR(像素字体/低分辨率文字)",
             install_hint="apt install gocr | dnf install gocr"),
    ToolInfo("zbarimg", "二维码/条码识别",
             install_hint="apt install zbar-tools | dnf install zbar"),
    ToolInfo("qrencode", "二维码测试/生成(辅助项)",
             install_hint="apt install qrencode | dnf install qrencode"),
    ToolInfo("ffmpeg", "视频/动图/罕见格式转换(增强项)",
             install_hint="apt install ffmpeg | dnf install ffmpeg-free"),
    ToolInfo("bpgdec", "BPG 图片解码(libbpg)",
             install_hint="源码编译 libbpg: 见 docs/环境安装指南.md"),
    ToolInfo("steghide", "JPEG steghide 隐写",
             install_hint="apt install steghide | CentOS 需源码编译(见安装指南)"),
    ToolInfo("stegseek", "steghide 字典爆破(按需手动)",
             install_hint="Kali/Ubuntu 可安装 stegseek；CentOS 建议使用 release 二进制或容器"),
    ToolInfo("outguess", "JPEG outguess 隐写(密码型)",
             install_hint="apt install outguess | Kali/Ubuntu 推荐安装；CentOS 多需源码编译"),
    ToolInfo("jphide", "JPEG jphide/jpseek 隐写(密码型)",
             install_hint="Kali: apt install jphide | 其他发行版多需源码编译"),
    ToolInfo("openstego", "OpenStego 隐写(常见 Java 工具)",
             install_hint="下载 OpenStego jar 或用发行版/容器安装"),
    ToolInfo("foremost", "文件雕刻(备用提取)",
             install_hint="apt install foremost | CentOS 需源码编译"),
    ToolInfo("gifsicle", "GIF 处理(备用)",
             install_hint="apt install gifsicle | dnf install gifsicle"),
]


# Python 标准库可用性(核心)
STDlib_MODULES = ("zlib", "struct", "gzip", "base64", "binascii", "re", "io", "os", "sys")


class ToolRegistry:
    """工具注册表。"""

    def __init__(self) -> None:
        self.tools: dict[str, ToolInfo] = {t.name: t for t in TOOL_REGISTRY}

    def have(self, name: str) -> bool:
        t = self.tools.get(name)
        return t.available if t else (shutil.which(name) is not None)

    def missing(self) -> list[ToolInfo]:
        return [t for t in self.tools.values() if not t.available and not t.required]

    def missing_required(self) -> list[ToolInfo]:
        return [t for t in self.tools.values() if not t.available and t.required]

    def check_stdlib(self) -> bool:
        for m in STDlib_MODULES:
            try:
                __import__(m)
            except ImportError:
                return False
        return True

    def has_pillow(self) -> bool:
        try:
            import PIL  # noqa: F401
            return True
        except ImportError:
            return False

    def report(self) -> str:
        """生成环境检测报告文本。"""
        lines = []
        for t in self.tools.values():
            mark = "✓" if t.available else ("✗" if t.required else "!")
            tag = "必需" if t.required else "可选"
            lines.append(f"  {mark} {t.name} ({t.description}) [{tag}]")
        # Pillow
        lines.append("")
        if self.has_pillow():
            lines.append("  ✓ Pillow (图像像素操作, 增强项) [可选]")
        else:
            lines.append("  ! Pillow 缺失 (图像像素操作, pip install Pillow) [可选]")
        # 标准库
        lines.append("")
        if self.check_stdlib():
            lines.append("  ✓ Python 标准库 (zlib/struct/base64/...) 就绪")
        else:
            lines.append("  ✗ Python 标准库异常 [必需]")
        return "\n".join(lines)


def install_guide_for(distros: tuple[str, ...]) -> str:
    """返回指定发行版的安装命令汇总。"""
    guides = {
        "debian/ubuntu/kali": {
            "file": "apt install file",
            "python3": "apt install python3 python3-pip",
            "strings": "apt install binutils",
            "xxd": "apt install xxd  (或 vim-common)",
            "exiftool": "apt install libimage-exiftool-perl",
            "binwalk": "apt install binwalk  (或 pip install binwalk)",
            "pngcheck": "apt install pngcheck",
            "zsteg": "apt install ruby && gem install zsteg",
            "convert/identify": "apt install imagemagick",
            "tesseract": "apt install tesseract-ocr",
            "gocr": "apt install gocr",
            "zbarimg": "apt install zbar-tools",
            "qrencode": "apt install qrencode",
            "ffmpeg": "apt install ffmpeg",
            "bpgdec": "源码编译 libbpg: wget https://bellard.org/bpg/libbpg-0.9.8.tar.gz && make bpgdec",
            "steghide": "apt install steghide",
            "stegseek": "apt install stegseek  (Kali/部分 Ubuntu 源可用；也可下载 release)",
            "outguess": "apt install outguess",
            "jphide": "apt install jphide",
            "openstego": "下载 OpenStego jar: https://www.openstego.com/",
            "foremost": "apt install foremost",
            "gifsicle": "apt install gifsicle",
            "Pillow": "pip install Pillow numpy",
        },
        "centos/rhel/fedora": {
            "file": "dnf install file",
            "python3": "dnf install python3 python3-pip",
            "strings": "dnf install binutils",
            "xxd": "dnf install vim-common",
            "exiftool": "dnf install perl-Image-ExifTool  (需 EPEL)",
            "binwalk": "pip install binwalk  (dnf 版本可能较旧)",
            "pngcheck": "dnf install pngcheck  (需 EPEL)",
            "zsteg": "dnf install ruby && gem install zsteg",
            "convert/identify": "dnf install ImageMagick",
            "tesseract": "dnf install tesseract",
            "gocr": "dnf install gocr  (需 EPEL)",
            "zbarimg": "dnf install zbar  (需 EPEL)",
            "qrencode": "dnf install qrencode",
            "ffmpeg": "dnf install ffmpeg-free  (或启用 RPM Fusion 后 dnf install ffmpeg)",
            "bpgdec": "源码编译 libbpg: 见 docs/环境安装指南.md",
            "steghide": "源码编译: 见 docs/环境安装指南.md  (CentOS 无官方包)",
            "stegseek": "下载 release 二进制或使用 Kali 容器",
            "outguess": "源码编译或在 Kali/Ubuntu 环境使用",
            "jphide": "源码编译或在 Kali 环境使用",
            "openstego": "下载 OpenStego jar 或使用容器",
            "foremost": "源码编译: 见 docs/环境安装指南.md  (CentOS 无官方包)",
            "gifsicle": "dnf install gifsicle  (需 EPEL)",
            "Pillow": "pip install Pillow numpy",
        },
    }
    out = []
    for key, cmds in guides.items():
        out.append(f"\n### {key}")
        for tool, cmd in cmds.items():
            out.append(f"  {tool:16s} {cmd}")
    return "\n".join(out)
