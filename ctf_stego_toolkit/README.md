# CTF Stego Toolkit

这是从 `stego_solver.sh` 演进出的 Python3 图片隐写自动分析项目，目标是对常见 CTF 图片隐写题做“一键分析 + 自动提取 flag + 生成可人工复核的中间产物”。

## 兼容性

- Python: 3.9+
- 核心扫描依赖 Python 标准库。
- 图像/OCR/结构扫描能力依赖外部工具；缺失时会降级并在运行日志里提示安装方式。

## 快速使用

单文件分析：

```bash
python3 ctf_stego_toolkit/solve.py path/to/image.png --no-color
```

也可以使用兼容入口：

```bash
./stego_solver.sh path/to/image.png --no-color
```

批量分析目录中的题目：

```bash
python3 ctf_stego_toolkit/solve.py questions \
  --batch --start 1 --end 45 \
  --expected-file questions/flags.md \
  --report-dir questions/batch_reports
```

批量模式会自动解压 `questions/miscN.zip` 到 `questions/challenges/miscN/`，然后逐题运行分析，输出：

- 单题日志：`questions/batch_reports/miscN_*.log`
- 汇总 JSON：`questions/batch_reports/results.json`
- 汇总 Markdown：`questions/batch_reports/results.md`

公开仓库不包含题目压缩包、真实 flag、批量报告或解题中间产物；请使用自己的题目目录运行。

## 当前能力

- 常见 flag 前缀识别：`flag{}`、`key{}`、`ctf{}`、`ctfhub{}`、`ctfshow{}`、`bugku{}` 等 40+ 常见平台前缀，**大小写不敏感**（`FLAG{}`/`Flag{}` 同样识别）。
- 前缀可扩展：默认内置列表见 `flag_prefixes.json`（留空即用内置）；可手动编辑该文件，或用 `solve.py --add-prefix myteam` / `--remove-prefix myteam` / `--list-prefixes` / `--reset-prefixes` 管理（写入后下次运行生效）。
- 明文、UTF-16、hex、base64、ZIP/gzip/zlib/bzip2/LZMA/XZ 递归扫描；并自动解码 HTML 数字/命名实体（`&#107;`/`&amp;`）、URL 百分号编码（`%6b`）、`\uXXXX`/`\xNN` 转义等常见文本编码。
- PNG/JPEG/GIF/BMP/TIFF/WebP/BPG 基础识别与深度规则。
- EXIF/缩略图/metadata 分片、时间戳、十进制转 hex。
- PNG IDAT 长度、CRC、APNG delay 编码。
- GIF delay bit、异常帧、宽高修复。
- JPEG/BMP/PNG/GIF 宽高修复候选。
- OCR：tesseract + gocr；同时保存增强图、彩色文字掩码、密集文本裁剪图，便于人工复核。
- 二维码/条码：`zbarimg` 自动扫描原图、提取图、位平面图。
- 通用位平面：自动生成 RGB bit0/bit1 重建图和 R/G/B/A 低 4 位接触图。
- 通用结构规则：BPG 解码、F001 十六进制编辑器高亮点阵解码、常见宽高/计时/分片套路。

## 自定义 flag 前缀

`flag_prefixes.json`（项目根目录，或设置环境变量 `STEGO_FLAG_PREFIXES_FILE` 指向自定义路径）：

```json
{
  "replace_default": false,
  "prefixes": ["myteam", "demoteam"]
}
```

- `replace_default: false`（默认）：与内置列表合并；`true`：完全用 `prefixes` 覆盖内置列表。
- 也可不改文件，直接用命令管理：`python3 solve.py --add-prefix myteam`（执行后退出，下次解题自动生效）。

## 当前仍不完美的地方

- 密码型隐写默认只提示，不自动爆破：`steghide`、`outguess`、`jphide`、`openstego`、`stegseek` 需要题目密码/字典后手动运行。
- 视觉模型缺失：极低对比度、艺术字、旋转/扭曲文字仍可能需要人工查看产物。
- 需要原图对比的隐写（差分图、盲水印、DCT 差分）目前只做提示，没有完整自动恢复。
- 专用算法类隐写（F5、JSteg、OpenPuff、SilentEye、LSB matching、调色板置换等）未全部内置。
- 加密压缩包可检测/提取，但不能在没有密码/字典时自动解密。

## 文档

- [环境安装指南](docs/环境安装指南.md)
- [通用隐写能力审计](docs/通用隐写能力审计.md)
