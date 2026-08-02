# CTF Stego Toolkit

Python 3 图片隐写自动分析工具，面向 CTF Misc/Stego 题：自动识别常见 flag 格式、扫描图片结构和附加数据、生成 OCR/位平面/条码等人工复核产物。

> 本仓库只发布工具源码和通用文档，不包含题目压缩包、真实 flag、批量解题报告或本地解题中间产物。

## 快速开始

直接运行源码入口：

```bash
python3 ctf_stego_toolkit/solve.py path/to/image.png --no-color
```

兼容旧脚本入口：

```bash
./stego_solver.sh path/to/image.png --no-color
```

安装为本地命令：

```bash
python3 -m pip install -e .
ctf-stego-solve path/to/image.png --no-color
```

批量分析自有题目目录：

```bash
ctf-stego-solve questions \
  --batch --start 1 --end 45 \
  --expected-file questions/flags.md \
  --report-dir questions/batch_reports
```

## 能力概览

- 常见 flag 前缀识别：`flag{}`、`ctf{}`、`ctfhub{}`、`ctfshow{}`、`bugku{}` 等，大小写不敏感。
- 明文、UTF-16、hex、base64、HTML 实体、URL 编码、`\uXXXX`/`\xNN` 等递归文本扫描。
- PNG/JPEG/GIF/BMP/TIFF/WebP/BPG 基础识别与深度规则。
- EXIF/缩略图/metadata 分片、时间戳、十进制转 hex。
- PNG IDAT/CRC/APNG、GIF delay/异常帧、JPEG/BMP/GIF/PNG 宽高修复候选。
- zsteg、binwalk、exiftool、pngcheck 等外部工具集成；缺失时降级运行并提示安装方式。
- OCR：tesseract + gocr；保存增强图、彩色文字掩码、密集文本裁剪图。
- QR/条码：`zbarimg` 自动扫描原图和派生产物。
- 通用位平面：生成 RGB bit0/bit1 重建图和 R/G/B/A 低 4 位接触图。

## 依赖

核心逻辑尽量使用 Python 标准库；图像/OCR/结构扫描能力依赖外部工具。完整安装说明见：

- [环境安装指南](ctf_stego_toolkit/docs/环境安装指南.md)
- [通用隐写能力审计](ctf_stego_toolkit/docs/通用隐写能力审计.md)

Python 增强依赖可选安装：

```bash
python3 -m pip install -e ".[image]"
```

## 开发检查

```bash
python3 -m compileall -q ctf_stego_toolkit
python3 ctf_stego_toolkit/solve.py --help
```

## License

MIT
