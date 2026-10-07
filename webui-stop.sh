#!/usr/bin/env bash
# CTF Stego WebUI 一键停止（Linux/WSL）。任意目录执行均可。
set -euo pipefail

PATTERN="ctf-stego-webui"

if ! pids=$(pgrep -f "$PATTERN"); then
  echo "WebUI 未在运行"
  exit 0
fi

echo "停止 WebUI (pid: $(echo $pids | tr '\n' ' '))..."
pkill -f "$PATTERN" || true

for _ in $(seq 1 10); do
  sleep 0.5
  pgrep -f "$PATTERN" >/dev/null 2>&1 || { echo "已停止"; exit 0; }
done

echo "5s 后仍有残留进程, 尝试强制杀死..." >&2
pkill -9 -f "$PATTERN" || true
sleep 1
if pgrep -f "$PATTERN" >/dev/null 2>&1; then
  echo "错误: 仍有进程残留, 请手动检查: pgrep -af $PATTERN" >&2
  exit 1
fi
echo "已强制停止"
