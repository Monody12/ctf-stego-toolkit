#!/usr/bin/env bash
# CTF Stego WebUI 一键启动（Linux/WSL）。任意目录执行均可。
#   ./webui-start.sh
# 端口/超时可用环境变量覆盖: STEGO_WEBUI_PORT(默认8800) / STEGO_WEBUI_TIMEOUT(默认900)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${STEGO_WEBUI_PORT:-8800}"
TIMEOUT="${STEGO_WEBUI_TIMEOUT:-900}"
LOG="$ROOT/webui_data/webui.log"
PATTERN="ctf-stego-webui"

if pids=$(pgrep -f "$PATTERN"); then
  echo "WebUI 已在运行 (pid: $(echo $pids | tr '\n' ' '))"
  echo "访问: http://127.0.0.1:$PORT"
  exit 0
fi

# 启动器: venv 优先, 其次 PATH
if [[ -x "$ROOT/.venv/bin/ctf-stego-webui" ]]; then
  BIN="$ROOT/.venv/bin/ctf-stego-webui"
elif command -v ctf-stego-webui >/dev/null 2>&1; then
  BIN="ctf-stego-webui"
else
  echo "错误: 未找到 ctf-stego-webui。请先在仓库根执行: python3 -m pip install -e \".[webui]\"" >&2
  exit 1
fi

mkdir -p "$ROOT/webui_data"
setsid nohup "$BIN" --port "$PORT" --timeout "$TIMEOUT" >>"$LOG" 2>&1 &

# 健康检查: 最多等 10s; 无 curl 时退化为探活进程
if command -v curl >/dev/null 2>&1; then
  for _ in $(seq 1 20); do
    sleep 0.5
    if curl -sf -o /dev/null "http://127.0.0.1:$PORT/" 2>/dev/null; then
      echo "WebUI 已启动: http://127.0.0.1:$PORT  (日志: $LOG)"
      exit 0
    fi
  done
else
  sleep 2
  if pgrep -f "$PATTERN" >/dev/null 2>&1; then
    echo "WebUI 已启动: http://127.0.0.1:$PORT  (日志: $LOG)"
    exit 0
  fi
fi

echo "错误: WebUI 启动后 10s 内未响应, 最近日志:" >&2
tail -20 "$LOG" >&2
exit 1
