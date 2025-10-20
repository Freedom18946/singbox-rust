#!/usr/bin/env zsh
# scripts/run_and_test.zsh
set -euo pipefail

BIN=${BIN:-"./target/debug/singbox-rust"}
CONFIG=${CONFIG:-"./config.yaml"}
HTTP_PROXY_ADDR=${HTTP_PROXY_ADDR:-"127.0.0.1:18081"}
SOCKS_PROXY_ADDR=${SOCKS_PROXY_ADDR:-"127.0.0.1:11080"}
METRICS_URL=${METRICS_URL:-"http://127.0.0.1:9900/metrics"}
LOG_DIR=${LOG_DIR:-".e2e"}
LOG_FILE=${LOG_FILE:-"${LOG_DIR}/sing.log"}
WAIT_LOG_TIMEOUT=${WAIT_LOG_TIMEOUT:-15}
WAIT_PROTO_TIMEOUT=${WAIT_PROTO_TIMEOUT:-10}

mkdir -p "${LOG_DIR}"

info() { print -r -- "[INFO] $*"; }
step() { print -r -- "[STEP] $*"; }
ok()   { print -r -- "[OK] $*"; }
err()  { print -r -- "[ERR] $*"; }

cleanup() {
  if [[ -n "${SBOX_PID-}" ]]; then
    kill "${SBOX_PID}" 2>/dev/null || true
    wait "${SBOX_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

step "后台启动服务：${BIN} --config ${CONFIG}"
: > "${LOG_FILE}"
set +e
# 强制禁用彩色日志，避免 ANSI 控制序列写入文件影响解析
env NO_COLOR=1 RUST_LOG_STYLE=never SB_HTTP_DISABLE_STOP=1 SB_SOCKS_DISABLE_STOP=1 "${BIN}" --config "${CONFIG}" >> "${LOG_FILE}" 2>&1 &
SBOX_PID=$!
set -e
info "日志: ${LOG_FILE}"

step "按日志等待就绪（bound|listening）…"
deadline=$(( $(date +%s) + WAIT_LOG_TIMEOUT ))
http_ready=0
socks_ready=0
until (( http_ready && socks_ready )); do
  grep -E "HTTP.+bound|listening.+HTTP|HTTP CONNECT bound" "${LOG_FILE}" >/dev/null 2>&1 && http_ready=1
  grep -E "SOCKS.*bound|listening.+SOCKS|SOCKS5 bound" "${LOG_FILE}" >/dev/null 2>&1 && socks_ready=1
  if (( $(date +%s) > deadline )); then
    err "日志未在 ${WAIT_LOG_TIMEOUT}s 内出现 bound 行：请检查 ${LOG_FILE}"
    tail -n +1 "${LOG_FILE}" | sed -n '1,200p'
    exit 2
  fi
  sleep 0.2
done
ok "日志显示已就绪"

# 生成去除 ANSI 控制序列后的干净日志，便于解析 actual= 与 local=
LOGC="${LOG_DIR}/sing.log.clean"
# 去除 \x1B[...<letter> 形式的 ANSI 序列，失败则回退原始文件
perl -pe 's/\x1B\[[0-9;]*[A-Za-z]//g' "${LOG_FILE}" > "$LOGC" 2>/dev/null || cp "${LOG_FILE}" "$LOGC"

# NOTE: 稳定性采样（临时实例 10 连发，不影响常规启动）
# 目的：避免端口复用导致拒连，采样拿到稳定 405 首行
# 先清掉可能遗留的默认值，避免误用 18081/11080
unset HTTP_PROXY_ADDR SOCKS_PROXY_ADDR
parse_last_actual() {
  local pat="$1" file="$2" deadline=$(( $(date +%s) + 3 ))
  local line=""
  while [ $(date +%s) -le "$deadline" ]; do
    line=$(grep -Eo "${pat}=127\\.0\\.0\\.1:[0-9]+" "$file" | tail -n1)
    [ -n "$line" ] && { echo "${line##*:}"; return 0; }
    sleep 0.1
  done
  return 1
}
### 解析 HTTP 端口：最后一行 + 重试（100ms * 30）
HTTP_PORT=""
for i in {1..30}; do
  HTTP_PORT="$(grep -Eo 'actual=127\.0\.0\.1:[0-9]+' .e2e/sing.log | tail -n 1 | sed -E 's/.*://')"
  if [[ "$HTTP_PORT" =~ ^[0-9]+$ ]]; then
    break
  fi
  sleep 0.1
done
if [[ ! "$HTTP_PORT" =~ ^[0-9]+$ ]]; then
  echo "[ERR] failed to parse HTTP actual port from .e2e/sing.log" >&2
  exit 1
fi
SOCKS_PORT=$(parse_last_actual "SOCKS" ".e2e/sing.log") || true
METR_PORT=$(parse_last_actual "METRICS" ".e2e/sing.log") || true
[[ -n "${HTTP_PORT}" ]] && export HTTP_PROXY_ADDR="127.0.0.1:${HTTP_PORT}"
[[ -n "${SOCKS_PORT}" ]] && export SOCKS_PROXY_ADDR="127.0.0.1:${SOCKS_PORT}"
echo "[INFO] resolved HTTP=${HTTP_PROXY_ADDR:-unset} SOCKS=${SOCKS_PROXY_ADDR:-unset} METRICS=${METR_PORT:-unset}"
# 没解析出 HTTP 实际端口就直接失败，避免继续误用默认端口
if [[ -z "${HTTP_PROXY_ADDR:-}" ]]; then
  echo "[ERR] 无法从日志解析 HTTP 实际端口"; exit 2;
fi

# HTTP 入站协议就绪检查（405）
echo "[STEP] HTTP 入站协议就绪检查（405） ${HTTP_PROXY_ADDR}…"
python3 scripts/probe_http.py "${HTTP_PROXY_ADDR}" "$(( $(date +%s) + 6 ))" || {
  echo "[ERR] HTTP 协议就绪探测失败"; exit 1;
}

# ---------- SOCKS method 探活（独立脚本） ----------
step "SOCKS5 入站协议就绪检查（NO_AUTH） ${SOCKS_PROXY_ADDR}…"
deadline=$(( $(date +%s) + WAIT_PROTO_TIMEOUT ))
python3 "scripts/probe_socks.py" "${SOCKS_PROXY_ADDR}" "${deadline}"

# ---------- 功能验证 ----------
step "curl 验证（HTTP CONNECT / SOCKS5）"
set +e
curl -sS -m 10 -I -x "http://${HTTP_PROXY_ADDR}" http://example.com/ >/dev/null
HTTP_OK=$?
curl -sS -m 10 -I --socks5-hostname "${SOCKS_PROXY_ADDR}" http://example.com/ >/dev/null
SOCKS_OK=$?
set -e
(( HTTP_OK == 0 )) || { err "HTTP CONNECT 代理验证失败（curl 返回码=${HTTP_OK}）"; exit 5; }
(( SOCKS_OK == 0 )) || { err "SOCKS5 代理验证失败（curl 返回码=${SOCKS_OK}）"; exit 6; }
ok "curl 功能验证通过"

# ---------- 指标采样 ----------
step "采样 Prometheus 指标（若启用 metrics）"
set -e

# 如果未启 metrics，优雅跳过采样（与主流程解耦，避免误报）
if [ -n "${METR_PORT:-}" ]; then
  curl -fsS "http://127.0.0.1:${METR_PORT}/metrics" | head -n5
else
  echo "[SKIP] metrics disabled"
fi

# 稳定性采样：临时实例 10 连发（不影响常规启动，只为观察 405 首行稳定性）

ok "全部通过"
exit 0
