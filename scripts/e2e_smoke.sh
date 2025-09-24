#!/usr/bin/env bash
set -euo pipefail

# ===== Config =====
HTTP_PROXY_ADDR="${HTTP_PROXY_ADDR:-127.0.0.1:8081}"
SOCKS_PROXY_ADDR="${SOCKS_PROXY_ADDR:-127.0.0.1:1080}"
METRICS_ADDR="${METRICS_ADDR:-127.0.0.1:9900}"
TARGET_OK_HTTPS="${TARGET_OK_HTTPS:-https://www.example.com/}"
THROUGHPUT_BYTES="${THROUGHPUT_BYTES:-2097152}"   # 2 MiB
THROUGHPUT_URL="${THROUGHPUT_URL:-https://speed.cloudflare.com/__down?bytes=${THROUGHPUT_BYTES}}"
TIMEOUT="${TIMEOUT:-20}"  # 放宽到 20s，避免冷启抖动

# ===== UI =====
c_green(){ printf "\033[32m%s\033[0m\n" "$*"; }
c_red(){ printf "\033[31m%s\033[0m\n" "$*"; }
c_yel(){ printf "\033[33m%s\033[0m\n" "$*"; }
step(){ printf "\n\033[36m[STEP]\033[0m %s\n" "$*"; }
ok(){ c_green "[OK] $*"; }
fail(){ c_red "[FAIL] $*"; exit 1; }

# ===== Helpers =====
wait_tcp(){
  local hp="$1" host="${1%:*}" port="${1##*:}" i=0
  step "等待端口 ${host}:${port} 可用…"
  while :; do
    if command -v nc >/dev/null 2>&1; then
      # macOS 自带 nc：-z 仅扫描, -G 超时(秒)
      if nc -z -G 1 "$host" "$port" >/dev/null 2>&1; then
        ok "端口 ${host}:${port} 已就绪"; return 0
      fi
    else
      # 兜底：/dev/tcp（部分环境不可用）
      if ( : > /dev/tcp/"$host"/"$port" ) >/dev/null 2>&1; then
        ok "端口 ${host}:${port} 已就绪"; return 0
      fi
    fi
    ((i++)); if (( i >= TIMEOUT )); then fail "端口 ${host}:${port} 不可达"; fi
    sleep 1
  done
}

has_metrics(){ curl -fsS "http://${METRICS_ADDR}/metrics" >/dev/null 2>&1; }

scrape_metric_sum(){
  local name="$1"; shift
  curl -fsS "http://${METRICS_ADDR}/metrics" \
    | grep -E "^${name}\{" \
    | { for f in "$@"; do grep -F "$f"; done } \
    | awk '{s+=$NF} END{if(s=="") s=0; print s}'
}

delta_gt(){
  local before="$1" after="$2" msg="$3"
  local d=$(( after - before ))
  if (( d > 0 )); then ok "$msg (+${d})"; else fail "$msg 未增长 (Δ=${d})"; fi
}

tmp_before="$(mktemp -t sbm_before.XXXX)"
tmp_after="$(mktemp -t sbm_after.XXXX)"
cleanup(){ rm -f "$tmp_before" "$tmp_after" || true; }
trap cleanup EXIT

# ===== 0) 探活 =====
wait_tcp "${HTTP_PROXY_ADDR}"
wait_tcp "${SOCKS_PROXY_ADDR}"

METRICS_ON=0
if has_metrics; then METRICS_ON=1; c_yel "检测到 metrics: http://${METRICS_ADDR}/metrics"; else c_yel "未检测到 metrics，转为功能验证模式（跳过指标断言）"; fi

# ==== 1) 指标快照前置 ====
if (( METRICS_ON==1 )); then
  step "采集基线指标"
  echo "sb_router_select_ok=$(scrape_metric_sum sb_router_select_total 'mode=\"ctx\"')" > "$tmp_before"
  echo "sb_out_connect_http_ok=$(scrape_metric_sum sb_outbound_connect_total 'kind=\"http\"' 'result=\"ok\"')" >> "$tmp_before"
  echo "sb_out_connect_direct_ok=$(scrape_metric_sum sb_outbound_connect_total 'kind=\"direct\"' 'result=\"ok\"')" >> "$tmp_before"
  echo "sb_out_handshake_http_ok=$(scrape_metric_sum sb_outbound_handshake_total 'kind=\"http\"' 'result=\"ok\"')" >> "$tmp_before"
  echo "sb_in_parse_http_ok=$(scrape_metric_sum sb_inbound_parse_total 'label=\"http\"' 'result=\"ok\"')" >> "$tmp_before"
  echo "sb_in_parse_socks_ok=$(scrape_metric_sum sb_inbound_parse_total 'label=\"socks\"' 'result=\"ok\"')" >> "$tmp_before"
  echo "sb_io_up_http=$(scrape_metric_sum sb_io_bytes_total 'label=\"http\"' 'dir=\"up\"')" >> "$tmp_before"
  echo "sb_io_down_http=$(scrape_metric_sum sb_io_bytes_total 'label=\"http\"' 'dir=\"down\"')" >> "$tmp_before"
fi

# ===== 2) HTTP CONNECT 成功 =====
step "HTTP CONNECT 成功路径"
curl -v -x "http://${HTTP_PROXY_ADDR}" "${TARGET_OK_HTTPS}" -o /dev/null --connect-timeout 10 --max-time 20

# ===== 3) SOCKS5 成功 =====
step "SOCKS5 成功路径"
curl -v --socks5-hostname "${SOCKS_PROXY_ADDR}" "${TARGET_OK_HTTPS}" -o /dev/null --connect-timeout 10 --max-time 20

# ===== 4) 错误路径（HTTP 非 CONNECT）=====
step "HTTP 非 CONNECT（期望 4xx）"
set +e
http_code=$(curl -s -x "http://${HTTP_PROXY_ADDR}" "http://www.example.com/" -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 10)
set -e
echo "HTTP code via proxy: ${http_code} (期望非 200)"

# ===== 5) 吞吐（流式计量应增长）=====
step "拉取 ${THROUGHPUT_BYTES} 字节，观察流式计量"
curl -L -x "http://${HTTP_PROXY_ADDR}" "${THROUGHPUT_URL}" -o /dev/null --connect-timeout 10 --max-time 60

# ==== 6) 指标快照后置 & 断言 ====
if (( METRICS_ON==1 )); then
  step "采集对比指标"
  echo "sb_router_select_ok=$(scrape_metric_sum sb_router_select_total 'mode=\"ctx\"')" > "$tmp_after"
  echo "sb_out_connect_http_ok=$(scrape_metric_sum sb_outbound_connect_total 'kind=\"http\"' 'result=\"ok\"')" >> "$tmp_after"
  echo "sb_out_connect_direct_ok=$(scrape_metric_sum sb_outbound_connect_total 'kind=\"direct\"' 'result=\"ok\"')" >> "$tmp_after"
  echo "sb_out_handshake_http_ok=$(scrape_metric_sum sb_outbound_handshake_total 'kind=\"http\"' 'result=\"ok\"')" >> "$tmp_after"
  echo "sb_in_parse_http_ok=$(scrape_metric_sum sb_inbound_parse_total 'label=\"http\"' 'result=\"ok\"')" >> "$tmp_after"
  echo "sb_in_parse_socks_ok=$(scrape_metric_sum sb_inbound_parse_total 'label=\"socks\"' 'result=\"ok\"')" >> "$tmp_after"
  echo "sb_io_up_http=$(scrape_metric_sum sb_io_bytes_total 'label=\"http\"' 'dir=\"up\"')" >> "$tmp_after"
  echo "sb_io_down_http=$(scrape_metric_sum sb_io_bytes_total 'label=\"http\"' 'dir=\"down\"')" >> "$tmp_after"

  step "断言指标增长"
  # shellcheck disable=SC2046
  source "$tmp_before"; b_router=$sb_router_select_ok; b_och=$sb_out_connect_http_ok; b_ocd=$sb_out_connect_direct_ok; b_ohh=$sb_out_handshake_http_ok; b_iph=$sb_in_parse_http_ok; b_ips=$sb_in_parse_socks_ok; b_up=$sb_io_up_http; b_down=$sb_io_down_http
  # shellcheck disable=SC2046
  source "$tmp_after";  a_router=$sb_router_select_ok; a_och=$sb_out_connect_http_ok; a_ocd=$sb_out_connect_direct_ok; a_ohh=$sb_out_handshake_http_ok; a_iph=$sb_in_parse_http_ok; a_ips=$sb_in_parse_socks_ok; a_up=$sb_io_up_http; a_down=$sb_io_down_http

  delta_gt "$b_router" "$a_router" "router_select_total 增长"
  delta_gt "$b_och"    "$a_och"    "outbound_connect{http,ok} 增长"
  delta_gt "$b_ocd"    "$a_ocd"    "outbound_connect{direct,ok} 增长"
  delta_gt "$b_ohh"    "$a_ohh"    "outbound_handshake{http,ok} 增长"
  delta_gt "$b_iph"    "$a_iph"    "inbound_parse{http,ok} 增长"
  delta_gt "$b_ips"    "$a_ips"    "inbound_parse{socks,ok} 增长"
  delta_gt "$b_up"     "$a_up"     "sb_io_bytes_total{http,up} 增长"
  delta_gt "$b_down"   "$a_down"   "sb_io_bytes_total{http,down} 增长"
fi

ok "冒烟完成 ✅"
