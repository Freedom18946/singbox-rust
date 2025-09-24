#!/usr/bin/env bash
# scripts/lib/os_probe.sh
# Process-level resource sampling: RSS(MiB)/FD/Threads; Linux prioritizes /proc; macOS falls back to ps/lsof
set -euo pipefail

pid_of() { pgrep -f "$1" | head -n1; }

rss_mib() {
  local pid="$1"
  if [[ -r "/proc/$pid/status" ]]; then
    awk '/VmRSS:/ {print int($2/1024)}' "/proc/$pid/status"
  else
    # macOS: ps rss KB
    ps -o rss= -p "$pid" | awk '{print int($1/1024)}'
  fi
}

fd_count() {
  local pid="$1"
  if [[ -d "/proc/$pid/fd" ]]; then
    ls -U "/proc/$pid/fd" 2>/dev/null | wc -l | awk '{print $1}'
  else
    lsof -p "$pid" 2>/dev/null | wc -l | awk '{print $1}'
  fi
}

thr_count() {
  local pid="$1"
  if [[ -r "/proc/$pid/status" ]]; then
    awk '/Threads:/ {print $2}' "/proc/$pid/status"
  else
    ps -M -p "$pid" 2>/dev/null | wc -l | awk '{print ($1>0?$1-1:0)}'
  fi
}

emit_proc_json() {
  local pid="$1"
  local rss=$(rss_mib "$pid"); local fds=$(fd_count "$pid"); local th=$(thr_count "$pid")
  jq -cn --argjson rss "$rss" --argjson fd "$fds" --argjson th "$th" '{rss_mib:$rss, fd:$fd, threads:$th}'
}

# 背景采样器：每 INTERVAL 秒采样一次，输出最大值到指定 JSON 文件；进程消失即退出
sampler() {
  local pid="$1"; local interval="${2:-1}"; local out="$3"; local ts_out="${4:-}"
  local rss_max=0 fd_max=0 th_max=0
  while kill -0 "$pid" 2>/dev/null; do
    local j; j="$(emit_proc_json "$pid")"
    local rss fd th
    rss="$(jq -r '.rss_mib' <<<"$j")"; fd="$(jq -r '.fd' <<<"$j")"; th="$(jq -r '.threads' <<<"$j")"
    if [[ -n "$ts_out" ]]; then echo "$(date +%s),$rss,$fd,$th" >> "$ts_out"; fi
    (( rss > rss_max )) && rss_max="$rss"
    (( fd  > fd_max  )) && fd_max="$fd"
    (( th  > th_max  )) && th_max="$th"
    echo "{\"rss_mib_max\":$rss_max,\"fd_max\":$fd_max,\"threads_max\":$th_max}" > "$out"
    sleep "$interval"
  done
}

pctl_from_csv() {
  # usage: pctl_from_csv file col_index(1:rss,2:fd,3:threads) pct(95)
  local f="$1"; local col="$2"; local p="$3"
  [[ -s "$f" ]] || { echo 0; return; }
  awk -F, -v C=$((col+1)) '{print $C}' "$f" | sort -n | awk -v P="$p" '{
    a[NR]=$1
  } END {
    if (NR==0) {print 0; exit}
    idx = int((P/100)*NR); if (idx<1) idx=1; if (idx>NR) idx=NR; print a[idx]
  }'
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  if [[ "${2:-}" == "sampler" ]]; then sampler "$1" "${3:-1}" "${4:-/dev/stdout}" "${5:-}"; else emit_proc_json "$1"; fi
fi