#!/usr/bin/env zsh
set -euo pipefail

echo "[INFO] e2e: socks5 udp error path (parse) -> inbound_error_total{socks_udp}"

# Config
LISTEN=${SB_SOCKS_UDP_LISTEN:-127.0.0.1:11090}
PROM=${PROM_LISTEN:-127.0.0.1:19090}
CFG=${CFG_PATH:-examples/e2e/minimal.yaml}

host="${LISTEN%:*}"
port="${LISTEN##*:}"

# Helper to scrape and sum metric family values with filters
scrape_metric_sum(){
  local name="$1"; shift
  curl -fsS "http://${PROM}/metrics" \
    | grep -E "^${name}\\{" \
    | { for f in "$@"; do grep -F "$f"; done } \
    | awk '{s+=$NF} END{if(s=="") s=0; print s}'
}

tmp_before="$(mktemp -t sbm_udp_err_before.XXXX)"
tmp_after="$(mktemp -t sbm_udp_err_after.XXXX)"
cleanup(){ rm -f "$tmp_before" "$tmp_after" || true; }
trap cleanup EXIT

echo "[RUN] launching app run with UDP inbound + metrics exporter"
(
  SB_SOCKS_UDP_ENABLE=1 \
  SB_SOCKS_UDP_LISTEN="${LISTEN}" \
  cargo run -q -p app --bin run -- \
    --config "${CFG}" \
    --prom-listen "${PROM}" \
    >/tmp/sb-udp-errors.log 2>&1 & echo $! > /tmp/sb-udp-errors.pid
)

APP_PID=$(cat /tmp/sb-udp-errors.pid)
trap 'kill ${APP_PID} 2>/dev/null || true' EXIT
sleep 1.2

echo "[SCRAPE] baseline inbound_error_total{protocol=\"socks_udp\"}"
base=$(scrape_metric_sum inbound_error_total 'protocol="socks_udp"')
echo "base=${base}" > "$tmp_before"

echo "[INJECT] send malformed UDP datagram to ${LISTEN} (expect parse error)"
if command -v nc >/dev/null 2>&1; then
  printf "bad" | nc -u -w 1 "$host" "$port" || true
else
  # Fallback: use bash /dev/udp if available
  if ( : > /dev/udp/"$host"/"$port" ) 2>/dev/null; then
    exec 3<>/dev/udp/"$host"/"$port" || true
    printf "bad" >&3 || true
    exec 3>&-
  else
    echo "[WARN] neither nc nor /dev/udp available; cannot inject packet"
  fi
fi

sleep 0.6

echo "[SCRAPE] compare inbound_error_total{protocol=\"socks_udp\"}"
after=$(scrape_metric_sum inbound_error_total 'protocol="socks_udp"')
echo "after=${after}" > "$tmp_after"

delta=$(( after - base ))
if (( delta > 0 )); then
  echo "[OK] inbound_error_total{protocol=socks_udp} increased by ${delta}"
else
  echo "[FAIL] inbound_error_total{protocol=socks_udp} did not increase (Δ=${delta})"
  echo "[HINT] ensure metrics exporter bound at ${PROM} and UDP inbound enabled at ${LISTEN}"
  exit 1
fi

echo "[CLEANUP] shutting down"
kill ${APP_PID} 2>/dev/null || true
sleep 0.2
echo "[DONE]"

