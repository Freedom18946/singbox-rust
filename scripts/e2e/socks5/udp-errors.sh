#!/usr/bin/env zsh
set -euo pipefail

echo "[INFO] e2e: socks5 udp error path (parse) -> inbound_error_total{socks_udp}"

# Config
LISTEN=${SB_SOCKS_UDP_LISTEN:-127.0.0.1:11090}
PROM=${PROM_LISTEN:-127.0.0.1:19090}
CFG=${CFG_PATH:-}
FEATS=${FEATS:-acceptance,adapters}
REASON_FILE=${REASON_FILE:-/tmp/sb-udp-errors.reason}

: > "${REASON_FILE}"

if [[ -z "${CFG}" ]]; then
  if [[ -f examples/e2e/minimal.yaml ]]; then
    CFG="examples/e2e/minimal.yaml"
  elif [[ -f .e2e/config.yaml ]]; then
    CFG=".e2e/config.yaml"
  else
    CFG="$(mktemp -t sb-udp-errors-config.XXXX.yaml)"
    cat > "${CFG}" <<'YAML'
log:
  level: error
inbounds:
  - type: socks
    listen: "127.0.0.1:11080"
outbounds:
  - type: direct
    tag: direct
route:
  rules:
    - outbound: direct
YAML
  fi
fi

host="${LISTEN%:*}"
port="${LISTEN##*:}"

# Helper to scrape and sum metric family values with filters
scrape_metric_sum(){
  local name="$1"; shift
  local lines
  lines="$(curl -fsS "http://${PROM}/metrics" | grep -E "^${name}\\{" || true)"
  for f in "$@"; do
    lines="$(printf '%s\n' "$lines" | grep -F "$f" || true)"
  done
  printf '%s\n' "$lines" | awk '{s+=$NF} END{if(s=="") s=0; print s}'
}

tmp_before="$(mktemp -t sbm_udp_err_before.XXXX)"
tmp_after="$(mktemp -t sbm_udp_err_after.XXXX)"
cleanup(){ rm -f "$tmp_before" "$tmp_after" || true; }
trap cleanup EXIT

echo "[RUN] launching app run with UDP inbound + metrics exporter"
launch_runtime() {
  if command -v setsid >/dev/null 2>&1; then
    setsid nohup env \
      SB_SOCKS_UDP_ENABLE=1 \
      SB_SOCKS_UDP_LISTEN="${LISTEN}" \
      target/debug/run \
      --config "${CFG}" \
      --prom-listen "${PROM}" \
      </dev/null >/tmp/sb-udp-errors.log 2>&1 &
  else
    nohup env \
      SB_SOCKS_UDP_ENABLE=1 \
      SB_SOCKS_UDP_LISTEN="${LISTEN}" \
      target/debug/run \
      --config "${CFG}" \
      --prom-listen "${PROM}" \
      </dev/null >/tmp/sb-udp-errors.log 2>&1 &
  fi
}

launch_runtime

APP_PID=$!
echo "${APP_PID}" > /tmp/sb-udp-errors.pid
trap 'kill ${APP_PID} 2>/dev/null || true' EXIT
for _ in {1..20}; do
  if ! kill -0 "${APP_PID}" 2>/dev/null; then
    echo "runtime-exited-before-metrics" > "${REASON_FILE}"
    echo "[FAIL] app runtime exited before metrics became reachable"
    exit 1
  fi
  if curl -fsS "http://${PROM}/metrics" >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

echo "[SCRAPE] baseline inbound_error_total{protocol=\"socks_udp\"}"
base=$(scrape_metric_sum inbound_error_total 'protocol="socks_udp"')
echo "base=${base}" > "$tmp_before"

echo "[INJECT] send malformed SOCKS5 UDP datagram to ${LISTEN} (expect parse error)"
if command -v nc >/dev/null 2>&1; then
  printf '\x01\x00\x00\x00' | nc -u -w 1 "$host" "$port" || true
else
  # Fallback: use bash /dev/udp if available
  if ( : > /dev/udp/"$host"/"$port" ) 2>/dev/null; then
    exec 3<>/dev/udp/"$host"/"$port" || true
    printf '\x01\x00\x00\x00' >&3 || true
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
  echo "metric-did-not-increase" > "${REASON_FILE}"
  echo "[FAIL] inbound_error_total{protocol=socks_udp} did not increase (Δ=${delta})"
  echo "[HINT] ensure metrics exporter bound at ${PROM} and UDP inbound enabled at ${LISTEN}"
  exit 1
fi

echo "[CLEANUP] shutting down"
kill ${APP_PID} 2>/dev/null || true
sleep 0.2
echo "[DONE]"
