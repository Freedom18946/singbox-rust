#!/usr/bin/env zsh
set -euo pipefail
echo "[INFO] e2e: SOCKS UDP metrics smoke"

# 1) 启动 singbox-rust（假定外部已编译好），并开启 metrics 与 UDP
export SB_METRICS_ADDR=${SB_METRICS_ADDR:-127.0.0.1:9090}
export SB_SOCKS_UDP_ENABLE=1
export SB_SOCKS_UDP_LISTEN=${SB_SOCKS_UDP_LISTEN:-127.0.0.1:11080}

echo "[INFO] send a few UDP packets to $SB_SOCKS_UDP_LISTEN"
RUSTFLAGS="" cargo run -q --example udp_blast -- ${SB_SOCKS_UDP_LISTEN%:*} ${SB_SOCKS_UDP_LISTEN#*:} 50

echo "[INFO] scrape metrics"
curl -s "http://$SB_METRICS_ADDR/metrics" | grep -E 'udp_pkts_in_total|udp_pkts_out_total|udp_bytes_' || {
  echo "[WARN] metrics missing; ensure app initialized exporter & feature=metrics"; exit 1;
}
echo "[OK] udp metrics present"