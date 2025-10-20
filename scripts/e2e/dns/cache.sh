#!/usr/bin/env zsh
set -euo pipefail

echo "[INFO] e2e: DNS cache smoke"
export RUST_LOG=${RUST_LOG:-warn}
export SB_DNS_CACHE_ENABLE=1
export SB_METRICS_ADDR=${SB_METRICS_ADDR:-127.0.0.1:9090}

# 只跑我们新增的跨路径测试（避免全仓网络测试时间过长）
echo "[RUN] cargo test -q --package sb-core --test dns_resolve"
cargo test -q --package sb-core --test dns_resolve -- --nocapture
echo "[OK] dns_resolve tests passed"

echo "[INFO] (optional) metrics probe"
set +e
curl -s "http://$SB_METRICS_ADDR/metrics" | grep -E 'dns_query_total|dns_resolve_seconds' >/dev/null && \
  echo "[OK] metrics available" || echo "[WARN] metrics exporter not enabled (set SB_METRICS_ADDR)"
set -e

echo "[TIP] 你也可以手动对比 'time'："
echo "  SB_DNS_CACHE_ENABLE=1  cargo run -q --example dns_lookup example.com"
echo "  SB_DNS_CACHE_ENABLE=0  cargo run -q --example dns_lookup example.com"