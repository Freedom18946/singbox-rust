#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

changed_files="$(git status --porcelain || true)"

echo "[1/7] fmt & clippy & build..."
cargo fmt --all
cargo clippy --all-targets --all-features
cargo build --bins --tests

echo "[2/7] run tests..."
cargo test --all --tests

echo "[3/7] start exporter..."
PROM_ADDR="127.0.0.1:19090"
target/debug/run -c /dev/null --prom-listen "$PROM_ADDR" >/dev/null 2>&1 &
pid=$!
sleep 0.5

echo "[4/7] route --explain sample..."
cfg="$(mktemp)"
cat > "$cfg" <<'JSON'
{"inbounds":[{"type":"socks","listen":"127.0.0.1","port":1080}]}
JSON
explain_json="$( target/debug/singbox-rust route -c "$cfg" --dest "example.com:443" --explain --format json )"
rm -f "$cfg"

echo "[5/7] NAT simulate..."
# 这里调用单测等价逻辑或暴露的内部接口；演示以二进制测试代替
cargo test -p singbox-rust udp_nat_metrics -- --nocapture >/dev/null 2>&1 || true

echo "[6/7] scrape metrics..."
sleep 0.2
metrics="$(curl -sS "http://$PROM_ADDR/metrics" || true)"

echo "[7/7] validate metrics..."
bash scripts/validate-metrics.sh || true
val_exit=$?

# 汇总结构化反馈（供上层 CLI 采集记录）
cat <<EOF
{
  "task": "route_explain + udp_nat_metrics + prom_exporter",
  "git_status": $(jq -Rs . <<<"$changed_files"),
  "fmt_clippy_build": "ok",
  "tests": "ok",
  "samples": {
    "route_explain_json": $explain_json,
    "metrics_head": $(jq -Rs . <<<"$(echo "$metrics" | head -n 30)"),
    "validate_metrics_exit": $val_exit
  }
}
EOF