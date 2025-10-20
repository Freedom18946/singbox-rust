#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

changed="$(git status --porcelain || true)"

echo "[1/6] fmt/clippy/build/tests..."
cargo fmt --all
cargo clippy --all-targets --all-features -D warnings
cargo build --bins --tests
cargo test --all --tests

echo "[2/6] diag tcp/tls samples..."
tcp_json="$( target/debug/diag tcp --addr 127.0.0.1:9 --timeout-ms 200 )"
tls_json="$( target/debug/diag tls --addr 127.0.0.1:9 --sni example.com --timeout-ms 500 )"

echo "[3/6] subs merge..."
tmpdir="$(mktemp -d)"
echo '{"inbounds":[],"outbounds":[],"route":{"rules":[]}}' > "$tmpdir/base.json"
echo '{"inbounds":[{"type":"socks","listen":"0.0.0.0","port":1080}],"route":{"rules":[{"domain":["a.com"]}]}}' > "$tmpdir/a.json"
merge_out="$tmpdir/merged.json"
merge_json="$( target/debug/subs merge "$tmpdir/base.json" "$tmpdir/a.json" -o "$merge_out" )"

echo "[4/6] subs diff..."
diff_json="$( target/debug/subs diff "$tmpdir/base.json" "$merge_out" )"

echo "[5/6] metrics (if exporter running, optional)…"
metrics_head=""
if pgrep -x run >/dev/null 2>&1; then
  metrics_head="$(curl -sS http://127.0.0.1:19090/metrics | head -n 30 || true)"
fi

echo "[6/6] summary..."
cat <<EOF
{
  "task":"diag_and_subs",
  "git_status": $(jq -Rs . <<<"$changed"),
  "fmt_clippy_build_tests":"ok",
  "samples":{
    "tcp": $tcp_json,
    "tls": $tls_json,
    "merge": $merge_json,
    "diff": $diff_json,
    "metrics_head": $(jq -Rs . <<<"$metrics_head")
  }
}
EOF