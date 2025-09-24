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

echo "[2/6] v2 schema error sample..."
tmp="$(mktemp)"; cat > "$tmp" <<'JSON'
{"inbounds":[{"type":"socks","listen":"0.0.0.0","port":"oops","__unknown__":true}]}
JSON
set +e
v2_json="$( target/debug/app check -c "$tmp" --schema-v2-validate --format json )"
v2_code=$?
set -e
rm -f "$tmp"

echo "[3/6] normalize & write out..."
cfg="$(mktemp)"; cat > "$cfg" <<'JSON'
{"inbounds":[{"type":"socks","listen":"127.0.0.1","port":1080}],
 "route":{"rules":[{"domain":["EXAMPLE.COM","a.Example.com",".b.com."],"port":["80-82","81","443"]}]}}
JSON
out="${cfg}.normalized.json"
target/debug/app check -c "$cfg" --write-normalized --out "$out" --format json >/dev/null
norm_size=$(wc -c < "$out" | tr -d ' ')
rm -f "$cfg"

echo "[4/6] minimize with negation..."
cfg2="$(mktemp)"; cat > "$cfg2" <<'JSON'
{"route":{"rules":[{"not_ipcidr":["10.0.0.0/8"],"ipcidr":["10.0.0.0/8","10.0.0.0/8"]}]}}
JSON
min_json="$( target/debug/app check -c "$cfg2" --minimize-rules --format json )"
rm -f "$cfg2"

echo "[5/6] pack summary..."
cat <<EOF
{
  "task":"config_ir_pipeline",
  "git_status": $(jq -Rs . <<<"$changed"),
  "fmt_clippy_build_tests":"ok",
  "samples":{
    "v2_json": $v2_json,
    "v2_exit": $v2_code,
    "normalized_bytes": $norm_size,
    "minimize_json": $min_json
  }
}
EOF

echo "[6/6] done."