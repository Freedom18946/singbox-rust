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

echo "[2/6] run --format json..."
run_json="$( target/debug/run -c /dev/null --format json --dns-from-env 2>/dev/null | head -n1 )"

echo "[3/6] check schema-v2 error..."
tmp="$(mktemp)"; cat > "$tmp" <<'JSON'
{"inbounds":[{"type":"socks","listen":"0.0.0.0","port":1080,"__unknown__":true}]}
JSON
set +e
check_json="$( target/debug/app check -c "$tmp" --schema-v2-validate --format json )"
check_code=$?
set -e
rm -f "$tmp"

echo "[4/6] route --explain json..."
cfg="$(mktemp)"; echo '{"inbounds":[{"type":"socks","listen":"127.0.0.1","port":1080}]}' > "$cfg"
explain_json="$( target/debug/app route -c "$cfg" --dest example.com:443 --explain --format json )"
rm -f "$cfg"

echo "[5/6] version json..."
ver_json="$( target/debug/version )"

echo "[6/6] summarize..."
cat <<EOF
{
  "task": "cli_json_contract",
  "git_status": $(jq -Rs . <<<"$changed"),
  "fmt_clippy_build_tests": "ok",
  "samples": {
    "run_json": $run_json,
    "check_json": $check_json,
    "check_exit": $check_code,
    "explain_json": $explain_json,
    "version_json": $ver_json
  }
}
EOF