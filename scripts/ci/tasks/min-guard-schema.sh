#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export RUST_BACKTRACE=1

changed_files="$(git status --porcelain || true)"

echo "[1/6] fmt & clippy..."
cargo fmt --all
cargo clippy --all-targets --all-features -D warnings

echo "[2/6] build bins..."
cargo build --bins

echo "[3/6] unit/integration tests..."
cargo test --all --tests

echo "[4/6] sample: minimize guard (text)"
tmp_cfg="$(mktemp)"
cat > "$tmp_cfg" <<'JSON'
{"route":{"rules":[{"domain":["a.com"]},{"not_geoip":["CN"],"outbound":"proxy"}]}}
JSON
text_err="$( ( target/debug/app check -c "$tmp_cfg" --minimize-rules 2>&1 1>/dev/null ) || true )"
rm -f "$tmp_cfg"

echo "[5/6] sample: schema-v2 unknown field (json)"
tmp_cfg2="$(mktemp)"
cat > "$tmp_cfg2" <<'JSON'
{"inbounds":[{"type":"socks","listen":"0.0.0.0","port":1080,"__unknown__":true}]}
JSON
set +e
json_out="$( target/debug/app check -c "$tmp_cfg2" --schema-v2-validate --format json )"
exit_code=$?
set -e
rm -f "$tmp_cfg2"

echo "[6/6] version json"
ver_json="$( target/debug/version )"

# 汇总结构化反馈（供上层 CLI 采集记录）
cat <<EOF
{
  "task": "minimize_guard + schema_v2_lock + sb_version",
  "git_status": $(jq -Rs . <<<"$changed_files"),
  "fmt_clippy": "ok",
  "tests": "ok",
  "samples": {
    "minimize_stderr": $(jq -Rs . <<<"$text_err"),
    "schema_v2_json": $json_out,
    "schema_v2_exit": $exit_code,
    "version_json": $ver_json
  }
}
EOF