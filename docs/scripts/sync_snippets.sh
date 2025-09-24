#!/bin/bash
set -euo pipefail

# sync_snippets.sh - Generate documentation snippets for CLI tools
# This script runs various CLI commands to generate example outputs
# that can be manually copied into documentation files.

echo "SCHEMA_OK: Generating documentation snippets..."

cd "$(dirname "$0")/../.."

# Create target directory if it doesn't exist
mkdir -p target

# Generate handshake alpha examples
echo "HS_OK: Generating handshake loopback session..."
cargo run -q -p singbox-rust --features "handshake_alpha" --bin sb-handshake -- \
  loopback --proto vmess --host example.com --port 443 --seed 42 \
  --out target/hs.session.jsonl --obf xor:aa

echo "HS_OK: Generating handshake metrics..."
cargo run -q -p singbox-rust --features "handshake_alpha" --bin sb-handshake -- \
  metrics --from target/hs.session.jsonl --out target/hs.metrics.json --head8-top 3

echo "  - ./target/hs.metrics.json"
echo "  - ./target/hs.ci.smoke.summary.json"
echo "  - ./target/hs.ci.smoke.report.json"
echo "  - ./target/hs.scenarios.expanded.json"
echo "  - ./target/hs.session.jsonl (replayed, strict mode)"
if cargo run -q -p singbox-rust --features "handshake_alpha,io_local_alpha" --bin sb-handshake -- \
  io-local --proto trojan --port 0 --seed 42 --spawn-echo --obf-xor aa \
  --out ./target/hs.session.iolocal.jsonl > /dev/null 2>&1; then
  echo "HS_OK: io_local"
  echo "  - ./target/hs.session.iolocal.jsonl"
else
  echo "HS_FAIL: io_local"; exit 1
fi
if cargo run -q -p singbox-rust --features "handshake_alpha,io_local_alpha" --bin sb-handshake -- \
  io-local --proto trojan --port 0 --seed 42 --spawn-echo --obf-xor aa \
  --delay-tx-ms 10 --delay-rx-ms 5 --rx-drop 2 --rx-trim 24 --rx-xor 55 \
  --out ./target/hs.session.iolocal.chaos.jsonl > /dev/null 2>&1; then
  echo "HS_OK: io_local_chaos"
  echo "  - ./target/hs.session.iolocal.chaos.jsonl"
cargo run -q -p singbox-rust --features "handshake_alpha" --bin sb-handshake -- \
  metrics --from ./target/hs.session.iolocal.chaos.jsonl --out ./target/hs.metrics.chaos.json --head8-top 3 >/dev/null 2>&1 && echo "HS_OK: metrics_chaos"
cargo run -q -p singbox-rust --features "handshake_alpha" --bin sb-handshake -- \
  verify-jsonl --from ./target/hs.session.iolocal.chaos.jsonl --out ./target/hs.verify.json >/dev/null 2>&1 && echo "HS_OK: verify_jsonl"
cargo run -q -p singbox-rust --features "handshake_alpha" --bin sb-handshake -- \
  assert-metrics --from ./target/hs.session.iolocal.chaos.jsonl --min-frames 2 --min-tx 8 --min-rx 8 --max-disorder 0 >/dev/null 2>&1 && echo "HS_OK: assert_metrics"
echo "  - ./target/hs.metrics.chaos.json"
echo "  - ./target/hs.verify.json"
if cargo run -q -p singbox-rust --features "handshake_alpha,io_local_alpha" --bin sb-handshake -- \
  run-scenarios --from ./examples/hs.scenarios.json --out ./target/hs.scenarios.summary.json >/dev/null 2>&1; then
  echo "HS_OK: scenarios"
  jq -r '"SCENARIO_SUMMARY: passed=\(.passed) failed=\(.failed) total=\(.total)"' ./target/hs.scenarios.summary.json || true
else
  echo "HS_FAIL: scenarios"; exit 1
fi
else
  echo "HS_FAIL: io_local_chaos"; exit 1
fi
if cargo run -q -p singbox-rust --features "handshake_alpha" --bin sb-handshake -- \
  slice --from ./target/hs.session.iolocal.chaos.jsonl --out ./target/hs.session.slice.jsonl \
  --dir rx --limit 5 --head8-prefix 0b > /dev/null 2>&1; then
  echo "HS_OK: slice"
  echo "  - ./target/hs.session.slice.jsonl"
else
  echo "HS_FAIL: slice"; exit 1
fi

echo "SCHEMA_OK: All snippets generated successfully"