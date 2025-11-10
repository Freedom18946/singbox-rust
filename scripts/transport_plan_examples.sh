#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

examples=(
  "docs/examples/vmess_ws_tls.yaml"
  "docs/examples/vless_httpupgrade_tls.yaml"
  "docs/examples/trojan_grpc_tls.yaml"
)

for cfg in "${examples[@]}"; do
  echo "==== transport plan for: $cfg ===="
  cargo run -p app --features router --bin transport-plan -- --config "$ROOT_DIR/$cfg"
  echo
done

