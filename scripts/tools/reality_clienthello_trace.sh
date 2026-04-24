#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

GO_JSON="${TMP_DIR}/go.json"
RUST_JSON="${TMP_DIR}/rust.json"

bash "${ROOT}/scripts/tools/reality_go_utls_trace.sh" > "${GO_JSON}"
(
  cd "${ROOT}"
  cargo run -q -p sb-tls --example reality_clienthello_trace > "${RUST_JSON}"
)

jq -n --slurpfile go "${GO_JSON}" --slurpfile rust "${RUST_JSON}" \
  '{go: $go[0], rust: $rust[0]}'
