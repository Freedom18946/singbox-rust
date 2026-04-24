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

bash "${ROOT}/scripts/tools/reality_go_utls_socket_trace.sh" > "${GO_JSON}"
(
  cd "${ROOT}"
  cargo run -q -p sb-tls --example reality_clienthello_socket_trace > "${RUST_JSON}"
)

jq -n --slurpfile go "${GO_JSON}" --slurpfile rust "${RUST_JSON}" \
  '{
    summary: {
      go: {
        client_connect_elapsed_micros: $go[0].client_connect_elapsed_micros,
        client_handshake_elapsed_micros: $go[0].client_handshake_elapsed_micros,
        client_first_write_after_connect_micros: $go[0].client_first_write_after_connect_micros,
        client_first_read_after_connect_micros: $go[0].client_first_read_after_connect_micros,
        client_event_kinds: ($go[0].client_event_trace | map(.kind)),
        server_first_read_delay_micros: $go[0].server_first_read_delay_micros,
        server_first_read_to_end_micros: $go[0].server_first_read_to_end_micros,
        server_trace_elapsed_micros: $go[0].server_trace_elapsed_micros,
        server_end_reason: $go[0].server_end_reason,
        server_chunk_offsets_micros: ($go[0].server_chunks | map(.offset_micros)),
        server_chunk_lens: ($go[0].server_chunks | map(.len))
      },
      rust: {
        client_connect_elapsed_micros: $rust[0].client_connect_elapsed_micros,
        client_handshake_elapsed_micros: $rust[0].client_handshake_elapsed_micros,
        client_first_write_after_connect_micros: $rust[0].client_first_write_after_connect_micros,
        client_first_read_after_connect_micros: $rust[0].client_first_read_after_connect_micros,
        client_event_kinds: ($rust[0].client_event_trace | map(.kind)),
        server_first_read_delay_micros: $rust[0].server_first_read_delay_micros,
        server_first_read_to_end_micros: $rust[0].server_first_read_to_end_micros,
        server_trace_elapsed_micros: $rust[0].server_trace_elapsed_micros,
        server_end_reason: $rust[0].server_end_reason,
        server_chunk_offsets_micros: ($rust[0].server_chunks | map(.offset_micros)),
        server_chunk_lens: ($rust[0].server_chunks | map(.len))
      }
    },
    go: $go[0],
    rust: $rust[0]
  }'
