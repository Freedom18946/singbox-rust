#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

run_probe() {
  local kind="$1"
  local server_json="${TMP_DIR}/${kind}_server.json"
  local client_json="${TMP_DIR}/${kind}_client.json"
  local port_file="${TMP_DIR}/${kind}_port.txt"

  python3 "${ROOT}/scripts/tools/reality_socket_server_probe.py" --output "${server_json}" >"${port_file}" &
  local server_pid=$!

  while [[ ! -s "${port_file}" ]]; do
    sleep 0.01
  done
  local port
  port="$(tr -d '\n' < "${port_file}")"
  local trace_addr="127.0.0.1:${port}"

  if [[ "${kind}" == "go" ]]; then
    SB_REALITY_TRACE_ADDR="${trace_addr}" \
      bash "${ROOT}/scripts/tools/reality_go_utls_remote_socket_trace.sh" > "${client_json}"
  else
    (
      cd "${ROOT}"
      SB_REALITY_TRACE_ADDR="${trace_addr}" \
        cargo run -q -p sb-tls --example reality_clienthello_remote_socket_trace > "${client_json}"
    )
  fi

  wait "${server_pid}"
}

run_probe go
run_probe rust

jq -n \
  --slurpfile go_server "${TMP_DIR}/go_server.json" \
  --slurpfile go_client "${TMP_DIR}/go_client.json" \
  --slurpfile rust_server "${TMP_DIR}/rust_server.json" \
  --slurpfile rust_client "${TMP_DIR}/rust_client.json" \
  '{
    summary: {
      go: {
        client_first_write_after_connect_micros: $go_client[0].client_first_write_after_connect_micros,
        client_first_read_after_connect_micros: $go_client[0].client_first_read_after_connect_micros,
        client_event_kinds: ($go_client[0].client_event_trace | map(.kind)),
        server_first_read_delay_micros: $go_server[0].server_first_read_delay_micros,
        server_chunk_lens: ($go_server[0].server_chunks | map(.len))
      },
      rust: {
        client_first_write_after_connect_micros: $rust_client[0].client_first_write_after_connect_micros,
        client_first_read_after_connect_micros: $rust_client[0].client_first_read_after_connect_micros,
        client_event_kinds: ($rust_client[0].client_event_trace | map(.kind)),
        server_first_read_delay_micros: $rust_server[0].server_first_read_delay_micros,
        server_chunk_lens: ($rust_server[0].server_chunks | map(.len))
      }
    },
    go: {
      client: $go_client[0],
      server: $go_server[0]
    },
    rust: {
      client: $rust_client[0],
      server: $rust_server[0]
    }
  }'
