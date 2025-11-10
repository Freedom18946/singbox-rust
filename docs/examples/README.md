Examples — Transport Chain Plans

This directory contains minimal example configs to demonstrate how transport chains are derived from config hints. Use the `transport-plan` CLI to print the derived chain for each outbound.

Usage
- Build and run (workspace root):
  - `cargo run -p app --features router --bin transport-plan -- --config docs/examples/vmess_ws_tls.yaml`
  - Repeat for other example files.

Files
- `vmess_ws_tls.yaml`: VMess over TLS+WebSocket (chain: tls,ws)
- `vless_httpupgrade_tls.yaml`: VLESS over TLS+HTTPUpgrade (chain: tls,httpupgrade)
- `trojan_grpc_tls.yaml`: Trojan over TLS+gRPC (chain: tls,grpc)

Notes
- These examples are for transport planning only; they are not intended for e2e connectivity. Secrets/servers are placeholders.
- The plan can also be printed at runtime by setting `SB_TRANSPORT_PLAN=1` or passing `--print-transport` to `app run`.

