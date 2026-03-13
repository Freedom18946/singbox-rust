# AGENTS

## Current Goal

- Primary objective: increase `Both-Covered` in `labs/interop-lab/docs/dual_kernel_golden_spec.md`.
- Do not treat Rust-only tests, repo-level unit tests, or workflow automation as dual-kernel parity completion.
- Prefer promoting existing strict Rust replay cases to `kernel_mode: both` over adding new Rust-only tests.

## Latest Dual-Kernel Status

- `dual_kernel_golden_spec.md` is the source of truth for parity coverage.
- Current verified total after the 2026-03-13 fakeip flush promotion: `39 / 60` behaviors are `Both-Covered` (`65.0%`).
- Newly promoted and verified strict both-cases:
  - `p0_clash_api_contract_strict`
  - `p1_gui_proxy_switch_replay`
  - `p1_gui_full_boot_replay`
  - `p1_gui_proxy_delay_replay`
  - `p1_gui_full_session_replay`
  - `p1_gui_connections_tracking`
  - `p1_lifecycle_restart_reload_replay`
  - `p1_rust_core_tcp_via_socks`
  - `p1_rust_core_http_via_socks`
  - `p1_http_connect_via_http_proxy`
  - `p1_selector_switch_traffic_replay`
  - `p1_rust_core_dns_via_socks`
  - `p1_rust_core_udp_via_socks`
  - `p1_block_outbound_via_socks`
  - `p1_version_endpoint_contract`
  - `p1_dns_query_endpoint_contract`
  - `p1_fakeip_dns_query_contract`
  - `p1_fakeip_cache_flush_contract`
  - `p1_ip_cidr_rule_via_socks`
  - `p2_dataplane_chain_proxy`
- Verified artifacts:
  - `labs/interop-lab/artifacts/p0_clash_api_contract_strict/20260312T003634Z-c20d5d82-232b-4f38-a377-9f358218d952/`
  - `labs/interop-lab/artifacts/p1_gui_proxy_switch_replay/20260312T003648Z-0230db00-789d-47c9-8f06-2468ec4e73c8/`
  - `labs/interop-lab/artifacts/p1_gui_full_boot_replay/20260312T004337Z-f4baafd7-f983-422f-9a9e-798c89b4fc5e/`
  - `labs/interop-lab/artifacts/p1_gui_proxy_delay_replay/20260312T004501Z-0c1cf3f9-f9a7-4be0-adee-7dc5985eff43/`
  - `labs/interop-lab/artifacts/p1_gui_full_session_replay/20260312T004725Z-4cd0253f-abc6-4333-b03b-0c09d27ccc74/`
  - `labs/interop-lab/artifacts/p1_gui_connections_tracking/20260313T191327Z-6e7f6667-5d4c-472a-9103-7884533a6d99/`
  - `labs/interop-lab/artifacts/p1_lifecycle_restart_reload_replay/20260313T193018Z-fc0dc13a-181c-4994-bb50-cc300f844c4f/`
  - `labs/interop-lab/artifacts/p1_rust_core_tcp_via_socks/20260312T010257Z-eba5d5e6-2d78-4374-9c0a-22f80800618b/`
  - `labs/interop-lab/artifacts/p1_rust_core_http_via_socks/20260312T010406Z-0ceb556d-2423-4543-aaed-3ddb8fed5055/`
  - `labs/interop-lab/artifacts/p1_http_connect_via_http_proxy/20260312T014530Z-11ecd234-c9a5-4758-966f-075d3624a3b4/`
  - `labs/interop-lab/artifacts/p1_selector_switch_traffic_replay/20260312T014809Z-4bcd0151-7b5b-43f0-b34e-28cf61aa0581/`
  - `labs/interop-lab/artifacts/p1_rust_core_dns_via_socks/20260312T010657Z-905f8c8b-607e-4237-831e-b6a932a67655/`
  - `labs/interop-lab/artifacts/p1_rust_core_udp_via_socks/20260312T010947Z-a98b12fd-6e72-4562-b34e-ed3e601ee8ad/`
  - `labs/interop-lab/artifacts/p1_block_outbound_via_socks/20260312T013351Z-aa75223e-0c05-424b-9d2a-3836982b642a/`
  - `labs/interop-lab/artifacts/p1_version_endpoint_contract/20260312T032518Z-036e6de0-2003-487a-b4e8-586c710f58a6/`
  - `labs/interop-lab/artifacts/p1_dns_query_endpoint_contract/20260312T023203Z-00d62392-1d30-47a1-97e9-a8a8ec6a9c04/`
  - `labs/interop-lab/artifacts/p1_fakeip_dns_query_contract/20260313T195112Z-f594fae4-8589-4b12-a34b-76676b75ea10/`
  - `labs/interop-lab/artifacts/p1_fakeip_cache_flush_contract/20260313T202530Z-8ba22eab-8f1e-4796-a9b9-8743c1fb365f/`
  - `labs/interop-lab/artifacts/p1_ip_cidr_rule_via_socks/20260312T023915Z-167aabe7-4afe-42a8-8955-7256bf8b1bf3/`
  - `labs/interop-lab/artifacts/p2_dataplane_chain_proxy/20260312T013053Z-06c897d5-3377-4a56-8f40-0d229fae81ba/`

## Known Strict Both-Mode Oracle Rules

- `p0_clash_api_contract_strict` currently needs documented oracle ignores for:
  - `/configs`
  - `/proxies`
  - `/connections`
  - `/proxies/direct/delay*`
- These ignores are tracked in `dual_kernel_golden_spec.md` as:
  - `DIV-M-006`
  - `DIV-M-007`
  - `DIV-M-008`
  - `DIV-M-009`

## Next Priority Order

1. `p1_service_failure_isolation` after converting it to a real broken-service dual-core model
2. `p1_gui_ws_reconnect_behavior`
3. `p1_urltest_auto_select_replay` only after Rust URLTest auto-selection semantics match Go

## Execution Rules

- For each promoted both-case:
  - ensure case YAML has real `bootstrap.go`
  - ensure required Go config exists
  - add only minimal oracle ignores/tolerances needed for stable parity
  - run the case in both mode
  - run `case diff`
  - update:
    - `labs/interop-lab/docs/dual_kernel_golden_spec.md`
    - `labs/interop-lab/docs/compat_matrix.md`
    - `labs/interop-lab/docs/case_backlog.md` when needed
- Prefer fixing product/config gaps only when they block a target both-case from passing.
- Do not revert unrelated workspace changes.

## Useful Commands

```bash
cargo build -p app --features acceptance,clash_api --bin app

cargo run -p interop-lab -- case run p0_clash_api_contract_strict --kernel both --env-class strict
cargo run -p interop-lab -- case diff p0_clash_api_contract_strict

cargo run -p interop-lab -- case run p1_gui_proxy_switch_replay --kernel both --env-class strict
cargo run -p interop-lab -- case diff p1_gui_proxy_switch_replay

cargo run -p interop-lab -- case run p2_dataplane_chain_proxy --kernel both --env-class strict
cargo run -p interop-lab -- case diff p2_dataplane_chain_proxy
```
