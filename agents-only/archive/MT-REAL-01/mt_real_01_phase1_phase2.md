# MT-REAL-01 Phase 1-2

Date: 2026-04-14

Scope:
- Phase 1: Rust kernel build + smoke on isolated Clash API port `127.0.0.1:19090`
- Phase 2: `interop-lab` strict + `kernel_mode: both` subset, under REALWORLD mode-A intent

Important:
- This is not parity completion.
- Go desktop baseline was not externally present on `127.0.0.1:9090` at session start.
- Several `strict` case assets were self-managed rather than pure passive mode-A reuse; this was tracked as harness context, not Rust parity evidence.

## Phase 1

Command:

```bash
cargo build -p app --features acceptance,clash_api --bin app
./target/debug/app \
  -c agents-only/mt_real_01_evidence/phase1_rust_core_clash_api_19090.json \
  run --admin-listen 127.0.0.1:19190
```

Result:
- PASS: `GET /version`
- PASS: `GET /configs`
- PASS: `GET /proxies`
- PASS: WS upgrade `101 Switching Protocols` on `/traffic`
- PASS: WS upgrade `101 Switching Protocols` on `/connections`
- PASS: WS upgrade `101 Switching Protocols` on `/logs`
- PASS: WS upgrade `101 Switching Protocols` on `/memory`
- PASS: port reclaim after SIGTERM (`19090` / `19190` released)

Evidence:
- `agents-only/mt_real_01_evidence/phase1_build.log`
- `agents-only/mt_real_01_evidence/phase1_rust_kernel.log`
- `agents-only/mt_real_01_evidence/phase1_http_*.headers`
- `agents-only/mt_real_01_evidence/phase1_http_*.body`
- `agents-only/mt_real_01_evidence/phase1_ws_*.headers`
- `agents-only/mt_real_01_evidence/phase1_ports_after_kill.txt`

## Phase 2

Requested target:
- strict dual-kernel regression, but only for `kernel_mode: both`

Initial blockers found:
- `p1_sniff_rule_action_tls` referenced `payload_tls_client_hello` without harness support.
- The same case used Rust `ready_path: /healthz` against Clash API base `:19290`; corrected to `/version`.
- `cargo build -p app --features acceptance,clash_api --bin app` was sufficient for Phase 1 control-plane smoke, but not for strict dual-kernel dataplane cases because adapter/protocol builders were not compiled into `target/debug/app`.

Follow-up build used for valid Phase 2 rerun:

```bash
cargo build -p app --features acceptance,parity --bin app
```

Effective matrix:
- Total `strict && kernel_mode: both`: 37
- PASS: 30
- FAIL: 7

Effective matrix file:
- `agents-only/mt_real_01_evidence/phase2_both_matrix_effective.tsv`

PASS cases:
- `l6_local_harness_smoke`
- `p0_clash_api_contract_strict`
- `p1_block_outbound_via_socks`
- `p1_clash_api_auth_enforcement`
- `p1_dns_cache_ttl_via_socks`
- `p1_dns_query_endpoint_contract`
- `p1_domain_rule_via_socks`
- `p1_fakeip_dns_query_contract`
- `p1_graceful_shutdown_drain`
- `p1_gui_full_boot_replay`
- `p1_gui_proxy_delay_replay`
- `p1_gui_proxy_switch_replay`
- `p1_gui_ws_reconnect_behavior`
- `p1_http_connect_via_http_proxy`
- `p1_inbound_hot_reload_sighup`
- `p1_ip_cidr_rule_via_socks`
- `p1_lifecycle_restart_reload_replay`
- `p1_mixed_inbound_dual_protocol`
- `p1_rust_core_dns_via_socks`
- `p1_rust_core_http_via_socks`
- `p1_rust_core_tcp_via_socks`
- `p1_rust_core_udp_via_socks`
- `p1_selector_switch_traffic_replay`
- `p1_sniff_rule_action_tls`
- `p1_urltest_auto_select_replay`
- `p1_version_endpoint_contract`
- `p2_dataplane_chain_proxy`
- `p2_shadowsocks_dual_dataplane_local`
- `p2_shadowtls_dual_dataplane_local`
- `p2_trojan_dual_dataplane_local`

FAIL cases and current attribution:
- `p1_fakeip_cache_flush_contract`
  - Go-side assertion mismatch on seeded FakeIP sequence (`198.18.0.5` expected vs `198.18.0.3` actual)
  - Not a Rust-only failure
- `p1_gui_connections_tracking`
  - Rust-side connection snapshot assertions fail on count / rule / chains / totals
  - Consistent with existing `/connections` aggregate cosmetic divergence area
- `p1_gui_full_session_replay`
  - Rust-side `connections.downloadTotal > 0` assertion fails
  - Same family as top-level `/connections` total divergence
- `p1_gui_group_delay_replay`
  - Go-side `GET /proxies/<group>/delay` returns `404`
  - Not a Rust-only failure
- `p2_connections_ws_soak_dual_core`
  - Both Rust and Go trip `memory.leak_detected=true`
  - Not a Rust-only differential finding
- `p2_vless_dual_dataplane_local`
  - Both Rust and Go fail `traffic.vless_tcp_ok.success`
  - Rust stderr shows outbound dial reset / registry fallback warning
- `p2_vmess_dual_dataplane_local`
  - Both Rust and Go fail `traffic.vmess_tcp_ok.success`
  - Rust stderr shows outbound dial EOF / registry fallback warning

Notable environment/harness notes:
- `p2_*_dual_dataplane_local` Go launch depended on `${INTEROP_GO_BINARY}`; after setting it to `go_fork_source/sing-box-1.12.14/sing-box`, `shadowsocks` / `shadowtls` / `trojan` local dual cases passed.
- The broad `cargo run -p interop-lab -- case run --env-class strict` command includes Rust-only strict cases and can get dragged by protocol-unit cases; the effective MT-REAL-01 Phase 2 matrix was therefore produced from the explicit `strict && both` subset.

Evidence:
- `agents-only/mt_real_01_evidence/phase2_both_cases_after_parity.log`
- `agents-only/mt_real_01_evidence/phase2_both_matrix_after_parity.tsv`
- `agents-only/mt_real_01_evidence/phase2_protocol_locals_with_go_bin.log`
- `agents-only/mt_real_01_evidence/phase2_protocol_locals_with_go_bin.tsv`
- `agents-only/mt_real_01_evidence/phase2_both_matrix_effective.tsv`

## Next gate

Phase 3 requires real upstream node information from the user:
- at least one Shadowsocks node
- at least one Trojan node
- at least one VMess node

Phase 4 requires manual GUI operation against `127.0.0.1:19090`.
