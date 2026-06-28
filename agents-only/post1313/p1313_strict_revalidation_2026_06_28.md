# P1313 Strict Revalidation - 2026-06-28

## Scope

Strict local revalidation was run across the P1313-01..12 post1313 package set. The audit
rechecked each package's documented acceptance commands, then forced selected ignored tests where
they looked relevant to package closure. No GitHub workflow automation was added or restored, and
no dual-kernel parity-count movement is claimed.

## Repairs Made During Revalidation

- Core admin `/explain` now reads the supervisor's current IR when a supervisor/runtime handle is
  available, so route previews reflect successful reloads instead of the startup-only engine.
- App reload integration tests now use a runtime-capable `run` binary path, current `tag`/selector
  config shape, explicit `SB_RUNTIME_DIFF=1` when asserting `changed`, readiness polling, and
  non-overlapping reload listen endpoints.
- Clash `/connections` WebSocket E2E now injects the same `ConnTracker` into the server that the
  test uses to register tracked connections. The two previously quarantined snapshot tests were
  unignored and pass.
- The legacy app-side core SOCKS5 direct UDP ignored-test message was updated to avoid implying a
  P1313-09 mainline gap. Current P1313-09 closure remains the app/adapter bridge plus Rust interop
  path, not the old core-inbound-only test path.

## Focused Revalidation Commands

- `cargo test -p sb-config --test compatibility_matrix`
- `cargo test -p sb-config --test schema_version_check`
- `cargo test -p sb-config gui1251`
- `cargo test -p sb-config --test gui1251_config`
- `cargo test -p sb-config --test dns_rule_parity`
- `cargo test -p sb-config --test route_options_parity`
- `cargo test -p sb-config dns`
- `cargo test -p sb-config route`
- `cargo test -p sb-config`
- `cargo test -p sb-core dns`
- `cargo test -p sb-core dns --features router,dns_udp,dns_doh,dns_dot,dns_doq,dns_doh3`
- `cargo test -p sb-core --test router_select_ctx_meta --features router`
- `cargo test -p sb-core router`
- `cargo test -p sb-core lifecycle`
- `cargo test -p sb-core --lib reload_atomicity`
- `cargo test -p sb-core --lib rollback`
- `cargo test -p sb-core --lib supervisor`
- `cargo test -p sb-core cache_file`
- `cargo test -p sb-core --test supervisor_reload_state`
- `cargo test -p sb-core --test adapter_surface_contract`
- `cargo test -p sb-core --test adapter_surface_contract --features router`
- `cargo test -p sb-core --test router_ruleset_integration test_remote_ruleset_cachefile_fallback_preserves_metadata`
- `cargo test -p sb-core adapter_services_expose_trait_object_contracts_without_downcast --features router`
- `cargo test -p sb-core udp --features router`
- `cargo test -p sb-core v2ray --features service_v2ray_api`
- `cargo test -p sb-core --features service_ssmapi ssmapi`
- `cargo test -p sb-core --features service_derp derp`
- `cargo test -p sb-core --features service_resolved dns_forwarder`
- `cargo test -p sb-core admin`
- `cargo test -p sb-api clash`
- `cargo test -p sb-api --test clash_http_e2e -- --nocapture`
- `cargo test -p sb-api --test clash_websocket_e2e -- --nocapture`
- `cargo test -p sb-api --test clash_websocket_e2e test_connections_ws_long_running_soak -- --ignored --nocapture`
- `cargo test -p sb-api --test connections_snapshot_test -- --nocapture`
- `cargo test -p sb-api v2ray`
- `cargo test -p sb-adapters --features adapter-shadowsocks,service_ssmapi shadowsocks`
- `cargo test -p sb-adapters resolved`
- `cargo test -p sb-adapters udp --features socks,e2e`
- `cargo test -p app --test gui_runtime_profile --features gui_runtime`
- `cargo test -p app clash --features "router clash_api" -- --nocapture`
- `cargo test -p app reload`
- `cargo test -p app --features gui_runtime --test reload_basic -- --ignored --nocapture`
- `cargo test -p app --features gui_runtime --test reload_rule_switch -- --ignored --nocapture`
- `cargo test -p app udp`
- `cargo test -p app --features parity --test ssmapi_service_regression_e2e`
- `cargo build -p app --bin app --features gui_runtime`
- `WORK=/tmp/p1313_12_gui1251 bash agents-only/post1313/p1313_12_gui1251_contract_probe.sh`
- `cargo run -p interop-lab -- case run p1_rust_core_udp_via_socks --kernel rust`
- `cargo run -p interop-lab -- case run p1_dataplane_large_payload_udp --kernel rust`
- `cargo run -p interop-lab -- case run p0_clash_api_contract_strict --kernel rust`
- `cargo run -p interop-lab -- case run p1_service_failure_isolation --kernel rust`

All focused commands above passed in this local revalidation.

## Common Gates

- `cargo check -p sb-config`
- `cargo check -p sb-types`
- `cargo check -p sb-core`
- `cargo check -p sb-core --features router`
- `cargo check -p sb-adapters`
- `cargo check -p app --features gui_runtime`
- `cargo check -p app --features parity`
- `cargo check --workspace --all-features`
- `cargo test -p sb-types`
- `cargo fmt --check`
- `git diff --check`
- `make boundaries`
- `./agents-only/06-scripts/verify-consistency.sh`

All common gates passed.

## Forced-Ignored Audit Notes

- `cargo test -p sb-api --test clash_websocket_e2e test_connections_ws_reflects_close_all_updates -- --ignored --nocapture`
  failed before repair; after the explicit tracker injection it is no longer ignored and passes in
  the default websocket suite.
- `cargo test -p sb-api --test clash_websocket_e2e test_connections_ws_memory_remains_bounded_over_time -- --ignored --nocapture`
  failed before repair; after the explicit tracker injection it is no longer ignored and passes in
  the default websocket suite.
- `cargo test -p app --test socks_udp_direct_e2e -- --ignored --nocapture` still exercises the
  legacy core-inbound-only path and timed out as expected for that path. It is not the P1313-09
  runtime acceptance path.
- `cargo test -p sb-adapters --features socks,e2e --test socks_udp_e2e_full -- --ignored --nocapture`
  and `cargo test -p sb-adapters --features socks,e2e --test socks_udp_e2e_balancer -- --ignored --nocapture`
  remain explicitly ignored unstable full-proxy/balancer tails; P1313-09 acceptance is carried by
  the non-ignored adapter UDP suite plus Rust interop cases.
