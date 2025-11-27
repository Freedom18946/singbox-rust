# Acceptance QC Report — 2025-11-24 14:10:56 +08:00

## Scope & Method
- Covers features already marked complete in `GO_PARITY_MATRIX.md` / `NEXT_STEPS.md`.
- 3-layer verification: source implementation, automated tests, and config/runtime behavior as exercised by integration tests.
- Test commands (all passed, warnings only):  
  - `cargo test -p app --features acceptance,service_derp,adapter-wireguard-endpoint --test direct_inbound_test --test naive_inbound_test --test tuic_inbound_test --test hysteria_inbound_test --test direct_block_outbound_test --test hysteria_outbound_test --test anytls_outbound_test --test tor_outbound_test --test selector_urltest_adapter_contract --test selector_urltest_runtime --test wireguard_endpoint_test -- --nocapture`  
  - `cargo test -p app --features acceptance,service_derp,adapter-wireguard-endpoint --test derp_service_bridge_test -- --nocapture`

## Results (per feature group)
- **Direct inbound** — ✅ `crates/sb-adapters/src/inbound/direct.rs`; tests `app/tests/direct_inbound_test.rs` verify override_host/override_port and tcp/udp/tcp+udp network modes via config IR; adapter instantiation paths validated.
- **Naive inbound** — ⚠️ Registration/IR covered (`app/tests/naive_inbound_test.rs`), runtime path gated by feature in this run; enable `adapter-naive` for live CONNECT/TLS exercise.
- **TUIC inbound** — ✅ `crates/sb-adapters/src/inbound/tuic.rs`; `app/tests/tuic_inbound_test.rs` covers `users_tuic` auth + congestion control IR mapping.
- **Hysteria v1 inbound** — ✅ `crates/sb-adapters/src/inbound/hysteria.rs`; `app/tests/hysteria_inbound_test.rs` covers multi-user, protocol variants, serde.
- **Direct & Block outbound** — ✅ `crates/sb-adapters/src/register.rs`; `app/tests/direct_block_outbound_test.rs` updated to new `AdapterOutboundContext` signature; validates builder wiring, UDP factory expectations, connect/error behavior.
- **AnyTLS outbound** — ✅ `crates/sb-adapters/src/outbound/anytls.rs`; `app/tests/anytls_outbound_test.rs` covers required `password`, padding, TLS SNI/ALPN, custom CA, skip verify, and missing-field failures.
- **Tor outbound** — ✅ `crates/sb-adapters/src/register.rs`; `app/tests/tor_outbound_test.rs` covers default/custom proxy address and Debug format.
- **Hysteria v1 outbound** — ✅ `crates/sb-core/src/outbound/hysteria/v1.rs`; `app/tests/hysteria_outbound_test.rs` covers auth/obfs/QUIC windows/ALPN-SNI combinations.
- **Selector / URLTest (adapter + runtime)** — ✅ `crates/sb-adapters/src/outbound/{selector,urltest}.rs` + `crates/sb-core/src/outbound/selector_group.rs`; contract tests (`app/tests/selector_urltest_adapter_contract.rs`) and runtime tests (`app/tests/selector_urltest_runtime.rs`) validate health checks, failover, tolerance, manual switching, and metrics emission.
- **WireGuard endpoint** — ✅ Feature `adapter-wireguard-endpoint`; `crates/sb-adapters/src/endpoint/wireguard.rs`; `app/tests/wireguard_endpoint_test.rs` exercises IR serialization + registration + instantiation; stub fallback covered when feature is off.
- **DERP service** — ⚠️ `crates/sb-core/src/services/derp/*`; `app/tests/derp_service_bridge_test.rs` executed (bridge mock skipped port bind under sandbox with graceful skip). Core lifecycle start/stop paths compile; rerun on non-sandboxed host to exercise TCP relay fully.

## Notable runtime/config observations
- Adapter builders now require `AdapterOutboundContext` (selector/urltest/direct/block/anytls/tor updated in tests); config-driven IR → Param wiring validated.
- Selector/URLTest health-check tolerances/failover validated against real timers; metrics counter `selector_health_check_total` observed in Prometheus export.
- WireGuard endpoint tests confirm IR fields (`wireguard_address`, `peers`, `mtu`, `listen_port`) serialize/deserialize correctly and registry wiring succeeds with/without feature gate.
- AnyTLS outbound tests exercised padding matrix, TLS options, and missing-field validation; registries now fail fast when `server`/`password` absent.

## Follow-ups / Risks
- Naive inbound runtime path still needs feature-enabled e2e (HTTP/2 CONNECT + TLS) to close Layer-3 gap.
- DERP bridge test skipped socket bind under sandbox; rerun on host with permitted ephemeral bind to validate bidirectional relay.
- Warnings observed (`unexpected cfg: v2ray_transport`, unused imports/vars) do not block functionality but should be cleaned to keep `-Dwarnings` runs green.
