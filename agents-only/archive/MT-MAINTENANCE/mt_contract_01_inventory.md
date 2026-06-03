# MT-CONTRACT-01 Inventory: Transport-Wrapper + Detached-Session Contract Hardening

Status: **Completed**  
Date: 2026-04-04

## Scope

Protocol-contract and session-lifecycle quality work. Not parity completion.

## ShadowTLS Wrapper Contract

### Added Types
- `WrapperEndpoint` — captures configured server, port, SNI, version as a named struct
- `DetourStreamResult` — type alias for `Result<BoxedStream>`
- `wrapper_endpoint()` accessor on `ShadowTlsConnector`

### Documentation
- Module-level doc rewritten to document transport-wrapper contract invariants
- `connect_detour_stream` doc comment documenting wrapper-vs-requested endpoint semantics, stream ownership, post-handshake capabilities per version

### Tests Added
- `wrapper_endpoint_captures_configured_server` — pins typed endpoint extraction
- `bridge_stream_simultaneous_shutdown_does_not_panic` — pins mid-relay drop safety

### E2E Fix
- `start_shadowtls_v1_relay` — replaced `.unwrap()` on `copy_bidirectional` with `let _ =` to tolerate BrokenPipe/ConnectionReset when mock server closes early

## TUN TCP Detached/Draining Session Policy

### Added Types
- `SessionPhase` enum (`Active`, `Detached`) — first-class lifecycle state
- `DrainPolicy` struct with configurable `drain_timeout` (default 30s)
- `phase` and `detached_at` fields on `TcpSession`
- `Display` impl for `FourTuple`

### Added Methods
- `TcpSessionManager::with_drain_policy()` — constructor with custom drain policy
- `TcpSessionManager::detach_count()` — detached session count
- `TcpSessionManager::run_eviction_sweep()` — periodic cleanup of expired detached sessions

### Tests Added
- `test_drain_policy_eviction_sweep` — drain_timeout=0 → immediate eviction
- `test_drain_policy_does_not_evict_fresh_detached_sessions` — drain_timeout=60s → no eviction
- `packet_loop_simultaneous_close_both_fin_no_rst` — verifies clean close without RST

### Updated Tests
- All 4 inline `TcpSession` constructions updated with `phase`/`detached_at` fields
- `test_detach_moves_session_into_draining_registry` extended with phase/detached_at assertions

## Files Changed
- `crates/sb-adapters/src/outbound/shadowtls.rs`
- `crates/sb-adapters/tests/shadowtls_e2e.rs`
- `crates/sb-adapters/src/inbound/tun_session.rs`
- `crates/sb-adapters/src/inbound/tun_enhanced.rs`

## Verification
- clippy: 0 warnings
- sb-adapters --lib: 208 pass / 0 fail / 1 ignored
- shadowtls_e2e: 9/9 pass (in isolation; pre-existing serial-group flakiness)
