# MT-CONTRACT-02 Inventory: Transport/Session Contract Convergence

**Status**: Complete (2026-04-04)
**Nature**: Maintenance / protocol-quality work (not parity completion)
**Baseline**: `MT-CONTRACT-01` completed artifacts

---

## ShadowTLS Typed Transport-Wrapper Contract

### New Types (shadowtls.rs)

| Type | Purpose |
|------|---------|
| `StreamCapability` | Typed enum: what the post-handshake stream provides (BareTcp / TlsRecordFramed / AuthenticatedTlsRecordFramed) |
| `WrapperContract` | Struct combining `WrapperEndpoint` + `StreamCapability` |

### New Methods

| Method | On | Purpose |
|--------|----|---------|
| `StreamCapability::from_version(u8)` | `StreamCapability` | Maps version → capability |
| `wrapper_contract()` | `ShadowTlsConnector` | Returns `Option<WrapperContract>` |

### Updated Docs

| File | What |
|------|------|
| `shadowtls.rs` | `connect_detour_stream` doc now references `StreamCapability` |
| `register.rs` | `ShadowTlsDetourBridge` doc clarifies typed wrapper-endpoint delegation |

### New Tests (shadowtls.rs)

- `wrapper_contract_v1_returns_bare_tcp_capability`
- `wrapper_contract_v2_returns_tls_record_framed`
- `wrapper_contract_v3_returns_authenticated_framed`
- `wrapper_contract_unsupported_version_returns_none`

---

## TUN TCP Detached/Draining Session Policy

### New Types (tun_session.rs)

| Type | Purpose |
|------|---------|
| `CleanupMode` | Typed enum: why a session terminates (ClientRst / ClientFin / ServerEof / DrainTimeout / OwnerDrop) |

### New/Updated Methods

| Method | On | Purpose |
|--------|----|---------|
| `remove_with_reason(tuple, reason)` | `TcpSessionManager` | Removes session with typed `CleanupMode` |
| `drain_policy()` | `TcpSessionManager` | Returns `&DrainPolicy` for introspection |

### Extended Types

| Type | Field Added | Default |
|------|------------|---------|
| `DrainPolicy` | `simultaneous_close_grace: Duration` | 5 seconds |

### Integration Points

| File | Change |
|------|--------|
| `tun_enhanced.rs` | RST branches use `remove_with_reason(ClientRst)` |
| `tun_session.rs` | `run_eviction_sweep()` logs `CleanupMode::DrainTimeout` |

### New Tests (tun_session.rs)

- `test_cleanup_mode_display`
- `test_drain_policy_accessors`
- `test_remove_with_reason_propagates_cleanup_mode`
- `test_simultaneous_close_grace_prevents_premature_eviction`

---

## Future Boundaries (Not In Scope)

- `CleanupMode::ClientFin` / `ServerEof` integration into relay task cleanup (requires async task refactor)
- `simultaneous_close_grace` enforcement logic in eviction sweep (requires timer coordination)
- Consumer metadata for detour chains
- `RuntimePlan` / `PlannedConfigIR` — explicitly paused
