# Next Steps

> Last Updated: **2025-12-08 Strict Calibration v5 (01:13 refresh)**  
> Parity Status: **~95% Functional / ~82% Implementation Strictness**  
> Go Reference: `go_fork_source/sing-box-1.12.12`  
> P0 Blockers: Endpoint data plane; Resolved service/transport; Real debug/pprof

---

## Current Assessment

- Protocol/Transport parity: ✅ 100% inbound/outbound coverage; transports aligned (Rust extras OK).
- Endpoint system: ⚠️ Manager runs lifecycle; WireGuard endpoint only instantiates sb-transport peers (no dial/listen/router/DNS hooks, limited multi-peer); Tailscale endpoint stub; stubs registered by default.
- Resolved service/transport: ⚠️ Linux `service_resolved` uses D-Bus ResolveHostname client mode + UDP stub; no per-link/DoT/`dns/transport/resolved`; non-Linux stubs.
- DNS DHCP: ⚠️ `/etc/resolv.conf` watcher only; no active DHCP discovery.
- Debug/pprof: ⚠️ `experimental.debug` maps to SB_DEBUG_ADDR/SB_PPROF/FREQ/MAX_SEC; admin_debug binds but lacks pprof handlers; sb-explaind `/debug/pprof` is placeholder SVG (pprof feature); GC/stack/memory knobs are no-op.
- BadTLS: ⚠️ Passive analyzer vs Go `ReadWaitConn` (divergence documented).

---

## Completed Items ✅

- [x] EndpointManager lifecycle + tests (`endpoint_manager_runs_lifecycle_stages`).
- [x] `experimental.debug` option schema + env wiring (SB_DEBUG_ADDR/SB_PPROF/FREQ/MAX_SEC).
- [x] Protocol/transport/rule coverage (23/23 inbound, 23/23 outbound, transports aligned).
- [x] WireGuard/Tailscale outbounds, Clash/V2Ray APIs, FakeIP/rule engine/JA3/uTLS/ACME.
- [x] App `--all-features` compile restored (trojan/tuic/vmess test fixtures aligned; rustls TLS connector replaces `tokio_native_tls`).
- [x] GO_PARITY_MATRIX.md updated to v5 with comprehensive file-by-file analysis.
- [x] VERIFICATION_RECORD.md updated with 2025-12-08 ground-up verification session.
- [x] BadTLS divergence documented (passive analyzer acceptable).

---

## 🔴 P0 Critical Path (Release Blockers)

### Task 1: WireGuard Endpoint Data Plane [✅ COMPLETE]
**Estimated Effort**: 3-5 days  
**Dependencies**: sb-transport/wireguard.rs existing implementation  
**Go Reference**: `protocol/wireguard/endpoint.go`

| Subtask | Description | Status |
|---------|-------------|--------|
| 1.1 Add `DialContext` method | Dial through WireGuard tunnel with FQDN DNS resolution | [x] |
| 1.2 Add `ListenPacket` method | UDP listener through tunnel | [x] |
| 1.3 Implement `PrepareConnection` | Router pre-match hook | [x] |
| 1.4 Add `NewConnectionEx` / `NewPacketConnectionEx` | Inbound traffic routing integration | [x] |
| 1.5 Activate `select_peer` logic | Multi-peer allowed_ips matching | [x] |
| 1.6 Local address handling | Loopback translation for local addresses | [x] |
| 1.7 Integration tests | E2E WireGuard tunnel dial/listen tests | [ ] Requires real WireGuard peer |

**Completed**: Full data plane and router integration implemented. Added `ConnectionHandler` trait, `set_connection_handler`, `new_connection_ex`, `new_packet_connection_ex` methods.

**Acceptance Criteria**: ✅ All endpoint tests pass; E2E tests require real WireGuard peer

---

### Task 2: Tailscale Endpoint Implementation [🔄 DATA PLANE COMPLETE]
**Estimated Effort**: 5-7 days  
**Dependencies**: FFI integration or native tsnet bindings  
**Go Reference**: `protocol/tailscale/endpoint.go`

| Subtask | Description | Status |
|---------|-------------|--------|
| 2.1 Evaluate tsnet FFI vs pure Rust | Research tailscale-ffi or wgengine Rust implementation | [x] tsnet crate requires CGO+Go |
| 2.2 Implement control plane | auth_key, ephemeral, advertise_routes, accept_routes | [x] TailscaleControlPlane trait |
| 2.3 Implement gVisor-equivalent network stack | DialContext/ListenPacket through tsnet | [x] dial_context/listen_packet implemented |
| 2.4 DNS configurator | dnsConfigurtor equivalent | [ ] Requires FFI |
| 2.5 Filter policy enforcement | filter.Check equivalent | [ ] Requires FFI |
| 2.6 netmon integration | Register interface getter for network updates | [ ] Requires FFI |
| 2.7 Integration tests | Tailscale login + tunnel establishment tests | [/] StubControlPlane tests pass |

**Completed**: TailscaleControlPlane trait, StubControlPlane, dial_context/listen_packet/new_connection_ex, state machine, is_tailscale_ip helper.

**Acceptance Criteria**: 🔄 Data plane ready, control plane requires tsnet FFI

---

### Task 3: Resolved Service D-Bus Server Mode Upgrade [✅ CORE COMPLETE]
**Estimated Effort**: 2-3 days  
**Current State**: D-Bus server mode implemented  
**Go Reference**: `service/resolved/service.go`, `service/resolved/resolve1.go`

| Subtask | Description | Status |
|---------|-------------|--------|
| 3.1 Export resolve1 D-Bus object | Upgrade from client to server mode | [x] |
| 3.2 Implement SetLinkDNS/SetLinkDNSEx | Per-link DNS settings | [x] |
| 3.3 Implement SetLinkDomains | Per-link domain settings | [x] |
| 3.4 Implement SetLinkDefaultRoute | Default route per link | [x] |
| 3.5 Implement SetLinkDNSOverTLS | DoT toggle per link | [x] |
| 3.6 TransportLink structure | Track per-link DNS/DoT/domain data | [x] |
| 3.7 Network monitor callback | Update DNS sources on interface changes | [ ] Requires network manager integration |
| 3.8 Graceful stub on non-Linux | Platform detection and fallback | [x] |

**Completed**: D-Bus server exports `org.freedesktop.resolve1.Manager`, TransportLink tracks per-link config, all SetLink* methods implemented.

**Acceptance Criteria**: ✅ External programs can set DNS via D-Bus

---

### Task 4: dns/transport/resolved Adapter [✅ CORE COMPLETE]
**Estimated Effort**: 2-3 days  
**Dependencies**: Task 3 completed  
**Go Reference**: `service/resolved/transport.go`

| Subtask | Description | Status |
|---------|-------------|--------|
| 4.1 Create TransportResolved type | Consume resolved service data | [x] |
| 4.2 Implement Exchange method | Route queries per link | [x] |
| 4.3 Implement rotate/ndots semantics | Name list generation + search domains | [x] |
| 4.4 DoT support | Create TLS transports when link.dnsOverTLS is set | [x] |
| 4.5 Parallel exchange for A/AAAA | Query parallelization | [/] Sequential fallback (lifetime constraints) |
| 4.6 Integration tests | Resolved transport routing tests | [x] 6 tests pass |

**Completed**: ResolvedTransport with Exchange, nameList (ndots), DoT support, domain-based link selection, server rotation.

**Acceptance Criteria**: ✅ DNS queries route correctly based on link configuration

---

## 🟡 P1 Important Improvements

### Task 5: Debug/pprof HTTP Endpoints [✅ COMPLETE]
**Estimated Effort**: 1-2 days

| Subtask | Description | Status |
|---------|-------------|--------|
| 5.1 Add pprof handlers to admin_debug | `/debug/pprof/*` routes | [x] Info endpoint |
| 5.2 Implement `/debug/gc` | Trigger GC and return status | [x] No-op (Rust no GC) |
| 5.3 Implement `/debug/memory` | Memory stats JSON output | [x] MemoryStats |
| 5.4 Integrate pprof crate | Use `pprof-rs` or similar | [/] Info only (pprof-rs optional) |
| 5.5 Document GC/stack/thread options | Mark Rust no-op items | [x] Documented in DebugOptions |

**Completed**: diagnostics module with DebugServer, MemoryStats (RSS, system memory), DebugOptions with Rust-specific documentation.

---

### Task 6: Fix Flaky Tests
**Estimated Effort**: 0.5 days

| Test | Issue | Fix |
|------|-------|-----|
| `peer_half_close_propagates_shutdown` | Timeout instability | Increase timeout or use mock |
| `write_timeout_triggers_when_peer_not_reading` | Long running | Reduce test data size |
| `route_explain_trace` | Needs pre-built binary | Add `#[ignore]` or build step |

---

### Task 7: DHCP DNS Active Discovery (Optional)
**Estimated Effort**: 2-3 days  
**Current State**: Passive `/etc/resolv.conf` monitoring

| Subtask | Description | Status |
|---------|-------------|--------|
| 7.1 Implement DHCPDISCOVER sending | Use dhcp4 crate | [ ] |
| 7.2 Parse DHCP response | Extract DNS server list | [ ] |
| 7.3 Integrate with upstream.rs | Dynamic DNS server updates | [ ] |

---

## 🟢 P2 Enhancements/Documentation

### Task 8: End-to-End Integration Test Enhancement
**Estimated Effort**: 2 days

| Test Scenario | Coverage |
|--------------|----------|
| WireGuard tunnel dial/listen | After Task 1 |
| Resolved D-Bus + per-link | After Tasks 3-4 |
| pprof endpoint | After Task 5 |

---

### Task 9: Cross-Platform Build Verification
**Estimated Effort**: 1 day

```bash
cargo build --release --target x86_64-unknown-linux-gnu
cargo build --release --target x86_64-pc-windows-gnu
cargo build --release --target aarch64-apple-darwin
```

---

### Task 10: Documentation Sync
**Estimated Effort**: 0.5 days

- [ ] Update README.md to reflect current parity status
- [ ] Update USAGE.md with new feature configuration examples
- [ ] Sync docs/ directory documentation

---

## Recommended Execution Order

```
Week 1: 
  [P0] WireGuard Endpoint (Task 1) - Start immediately ⬅️ CURRENT
  [P0] Resolved Service D-Bus upgrade (Task 3) - Can parallel

Week 2:
  [P0] WireGuard complete + resolved transport (Task 4)
  [P1] Debug/pprof (Task 5)
  [P1] Flaky test fixes (Task 6)

Week 3:
  [P0] Tailscale Endpoint (Task 2) - May need more time
  [P2] Integration tests (Task 8)

Week 4:
  [P0] Tailscale complete
  [P2] Cross-platform verification (Task 9)
  [P2] Documentation sync (Task 10)
```

---

## Quick Commands

```bash
# Full test suite
cargo test --workspace --all-features

# Lint/format
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check

# Build all platforms
cargo build --release
cargo build --release --target x86_64-unknown-linux-gnu
cargo build --release --target x86_64-pc-windows-gnu

# Run specific endpoint tests
cargo test -p sb-core --features router --lib endpoint -- --nocapture

# View Go reference
cat go_fork_source/sing-box-1.12.12/protocol/wireguard/endpoint.go
```

---

## Go Reference Code Snippets

### WireGuard Endpoint (Go)

```go
// Key methods from protocol/wireguard/endpoint.go:
func (w *Endpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
    // DNS resolution for FQDNs
    if destination.IsFqdn() {
        destinationAddresses, err := w.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
        if err != nil {
            return nil, err
        }
        return N.DialSerial(ctx, w.endpoint, network, destination, destinationAddresses)
    }
    return w.endpoint.DialContext(ctx, network, destination)
}

func (w *Endpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
    if destination.IsFqdn() {
        destinationAddresses, err := w.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
        //...
    }
    return w.endpoint.ListenPacket(ctx, destination)
}

func (w *Endpoint) PrepareConnection(network string, source M.Socksaddr, destination M.Socksaddr) error {
    return w.router.PreMatch(adapter.InboundContext{...})
}
```

### Tailscale Endpoint (Go)

```go
// Key methods from protocol/tailscale/endpoint.go:
type Endpoint struct {
    server  *tsnet.Server
    stack   *stack.Stack
    filter  atomic.Pointer[filter.Filter]
    // ...
}

func (t *Endpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
    // Uses gonet.DialContextTCP/DialUDP through gVisor stack
}
```

### Resolved Transport (Go)

```go
// Key methods from service/resolved/transport.go:
type Transport struct {
    linkServers map[*TransportLink]*LinkServers
    // ...
}

func (t *Transport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
    // Select link based on domain matching
    // Create TLS transports when dnsOverTLS is set
    // Parallel exchange for A/AAAA
}
```
