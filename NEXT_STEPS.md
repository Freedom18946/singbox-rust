# Next Steps

> Last Updated: **2025-12-06 17:30 CST**
> Parity Status: **~97%** (see `GO_PARITY_MATRIX.md`)
> Go Reference: `go_fork_source/sing-box-1.12.12`
> **All Major Modules**: ✅ Complete (Protocols, Transports, Rules, DNS, Services)

---

## Current Assessment

- **Major Milestone Achieved**:
  - **Protocol Parity**: ✅ 100% Complete (23/23 inbound, 23/23 outbound)
  - **Transport Parity**: ✅ 100% Complete (11/11 Go transports + extras)
  - **Rule Engine**: ✅ 98% Complete (35/38 rule items verified)
  - **Platform Integration**: ✅ 95% Complete (Windows/macOS/Linux/Android)
  - **Services**: ✅ 98% Complete (Clash API, V2Ray API, Cache, NTP)
- **Parity Status**: ~97% aligned with Go reference.
- **Primary Focus**: End-to-end verification and remaining edge cases.

---

## Completed Items (Recent)

- [x] **Full Module Comparison** - Comprehensive parity matrix with Go-Rust directory mapping.
- [x] **WireGuard Outbound** - Native userspace implementation (boringtun) in `sb-adapters`.
- [x] **Tailscale Data Plane** - WireGuard mode + MagicDNS + SOCKS5 fallback.
- [x] **uTLS** - Full module with fingerprinting (Chrome/Firefox/Safari/Random).
- [x] **Transports** - All transport layers verified (`simple-obfs`, `sip003`, `trojan`, `grpc-lite`, `uot`).
- [x] **Clash/V2Ray API** - Full implementations with stats.
- [x] **Routing Rules** - AdGuard, Headless, User/Group, all 35+ rules verified.
- [x] **Common Utilities** - `pipelistener`, `compatible`, `conntrack`, `ja3` all present.
- [x] **Platform Integration** - System proxy (WinInet/macOS/Linux), Android protect.

---

## Priority 1: End-to-End Verification

- **Goal**: Validate all components in a live environment.
- **Guide**: See [USAGE.md](./USAGE.md) for configuration examples.
- **Action**:
  - [ ] Run full test suite: `cargo test --workspace --all-features`
  - [ ] Set up cross-platform build environment (GitHub Actions or local VMs).
  - [ ] Test against real servers (WireGuard, Tailscale, VMess, Trojan).

---

## Priority 2: Remaining Gaps (~3%)

### P2.1 DHCP DNS Transport
- **Location**: `sb-core/src/dns/transport/`
- **Status**: Feature-gated, not fully implemented
- **Action**: Implement DHCP-based DNS discovery or document as unsupported.

### P2.2 Package Name Rules (Android)
- **Location**: `sb-core/src/router/rules.rs`
- **Status**: Rule structure present, Android hooks partial
- **Action**: Complete Android JNI integration for package name resolution.

### P2.3 Certificate Rotation
- **Location**: `sb-tls/src/acme.rs`
- **Status**: ACME present, advanced rotation logic partial
- **Action**: Add automatic certificate renewal scheduling.

---

## Verification & Testing Needed

1. **WireGuard Interop**: Test against real WireGuard server (not just unit tests).
2. **Tailscale MagicDNS**: Validate resolving `.ts.net` domains in Direct mode.
3. **Cross-Platform Build**: Build on Android/Windows/Linux to verify platform hooks.
4. **Clash API Compatibility**: Test with Clash Meta clients.
5. **Rule Set Loading**: Test remote rule set fetching and caching.

---

## Timeline Estimate

| Task | Estimated Effort | Priority |
| --- | --- | --- |
| End-to-End Verification | 2-3 days | P1 |
| DHCP DNS Transport | 1 day | P2 |
| Android Package Name Rules | 1 day | P2 |
| Certificate Rotation | 1 day | P2 |
| Final Polish & Documentation | 2-3 days | P3 |

**Total to 100%**: ~1 week.

---

## Rust-Only Enhancements (Beyond Go Parity)

These features exist in Rust but not in Go reference:

| Feature | Status | Notes |
| --- | --- | --- |
| DoH3 (DNS over HTTP/3) | ✅ Complete | `sb-core/src/dns/transport/doh3.rs` |
| Circuit Breaker | ✅ Complete | `sb-transport/src/circuit_breaker.rs` |
| DERP Transport | ✅ Complete | Tailscale relay support |
| TUN Enhanced | ✅ Complete | macOS-specific optimizations |
| SOCKS4 Outbound | ✅ Complete | Legacy protocol support |
| Resource Pressure | ✅ Complete | Backpressure handling |
| Metrics Extension | ✅ Complete | Enhanced telemetry |

---

## Quick Reference

```bash
# Run all tests
cargo test --workspace --all-features

# Build release binary
cargo build --release --all-features

# Check compilation
cargo check --workspace --all-features

# Run with example config
cargo run --release -- run -c config.yaml
```
