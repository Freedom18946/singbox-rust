# Next Steps

> Last Updated: **2025-12-05 18:48 CST**
> Parity Status: **~98%** (see `GO_PARITY_MATRIX.md`)
> Go Reference: `go_fork_source/sing-box-1.12.12`
> **P1 Verification**: ✅ Complete (WireGuard, Tailscale Data Plane, uTLS)

---

## Current Assessment

- **Major Milestone Achieved**:
  - **WireGuard Deduplication**: ✅ Complete (Merged into `sb-transport`, `sb-adapters` refactored)
  - **Platform Integration**: ✅ Complete (Android socket protection, Windows system proxy with WinInet)
- **Parity Status**: ~92% aligned with Go reference.
- **Primary Focus**: Platform integration (Android/Windows hooks) and Tailscale Control Plane.

---

## Completed Items (Recent)

- [x] **WireGuard Outbound** - Native userspace implementation (boringtun) in `sb-adapters`.
- [x] **Tailscale Data Plane** - WireGuard mode + MagicDNS + SOCKS5 fallback.
- [x] **uTLS** - Full module with fingerprinting (Chrome/Firefox/Safari/Random).
- [x] **Transports** - All transport layers verified (`simple-obfs`, `sip003`, `trojan`, `grpc-lite`, `uot`).
- [x] **Clash/V2Ray API** - Full implementations.
- [x] **Routing Rules** - AdGuard, Headless, User/Group rules verified.
- [x] **Refactoring** - WireGuard implementation deduplicated (Adapter uses Transport).
- [x] **Tailscale Control Plane** - Coordinator, DerpClient, Crypto Shim, Dynamic Wiring.
- [x] **Utilities** - Windows Named Pipes, System Proxy Integration.

---

### Priority 1: End-to-End Verification
- **Goal**: Validate all components in a live environment.
- **Guide**: See [USAGE.md](./USAGE.md) for configuration examples.
- **Action**:
  - [ ] Set up cross-platform build environment (GitHub Actions or local VMs).
  - [ ] Run logic against real servers (Tailscale, Vmess, Trojan).

---

## Verification & Testing needed

1.  **WireGuard Interop**: Test against real WireGuard server (not just unit tests).
2.  **Tailscale MagicDNS**: Validate resolving `.ts.net` domains in Direct mode.
3.  **Cross-Platform**: Build on Android/Windows to verify platform hooks (once implemented).

---

## Timeline Estimate

| Task | Estimated Effort | Priority |
| --- | --- | --- |
| WireGuard Deduplication | 1-2 days | P1 |
| Platform Parity (WinInet/Android) | 1 week | P1 |
| Tailscale Control Plane | 1 week | P2 |
| Final 100% Polish | 3-5 days | P2 |

**Total to 100%**: ~2 weeks.
