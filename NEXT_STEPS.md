# Next Steps & Priorities

**Objective**: Achieve 100% parity (feature-gated parity build) with `sing-box-1.12.14`.

## Current Status (2026-01-07)

**Parity: 88% (183/209 items aligned)**

Key blockers:
- Parity feature gates (default build registers stubs; ensure CI parity build)
- TLS fragmentation parity gaps (Windows ACK best-effort only)
- WireGuard endpoint parity gaps (UDP listen/reserved unsupported in userspace)

---

## Immediate Next Steps

- [x] Define a single `parity` feature set and run parity build (`router`, `adapters`, `dns_*`, `service_*`, `clash_api`, `v2ray_api`)
- [x] Decide on Windows ACK parity for TLS fragmentation (best-effort TCP_INFO + fallback delay)
- [x] Document WireGuard endpoint UDP listen/reserved limitations (userspace transport)
- [x] Finish UDP packet stats + router-level tracking for V2Ray API (direct/socks/shadowsocks/trojan/tuic + core socks5 + DNS inbound wired; remaining UDP paths + packet counters)
- [x] Align DNS scheme comments in `crates/sb-config/src/ir/mod.rs`

---

## De-scoped / Limitations

### De-scoped (accepted)
- Tailscale endpoint (tsnet/gVisor)
- ShadowsocksR (Go removed upstream)
- libbox/mobile clients (`clients/`, `include/`, `experimental/libbox`)
- locale (`experimental/locale`)
- release packaging (`release/`)

### Library limitations
- TLS uTLS (rustls ClientHello ordering)
- TLS ECH (handshake integration)
- WireGuard endpoint (userspace boringtun): no UDP listen_packet + no reserved bytes (TUN/wireguard-go required)
- TLS fragmentation on Windows: no winiphlpapi ACK wait; TCP_INFO best-effort with fallback delay

---

## Completed (2026-01-07)

- [x] Recalibrated parity matrix and updated next steps
- [x] Implemented TLS fragmentation in `crates/sb-core/src/router/conn.rs` (Windows ACK best-effort only)
- [x] Aligned WireGuard endpoint builder + StartStage peer DNS resolution (UDP/reserved unsupported in userspace)
- [x] Added V2Ray API gRPC stats patterns/regex + TCP traffic recorder hooks across adapters/core inbounds
- [x] Added UDP traffic recording hooks for router connection manager + direct/socks/shadowsocks/trojan/tuic + core socks5 + DNS inbound paths (packet counters pending)
- [x] Updated parity feature wiring for sb-api clash/v2ray + parity build check
- [x] Added V2Ray API UDP packet counters + recorder test coverage
- [x] Aligned DNS scheme comments with feature-gated implementations
- [x] Loaded public suffix list for TLS fragmentation + added validation tests
- [x] Documented Windows ACK best-effort + WireGuard endpoint UDP/reserved limitations
- [x] De-scoped libbox/locale/clients/release artifacts

---

## Historical Completions

| Date | Parity | Key Changes |
|------|--------|-------------|
| 2026-01-07 | 88% | Parity recalibration + gap re-scoping |
| 2026-01-01 | 97% | SOCKS5, DNS, WireGuard, Clash, V2Ray, DERP |
| 2025-12-31 | 91% | TUN, DNS rules, SSH |
| 2025-12-30 | 88% | DNS transports |
