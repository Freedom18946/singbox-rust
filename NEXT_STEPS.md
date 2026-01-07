# Next Steps & Priorities

**Objective**: Achieve 100% parity (feature-gated parity build) with `sing-box-1.12.14`.

## Current Status (2026-01-07)

**Parity: 88% (183/209 items aligned)**

Key blockers:
- Parity feature gates (default build registers stubs)
- TLS fragmentation parity gaps (publicsuffix + Windows ACK)
- WireGuard endpoint parity gaps (UDP listen/reserved)
- V2Ray API tracking parity (UDP traffic recording wired for most inbounds; packet stats + remaining UDP paths)
- Repo structure gaps (`clients/`, `include/`, `release/`, `experimental/libbox`, `experimental/locale`)
- DNS scheme comments out of sync with feature-gated implementations

---

## Immediate Next Steps

- [ ] Define a single `parity` feature set and run CI with it (`router`, `adapters`, `dns_*`, `service_*`, `clash_api`, `v2ray_api`)
- [ ] Decide on publicsuffix + Windows ACK parity for TLS fragmentation + add tests
- [ ] Resolve WireGuard endpoint UDP listen/reserved gaps or document unsupported behavior
- [ ] Decide for libbox/locale/clients/release: port or explicitly de-scope
- [ ] Finish UDP packet stats + router-level tracking for V2Ray API (direct/socks/shadowsocks/trojan/tuic + core socks5 + DNS inbound wired; remaining UDP paths + packet counters)
- [ ] Align DNS scheme comments in `crates/sb-config/src/ir/mod.rs`

---

## De-scoped / Limitations

### De-scoped (accepted)
- Tailscale endpoint (tsnet/gVisor)
- ShadowsocksR (Go removed upstream)

### Pending de-scope decision
- libbox/mobile clients (`clients/`, `include/`, `experimental/libbox`)
- locale (`experimental/locale`)
- release packaging (`release/`)

### Library limitations
- TLS uTLS (rustls ClientHello ordering)
- TLS ECH (handshake integration)

---

## Completed (2026-01-07)

- [x] Recalibrated parity matrix and updated next steps
- [x] Implemented TLS fragmentation in `crates/sb-core/src/router/conn.rs` (publicsuffix/Windows ACK gaps remain)
- [x] Aligned WireGuard endpoint builder + StartStage peer DNS resolution (UDP/reserved gaps remain)
- [x] Added V2Ray API gRPC stats patterns/regex + TCP traffic recorder hooks across adapters/core inbounds
- [x] Added UDP traffic recording hooks for router connection manager + direct/socks/shadowsocks/trojan/tuic + core socks5 + DNS inbound paths (packet counters pending)

---

## Historical Completions

| Date | Parity | Key Changes |
|------|--------|-------------|
| 2026-01-07 | 88% | Parity recalibration + gap re-scoping |
| 2026-01-01 | 97% | SOCKS5, DNS, WireGuard, Clash, V2Ray, DERP |
| 2025-12-31 | 91% | TUN, DNS rules, SSH |
| 2025-12-30 | 88% | DNS transports |
