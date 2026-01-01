# Next Steps & Priorities

**Objective**: Maintain 97%+ parity with `sing-box-1.12.14`.

## Current Status (2026-01-01)

**Parity: 97% (183/189 items aligned)** ✅

**All partial items resolved - only de-scoped and library limitations remain.**

---

## Completed Today (2026-01-01)

- [x] SOCKS5 IPv6 dual-stack → Fixed UDP bind in `socks5.rs`
- [x] Clash API wiring → Verified mode/selection persistence via cache_file
- [x] CacheFile persistence → Sled working with full feature set
- [x] V2Ray API → HTTP equivalent accepted
- [x] DERP service → Verified 4295-line implementation (relay/STUN/mesh)
- [x] TunStack connect_tcp → Added smoltcp TCP client foundation
- [x] DNS inbound/outbound → Verified complete with geosite/geoip
- [x] HTTP inbound → Verified HTTP proxy complete
- [x] WireGuard dial_context → Implemented via TUN routing

---

## Remaining Items

### De-scoped (4)
- Tailscale endpoint (requires tsnet/gVisor - daemon approach used)
- ShadowsocksR (Go removed it)
- libbox (mobile bindings)
- locale (i18n)

### Library Limitations (2)
- TLS uTLS (rustls can't replicate ClientHello ordering)
- TLS ECH (library limitation)

---

## Historical Completions

| Date | Parity | Key Changes |
|------|--------|-------------|
| 2026-01-01 | 97% | SOCKS5, DNS, WireGuard, Clash, V2Ray, DERP |
| 2025-12-31 | 91% | TUN, DNS rules, SSH |
| 2025-12-30 | 88% | DNS transports |
