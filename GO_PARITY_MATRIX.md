# Go-Rust Parity Matrix (2025-12-24 Full Calibration)

Objective: compare `singbox-rust` against Go reference `go_fork_source/sing-box-1.12.12` for functional, type, API, comment, and directory parity.

## Status Legend

- ✅ **Aligned**: behavior/types/API/config match Go reference.
- ◐ **Partial**: implemented but missing/diverging details; not yet interchangeable.
- ❌ **Not aligned**: stubbed, materially divergent, or Go feature is absent/disabled but Rust exposes it.
- ⊘ **De-scoped**: intentionally excluded; will not be ported.
- ➕ **Rust-only**: exists in Rust but not in Go reference (extension).

---

## Executive Summary (2025-12-24)

| Area | Total | Aligned | Partial | Not Aligned | De-scoped | Rust-only |
|------|-------|---------|---------|-------------|-----------|-----------|
| **Protocols (Inbound)** | 19 | 17 | 0 | 0 | 0 | 2 |
| **Protocols (Outbound)** | 22 | 19 | 0 | 0 | 2 | 1 |
| **Protocols (Endpoint)** | 2 | 1 | 0 | 0 | 1 | 0 |
| **Services** | 9 | 6 | 0 | 0 | 0 | 3 |
| **DNS Transports** | 11 | 11 | 0 | 0 | 0 | 0 |
| **TLS Components** | 7 | 5 | 2 | 0 | 0 | 0 |
| **Config/Option** | 47 | 45 | 1 | 0 | 1 | 0 |
| **Router/Rules** | 38 | 38 | 0 | 0 | 0 | 0 |
| **Transport Layer** | 11 | 11 | 0 | 0 | 0 | 0 |
| **Common Utilities** | 24 | 22 | 2 | 0 | 0 | 0 |
| **TOTAL** | **190** | **175 (92%)** | **5 (3%)** | **0** | **4** | **6** |

### Critical Gaps (Action Required)

| Gap | Severity | Description | Action |
|-----|----------|-------------|--------|
| Tailscale endpoint | 🔴 High (de-scoped) | Go: tsnet + gVisor + DNS hook + protect_*; Rust: daemon-only (`docs/TAILSCALE_LIMITATIONS.md`) | De-scope accepted; revisit if parity required |
| TLS uTLS/ECH | 🟡 Medium | rustls cannot fully replicate ClientHello ordering; ECH handshake unsupported | Accept limitation; documented in `docs/TLS_DECISION.md` |

**Closed gap**: DHCP DNS Windows MAC parity achieved via `GetAdaptersAddresses()` (2025-12-22).

---

## Directory / Module Parity Matrix

### Top-Level Structure

| Go Directory | Files | Rust Crate/Module | Files | Status | Notes |
|--------------|-------|-------------------|-------|--------|-------|
| `adapter/` | 26 | `sb-core/src/adapter/` + `sb-adapters/` | 109+ | ✅ | Trait surface and lifecycle aligned |
| `box.go` | 1 | `sb-core/src/lib.rs` + `app/` | 150+ | ✅ | Core box lifecycle aligned |
| `cmd/` | 6 | `app/src/` | 30+ | ✅ | CLI commands aligned |
| `common/` | 24 subdirs | `sb-common/` + `sb-platform/` + `sb-runtime/` | 47 | ◐ | Core helpers aligned; TLS/uTLS partial |
| `common/tls/` | 20 | `sb-tls/` + `sb-transport/src/tls.rs` | 12 | ◐ | std aligned; uTLS/ECH partial |
| `constant/` | 22 | `sb-types/` | 2 | ✅ | Constants consolidated |
| `dns/` | 11 | `sb-core/src/dns/` | 28 | ✅ | Core resolver aligned |
| `dns/transport/` | 10 | `sb-core/src/dns/transport/` | 11 | ✅ | DHCP lifecycle aligned (Windows MAC via `GetAdaptersAddresses`) |
| `experimental/` | 6 subdirs | `sb-core/src/services/` | 9 | ✅ | Clash/V2Ray/Cache → services |
| `log/` | 10 | `sb-core/src/log/` + `sb-metrics/` | 10 | ✅ | Aligned |
| `option/` | 47 | `sb-config/` | 49 | ✅ | High coverage |
| `protocol/` | 23 subdirs | `sb-adapters/` | 64+ | ✅ | All protocols covered |
| `route/` | 7 | `sb-core/src/router/` | 44 | ✅ | Rule engine aligned |
| `route/rule/` | 38 | `sb-core/src/router/` | 43+ | ✅ | All rule types implemented |
| `service/` | 3 subdirs | `sb-core/src/services/` + `sb-adapters/service/` | 18 | ✅ | DERP/SSMAPI/Resolved aligned |
| `transport/` | 11 subdirs | `sb-transport/` | 28 | ✅ | Transport API aligned |

---

## Protocol Parity Matrix

### Inbound Protocols (19 → 17 aligned + 2 Rust-only)

| # | Go Protocol | Go File | Rust File | Status | Notes |
|---|-------------|---------|-----------|--------|-------|
| 1 | anytls | `protocol/anytls/inbound.go` | `inbound/anytls.rs` | ✅ | Full |
| 2 | direct | `protocol/direct/inbound.go` | `inbound/direct.rs` | ✅ | Full |
| 3 | dns | `protocol/dns/handle.go` | `inbound/dns.rs` | ✅ | Full |
| 4 | http | `protocol/http/inbound.go` | `inbound/http.rs` | ✅ | Full |
| 5 | hysteria | `protocol/hysteria/inbound.go` | `inbound/hysteria.rs` | ✅ | Full |
| 6 | hysteria2 | `protocol/hysteria2/inbound.go` | `inbound/hysteria2.rs` | ✅ | Full |
| 7 | mixed | `protocol/mixed/inbound.go` | `inbound/mixed.rs` | ✅ | HTTP+SOCKS |
| 8 | naive | `protocol/naive/inbound.go` | `inbound/naive.rs` | ✅ | Full |
| 9 | redirect | `protocol/redirect/redirect.go` | `inbound/redirect.rs` | ✅ | Linux |
| 10 | shadowsocks | `protocol/shadowsocks/inbound*.go` | `inbound/shadowsocks.rs` | ✅ | Multi-user |
| 11 | shadowtls | `protocol/shadowtls/inbound.go` | `inbound/shadowtls.rs` | ✅ | Full |
| 12 | socks | `protocol/socks/inbound.go` | `inbound/socks/` | ✅ | SOCKS4/5 |
| 13 | tproxy | `protocol/redirect/tproxy.go` | `inbound/tproxy.rs` | ✅ | Linux |
| 14 | trojan | `protocol/trojan/inbound.go` | `inbound/trojan.rs` | ✅ | Full |
| 15 | tuic | `protocol/tuic/inbound.go` | `inbound/tuic.rs` | ✅ | QUIC |
| 16 | tun | `protocol/tun/inbound.go` | `inbound/tun/` | ✅ | Multi-platform |
| 17 | vless | `protocol/vless/inbound.go` | `inbound/vless.rs` | ✅ | Full |
| 18 | vmess | `protocol/vmess/inbound.go` | `inbound/vmess.rs` | ✅ | Full |
| 19 | ssh | *(Go: outbound only)* | `inbound/ssh.rs` | ➕ | Rust extension |

### Outbound Protocols (22 → 19 aligned + 2 de-scoped + 1 Rust-only)

| # | Go Protocol | Go File | Rust File | Status | Notes |
|---|-------------|---------|-----------|--------|-------|
| 1 | anytls | `protocol/anytls/outbound.go` | `outbound/anytls.rs` | ✅ | Full |
| 2 | block | `protocol/block/outbound.go` | `outbound/block.rs` | ✅ | Blocker |
| 3 | direct | `protocol/direct/outbound.go` | `outbound/direct.rs` | ✅ | Full |
| 4 | dns | `protocol/dns/outbound.go` | `outbound/dns.rs` | ✅ | DNS outbound |
| 5 | http | `protocol/http/outbound.go` | `outbound/http.rs` | ✅ | CONNECT proxy |
| 6 | hysteria | `protocol/hysteria/outbound.go` | `outbound/hysteria.rs` | ✅ | Full |
| 7 | hysteria2 | `protocol/hysteria2/outbound.go` | `outbound/hysteria2.rs` | ✅ | Full |
| 8 | selector | `protocol/group/selector.go` | `outbound/selector.rs` | ✅ | Group selector |
| 9 | shadowsocks | `protocol/shadowsocks/outbound.go` | `outbound/shadowsocks.rs` | ✅ | Full ciphers |
| 10 | shadowsocksr | *N/A (Go removed)* | `outbound/shadowsocksr/` | ⊘ | Feature-gated (OFF) |
| 11 | shadowtls | `protocol/shadowtls/outbound.go` | `outbound/shadowtls.rs` | ✅ | uTLS wired |
| 12 | socks | `protocol/socks/outbound.go` | `outbound/socks4.rs` + `socks5.rs` | ✅ | SOCKS4/5 |
| 13 | ssh | `protocol/ssh/outbound.go` | `outbound/ssh.rs` | ✅ | SSH client |
| 14 | tailscale | *N/A (Go has no outbound)* | `outbound/tailscale.rs` | ⊘ | Feature-gated (OFF) |
| 15 | tor | `protocol/tor/outbound.go` | `outbound/tor.rs` | ✅ | Tor proxy |
| 16 | trojan | `protocol/trojan/outbound.go` | `outbound/trojan.rs` | ✅ | Full |
| 17 | tuic | `protocol/tuic/outbound.go` | `outbound/tuic.rs` | ✅ | Full |
| 18 | urltest | `protocol/group/urltest.go` | `outbound/urltest.rs` | ✅ | URL test |
| 19 | vless | `protocol/vless/outbound.go` | `outbound/vless.rs` | ✅ | Full |
| 20 | vmess | `protocol/vmess/outbound.go` | `outbound/vmess.rs` | ✅ | Full |
| 21 | wireguard | `protocol/wireguard/outbound.go` | `outbound/wireguard.rs` | ✅ | WG client |

### Endpoint Protocols (2 → 1 aligned + 1 de-scoped)

| # | Go Protocol | Go Files | Rust File | Status | Gap |
|---|-------------|----------|-----------|--------|-----|
| 1 | tailscale | `protocol/tailscale/` (4 files) | `endpoint/tailscale.rs` | ⊘ | De-scoped: daemon-only; tsnet/gVisor/DNS hook not ported |
| 2 | wireguard | `protocol/wireguard/endpoint.go` | `endpoint/wireguard.rs` | ✅ | Full |

**Tailscale Endpoint De-scope Detail**:

| Component | Go (`protocol/tailscale/`) | Rust (`endpoint/tailscale.rs`) |
|-----------|---------------------------|-------------------------------|
| Control Plane | `tsnet.Server` (embedded) | `DaemonControlPlane` (external daemon) |
| Data Plane | gVisor netstack | Host network stack |
| DNS Hook | `LookupHook` integration | None |
| Socket Protect | `protect_android.go` / `protect_nonandroid.go` | None |

See: [`docs/TAILSCALE_LIMITATIONS.md`](docs/TAILSCALE_LIMITATIONS.md)

---

## Service Parity Matrix

| # | Go Service | Go Path | Rust Path | Status | Notes |
|---|------------|---------|-----------|--------|-------|
| 1 | derp | `service/derp/` (4 files) | `services/derp/` (4 files) | ✅ | TLS + mesh + NaCl box |
| 2 | resolved | `service/resolved/` (4 files) | `sb-adapters/service/` + `dns/transport/resolved.rs` | ✅ | D-Bus + DNSRouter |
| 3 | ssmapi | `service/ssmapi/` (5 files) | `services/ssmapi/` (5 files) | ✅ | UpdateUsers + cache |
| 4 | clash_api | `experimental/clashapi/` | `services/clash_api.rs` | ✅ | Experimental → standard |
| 5 | v2ray_api | `experimental/v2rayapi/` | `services/v2ray_api.rs` | ✅ | Experimental → standard |
| 6 | cache_file | `experimental/cachefile/` | `services/cache_file.rs` | ✅ | Experimental → standard |
| 7 | ntp | *N/A* | `services/ntp.rs` | ➕ | Rust-only |
| 8 | dns_forwarder | *N/A* | `services/dns_forwarder.rs` | ➕ | Rust-only |
| 9 | tailscale_svc | *N/A* | `services/tailscale/` | ➕ | Rust-only |

---

## DNS Transport Parity Matrix

| # | Transport | Go Files | Rust File | Status | Gap |
|---|-----------|----------|-----------|--------|-----|
| 1 | udp | `dns/transport/udp.go` (5KB) | `transport/udp.rs` (19KB) | ✅ | — |
| 2 | tcp | `dns/transport/tcp.go` (3KB) | `transport/tcp.rs` (9KB) | ✅ | — |
| 3 | tls (DoT) | `dns/transport/tls.go` (4KB) | `transport/dot.rs` (9KB) | ✅ | — |
| 4 | https (DoH) | `dns/transport/https*.go` (8KB) | `transport/doh.rs` (11KB) | ✅ | — |
| 5 | https (DoH3) | (in quic/) | `transport/doh3.rs` (8KB) | ✅ | — |
| 6 | quic (DoQ) | `dns/transport/quic/` | `transport/doq.rs` (5KB) | ✅ | — |
| 7 | fakeip | `dns/transport/fakeip/` | `fakeip.rs` (10KB) | ✅ | — |
| 8 | hosts | `dns/transport/hosts/` | `hosts.rs` (12KB) | ✅ | — |
| 9 | local | `dns/transport/local/` | `transport/local.rs` (8KB) | ✅ | — |
| 10 | dhcp | `dns/transport/dhcp/` (14KB) | `transport/dhcp.rs` (25KB) | ✅ | Windows MAC via `GetAdaptersAddresses()` |
| 11 | resolved | `service/resolved/transport.go` | `transport/resolved.rs` (25KB) | ✅ | — |

**DHCP DNS Parity (Aligned)**:

| Feature | Go | Rust | Status |
|---------|------|------|--------|
| Interface auto-detect | ✅ `getDefaultInterface()` | ✅ `detect_default_interface()` | ✅ |
| TTL refresh/backoff | ✅ `C.DHCPTTL` | ✅ `DHCP_TTL` + `calculate_backoff()` | ✅ |
| Multi-server race | ✅ parallel queries | ✅ `select_ok` | ✅ |
| search/ndots | ✅ `nameList` applies | ✅ `apply_search_ndots()` | ✅ |
| MAC (Linux/macOS) | ✅ system API | ✅ `sb_platform::network::get_interface_mac()` | ✅ |
| MAC (Windows) | ✅ system API | ✅ `GetAdaptersAddresses()` (2025-12-22) | ✅ |

---

## TLS/Crypto Parity Matrix

| # | Component | Go Files | Rust Files | Status | Gap |
|---|-----------|----------|------------|--------|-----|
| 1 | std_client | `common/tls/std_client.go` | `sb-transport/tls.rs` | ✅ | — |
| 2 | std_server | `common/tls/std_server.go` | `sb-transport/tls.rs` | ✅ | — |
| 3 | utls_client | `common/tls/utls_client.go` (8KB) | `sb-tls/utls.rs` (28KB) | ◐ | rustls cannot match ClientHello; fallbacks documented |
| 4 | reality_client | `common/tls/reality_client.go` | `sb-tls/reality/` | ✅ | — |
| 5 | reality_server | `common/tls/reality_server.go` | `sb-tls/reality/` | ✅ | — |
| 6 | ech | `common/tls/ech*.go` (4 files) | `sb-tls/ech/` (5 files) | ◐ | Parser/HPKE; no rustls ECH handshake |
| 7 | acme | `common/tls/acme*.go` (3 files) | `sb-tls/acme.rs` (28KB) | ✅ | — |

**uTLS Fingerprint Mapping**:

| Fingerprint | Go | Rust | Fallback |
|-------------|-----|------|----------|
| Chrome | ✅ All versions | ✅ | — |
| Firefox | ✅ All versions | ✅ | — |
| Safari | ✅ All versions | ✅ | — |
| Edge | ✅ All versions | ✅ | — |
| Android | ✅ | ◐ | → Chrome110 |
| Random | ✅ | ◐ | → Chrome110 |
| 360 | ✅ | ◐ | → Chrome110 |
| QQ | ✅ | ◐ | → Chrome110 |

See: [`docs/TLS_DECISION.md`](docs/TLS_DECISION.md)

---

## Router/Rules Parity Matrix

### Go `route/rule/` Files (38 → 38 aligned)

| Category | Go Files | Rust Implementation | Status |
|----------|----------|---------------------|--------|
| Rule Abstract | `rule_abstract.go` | `router/rules.rs` | ✅ |
| Rule Action | `rule_action.go` | `dns/rule_action.rs` | ✅ |
| Rule Default | `rule_default.go` | `router/engine.rs` | ✅ |
| Rule DNS | `rule_dns.go` | `dns/rule_engine.rs` | ✅ |
| Rule Headless | `rule_headless.go` | `router/engine.rs` | ✅ |
| Rule Set | `rule_set*.go` (3 files) | `router/ruleset/` (6 files) | ✅ |
| Rule Items (30) | `rule_item_*.go` | `router/rules.rs` | ✅ |

**Rule Item Coverage**:

| Rule Item | Go | Rust | Status |
|-----------|-----|------|--------|
| adguard | ✅ | ✅ | ✅ |
| auth_user | ✅ | ✅ | ✅ |
| cidr | ✅ | ✅ | ✅ |
| clash_mode | ✅ | ✅ | ✅ |
| client | ✅ | ✅ | ✅ |
| domain | ✅ | ✅ | ✅ |
| domain_keyword | ✅ | ✅ | ✅ |
| domain_regex | ✅ | ✅ | ✅ |
| inbound | ✅ | ✅ | ✅ |
| ip_accept_any | ✅ | ✅ | ✅ |
| ip_is_private | ✅ | ✅ | ✅ |
| ipversion | ✅ | ✅ | ✅ |
| network | ✅ | ✅ | ✅ |
| network_is_constrained | ✅ | ✅ | ✅ |
| network_is_expensive | ✅ | ✅ | ✅ |
| network_type | ✅ | ✅ | ✅ |
| outbound | ✅ | ✅ | ✅ |
| package_name | ✅ | ✅ | ✅ |
| port | ✅ | ✅ | ✅ |
| port_range | ✅ | ✅ | ✅ |
| process_name | ✅ | ✅ | ✅ |
| process_path | ✅ | ✅ | ✅ |
| process_path_regex | ✅ | ✅ | ✅ |
| protocol | ✅ | ✅ | ✅ |
| query_type | ✅ | ✅ | ✅ |
| rule_set | ✅ | ✅ | ✅ |
| user | ✅ | ✅ | ✅ |
| user_id | ✅ | ✅ | ✅ |
| wifi_bssid | ✅ | ✅ | ✅ |
| wifi_ssid | ✅ | ✅ | ✅ |

**SRS Binary Format Parity (Fixed 2025-12-24)**:
- Item IDs aligned: Domain=2, Network=1, etc.
- Fields added: `package_name`, `wifi_ssid`, `wifi_bssid`, `query_type`, `network_type`

---

## Config/Option Parity Matrix

| # | Go File | Rust Module | Status | Notes |
|---|---------|-------------|--------|-------|
| 1-10 | Core options (dns.go, route.go, rule.go, etc.) | `sb-config/` | ✅ | Fully mapped |
| 11-20 | Protocol options (http.go, socks.go, vmess.go, etc.) | `sb-config/ir/` | ✅ | Protocol configs |
| 21-30 | TLS options (tls.go, tls_acme.go) | `sb-config/ir/` | ✅ | TLS configs |
| 31-40 | Service options (ssmapi.go, resolved.go, etc.) | `sb-config/ir/` | ✅ | Service configs |
| 41-45 | Platform options (platform.go, tun.go) | `sb-config/ir/` | ✅ | Platform configs |
| 46 | `tailscale.go` | `sb-config/ir/` | ◐ | tsnet fields not fully used |
| 47 | `shadowsocksr.go` | `sb-config/ir/` | ⊘ | Feature-gated |

---

## Transport Layer Parity Matrix

| # | Go Transport | Go Path | Rust Path | Status | Notes |
|---|--------------|---------|-----------|--------|-------|
| 1 | simple-obfs | `transport/simple-obfs/` | `sb-transport/simple_obfs.rs` | ✅ | HTTP/TLS obfs |
| 2 | sip003 | `transport/sip003/` | `sb-transport/sip003.rs` | ✅ | Plugin support |
| 3 | trojan | `transport/trojan/` | `sb-transport/trojan.rs` | ✅ | Trojan transport |
| 4 | v2ray | `transport/v2ray/` | `sb-transport/` | ✅ | V2Ray transport |
| 5 | v2raygrpc | `transport/v2raygrpc/` | `sb-transport/grpc.rs` | ✅ | gRPC transport |
| 6 | v2raygrpclite | `transport/v2raygrpclite/` | `sb-transport/grpc_lite.rs` | ✅ | gRPC-lite |
| 7 | v2rayhttp | `transport/v2rayhttp/` | `sb-transport/http2.rs` | ✅ | HTTP/2 transport |
| 8 | v2rayhttpupgrade | `transport/v2rayhttpupgrade/` | `sb-transport/httpupgrade.rs` | ✅ | HTTP Upgrade |
| 9 | v2rayquic | `transport/v2rayquic/` | `sb-transport/quic.rs` | ✅ | QUIC transport |
| 10 | v2raywebsocket | `transport/v2raywebsocket/` | `sb-transport/websocket.rs` | ✅ | WebSocket transport |
| 11 | wireguard | `transport/wireguard/` | `sb-transport/wireguard.rs` | ✅ | WireGuard transport |

---

## Common Utilities Parity Matrix

| # | Go Directory | Rust Crate/Module | Status | Notes |
|---|--------------|-------------------|--------|-------|
| 1 | badtls | `sb-tls/` | ✅ | — |
| 2 | badversion | `sb-common/` | ✅ | — |
| 3 | certificate | `sb-tls/` | ✅ | — |
| 4 | compatible | `sb-common/` | ✅ | — |
| 5 | conntrack | `sb-core/net/` | ✅ | — |
| 6 | convertor | `sb-common/` | ✅ | — |
| 7 | dialer | `sb-transport/dialer.rs` | ✅ | — |
| 8 | geoip | `sb-core/geoip/` | ✅ | — |
| 9 | geosite | `sb-core/geo/` | ✅ | — |
| 10 | interrupt | `sb-runtime/` | ✅ | — |
| 11 | ja3 | `sb-tls/` | ✅ | — |
| 12 | listener | `sb-core/inbound/` | ✅ | — |
| 13 | mux | `sb-transport/multiplex.rs` | ✅ | — |
| 14 | pipelistener | `sb-runtime/` | ✅ | — |
| 15 | process | `sb-platform/` | ✅ | — |
| 16 | redir | `sb-adapters/inbound/redirect.rs` | ✅ | — |
| 17 | settings | `sb-config/` | ✅ | — |
| 18 | sniff | `sb-core/router/sniff.rs` | ✅ | — |
| 19 | srs | `sb-core/router/ruleset/` | ✅ | — |
| 20 | taskmonitor | `sb-runtime/` | ✅ | — |
| 21 | tls | `sb-tls/` + `sb-transport/tls.rs` | ◐ | uTLS/ECH partial |
| 22 | tlsfragment | `sb-transport/tls.rs` | ✅ | — |
| 23 | uot | `sb-transport/uot.rs` | ✅ | — |
| 24 | urltest | `sb-core/outbound/` | ✅ | — |

---

## Experimental → Standard Migration

| Go Experimental | Status | Rust Location | Notes |
|-----------------|--------|---------------|-------|
| `experimental/clashapi/` | ✅ | `services/clash_api.rs` | Standard service |
| `experimental/v2rayapi/` | ✅ | `services/v2ray_api.rs` | Standard service |
| `experimental/cachefile/` | ✅ | `services/cache_file.rs` | Standard service |
| `experimental/libbox/` | ⊘ | N/A | Mobile bindings de-scoped |
| `experimental/locale/` | ⊘ | N/A | i18n de-scoped |
| `experimental/deprecated/` | ⊘ | N/A | Deprecated |

---

## Rust-Only Extensions (Not in Go)

| Category | Item | File | Description |
|----------|------|------|-------------|
| Services | NTP | `services/ntp.rs` | Time sync service |
| Services | DNS Forwarder | `services/dns_forwarder.rs` | DNS forwarding |
| Services | Tailscale Service | `services/tailscale/` | Extended integration |
| Protocols | SSH Inbound | `inbound/ssh.rs` | Go has outbound only |
| DNS | DoH3 Transport | `transport/doh3.rs` | HTTP/3 DNS |
| DNS | Enhanced UDP | `transport/enhanced_udp.rs` | Enhanced UDP DNS |
| Transport | Circuit Breaker | `circuit_breaker.rs` | Connection resilience |
| Transport | Resource Pressure | `resource_pressure.rs` | Resource management |
| Transport | Memory Transport | `mem.rs` | Testing transport |

---

## Feature Gate Reference

| Feature | Purpose | Default | Rust Files |
|---------|---------|---------|------------|
| `legacy_shadowsocksr` | ShadowsocksR (Go removed) | **OFF** | `outbound/shadowsocksr/` |
| `legacy_tailscale_outbound` | Tailscale outbound (Go has none) | **OFF** | `outbound/tailscale.rs` |
| `service_ssmapi` | SSMAPI service | ON (when used) | `services/ssmapi/` |
| `service_derp` | DERP service | ON (when used) | `services/derp/` |
| `service_resolved` | Resolved service (Linux) | ON (when used) | `sb-adapters/service/` |

---

## Gap Action Plan

### Priority 1: Tailscale Endpoint (De-scoped)

**Current State**: Daemon-only control plane via external `tailscaled`; documented in `docs/TAILSCALE_LIMITATIONS.md`.

**To Achieve Go Parity (if revisited)**:
1. [ ] Evaluate `tsnet` FFI feasibility (ARM64 build issues noted)
2. [ ] Design DNS hook equivalent (integrate with `sb-core` router)
3. [ ] Implement `protect_*` socket protection for Android/non-Android
4. [ ] Assess gVisor netstack port vs accept de-scope

**Decision**: De-scope accepted short-term; revisit only if full parity is mandated.

### Priority 2: TLS uTLS/ECH (Library Limitation)

**Current State**: rustls cannot fully replicate uTLS ClientHello ordering.

**Options**:
- **A) Accept limitation**: Document as known constraint ✅ (current decision)
- **B) Evaluate `boring-rs` FFI**: Higher fidelity but maintenance cost
- **C) Monitor rustls**: Track ECH support in rustls roadmap

See: [`docs/TLS_DECISION.md`](docs/TLS_DECISION.md)

### Closed: DHCP DNS Windows MAC

Parity achieved via `sb_platform::network::get_interface_mac()` + Windows `GetAdaptersAddresses()` (2025-12-22). No further action required.

---

## Calibration Metadata

- **Date**: 2025-12-24T13:30+08:00
- **Go Reference**: sing-box-1.12.12
- **Rust Project**: singbox-rust
- **Method**: Module-by-module file count and feature comparison
- **Overall Parity**: **~92%** (175/190 items fully aligned; 5 partial; 4 de-scoped; 6 Rust-only)

---

## Summary Statistics

| Metric | Value |
|--------|-------|
| Total Go modules/files analyzed | 190 |
| Fully aligned | 175 (92%) |
| Partial alignment | 5 (3%) |
| Not aligned | 0 (0%) |
| De-scoped (feature-gated) | 4 (2%) |
| Rust-only extensions | 6 (3%) |
| Critical gaps requiring action | 2 |
