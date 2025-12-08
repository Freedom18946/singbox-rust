# Go-Rust Parity Matrix (2025-12-08 Strict Calibration v5)

Objective: align the Rust refactor (`singbox-rust`) with the Go reference (`go_fork_source/sing-box-1.12.12`) across functionality, types, APIs, comments, and directory structure.

## Executive Summary

| Metric | Score | Details |
| --- | --- | --- |
| Functional Parity | ~95% | Protocols/transports/rules match; remaining gaps are endpoint data planes, resolved transport, and real debug/pprof. |
| Implementation Strictness | ~82% | Endpoint lifecycle runs; data-plane hooks (WireGuard/Tailscale), resolved per-link/DoT, and pprof are stubbed. |
| Overall Status | ⚠️ Needs P0 Fixes | Ship endpoint + resolved + pprof parity to reach 100%. |

### P0 Blockers

| Priority | Component | Gap Description |
| --- | --- | --- |
| **P0** | Endpoint System Data Plane | Rust manager runs lifecycle stages, but WireGuard endpoint only instantiates sb-transport peers (no dial/listen/router/DNS hooks, limited multi-peer). Tailscale endpoint is a stub (no tsnet/wgengine). |
| **P0** | Resolved Service & DNS Transport | Go resolve1 D-Bus with per-link DNS/DoT and `dns/transport/resolved`; Rust has Linux-only D-Bus ResolveHostname + UDP stub, no per-link/DoT/transport, stubs on other platforms. |

### Critical Divergences

| Component | Go Approach | Rust Approach | Status |
| --- | --- | --- | --- |
| Endpoint system (`adapter/endpoint`, `protocol/{wireguard,tailscale}/endpoint.go`) | Lifecycle manager starts WireGuard (gVisor) and Tailscale tsnet endpoints; used by DNS and routing. | Endpoint manager runs stages; WireGuard endpoint spins sb-transport peers but lacks dial/listen/router integration and multi-peer routing; Tailscale endpoint is a stub and stubs register by default. | ❌ P0 — Data plane incomplete |
| Resolved service + transport (`service/resolved`, `dns/transport/resolved`) | `resolve1` D-Bus server exports full API with per-link DNS, DoT, netmon updates; `dns/transport/resolved` routes per link. | Linux `service_resolved` uses systemd-resolved ResolveHostname + UDP stub; no per-link/DoT or `dns/transport/resolved`; other platforms use stub. | ⚠️ P0 — Platform-limited/stub |
| Debug/pprof (`debug.go`, `debug_http.go`, `option/debug.go`) | Experimental debug options (GC, stack, threads, panic_on_fault, OOM killer) and `/debug/pprof` HTTP server with real handlers. | `experimental.debug` options present; listen sets SB_DEBUG_ADDR/SB_PPROF/FREQ/MAX_SEC; admin_debug uses the address but has no pprof handlers; sb-explaind `/debug/pprof` returns placeholder SVG (pprof feature). GC/stack/thread/oom are recorded only. | ⚠️ P1 — Env/stub only |
| DHCP DNS (`dns/transport/dhcp`) | Active DHCPDISCOVER to harvest DNS servers. | Passive `/etc/resolv.conf` watcher; `system` alias added for resolved/system resolver. | ✅ P1 — Accepted divergence (documented) |
| BadTLS (`common/badtls`) | Active `ReadWaitConn` wrapper for uTLS buffering and handshake inspection. | Passive `TlsAnalyzer` bytecode parser; no connection wrapping. | ✅ P2 — Accepted divergence (rustls handles buffering) |

---

## High-Level Status

| Area | Status | Notes |
| --- | --- | --- |
| Configuration / Options | ✅ 100% | All Go option structs mapped (incl. `experimental.debug`); runtime pprof still stubbed. |
| Adapter runtime | ~92% | Endpoint lifecycle wired; data-plane endpoints partial. |
| Protocols - Inbound | ✅ 100% | 23 Go → 25 Rust (2 extras). |
| Protocols - Outbound | ✅ 100% | 23/23 aligned. |
| Transport layer | ✅ 100% | All Go transports + Rust extras. |
| Routing / Rule engine | ~98% | Rule coverage intact (38 Go rule items). |
| DNS system | ~90% | Linux ResolveHostname support; per-link/DoT/transport missing; DHCP divergence accepted. |
| Endpoint system | ~55% | Lifecycle runs; WireGuard data plane partial; Tailscale stub. |
| Services / Experimental | ~85% | Resolved service partial. |
| Common utilities | ~95% | BadTLS divergence accepted. |
| Platform integration | ~92% | Endpoint data planes not wired. |
| Debug / Observability | ~60% | Config/env wired; pprof/debug HTTP is placeholder only. |

---

## Directory Structure Mapping

| Go Directory | Rust Crate/Module | Parity |
| --- | --- | --- |
| `protocol/` (23 dirs) | `sb-adapters/src/{inbound,outbound}/` | ✅ |
| `transport/` (11 dirs) | `sb-transport/src/` | ✅ |
| `route/` (6 files + rule/) | `sb-core/src/router/` | ✅ |
| `route/rule/` (38 files) | `sb-core/src/router/rules.rs` + ruleset/ | ✅ |
| `dns/` (10 files) | `sb-core/src/dns/` | ⚠️ Resolved/DHCP gaps |
| `dns/transport/` (5 dirs + 5 files) | `sb-core/src/dns/transport/` | ⚠️ Missing resolved transport |
| `adapter/endpoint/` (3 files) | `sb-core/src/endpoint/` + stubs | ⚠️ Lifecycle wired; data-plane partial |
| `service/` (3 dirs) | `sb-core/src/services/` + `sb-adapters/src/service/` | ⚠️ Resolved partial |
| `option/` (47 files) | `sb-config/src/` | ✅ (runtime pprof stub) |
| `common/` (24 dirs) | `sb-common/src/` + `sb-platform/` | ⚠️ BadTLS divergence |
| `experimental/` (6 dirs) | `sb-core/src/services/` | ✅ |

---

## Protocol Adapters — Inbound (23 Go → 25 Rust)

| Protocol | Go Path | Rust Path | Status |
| --- | --- | --- | --- |
| Direct | `protocol/direct` | `sb-adapters/src/inbound/direct.rs` | ✅ Present |
| DNS | `protocol/dns` | `sb-adapters/src/inbound/dns.rs` | ✅ Present |
| HTTP | `protocol/http` | `sb-adapters/src/inbound/http.rs` | ✅ Present |
| SOCKS | `protocol/socks` | `sb-adapters/src/inbound/socks/` | ✅ Present |
| Mixed | `protocol/mixed` | `sb-adapters/src/inbound/mixed.rs` | ✅ Present |
| Naive | `protocol/naive` | `sb-adapters/src/inbound/naive.rs` | ✅ Present |
| Redirect | `protocol/redirect` | `sb-adapters/src/inbound/redirect.rs` | ✅ Present |
| TProxy | (linux only) | `sb-adapters/src/inbound/tproxy.rs` | ✅ Present |
| Shadowsocks | `protocol/shadowsocks` | `sb-adapters/src/inbound/shadowsocks.rs` | ✅ Present |
| ShadowTLS | `protocol/shadowtls` | `sb-adapters/src/inbound/shadowtls.rs` | ✅ Present |
| Trojan | `protocol/trojan` | `sb-adapters/src/inbound/trojan.rs` | ✅ Present |
| VMess | `protocol/vmess` | `sb-adapters/src/inbound/vmess.rs` | ✅ Present |
| VLESS | `protocol/vless` | `sb-adapters/src/inbound/vless.rs` | ✅ Present |
| Hysteria | `protocol/hysteria` | `sb-adapters/src/inbound/hysteria.rs` | ✅ Present |
| Hysteria2 | `protocol/hysteria2` | `sb-adapters/src/inbound/hysteria2.rs` | ✅ Present |
| TUIC | `protocol/tuic` | `sb-adapters/src/inbound/tuic.rs` | ✅ Present |
| AnyTLS | `protocol/anytls` | `sb-adapters/src/inbound/anytls.rs` | ✅ Present |
| TUN | `protocol/tun` | `sb-adapters/src/inbound/tun/` | ✅ Present |
| SSH | `protocol/ssh` | `sb-adapters/src/inbound/ssh.rs` | ✅ Present |
| TUN Enhanced | — | `sb-adapters/src/inbound/tun_enhanced.rs` | ➕ Rust-only |
| TUN macOS | — | `sb-adapters/src/inbound/tun_macos.rs` | ➕ Rust-only |

---

## Protocol Adapters — Outbound (23 Go → 23 Rust)

| Protocol | Go Path | Rust Path | Status |
| --- | --- | --- | --- |
| Direct | `protocol/direct` | `sb-adapters/src/outbound/direct.rs` | ✅ Present |
| Block | `protocol/block` | `sb-adapters/src/outbound/block.rs` | ✅ Present |
| DNS | `protocol/dns` | `sb-adapters/src/outbound/dns.rs` | ✅ Present |
| HTTP | `protocol/http` | `sb-adapters/src/outbound/http.rs` | ✅ Present |
| SOCKS4 | `protocol/socks` | `sb-adapters/src/outbound/socks4.rs` | ✅ Present |
| SOCKS5 | `protocol/socks` | `sb-adapters/src/outbound/socks5.rs` | ✅ Present |
| Shadowsocks | `protocol/shadowsocks` | `sb-adapters/src/outbound/shadowsocks.rs` | ✅ Present |
| ShadowsocksR | (removed in Go) | `sb-adapters/src/outbound/shadowsocksr/` | ✅ Restored |
| ShadowTLS | `protocol/shadowtls` | `sb-adapters/src/outbound/shadowtls.rs` | ✅ Present |
| Trojan | `protocol/trojan` | `sb-adapters/src/outbound/trojan.rs` | ✅ Present |
| VMess | `protocol/vmess` | `sb-adapters/src/outbound/vmess.rs` | ✅ Present |
| VLESS | `protocol/vless` | `sb-adapters/src/outbound/vless.rs` | ✅ Present |
| Hysteria | `protocol/hysteria` | `sb-adapters/src/outbound/hysteria.rs` | ✅ Present |
| Hysteria2 | `protocol/hysteria2` | `sb-adapters/src/outbound/hysteria2.rs` | ✅ Present |
| TUIC | `protocol/tuic` | `sb-adapters/src/outbound/tuic.rs` | ✅ Present |
| AnyTLS | `protocol/anytls` | `sb-adapters/src/outbound/anytls.rs` | ✅ Present |
| WireGuard | `protocol/wireguard` | `sb-adapters/src/outbound/wireguard.rs` | ✅ Present |
| Tailscale | `protocol/tailscale` | `sb-adapters/src/outbound/tailscale.rs` | ✅ Present |
| Tor | `protocol/tor` | `sb-adapters/src/outbound/tor.rs` | ✅ Present |
| SSH | `protocol/ssh` | `sb-adapters/src/outbound/ssh.rs` | ✅ Present |
| Selector | `protocol/group` | `sb-adapters/src/outbound/selector.rs` | ✅ Present |
| URLTest | `protocol/group` | `sb-adapters/src/outbound/urltest.rs` | ✅ Present |

---

## Transport Layer (11 Go → 15 Rust)

| Transport | Go Path | Rust Path | Status |
| --- | --- | --- | --- |
| WebSocket | `transport/v2raywebsocket` | `sb-transport/src/websocket.rs` | ✅ Present |
| HTTP/2 | `transport/v2rayhttp` | `sb-transport/src/http2.rs` | ✅ Present |
| gRPC | `transport/v2raygrpc` | `sb-transport/src/grpc.rs` | ✅ Present |
| gRPC Lite | `transport/v2raygrpclite` | `sb-transport/src/grpc_lite.rs` | ✅ Present |
| QUIC | `transport/v2rayquic` | `sb-transport/src/quic.rs` | ✅ Present |
| HTTP Upgrade | `transport/v2rayhttpupgrade` | `sb-transport/src/httpupgrade.rs` | ✅ Present |
| Simple-Obfs | `transport/simple-obfs` | `sb-transport/src/simple_obfs.rs` | ✅ Present |
| SIP003 | `transport/sip003` | `sb-transport/src/sip003.rs` | ✅ Present |
| Trojan | `transport/trojan` | `sb-transport/src/trojan.rs` | ✅ Present |
| WireGuard | `transport/wireguard` | `sb-transport/src/wireguard.rs` | ✅ Present |
| UDP over TCP | (in common/) | `sb-transport/src/uot.rs` | ✅ Present |
| Multiplex | (in common/) | `sb-transport/src/multiplex.rs` | ✅ Present |
| TLS | (in common/) | `sb-transport/src/tls.rs` | ✅ Present |
| Circuit Breaker | — | `sb-transport/src/circuit_breaker.rs` | ➕ Rust-only |
| DERP | — | `sb-transport/src/derp/` | ➕ Rust-only |

---

## Routing & Rules (38 Go → 43+ Rust)

All 38 Go rule items in `route/rule/` are implemented. Rule types:
- domain, domain_regex, domain_keyword, domain_suffix
- ip_cidr, ip_accept_any, source_ip_cidr
- port, port_range, source_port, source_port_range
- network, network_type, network_is_constrained
- protocol, user, inbound, outbound
- geoip, geosite, rule_set, rule_set_local, rule_set_remote
- process_name, process_path, process_path_regex
- package_name (android)
- wifi_ssid, wifi_bssid
- clash_mode, query_type

No regression detected in this pass.

---

## Endpoint System (WireGuard/Tailscale)

| Component | Go Path | Rust Path | Status | Notes |
| --- | --- | --- | --- | --- |
| Endpoint Registry/Manager | `adapter/endpoint/manager.go` (145 LOC) | `sb-core/src/endpoint/mod.rs` | ⚠️ | Lifecycle start/close executed for all endpoints; manager API parity good. |
| WireGuard Endpoint | `protocol/wireguard/endpoint.go` (~200 LOC) | `sb-core/src/endpoint/wireguard.rs` (180 LOC) | ⚠️ | Instantiates sb-transport peers; **missing**: dial/listen router integration, DNS hooks, multi-peer routing, local address handling. |
| Tailscale Endpoint | `protocol/tailscale/endpoint.go` (~400 LOC) | `sb-core/src/endpoint/tailscale.rs` (248 LOC) | ❌ | Stub lifecycle only; **missing**: tsnet/wgengine control plane, stack-based dial/listen, DNS/netmon integration, filter checks. |
| Endpoint Stubs | — | `sb-adapters/src/endpoint_stubs.rs` | ⚠️ | Returns "not implemented"; used as placeholder. |

### Go WireGuard Endpoint Features (missing in Rust)

1. `DialContext(ctx, network, destination)` — Dials through WireGuard tunnel with DNS resolution for FQDNs
2. `ListenPacket(ctx, destination)` — UDP listener through tunnel
3. `PrepareConnection(network, source, destination)` — Pre-match routing
4. `NewConnectionEx/NewPacketConnectionEx` — Router integration for inbound traffic
5. Multi-peer routing with allowed_ips matching
6. Local address handling for loopback

### Go Tailscale Endpoint Features (missing in Rust)

1. tsnet.Server with gVisor stack
2. Control plane authentication (auth_key, ephemeral, advertise routes)
3. DNS configuration via dnsConfigurtor
4. Filter for tailscale policy enforcement
5. netmon interface getter registration
6. DialContext/ListenPacket via gonet TCP/UDP

---

## DNS System (10 Go files → 28+ Rust files)

| Component | Go Path | Rust Path | Status |
| --- | --- | --- | --- |
| Client | `dns/client.go` | `sb-core/src/dns/client.rs` | ✅ Present |
| Router | `dns/router.go` | `sb-core/src/dns/router.rs` | ✅ Present |
| Transport Manager | `dns/transport_manager.go` | `sb-core/src/dns/upstream.rs` | ✅ Present |
| Transport Adapter | `dns/transport_adapter.go` | `sb-core/src/dns/transport/mod.rs` | ✅ Present |
| Transport Dialer | `dns/transport_dialer.go` | `sb-core/src/dns/transport/mod.rs` | ✅ Present |
| UDP Transport | `dns/transport/udp.go` | `sb-core/src/dns/transport/udp.rs` | ✅ Present |
| TCP Transport | `dns/transport/tcp.go` | `sb-core/src/dns/transport/tcp.rs` | ✅ Present |
| DoH Transport | `dns/transport/https.go` | `sb-core/src/dns/transport/doh.rs` | ✅ Present |
| DoT Transport | `dns/transport/tls.go` | `sb-core/src/dns/transport/dot.rs` | ✅ Present |
| DoQ Transport | `dns/transport/quic/` | `sb-core/src/dns/transport/doq.rs` | ✅ Present |
| DoH3 Transport | — | `sb-core/src/dns/transport/doh3.rs` | ➕ Rust-only |
| FakeIP | `dns/transport/fakeip/` | `sb-core/src/dns/fakeip.rs` | ✅ Present |
| Hosts | `dns/transport/hosts/` | `sb-core/src/dns/hosts.rs` | ✅ Present |
| Local | `dns/transport/local/` | `sb-core/src/dns/transport/local.rs` | ✅ Present |
| DHCP | `dns/transport/dhcp/` (2 files) | `sb-core/src/dns/upstream.rs` | ⚠️ Passive only (no DHCPDISCOVER) |
| Resolved transport | `service/resolved/transport.go` (~200 LOC) | — | ❌ Missing (no per-link/DoT routing) |

---

## Services / Experimental

| Component | Go Path | Rust Path | Status |
| --- | --- | --- | --- |
| Clash API Server | `experimental/clashapi/server.go` | `sb-core/src/services/clash_api.rs` | ✅ Present |
| V2Ray API | `experimental/v2rayapi/` | `sb-core/src/services/v2ray_api.rs` | ✅ Present |
| Cache File | `experimental/cachefile/` | `sb-core/src/services/cache_file.rs` | ✅ Present |
| NTP Service | — | `sb-core/src/services/ntp.rs` | ✅ Present |
| DERP Service | `service/derp/` | `sb-core/src/services/derp/` | ✅ Present |
| Tailscale Service | — | `sb-core/src/services/tailscale/` | ➕ Rust-only |
| Resolved Service | `service/resolved/service.go` (~200 LOC) | `sb-core/src/services/resolved.rs` | ⚠️ UDP stub only |
| Resolved Service (D-Bus) | `service/resolved/resolve1.go` (~450 LOC) | `sb-adapters/src/service/resolved_impl.rs` | ⚠️ Linux ResolveHostname only; no per-link/DoT/netmon |
| SSM API | `service/ssmapi/` | `sb-core/src/services/ssmapi/` | ✅ Present |

### Go Resolved Service Features (missing in Rust)

1. **resolve1 D-Bus Object** — Exports full org.freedesktop.resolve1.Manager API
2. **Per-link DNS tracking** — `TransportLink` with address, addressEx, domain, dnsOverTLS
3. **Network monitor callbacks** — Updates DNS sources on interface changes
4. **DoT support** — Creates TLS transports when dnsOverTLS is set
5. **`dns/transport/resolved`** — Separate transport type consuming service data with:
   - Per-link server selection based on domain matching
   - rotate/ndots semantics
   - Parallel exchange for A/AAAA
   - Name list generation (search domains)

---

## Common Utilities

| Go Module | Rust Location | Status |
| --- | --- | --- |
| `common/badtls` (3 files) | `sb-common/src/badtls.rs` | ⚠️ Passive analyzer (not ReadWaitConn) |
| `common/compatible` | `sb-common/src/compatible.rs` | ✅ Present |
| `common/conntrack` | `sb-common/src/conntrack.rs` | ✅ Present |
| `common/convertor` | `sb-common/src/convertor.rs` | ✅ Present |
| `common/interrupt` | `sb-common/src/interrupt.rs` | ✅ Present |
| `common/ja3` | `sb-common/src/ja3.rs` | ✅ Present |
| `common/pipelistener` | `sb-common/src/pipelistener.rs` | ✅ Present |
| `common/tlsfragment` | `sb-common/src/tlsfrag.rs` | ✅ Present |
| `common/uot` | `sb-transport/src/uot.rs` | ✅ Present |
| `common/mux` | `sb-transport/src/multiplex.rs` | ✅ Present |
| `common/sniff` | `sb-core/src/router/sniff.rs` | ✅ Present |
| `common/process` | `sb-platform/src/process/` | ✅ Present |
| `common/settings` | `sb-platform/src/system_proxy.rs` | ✅ Present |

---

## TLS & Security

| Component | Go Path | Rust Path | Status |
| --- | --- | --- | --- |
| Standard TLS | `common/tls` | `sb-tls/src/standard.rs` | ✅ Present |
| uTLS | (external) | `sb-tls/src/utls.rs` | ✅ Present |
| REALITY | (external) | `sb-tls/src/reality/` | ✅ Present |
| ECH | (external) | `sb-tls/src/ech/` | ✅ Present |
| ACME | `option/tls_acme.go` | `sb-tls/src/acme.rs` | ✅ Present |
| TLS Fragment | `common/tlsfragment` | `sb-common/src/tlsfrag.rs` | ✅ Present |
| Bad TLS | `common/badtls` | `sb-common/src/badtls.rs` | ⚠️ Passive |

---

## Configuration Options

| Go Option File | Rust Coverage | Notes |
| --- | --- | --- |
| `option/options.go` | ✅ `sb-config/src/lib.rs` | Main config structure |
| `option/inbound.go` | ✅ `sb-config/src/inbound.rs` | All inbound options |
| `option/outbound.go` | ✅ `sb-config/src/outbound.rs` | All outbound options |
| `option/route.go` | ✅ `sb-config/src/rule/` | Route config |
| `option/rule.go` | ✅ `sb-config/src/rule/` | Rule items |
| `option/rule_dns.go` | ✅ `sb-config/src/rule/` | DNS rules |
| `option/rule_action.go` | ✅ `sb-config/src/rule/` | Rule actions |
| `option/rule_set.go` | ✅ `sb-config/src/rule/` | Rule sets |
| `option/dns.go` | ✅ `sb-config/src/lib.rs` | DNS options |
| `option/tls.go` | ✅ `sb-config/src/lib.rs` | TLS options |
| `option/tls_acme.go` | ✅ `sb-config/src/acme_config.rs` | ACME options |
| `option/wireguard.go` | ✅ `sb-config/src/ir/mod.rs` | WireGuard config |
| `option/tailscale.go` | ✅ `sb-config/src/ir/mod.rs` | Tailscale config |
| `option/shadowsocksr.go` | ✅ `sb-config/src/ir/mod.rs` | ShadowsocksR config |
| `option/udp_over_tcp.go` | ✅ `sb-config/src/lib.rs` | UoT config |
| `option/multiplex.go` | ✅ `sb-config/src/lib.rs` | Multiplex config |
| `option/v2ray_transport.go` | ✅ `sb-config/src/lib.rs` | V2Ray transport config |
| `option/platform.go` | ✅ `sb-config/src/lib.rs` | Platform options |
| `option/experimental.go` | ✅ | All fields mapped (cache/clash/v2ray/debug); runtime pprof remains stubbed. |
| `option/debug.go` | ⚠️ | Config fields mapped; listen → SB_DEBUG_ADDR/SB_PPROF/FREQ/MAX_SEC, but no Go-equivalent pprof/GC behavior. |

---

## Detailed Implementation Comparisons

### Endpoint System

**Go (`adapter/endpoint/manager.go` + `protocol/wireguard/endpoint.go` + `protocol/tailscale/endpoint.go`):**
- Manager executes full lifecycle stages (`StartStateStart`, `StartStatePostStart`) and maintains endpoint registry
- WireGuard endpoint creates gVisor-based tunnel with:
  - DNS resolver integration (`dnsRouter.Lookup`)
  - Full dial/listen methods (TCP/UDP through tunnel)
  - Connection routing via `router.RouteConnectionEx`
  - Multi-peer selection based on allowed_ips
- Tailscale endpoint creates tsnet.Server with:
  - gVisor network stack (gonet.DialContextTCP/UDP)
  - Filter policy enforcement
  - netmon integration
  - DNS configurator

**Rust (`sb-core/src/endpoint/{mod,wireguard,tailscale}.rs`):**
- Manager runs lifecycle stages and holds endpoint registry (✅ parity)
- WireGuard endpoint instantiates sb-transport peers but:
  - ❌ No `DialContext/ListenPacket` methods exposed
  - ❌ No router integration (`RouteConnectionEx`)
  - ⚠️ Partial multi-peer selection (select_peer exists but unused)
- Tailscale endpoint is stub:
  - ❌ No tsnet/wgengine
  - ❌ No control plane auth
  - ❌ No stack-based networking

### Resolved Service & Transport

**Go (`service/resolved/service.go` + `resolve1.go` + `transport.go`):**
- D-Bus service exports full resolve1 API:
  - `SetLinkDNS`, `SetLinkDNSEx`, `SetLinkDomains`, `SetLinkDefaultRoute`, `SetLinkDNSOverTLS`
  - Network monitor callback updates links on interface changes
  - Per-interface DNS tracking with `TransportLink`
- Transport (`dns/transport/resolved`) routes queries:
  - Domain matching against link domains
  - DoT fallback based on `dnsOverTLS` flag
  - Parallel exchange for A/AAAA
  - ndots/rotate semantics

**Rust (`sb-core/src/services/resolved.rs` + `sb-adapters/src/service/resolved_impl.rs`):**
- Core `resolved.rs`: Simple UDP DNS stub using global resolver
- Adapters `resolved_impl.rs`: Linux D-Bus client (not server!) calling systemd-resolved's ResolveHostname
  - ⚠️ Client mode only (queries systemd-resolved, doesn't replace it)
  - ❌ No per-link DNS tracking
  - ❌ No DoT support
  - ❌ No `dns/transport/resolved` equivalent

### Debug / pprof

**Go (`debug.go` + `debug_http.go` + `option/debug.go`):**
- Options: GCPercent, MaxStack, MaxThreads, PanicOnFault, TraceBack, MemoryLimit, OOMKiller
- `applyDebugOptions`: Calls `runtime/debug.Set*` functions
- HTTP endpoints: `/debug/gc`, `/debug/memory`, `/debug/pprof/*`

**Rust:**
- Config options mapped to env vars (SB_DEBUG_ADDR, SB_PPROF, etc.)
- admin_debug binds to address but no pprof handlers
- sb-explaind `/debug/pprof` returns placeholder SVG
- GC/stack/thread/memory options recorded but no runtime effect

### DHCP DNS

**Go (`dns/transport/dhcp/dhcp.go`):**
- Sends DHCPDISCOVER packets to discover DNS servers
- Maintains pool of discovered servers

**Rust:**
- Watches `/etc/resolv.conf` only
- `system` alias for platform resolver

### BadTLS

**Go (`common/badtls/read_wait.go`):**
- `ReadWaitConn` wraps connection for uTLS handshake inspection
- Buffers data for analysis before passing through

**Rust (`sb-common/src/badtls.rs`):**
- `TlsAnalyzer` passive bytecode parser
- No connection wrapper (rustls handles buffering)

---

## Summary Statistics

| Category | Coverage |
| --- | --- |
| Protocol Inbound | 100% (+2 Rust extras) |
| Protocol Outbound | 100% |
| Transports | 100% (+ Rust extras) |
| Rule Items | 100% (38/38) |
| DNS Components | ~88% (resolved per-link/DoT/transport missing; DHCP passive) |
| Endpoint System | ~50% (manager wired; WireGuard partial; Tailscale stub) |
| Services | ~85% (resolved gap) |
| Config Options | 100% (runtime pprof stub) |
| Common Utilities | ~90% (badtls) |
| Debug/Observability | ~55% (env wired; pprof placeholder) |

---

## File Count Comparison

| Area | Go Files | Rust Files | Notes |
| --- | --- | --- | --- |
| Protocol | 23 protocol dirs | 47+ inbound/outbound files | Rust has modular split |
| Transport | 11 transport dirs | 28 transport files | Rust adds extras |
| Route/Rule | 38 rule files | 43+ router files | Rust has additional helpers |
| DNS | 10 dns files + 5 transport | 27 dns files + 9 transport | Rust has enhanced features |
| Option | 47 option files | ~20 config files | Rust uses fewer, larger modules |
| Common | 24 common dirs | 9 sb-common files | Some moved to sb-platform |
