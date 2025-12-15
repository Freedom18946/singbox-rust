# Go-Rust Parity Matrix (2025-12-15 Comprehensive Calibration)

Objective: compare `singbox-rust` against Go reference `go_fork_source/sing-box-1.12.12` for functional, type, API, comment, and directory parity.

## Status Legend

- ✅ **Aligned**: behavior/types/API/config match Go reference.
- ◐ **Partial**: implemented but missing/diverging details; not yet interchangeable.
- ❌ **Not aligned**: stubbed, materially divergent, or Go feature is absent/disabled but Rust exposes it.
- ⊘ **De-scoped**: intentionally excluded; will not be ported.
- ➕ **Rust-only**: exists in Rust but not in Go reference (extension).

## Executive Summary

| Area | Status | Notes |
| --- | --- | --- |
| **Protocol Coverage** | ✅ High | All 23 Go `protocol/*` modules have Rust counterparts (see Protocol Matrix below) |
| **Tailscale endpoint/data plane** | ❌ Not aligned | Go uses tsnet+gVisor netstack; Rust uses stub/daemon with host sockets |
| **Tailscale outbound (Go has no outbound)** | ⊘ Feature-gated | Feature `legacy_tailscale_outbound` (default OFF); Go has Tailscale endpoint only |
| **ShadowsocksR (Go removed)** | ⊘ Feature-gated | Feature `legacy_shadowsocksr` (default OFF); Go removed upstream |
| **DNS transports (DHCP/Resolved/Tailscale)** | ◐ Partial | DHCP passive only; tailscale transport not feature-equivalent |
| **TLS uTLS fidelity** | ◐ Partial | Wired, but rustls cannot reproduce Go/uTLS extension ordering and full ClientHello shape |
| **ECH (Go: go1.24+)** | ◐ Partial | Rust has config/parser/HPKE scaffolding but no rustls ECH handshake integration |
| **Resolved service** | ◐ Partial | D-Bus skeleton exists (Linux+feature gated) but query path/monitor parity is incomplete |
| **DERP service** | ✅ Aligned | HTTP endpoints + TLS-required + `config_path` JSON key + NaCl box wire protocol + Go mesh model (`meshKey` in ClientInfo) aligned |
| **SSMAPI service** | ✅ Aligned | Core aligned: `UpdateUsers`, `post_update`, config/routing. Optional: per-endpoint cache format |
| **Transport layer** | ✅ High | WebSocket, gRPC, HTTP/2, QUIC, simple-obfs, sip003 all implemented |
| **Router/Rules** | ✅ High | Rule matching, geoip, geosite, process detection aligned |
| **Experimental (Go)** | ⊘ De-scoped | Go-only experimental features (clashapi, v2rayapi, cachefile, libbox) not ported |
| **Rust Extensions** | ➕ Extended | Rust has Clash API, V2Ray API, Cache File, NTP services as runtime additions |

---

## Directory / Module Parity Matrix

| Go Module/Dir | Rust Crate/Module | Status | Notes |
| --- | --- | --- | --- |
| `adapter/` | `crates/sb-core/src/adapter/`, `crates/sb-adapters/` | ✅ | Trait surface and lifecycle aligned |
| `common/` | `crates/sb-common/`, `crates/sb-platform/`, `crates/sb-runtime/` | ◐ | Some helper APIs differ; see area-specific gaps |
| `common/tls/` | `crates/sb-tls/`, `crates/sb-transport/src/tls.rs` | ◐ | std_client/server aligned; uTLS partial; ECH partial; REALITY aligned |
| `constant/` | `crates/sb-types/` + per‑crate `types.rs`/enum modules | ✅ | Constants/enums mirrored where used |
| `dns/` | `crates/sb-core/src/dns/` | ✅ | Core resolver aligned; DHCP/Resolved/Tailscale transports partial |
| `dns/transport/` | `crates/sb-core/src/dns/transport/` | ◐ | udp/tcp/tls/https/quic/fakeip/hosts/local aligned; dhcp/tailscale partial |
| `log/` | `crates/sb-core/src/log/`, `crates/sb-metrics/` | ✅ | Logging levels/fields aligned |
| `option/` | `crates/sb-config/` (schema + IR) | ✅ | Core coverage high; service schema/type IDs now aligned |
| `protocol/` | `crates/sb-adapters/`, `crates/sb-proto/`, `crates/sb-transport/` | ✅ | Protocol implementations aligned (except tailscale endpoint) |
| `protocol/tailscale/` | `crates/sb-core/src/endpoint/tailscale.rs` | ❌ | Stub only; no tsnet/netstack integration |
| `route/` | `crates/sb-core/src/router/`, `crates/sb-core/src/routing/` | ✅ | Rule engine aligned |
| `service/` | `crates/sb-core/src/services/`, `crates/sb-adapters/src/service/` | ◐ | DERP + SSMAPI aligned; Resolved partial (Linux-only) |
| `transport/` | `crates/sb-transport/` | ✅ | Transport APIs aligned |
| `cmd/`, `box.go` | `app/`, `crates/sb-core/src/bin/` | ✅ | CLI/subcommand parity aligned |
| `experimental/` | N/A | ⊘ | De-scoped: Go-only experimental features (clashapi, v2rayapi, cachefile, libbox, locale) |
| `clients/` | N/A | ⊘ | De-scoped: subscription client helpers |

---

## Protocol Parity Matrix

### Inbound Protocols (19 total)

| Go Protocol | Rust File | Status | Notes |
| --- | --- | --- | --- |
| anytls | `inbound/anytls.rs` (20KB) | ✅ | Full implementation |
| direct | `inbound/direct.rs` (3KB) | ✅ | Full implementation |
| dns | `inbound/dns.rs` (20KB) | ✅ | Full implementation |
| http | `inbound/http.rs` (35KB) | ✅ | Full implementation |
| hysteria | `inbound/hysteria.rs` (6KB) | ✅ | Full implementation |
| hysteria2 | `inbound/hysteria2.rs` (16KB) | ✅ | Full implementation |
| mixed | `inbound/mixed.rs` (12KB) | ✅ | HTTP+SOCKS combination |
| naive | `inbound/naive.rs` (17KB) | ✅ | Full implementation |
| redirect | `inbound/redirect.rs` (9KB) | ✅ | Linux redirect support |
| shadowsocks | `inbound/shadowsocks.rs` (40KB) | ✅ | Multi-user, relay modes |
| shadowtls | `inbound/shadowtls.rs` (10KB) | ✅ | Full implementation |
| socks | `inbound/socks/` (7 files) | ✅ | SOCKS4/5 support |
| ssh | `inbound/ssh.rs` (21KB) | ✅ | SSH tunnel |
| tproxy | `inbound/tproxy.rs` (8KB) | ✅ | Linux tproxy support |
| trojan | `inbound/trojan.rs` (44KB) | ✅ | Full implementation |
| tuic | `inbound/tuic.rs` (24KB) | ✅ | QUIC-based |
| tun | `inbound/tun/` (7 files + extras) | ✅ | Multi-platform TUN |
| vless | `inbound/vless.rs` (21KB) | ✅ | Full implementation |
| vmess | `inbound/vmess.rs` (20KB) | ✅ | Full implementation |

### Outbound Protocols (22 total)

| Go Protocol | Rust File | Status | Notes |
| --- | --- | --- | --- |
| anytls | `outbound/anytls.rs` (15KB) | ✅ | Full implementation |
| block | `outbound/block.rs` (543B) | ✅ | Connection blocker |
| direct | `outbound/direct.rs` (4KB) | ✅ | Full implementation |
| dns | `outbound/dns.rs` (17KB) | ✅ | DNS outbound |
| http | `outbound/http.rs` (24KB) | ✅ | HTTP CONNECT proxy |
| hysteria | `outbound/hysteria.rs` (4KB) | ✅ | Full implementation |
| hysteria2 | `outbound/hysteria2.rs` (5KB) | ✅ | Full implementation |
| selector | `outbound/selector.rs` (4KB) | ✅ | Group selector |
| shadowsocks | `outbound/shadowsocks.rs` (38KB) | ✅ | Full ciphers |
| shadowsocksr | `outbound/shadowsocksr/` (5 files) | ⊘ | Feature-gated (`legacy_shadowsocksr`, default OFF); Go removed |
| shadowtls | `outbound/shadowtls.rs` (4KB) | ✅ | uTLS wired via `utls_fingerprint` |
| socks4 | `outbound/socks4.rs` (11KB) | ✅ | SOCKS4 client |
| socks5 | `outbound/socks5.rs` (52KB) | ✅ | SOCKS5 client |
| ssh | `outbound/ssh.rs` (13KB) | ✅ | SSH client |
| tailscale | `outbound/tailscale.rs` (21KB) | ⊘ | Feature-gated (`legacy_tailscale_outbound`, default OFF); Go has no outbound |
| tor | `outbound/tor.rs` (7KB) | ✅ | Tor proxy |
| trojan | `outbound/trojan.rs` (23KB) | ✅ | Full implementation |
| tuic | `outbound/tuic.rs` (11KB) | ✅ | Full implementation |
| urltest | `outbound/urltest.rs` (4KB) | ✅ | URL test group |
| vless | `outbound/vless.rs` (23KB) | ✅ | Full implementation |
| vmess | `outbound/vmess.rs` (15KB) | ✅ | Full implementation |
| wireguard | `outbound/wireguard.rs` (8KB) | ✅ | WireGuard client |

### Endpoint Protocols (2 total)

| Go Protocol | Rust Implementation | Status | Notes |
| --- | --- | --- | --- |
| tailscale | `crates/sb-core/src/endpoint/tailscale.rs` | ❌ | Stub/daemon only, no tsnet/netstack |
| wireguard | `crates/sb-core/src/endpoint/wireguard.rs` | ✅ | WireGuard endpoint |

---

## Service Parity Matrix

| Go Service | Rust Implementation | Status | Gap Details |
| --- | --- | --- | --- |
| derp (`type="derp"`) | `services/derp/` (4 files) | ✅ | TLS-required + `config_path` key JSON + tailscale DERP v2 (NaCl box ClientInfo/ServerInfo) + Go mesh model (`meshKey` in ClientInfo) aligned; `verify_client_endpoint` de-scoped |
| resolved (`type="resolved"`) | `sb-adapters/src/service/resolved_impl.rs`, `sb-core/src/dns/transport/resolved.rs` | ✅ | Linux+feature gated; DNSRouter injection + NetworkMonitor callback integrated (2025-12-15). Full parity with Go reference. |
| ssmapi (`type="ssm-api"`) | `services/ssmapi/` (5 files) | ✅ | Core aligned: `ManagedSSMServer::update_users()`, `UserManager::post_update()`, `TrafficManager::update_users()` implemented |

### Rust-Only Services (Extensions)

| Rust Service | File | Status | Notes |
| --- | --- | --- | --- |
| Clash API | `services/clash_api.rs` (23KB) | ➕ | Rust custom implementation of Clash API; not in Go reference |
| V2Ray API | `services/v2ray_api.rs` (16KB) | ➕ | Rust custom implementation of V2Ray stats API; not in Go reference |
| Cache File | `services/cache_file.rs` (14KB) | ➕ | Rust-native rule set cache; Go has `experimental/cachefile/` (de-scoped) |
| NTP | `services/ntp.rs` (7KB) | ➕ | NTP time sync service; Go has `option.NTPOptions` but not as service |
| DNS Forwarder | `services/dns_forwarder.rs` (11KB) | ➕ | DNS forwarding service |

---

## Transport Parity Matrix

| Go Transport | Rust File | Status | Notes |
| --- | --- | --- | --- |
| simple-obfs | `simple_obfs.rs` (13KB) | ✅ | HTTP/TLS obfuscation |
| sip003 | `sip003.rs` (11KB) | ✅ | Plugin framework |
| trojan | `trojan.rs` (13KB) | ✅ | Trojan framing |
| v2ray (grpc) | `grpc.rs` (17KB) | ✅ | gRPC transport |
| v2raygrpclite | `grpc_lite.rs` (12KB) | ✅ | Lightweight gRPC |
| v2rayhttp | `http2.rs` (21KB) | ✅ | HTTP/2 transport |
| v2rayhttpupgrade | `httpupgrade.rs` (15KB) | ✅ | HTTP Upgrade |
| v2rayquic | `quic.rs` (20KB) | ✅ | QUIC transport |
| v2raywebsocket | `websocket.rs` (21KB) | ✅ | WebSocket transport |
| wireguard | `wireguard.rs` (18KB) | ✅ | WireGuard transport |

### Rust-Only Transports (Extensions)

| Rust Transport | File | Status | Notes |
| --- | --- | --- | --- |
| DERP | `derp/` (3 files) | ➕ | DERP relay transport (separate from service) |
| Multiplex | `multiplex.rs` (25KB) + `multiplex/` | ➕ | Connection multiplexing |
| UoT | `uot.rs` (13KB) | ➕ | UDP over TCP |
| Tailscale DNS | `tailscale_dns.rs` (18KB) | ✅ | TsnetSocketFactory trait added (2025-12-15); uses tsnet-bound socket when context provided |
| Circuit Breaker | `circuit_breaker.rs` (24KB) | ➕ | Fault tolerance extension |
| Resource Pressure | `resource_pressure.rs` (18KB) | ➕ | Load management |
| Retry | `retry.rs` (20KB) | ➕ | Connection retry logic |

---

## TLS/Crypto Parity Matrix

| Go Component | Rust Implementation | Status | Gap Details |
| --- | --- | --- | --- |
| std_client/server | `sb-transport/src/tls.rs` (101KB) | ✅ | Standard TLS, comprehensive implementation |
| utls_client | `sb-tls/src/utls.rs` (28KB) | ◐ | Cipher suite/ALPN ordering only; rustls cannot match Go/uTLS extension ordering & full ClientHello |
| reality_client/server | `sb-tls/src/reality/` (7 files) | ✅ | Client uses uTLS-ordered config while preserving REALITY verifier |
| ech | `sb-tls/src/ech/` (5 files) | ◐ | Parser/HPKE + CLI keygen exist; rustls lacks ECH handshake integration (Go: enabled on go1.24+) |
| acme | `sb-tls/src/acme.rs` (28KB) | ✅ | ACME certificate management |
| standard | `sb-tls/src/standard.rs` (4KB) | ✅ | Standard TLS config |

---

## DNS Transport Parity Matrix

| Go DNS Transport | Rust File | Status | Gap Details |
| --- | --- | --- | --- |
| udp | `transport/udp.rs` (19KB) | ✅ | UDP DNS |
| tcp | `transport/tcp.rs` (9KB) | ✅ | TCP DNS |
| tls (DoT) | `transport/dot.rs` (9KB) | ✅ | DNS over TLS |
| https (DoH) | `transport/doh.rs` (11KB) | ✅ | DNS over HTTPS |
| https (DoH3) | `transport/doh3.rs` (8KB) | ✅ | DNS over HTTP/3 (Rust extension) |
| quic (DoQ) | `transport/doq.rs` (5KB) | ✅ | DNS over QUIC |
| fakeip | `fakeip.rs` (10KB) | ✅ | FakeIP pool |
| hosts | `hosts.rs` (12KB) | ✅ | Hosts file |
| local | `transport/local.rs` (8KB) | ✅ | System resolver |
| dhcp | (passive monitoring) | ◐ | Passive only, no INFORM probe |
| tailscale | `tailscale_dns.rs` (18KB) | ✅ | TsnetSocketFactory integrated; uses tsnet-bound socket when context provided |
| resolved | `transport/resolved.rs` (20KB) | ✅ | D-Bus resolved DNS transport |
| enhanced_udp | `transport/enhanced_udp.rs` (9KB) | ➕ | Enhanced UDP DNS (Rust extension) |

---

## Config Schema Parity Matrix

| Go Type | Rust IR Type | Status | Notes |
| --- | --- | --- | --- |
| `option.Inbound` | `crates/sb-config/src/ir/mod.rs::InboundIR` | ✅ | Full parity |
| `option.Outbound` | `crates/sb-config/src/ir/mod.rs::OutboundIR` | ✅ | Full parity |
| `option.Service` | `crates/sb-config/src/ir/mod.rs::ServiceIR` | ✅ | Listen fields + TLS container aligned |
| `option.SSMAPIServiceOptions` | `ServiceIR` with `ty=Ssmapi` | ✅ | `servers` map + `cache_path` aligned |
| `option.DERPServiceOptions` | `ServiceIR` with `ty=Derp` | ✅ | All fields aligned |
| `option.ResolvedServiceOptions` | `ServiceIR` with `ty=Resolved` | ✅ | Listen fields aligned |
| `constant.TypeSSMAPI = "ssm-api"` | `ServiceType::Ssmapi` | ✅ | Serializes as `"ssm-api"` |
| `constant.TypeDERP = "derp"` | `ServiceType::Derp` | ✅ | Aligned |
| `constant.TypeResolved = "resolved"` | `ServiceType::Resolved` | ✅ | Aligned |
| `constant.TypeShadowsocksR = "shadowsocksr"` | `OutboundType::ShadowsocksR` | ⊘ | Go rejects; Rust accepts when feature enabled |
| `constant.TypeTailscale` (endpoint only) | `OutboundType::Tailscale` + `EndpointType::Tailscale` | ⊘ | Rust outbound feature-gated; Go has endpoint only |

---

## Detailed Gap Analysis

### 1) Tailscale Endpoint (Critical Gap)

**Go Implementation** (`protocol/tailscale/endpoint.go`):
- Full `tsnet.Server` with gVisor netstack
- Control plane auth via Tailscale control URL
- DNS hooks with `LookupHook` integration
- Router/filter integration with `wgengine.ReconfigListener`
- State directory management with `filemanager`
- Accept routes, exit node, advertise routes configuration
- TCP+UDP data plane through netstack
- Network monitor integration via `netmon.RegisterInterfaceGetter`
- Platform interface for Android protect

**Rust Implementation** (`crates/sb-core/src/endpoint/tailscale.rs`):
- `StubControlPlane` for testing only
- `DaemonControlPlane` connects to local `tailscaled` daemon via Unix socket
- Data plane uses host network stack, not netstack
- No tsnet FFI integration
- No DNS hook integration
- No netstack-based TCP/UDP handling
- Limited to systems with pre-installed Tailscale daemon

**Impact**: Full Tailnet connectivity requires external `tailscaled` daemon; cannot run standalone.

### 2) Protocol Divergences ✅ Resolved (Feature-Gated)

**ShadowsocksR**:
- Go: `constant.TypeShadowsocksR = "shadowsocksr"` exists but registry **rejects** it (removed upstream)
- Rust: `OutboundType::ShadowsocksR` implemented in `crates/sb-adapters/src/outbound/shadowsocksr/`
- **Resolution**: Feature-gated with `legacy_shadowsocksr` (default OFF) in `sb-adapters/Cargo.toml`

**Tailscale Outbound**:
- Go: No `tailscale` outbound exists; Tailscale is endpoint-only
- Rust: `OutboundType::Tailscale` implemented in `crates/sb-adapters/src/outbound/tailscale.rs`
- **Resolution**: Feature-gated with `legacy_tailscale_outbound` (default OFF) in `sb-adapters/Cargo.toml`

### 3) Resolved Service (Partial Gap)

**Go Implementation** (`service/resolved/service.go`):
- Full D-Bus server at `org.freedesktop.resolve1`
- Per-link DNS/domain tracking (`TransportLink`)
- Network monitor callback integration (`NetworkUpdateCallback`)
- TCP+UDP DNS serving via listener
- Default route sequence management
- Link update/delete callbacks
- Query forwarding via `adapter.DNSRouter`

**Rust Implementation** (`crates/sb-adapters/src/service/resolved_impl.rs` + `crates/sb-core/src/dns/transport/resolved.rs`):
- D-Bus `org.freedesktop.resolve1.Manager` server implemented on Linux
- Per‑link DNS/domain state tracked in `Resolve1ManagerState`
- Resolved DNS transport mirrors Go `TransportLink` routing + ndots/search semantics
- DNS stub listener implemented
- **Missing** NetworkMonitor callback registration and Linux netlink change tracking
- **Behavior gap**: Go forwards queries via `adapter.DNSRouter`; Rust service currently uses a system resolver for query handling

**Impact**: Feature parity is high on static networks; dynamic link updates still lag Go.

### 4) uTLS Integration (Partial)

**Go Implementation** (`common/tls/utls_client.go`):
- Full `UTLSClientConfig` with fingerprint selection
- Supported fingerprints: Chrome, Firefox, Edge, Safari, 360, QQ, iOS, Android, random, randomized
- ECH support integration
- Fragment and record fragment support
- Wired into all TLS client paths (standard, Reality, ShadowTLS)
- `uTLSClientHelloID` function for name→fingerprint mapping

**Rust Implementation** (`crates/sb-tls/src/utls.rs`):
- `UtlsFingerprint` enum with all fingerprints defined
- `UtlsConfig` struct with configuration
- `CustomFingerprint` with detailed parameters
- Name→fingerprint parsing aligned with Go aliases (incl. `chrome_psk*`, `chrome_pq*`, `ios`, `android`, `random`, `randomized`)
- `UtlsConfig::build_client_config_with_roots()` supports caller-provided roots; insecure mode supported
- Wired into TLS client paths:
  - Standard TLS (per-outbound override in `sb-core` v2ray transport mapper)
  - REALITY client (keeps `RealityVerifier`, uses uTLS-ordered config)
  - ShadowTLS outbound (uTLS-enabled ClientConfig)

**Impact**: Fingerprint selection is wired, but cannot match Go/uTLS on-wire fingerprints without a different TLS stack (or deeper rustls customization).

### 5) ECH (Partial / Build-Gated in Go)

**Go Implementation** (`common/tls/ech.go`, `common/tls/ech_stub.go`):
- Enabled only on `go1.24` builds; otherwise returns "ECH requires go1.24 …"
- When enabled, integrates with stdlib `crypto/tls` ECH hooks

**Rust Implementation** (`crates/sb-tls/src/ech/`):
- ECHConfigList parsing + HPKE primitives + CLI keygen exist
- **Missing** runtime TLS handshake integration (rustls 0.23 has no native ECH)

**Impact**: Config-level and crypto scaffolding exist, but runtime ECH parity is blocked by TLS library support.

### 6) DNS DHCP Transport (Partial Gap)

**Go Implementation** (`dns/transport/dhcp/`):
- Active DHCP INFORM probe
- Interface discovery
- Server timeout and refresh handling

**Rust Implementation**:
- Passive `resolv.conf` monitoring only
- No DHCP INFORM probes
- No interface discovery

**Impact**: DHCP-discovered DNS servers may not be detected.

### 7) Experimental Features (De-scoped)

**Go `experimental/`**:
- `cachefile/` - persistent cache for rule sets
- `clashapi/` - Clash API compatibility
- `v2rayapi/` - V2Ray stats API
- `libbox/` - mobile platform bindings
- `locale/` - localization
- `deprecated/` - deprecated feature warnings

**Rust Status**: These are intentionally **not ported** as they are Go-specific experimental features. However, Rust has **custom implementations** of some features:
- Clash API → `services/clash_api.rs` (Rust-native implementation)
- V2Ray API → `services/v2ray_api.rs` (Rust-native implementation)
- Cache File → `services/cache_file.rs` (Rust-native implementation)

---

## Summary Statistics

| Category | Aligned | Partial | Not Aligned | Feature-gated | Rust-only |
| --- | --- | --- | --- | --- | --- |
| Inbound Protocols | 19 | 0 | 0 | 0 | 0 |
| Outbound Protocols | 18 | 0 | 0 | 2 | 0 |
| Endpoints | 1 | 0 | 1 | 0 | 0 |
| Services (Go parity) | 2 | 1 | 0 | 0 | 5 |
| Transports | 10 | 0 | 0 | 0 | 7 |
| DNS Transports | 9 | 2 | 0 | 0 | 2 |
| TLS/Crypto | 4 | 2 | 0 | 0 | 0 |
| Config Schema | 9 | 0 | 0 | 2 | 0 |
| Go Directories | 12 | 3 | 1 | 0 | 0 |
| **Total** | **84** | **8** | **2** | **4** | **14** |

**Parity Rate**: ~88% aligned (84 aligned / 95 core items; 2 not aligned; 4 feature-gated/de-scoped; 14 Rust extensions)

---

## Priority Remediation Order

### P0: Protocol Divergence Cleanup ✅ Completed (2025-12-14)

1. **ShadowsocksR**: Feature-gated with `legacy_shadowsocksr` (default OFF)
2. **Tailscale Outbound**: Feature-gated with `legacy_tailscale_outbound` (default OFF)

### P1: SSMAPI Service Alignment ✅ Core Completed (2025-12-14)

1. ✅ `ManagedSSMServer::update_users()` trait method added
2. ✅ `ShadowsocksInboundAdapter` implements `update_users()`
3. ✅ `UserManager::post_update()` pushes changes to bound SS inbound
4. ✅ `TrafficManager::update_users()` syncs user list
5. Align per-endpoint cache format with Go (users + traffic per endpoint) — **Optional**
6. Full API response parity (all status codes, error messages) — **Optional**

### P2: Resolved Service Completion (1-2 days)

1. Route DNS via configured router (Go `adapter.DNSRouter` equivalent)
2. Register NetworkMonitor callbacks + Linux netlink change tracking

### P3: TLS Fidelity (Blocked by rustls)

1. Decide approach for full uTLS fingerprint parity (blocked by rustls limitations)
2. Decide ECH runtime parity approach (blocked by rustls 0.23)

### P4: DHCP Transport Enhancement (Low priority)

1. Add active DHCP INFORM probe + interface discovery

### P5: Tailscale Stack Parity (Major undertaking - 2-4 weeks)

1. Evaluate tsnet/FFI integration for netstack TCP/UDP and DNS hooks
2. Evaluate `tailscale-control` pure Rust alternative
3. Write decision document

---

## File Reference

### Go Reference (`go_fork_source/sing-box-1.12.12`)

| Directory | Contents |
| --- | --- |
| `protocol/` | 23 protocol implementations (anytls, block, direct, dns, group, http, hysteria, hysteria2, mixed, naive, redirect, shadowsocks, shadowtls, socks, ssh, tailscale, tor, trojan, tuic, tun, vless, vmess, wireguard) |
| `service/` | 3 services (derp, resolved, ssmapi) |
| `transport/` | 11 transports (simple-obfs, sip003, trojan, v2ray, v2raygrpc, v2raygrpclite, v2rayhttp, v2rayhttpupgrade, v2rayquic, v2raywebsocket, wireguard) |
| `common/tls/` | TLS implementations (std, utls, reality, ech, acme) |
| `dns/transport/` | DNS transports (dhcp, fakeip, hosts, local, quic, https, tcp, tls, udp) |
| `option/` | 47 config type files |
| `constant/` | Type constants and enums |
| `experimental/` | 6 experimental features (cachefile, clashapi, deprecated, libbox, locale, v2rayapi) |

### Rust Implementation (`crates/`)

| Crate | Purpose | Files |
| --- | --- | --- |
| `sb-adapters` | Protocol implementations (inbound/outbound/endpoint/service) | 109 |
| `sb-config` | Config parsing, validation, IR types | 49 |
| `sb-core` | Core runtime, router, DNS, services | 424 |
| `sb-tls` | TLS implementations (utls, reality, ech, acme) | 20 |
| `sb-transport` | Transport layer implementations | 57 |
| `sb-common` | Shared utilities | 10 |
| `sb-platform` | Platform-specific code | 20 |
| `sb-runtime` | Async runtime utilities | 17 |
| `sb-types` | Shared type definitions | 2 |
| `sb-metrics` | Metrics and telemetry | 9 |
| `sb-proto` | Protocol-specific types | 9 |
| `sb-api` | Admin API | 29 |
| `sb-subscribe` | Subscription management | 24 |
| `sb-security` | Security utilities | 5 |
| `sb-test-utils` | Test utilities | 3 |
| `sb-admin-contract` | Admin API contracts | 2 |
