# Go-Rust Parity Matrix (2025-12-14 Comprehensive Calibration)

Objective: compare `singbox-rust` against Go reference `go_fork_source/sing-box-1.12.12` for functional, type, API, comment, and directory parity.

## Status Legend

- ✅ **Aligned**: behavior/types/API/config match Go reference.
- ◐ **Partial**: implemented but missing/ diverging details; not yet interchangeable.
- ❌ **Not aligned**: stubbed, materially divergent, or Go feature is absent/disabled but Rust exposes it.
- ⊘ **De-scoped**: intentionally excluded; will not be ported.

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

## Protocol Parity Matrix

### Inbound Protocols

| Go Protocol | Rust Implementation | Status | Notes |
| --- | --- | --- | --- |
| anytls | `crates/sb-adapters/src/inbound/anytls.rs` | ✅ | Full implementation |
| direct | `crates/sb-adapters/src/inbound/direct.rs` | ✅ | Full implementation |
| dns | `crates/sb-adapters/src/inbound/dns.rs` | ✅ | Full implementation |
| http | `crates/sb-adapters/src/inbound/http.rs` | ✅ | Full implementation |
| hysteria | `crates/sb-adapters/src/inbound/hysteria.rs` | ✅ | Full implementation |
| hysteria2 | `crates/sb-adapters/src/inbound/hysteria2.rs` | ✅ | Full implementation |
| mixed | `crates/sb-adapters/src/inbound/mixed.rs` | ✅ | HTTP+SOCKS combination |
| naive | `crates/sb-adapters/src/inbound/naive.rs` | ✅ | Full implementation |
| redirect | `crates/sb-adapters/src/inbound/redirect.rs` | ✅ | Linux redirect support |
| shadowsocks | `crates/sb-adapters/src/inbound/shadowsocks.rs` | ✅ | Multi-user, relay modes |
| shadowtls | `crates/sb-adapters/src/inbound/shadowtls.rs` | ✅ | Full implementation |
| socks | `crates/sb-adapters/src/inbound/socks/` | ✅ | SOCKS4/5 support |
| ssh | `crates/sb-adapters/src/inbound/ssh.rs` | ✅ | SSH tunnel |
| tproxy | `crates/sb-adapters/src/inbound/tproxy.rs` | ✅ | Linux tproxy support |
| trojan | `crates/sb-adapters/src/inbound/trojan.rs` | ✅ | Full implementation |
| tuic | `crates/sb-adapters/src/inbound/tuic.rs` | ✅ | QUIC-based |
| tun | `crates/sb-adapters/src/inbound/tun/` | ✅ | Multi-platform TUN |
| vless | `crates/sb-adapters/src/inbound/vless.rs` | ✅ | Full implementation |
| vmess | `crates/sb-adapters/src/inbound/vmess.rs` | ✅ | Full implementation |

### Outbound Protocols

| Go Protocol | Rust Implementation | Status | Notes |
| --- | --- | --- | --- |
| anytls | `crates/sb-adapters/src/outbound/anytls.rs` | ✅ | Full implementation |
| block | `crates/sb-adapters/src/outbound/block.rs` | ✅ | Connection blocker |
| direct | `crates/sb-adapters/src/outbound/direct.rs` | ✅ | Full implementation |
| dns | `crates/sb-adapters/src/outbound/dns.rs` | ✅ | DNS outbound |
| http | `crates/sb-adapters/src/outbound/http.rs` | ✅ | HTTP CONNECT proxy |
| hysteria | `crates/sb-adapters/src/outbound/hysteria.rs` | ✅ | Full implementation |
| hysteria2 | `crates/sb-adapters/src/outbound/hysteria2.rs` | ✅ | Full implementation |
| selector | `crates/sb-adapters/src/outbound/selector.rs` | ✅ | Group selector |
| shadowsocks | `crates/sb-adapters/src/outbound/shadowsocks.rs` | ✅ | Full ciphers |
| shadowsocksr | `crates/sb-adapters/src/outbound/shadowsocksr/` | ⊘ | Feature-gated (`legacy_shadowsocksr`, default OFF); Go removed |
| shadowtls | `crates/sb-adapters/src/outbound/shadowtls.rs` | ✅ | uTLS wired via `utls_fingerprint` |
| socks (socks4/5) | `crates/sb-adapters/src/outbound/socks4.rs`, `socks5.rs` | ✅ | SOCKS4/5 client |
| ssh | `crates/sb-adapters/src/outbound/ssh.rs` | ✅ | SSH client |
| tailscale | `crates/sb-adapters/src/outbound/tailscale.rs` | ⊘ | Feature-gated (`legacy_tailscale_outbound`, default OFF); Go has no outbound |
| tor | `crates/sb-adapters/src/outbound/tor.rs` | ✅ | Tor proxy |
| trojan | `crates/sb-adapters/src/outbound/trojan.rs` | ✅ | Full implementation |
| tuic | `crates/sb-adapters/src/outbound/tuic.rs` | ✅ | Full implementation |
| urltest | `crates/sb-adapters/src/outbound/urltest.rs` | ✅ | URL test group |
| vless | `crates/sb-adapters/src/outbound/vless.rs` | ✅ | Full implementation |
| vmess | `crates/sb-adapters/src/outbound/vmess.rs` | ✅ | Full implementation |
| wireguard | `crates/sb-adapters/src/outbound/wireguard.rs` | ✅ | WireGuard client |

### Endpoint Protocols

| Go Protocol | Rust Implementation | Status | Notes |
| --- | --- | --- | --- |
| tailscale | `crates/sb-core/src/endpoint/tailscale.rs` | ❌ | Stub/daemon only, no tsnet/netstack |
| wireguard | `crates/sb-core/src/endpoint/wireguard.rs` | ✅ | WireGuard endpoint |

---

## Service Parity Matrix

| Go Service | Rust Implementation | Status | Gap Details |
| --- | --- | --- | --- |
| derp (`type="derp"`) | `crates/sb-core/src/services/derp/` | ✅ | TLS-required + `config_path` key JSON + tailscale DERP v2 (NaCl box ClientInfo/ServerInfo) + Go mesh model (`meshKey` in ClientInfo) aligned; `verify_client_endpoint` de-scoped (requires Tailscale LocalClient daemon) |
| resolved (`type="resolved"`) | `crates/sb-adapters/src/service/resolved_impl.rs`, `crates/sb-adapters/src/service/resolve1.rs` | ◐ | Linux+feature gated; DNS routing/monitor parity incomplete vs Go `adapter.DNSRouter` + netmon |
| ssmapi (`type="ssm-api"`) | `crates/sb-core/src/services/ssmapi/` | ✅ | Core aligned: `ManagedSSMServer::update_users()`, `UserManager::post_update()`, `TrafficManager::update_users()` implemented. Config type/schema + per-endpoint routing aligned. Optional: per-endpoint state/cache format |

---

## Transport Parity Matrix

| Go Transport | Rust Implementation | Status | Notes |
| --- | --- | --- | --- |
| simple-obfs | `crates/sb-transport/src/simple_obfs.rs` | ✅ | HTTP/TLS obfuscation |
| sip003 | `crates/sb-transport/src/sip003.rs` | ✅ | Plugin framework |
| trojan | `crates/sb-transport/src/trojan.rs` | ✅ | Trojan framing |
| v2ray (grpc) | `crates/sb-transport/src/grpc.rs` | ✅ | gRPC transport |
| v2raygrpclite | `crates/sb-transport/src/grpc_lite.rs` | ✅ | Lightweight gRPC |
| v2rayhttp | `crates/sb-transport/src/http2.rs` | ✅ | HTTP/2 transport |
| v2rayhttpupgrade | `crates/sb-transport/src/httpupgrade.rs` | ✅ | HTTP Upgrade |
| v2rayquic | `crates/sb-transport/src/quic.rs` | ✅ | QUIC transport |
| v2raywebsocket | `crates/sb-transport/src/websocket.rs` | ✅ | WebSocket transport |
| wireguard | `crates/sb-transport/src/wireguard.rs` | ✅ | WireGuard transport |

---

## TLS/Crypto Parity Matrix

| Go Component | Rust Implementation | Status | Gap Details |
| --- | --- | --- | --- |
| std_client/server | `crates/sb-transport/src/tls.rs` | ✅ | Standard TLS |
| utls_client | `crates/sb-tls/src/utls.rs` | ◐ | Cipher suite/ALPN ordering only; rustls cannot match Go/uTLS extension ordering & full ClientHello |
| reality_client/server | `crates/sb-tls/` | ✅ | Client uses uTLS-ordered config while preserving REALITY verifier |
| ech | `crates/sb-tls/src/ech/` | ◐ | Parser/HPKE + CLI keygen exist; rustls lacks ECH handshake integration (Go: enabled on go1.24+) |
| acme | `crates/sb-tls/src/acme.rs` | ✅ | ACME certificate management |

---

## DNS Transport Parity Matrix

| Go DNS Transport | Rust Implementation | Status | Gap Details |
| --- | --- | --- | --- |
| udp | `crates/sb-core/src/dns/` | ✅ | UDP DNS |
| tcp | `crates/sb-core/src/dns/` | ✅ | TCP DNS |
| tls (DoT) | `crates/sb-core/src/dns/` | ✅ | DNS over TLS |
| https (DoH) | `crates/sb-core/src/dns/` | ✅ | DNS over HTTPS |
| quic (DoQ) | `crates/sb-core/src/dns/` | ✅ | DNS over QUIC |
| fakeip | `crates/sb-core/src/dns/` | ✅ | FakeIP pool |
| hosts | `crates/sb-core/src/dns/` | ✅ | Hosts file |
| local | `crates/sb-core/src/dns/` | ✅ | System resolver |
| dhcp | `crates/sb-core/src/dns/` | ◐ | Passive only, no INFORM probe |
| tailscale | `crates/sb-transport/src/tailscale_dns.rs` | ◐ | Raw UDP to 100.100.100.100, not tsnet-bound |

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
| `constant.TypeSSMAPI` = `"ssm-api"` | `ServiceType::Ssmapi` | ✅ | Serializes as `"ssm-api"` |
| `constant.TypeDERP` = `"derp"` | `ServiceType::Derp` | ✅ | Aligned |
| `constant.TypeResolved` = `"resolved"` | `ServiceType::Resolved` | ✅ | Aligned |
| `constant.TypeShadowsocksR` = `"shadowsocksr"` | `OutboundType::ShadowsocksR` | ❌ | Go rejects; Rust accepts (divergence) |
| `constant.TypeTailscale` (endpoint only) | `OutboundType::Tailscale` + `EndpointType::Tailscale` | ❌ | Rust has outbound (divergence) |

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

### 3) SSMAPI Service (Partial)

**Go Implementation** (`service/ssmapi/server.go`):
- Binds to managed Shadowsocks inbounds via `InboundManager`
- `TrafficManager` for bandwidth tracking
- `UserManager` for user management on managed SSM servers
- Per-server routing via chi router (`chiRouter.Route(entry.Key, ...)`)
- Optional TLS support + HTTP/2 enablement
- Cache persistence per endpoint (`CachePath`, `loadCache`, `saveCache`) including users + traffic
- HTTP/2 enabled when TLS active

**Rust Implementation** (`crates/sb-core/src/services/ssmapi/`):
- HTTP server exists with API handlers
- Config-level parity:
  - `type="ssm-api"` + Listen Fields + `tls` object supported
  - `servers` endpoint→inbound tag is parsed and used for routing
- **API parity**: `GET /server/v1/users` returns `{"users":[UserObject...]}` ✅
- **Cache model mismatch**: Go caches per-endpoint traffic + users; Rust cache is global and incomplete
- **Missing** `ManagedSSMServer.UpdateUsers` parity: Rust `UserManager` does not push user set to managed SS inbound

**Impact**: Config and routing are aligned, but service is not drop-in compatible until managed inbound binding + API response + cache format match Go.

### 4) Resolved Service (Partial Gap)

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

### 5) uTLS Integration (Partial)

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

### 6) ECH (Partial / Build-Gated in Go)

**Go Implementation** (`common/tls/ech.go`, `common/tls/ech_stub.go`):
- Enabled only on `go1.24` builds; otherwise returns "ECH requires go1.24 …"
- When enabled, integrates with stdlib `crypto/tls` ECH hooks

**Rust Implementation** (`crates/sb-tls/src/ech/`):
- ECHConfigList parsing + HPKE primitives + CLI keygen exist
- **Missing** runtime TLS handshake integration (rustls 0.23 has no native ECH)

**Impact**: Config-level and crypto scaffolding exist, but runtime ECH parity is blocked by TLS library support.

### 7) DNS DHCP Transport (Partial Gap)

**Go Implementation** (`dns/transport/dhcp/`):
- Active DHCP INFORM probe
- Interface discovery
- Server timeout and refresh handling

**Rust Implementation**:
- Passive `resolv.conf` monitoring only
- No DHCP INFORM probes
- No interface discovery

**Impact**: DHCP-discovered DNS servers may not be detected.

### 8) Experimental Features (De-scoped)

**Go `experimental/`**:
- `cachefile/` - persistent cache for rule sets
- `clashapi/` - Clash API compatibility
- `v2rayapi/` - V2Ray stats API
- `libbox/` - mobile platform bindings
- `locale/` - localization
- `deprecated/` - deprecated feature warnings

**Rust Status**: These are intentionally **not ported** as they are Go-specific experimental features. The Rust implementation focuses on core proxy functionality.

---

## Summary Statistics

| Category | Aligned | Partial | Not Aligned | Feature-gated |
| --- | --- | --- | --- | --- |
| Inbound Protocols | 19 | 0 | 0 | 0 |
| Outbound Protocols | 18 | 0 | 0 | 2 |
| Endpoints | 1 | 0 | 1 | 0 |
| Services | 2 | 1 | 0 | 0 |
| Transports | 10 | 0 | 0 | 0 |
| DNS Transports | 8 | 2 | 0 | 0 |
| TLS/Crypto | 3 | 2 | 0 | 0 |
| Config Schema | 7 | 0 | 0 | 2 |
| Go Directories | 12 | 3 | 1 | 2 |
| **Total** | **80** | **8** | **2** | **6** |

**Parity Rate**: ~87% aligned (80 aligned / 92 core items; 2 not aligned; 6 feature-gated/de-scoped)

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
2. Align per-endpoint cache format with Go (users + traffic per endpoint)
3. Full API response parity (all status codes, error messages)

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

| Crate | Purpose |
| --- | --- |
| `sb-adapters` | Protocol implementations (inbound/outbound/endpoint/service) |
| `sb-config` | Config parsing, validation, IR types |
| `sb-core` | Core runtime, router, DNS, services |
| `sb-tls` | TLS implementations (utls, reality, ech, acme) |
| `sb-transport` | Transport layer implementations |
| `sb-common` | Shared utilities |
| `sb-platform` | Platform-specific code |
| `sb-runtime` | Async runtime utilities |
| `sb-types` | Shared type definitions |
| `sb-metrics` | Metrics and telemetry |
| `sb-proto` | Protocol-specific types |
| `sb-api` | Admin API |
| `sb-subscribe` | Subscription management |
| `sb-security` | Security utilities |
| `sb-test-utils` | Test utilities |
