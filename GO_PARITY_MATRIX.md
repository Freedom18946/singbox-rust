# Go-Rust Parity Matrix (2025-12-16 Comprehensive Calibration)

Objective: compare `singbox-rust` against Go reference `go_fork_source/sing-box-1.12.12` for functional, type, API, comment, and directory parity.

## Status Legend

- ✅ **Aligned**: behavior/types/API/config match Go reference.
- ◐ **Partial**: implemented but missing/diverging details; not yet interchangeable.
- ❌ **Not aligned**: stubbed, materially divergent, or Go feature is absent/disabled but Rust exposes it.
- ⊘ **De-scoped**: intentionally excluded; will not be ported.
- ➕ **Rust-only**: exists in Rust but not in Go reference (extension).

---

## Executive Summary

| Area | Status | Notes |
| --- | --- | --- |
| **Protocol Coverage** | ✅ High | All 23 Go `protocol/*` modules have Rust counterparts |
| **Tailscale endpoint/data plane** | ❌ Not aligned | Go uses tsnet+gVisor netstack; Rust uses stub/daemon with host sockets |
| **Tailscale outbound (Go has no outbound)** | ⊘ Feature-gated | Feature `legacy_tailscale_outbound` (default OFF); Go has Tailscale endpoint only |
| **ShadowsocksR (Go removed)** | ⊘ Feature-gated | Feature `legacy_shadowsocksr` (default OFF); Go removed upstream |
| **DNS transports (DHCP/Resolved/Tailscale)** | ◐ Partial | DHCP passive only; tailscale transport aligned with TsnetSocketFactory |
| **TLS uTLS fidelity** | ◐ Partial | Wired, but rustls cannot reproduce Go/uTLS extension ordering and full ClientHello shape |
| **ECH (Go: go1.24+)** | ◐ Partial | Rust has config/parser/HPKE scaffolding but no rustls ECH handshake integration |
| **Resolved service** | ✅ Aligned | D-Bus server + DNSRouter injection + NetworkMonitor callbacks integrated |
| **DERP service** | ✅ Aligned | HTTP endpoints + TLS-required + `config_path` JSON key + NaCl box wire protocol + Go mesh model aligned |
| **SSMAPI service** | ✅ Aligned | Core aligned: `UpdateUsers`, `post_update`, config/routing |
| **Transport layer** | ✅ High | WebSocket, gRPC, HTTP/2, QUIC, simple-obfs, sip003 all implemented |
| **Router/Rules** | ✅ High | Rule matching, geoip, geosite, process detection aligned |
| **Experimental (Go)** | ⊘ De-scoped | Go-only experimental features (clashapi, v2rayapi, cachefile, libbox) not ported |
| **Rust Extensions** | ➕ Extended | Rust has Clash API, V2Ray API, Cache File, NTP services as runtime additions |

---

## Directory / Module Parity Matrix

| Go Module/Dir | Rust Crate/Module | Status | Notes |
| --- | --- | --- | --- |
| `adapter/` (26 files) | `crates/sb-core/src/adapter/`, `crates/sb-adapters/` | ✅ | Trait surface and lifecycle aligned |
| `common/` (24 subdirs) | `crates/sb-common/`, `crates/sb-platform/`, `crates/sb-runtime/` | ◐ | Some helper APIs differ; see area-specific gaps |
| `common/tls/` (20 files) | `crates/sb-tls/`, `crates/sb-transport/src/tls.rs` | ◐ | std_client/server aligned; uTLS partial; ECH partial; REALITY aligned |
| `constant/` (22 files) | `crates/sb-types/` + per‑crate `types.rs`/enum modules | ✅ | Constants/enums mirrored where used |
| `dns/` (11 files) | `crates/sb-core/src/dns/` (28 files) | ✅ | Core resolver aligned; comprehensive DNS implementation |
| `dns/transport/` (5 subdirs) | `crates/sb-core/src/dns/transport/` (10 files) | ◐ | udp/tcp/tls/https/quic/fakeip/hosts/local aligned; dhcp partial |
| `log/` (10 files) | `crates/sb-core/src/log/`, `crates/sb-metrics/` | ✅ | Logging levels/fields aligned |
| `option/` (47 files) | `crates/sb-config/` (18 files + subdirs) | ✅ | Core coverage high; service schema/type IDs aligned |
| `protocol/` (23 subdirs) | `crates/sb-adapters/` (inbound/outbound/endpoint) | ✅ | Protocol implementations aligned (except tailscale endpoint) |
| `protocol/tailscale/` (4 files) | `crates/sb-core/src/endpoint/tailscale.rs` (38KB) | ❌ | Enhanced stub with DaemonControlPlane; no tsnet/netstack integration |
| `route/` (7 files + rule/) | `crates/sb-core/src/router/` (49 files), `crates/sb-core/src/routing/` (7 files) | ✅ | Rule engine aligned with advanced features |
| `service/` (3 subdirs) | `crates/sb-core/src/services/`, `crates/sb-adapters/src/service/` | ✅ | DERP + SSMAPI + Resolved aligned |
| `transport/` (11 subdirs) | `crates/sb-transport/` (28 files) | ✅ | Transport APIs aligned |
| `cmd/`, `box.go` | `app/`, `crates/sb-core/src/bin/` | ✅ | CLI/subcommand parity aligned |
| `experimental/` (6 subdirs) | N/A | ⊘ | De-scoped: Go-only experimental features |
| `clients/` | N/A | ⊘ | De-scoped: subscription client helpers |

---

## Protocol Parity Matrix

### Inbound Protocols (19 total)

| Go Protocol | Go Files | Rust File | Status | Notes |
| --- | --- | --- | --- | --- |
| anytls | `protocol/anytls/inbound.go` | `inbound/anytls.rs` (20KB) | ✅ | Full implementation |
| direct | `protocol/direct/inbound.go` | `inbound/direct.rs` (3KB) | ✅ | Full implementation |
| dns | `protocol/dns/handle.go` | `inbound/dns.rs` (20KB) | ✅ | Full implementation |
| http | `protocol/http/inbound.go` | `inbound/http.rs` (35KB) | ✅ | Full implementation |
| hysteria | `protocol/hysteria/inbound.go` | `inbound/hysteria.rs` (6KB) | ✅ | Full implementation |
| hysteria2 | `protocol/hysteria2/inbound.go` | `inbound/hysteria2.rs` (16KB) | ✅ | Full implementation |
| mixed | `protocol/mixed/inbound.go` | `inbound/mixed.rs` (12KB) | ✅ | HTTP+SOCKS combination |
| naive | `protocol/naive/inbound.go` | `inbound/naive.rs` (17KB) | ✅ | Full implementation |
| redirect | `protocol/redirect/redirect.go` | `inbound/redirect.rs` (9KB) | ✅ | Linux redirect support |
| shadowsocks | `protocol/shadowsocks/inbound*.go` (4 files) | `inbound/shadowsocks.rs` (40KB) | ✅ | Multi-user, relay modes |
| shadowtls | `protocol/shadowtls/inbound.go` | `inbound/shadowtls.rs` (10KB) | ✅ | Full implementation |
| socks | `protocol/socks/inbound.go` | `inbound/socks/` (7 files) | ✅ | SOCKS4/5 support |
| ssh | `protocol/ssh/outbound.go` (no inbound) | `inbound/ssh.rs` (21KB) | ➕ | Rust extension: SSH inbound |
| tproxy | `protocol/redirect/tproxy.go` | `inbound/tproxy.rs` (8KB) | ✅ | Linux tproxy support |
| trojan | `protocol/trojan/inbound.go` | `inbound/trojan.rs` (44KB) | ✅ | Full implementation |
| tuic | `protocol/tuic/inbound.go` | `inbound/tuic.rs` (24KB) | ✅ | QUIC-based |
| tun | `protocol/tun/inbound.go` | `inbound/tun/` (7+ files) | ✅ | Multi-platform TUN |
| vless | `protocol/vless/inbound.go` | `inbound/vless.rs` (21KB) | ✅ | Full implementation |
| vmess | `protocol/vmess/inbound.go` | `inbound/vmess.rs` (20KB) | ✅ | Full implementation |

### Outbound Protocols (22 total)

| Go Protocol | Go Files | Rust File | Status | Notes |
| --- | --- | --- | --- | --- |
| anytls | `protocol/anytls/outbound.go` | `outbound/anytls.rs` (15KB) | ✅ | Full implementation |
| block | `protocol/block/outbound.go` | `outbound/block.rs` (543B) | ✅ | Connection blocker |
| direct | `protocol/direct/outbound.go` | `outbound/direct.rs` (4KB) | ✅ | Full implementation |
| dns | `protocol/dns/outbound.go` | `outbound/dns.rs` (17KB) | ✅ | DNS outbound |
| http | `protocol/http/outbound.go` | `outbound/http.rs` (24KB) | ✅ | HTTP CONNECT proxy |
| hysteria | `protocol/hysteria/outbound.go` | `outbound/hysteria.rs` (4KB) | ✅ | Full implementation |
| hysteria2 | `protocol/hysteria2/outbound.go` | `outbound/hysteria2.rs` (5KB) | ✅ | Full implementation |
| selector | `protocol/group/selector.go` | `outbound/selector.rs` (4KB) | ✅ | Group selector |
| shadowsocks | `protocol/shadowsocks/outbound.go` | `outbound/shadowsocks.rs` (38KB) | ✅ | Full ciphers |
| shadowsocksr | N/A (Go removed) | `outbound/shadowsocksr/` (5 files) | ⊘ | Feature-gated (`legacy_shadowsocksr`, default OFF) |
| shadowtls | `protocol/shadowtls/outbound.go` | `outbound/shadowtls.rs` (4KB) | ✅ | uTLS wired via `utls_fingerprint` |
| socks | `protocol/socks/outbound.go` | `outbound/socks4.rs` (11KB), `outbound/socks5.rs` (52KB) | ✅ | SOCKS4/5 client |
| ssh | `protocol/ssh/outbound.go` | `outbound/ssh.rs` (13KB) | ✅ | SSH client |
| tailscale | N/A (Go has no outbound) | `outbound/tailscale.rs` (21KB) | ⊘ | Feature-gated (`legacy_tailscale_outbound`, default OFF) |
| tor | `protocol/tor/outbound.go` | `outbound/tor.rs` (7KB) | ✅ | Tor proxy |
| trojan | `protocol/trojan/outbound.go` | `outbound/trojan.rs` (23KB) | ✅ | Full implementation |
| tuic | `protocol/tuic/outbound.go` | `outbound/tuic.rs` (11KB) | ✅ | Full implementation |
| urltest | `protocol/group/urltest.go` | `outbound/urltest.rs` (4KB) | ✅ | URL test group |
| vless | `protocol/vless/outbound.go` | `outbound/vless.rs` (23KB) | ✅ | Full implementation |
| vmess | `protocol/vmess/outbound.go` | `outbound/vmess.rs` (15KB) | ✅ | Full implementation |
| wireguard | `protocol/wireguard/outbound.go` | `outbound/wireguard.rs` (8KB) | ✅ | WireGuard client |

### Endpoint Protocols (2 total)

| Go Protocol | Go Files | Rust Implementation | Status | Notes |
| --- | --- | --- | --- | --- |
| tailscale | `protocol/tailscale/` (4 files) | `sb-core/src/endpoint/tailscale.rs` (38KB) | ❌ | Stub/daemon only, no tsnet/netstack |
| wireguard | `protocol/wireguard/endpoint.go` | `sb-core/src/endpoint/wireguard.rs` (18KB) | ✅ | WireGuard endpoint |

---

## Service Parity Matrix

| Go Service | Go Files | Rust Implementation | Status | Gap Details |
| --- | --- | --- | --- | --- |
| derp (`type="derp"`) | `service/derp/service.go` (15KB) | `services/derp/` (4 files, 197KB total) | ✅ | TLS-required + `config_path` key JSON + tailscale DERP v2 (NaCl box) + mesh model aligned |
| resolved (`type="resolved"`) | `service/resolved/` (4 files, 35KB total) | `sb-adapters/src/service/` (3 files, 47KB) + `sb-core/src/dns/transport/resolved.rs` | ✅ | D-Bus server + DNSRouter injection + NetworkMonitor callbacks integrated |
| ssmapi (`type="ssm-api"`) | `service/ssmapi/` (5 files, 25KB total) | `services/ssmapi/` (5 files, 53KB total) | ✅ | Core aligned: `update_users()`, `post_update()`, `TrafficManager` implemented |

### Rust-Only Services (Extensions)

| Rust Service | File | Status | Notes |
| --- | --- | --- | --- |
| Clash API | `services/clash_api.rs` (23KB) | ➕ | Rust custom implementation of Clash API; not in Go reference |
| V2Ray API | `services/v2ray_api.rs` (16KB) | ➕ | Rust custom implementation of V2Ray stats API |
| Cache File | `services/cache_file.rs` (14KB) | ➕ | Rust-native rule set cache |
| NTP | `services/ntp.rs` (7KB) | ➕ | NTP time sync service |
| DNS Forwarder | `services/dns_forwarder.rs` (11KB) | ➕ | DNS forwarding service |
| Tailscale Service | `services/tailscale/` (3 files) | ➕ | Extended Tailscale service integration |

---

## Transport Parity Matrix

| Go Transport | Go Files | Rust File | Status | Notes |
| --- | --- | --- | --- | --- |
| simple-obfs | `transport/simple-obfs/` (2 files) | `simple_obfs.rs` (13KB) | ✅ | HTTP/TLS obfuscation |
| sip003 | `transport/sip003/` (4 files) | `sip003.rs` (11KB) | ✅ | Plugin framework |
| trojan | `transport/trojan/` (5 files) | `trojan.rs` (13KB) | ✅ | Trojan framing |
| v2ray (grpc) | `transport/v2raygrpc/` (8 files) | `grpc.rs` (17KB) | ✅ | gRPC transport |
| v2raygrpclite | `transport/v2raygrpclite/` (3 files) | `grpc_lite.rs` (12KB) | ✅ | Lightweight gRPC |
| v2rayhttp | `transport/v2rayhttp/` (5 files) | `http2.rs` (21KB) | ✅ | HTTP/2 transport |
| v2rayhttpupgrade | `transport/v2rayhttpupgrade/` (2 files) | `httpupgrade.rs` (15KB) | ✅ | HTTP Upgrade |
| v2rayquic | `transport/v2rayquic/` (4 files) | `quic.rs` (20KB) | ✅ | QUIC transport |
| v2raywebsocket | `transport/v2raywebsocket/` (4 files) | `websocket.rs` (21KB) | ✅ | WebSocket transport |
| wireguard | `transport/wireguard/` (9 files) | `wireguard.rs` (18KB) | ✅ | WireGuard transport |
| v2ray (coordinator) | `transport/v2ray/transport.go` | N/A (integrated) | ✅ | Integrated into Rust transport selection |

### Rust-Only Transports (Extensions)

| Rust Transport | File | Status | Notes |
| --- | --- | --- | --- |
| DERP | `derp/` (3 files) | ➕ | DERP relay transport |
| Multiplex | `multiplex.rs` (25KB) + `multiplex/` | ➕ | Connection multiplexing |
| UoT | `uot.rs` (13KB) | ➕ | UDP over TCP |
| Tailscale DNS | `tailscale_dns.rs` (20KB) | ✅ | TsnetSocketFactory trait integrated |
| Circuit Breaker | `circuit_breaker.rs` (24KB) | ➕ | Fault tolerance extension |
| Resource Pressure | `resource_pressure.rs` (18KB) | ➕ | Load management |
| Retry | `retry.rs` (20KB) | ➕ | Connection retry logic |
| Memory Transport | `mem.rs` (12KB) | ➕ | In-memory testing transport |
| Pool | `pool/` (2 files) | ➕ | Connection pooling |

---

## TLS/Crypto Parity Matrix

| Go Component | Go Files | Rust Implementation | Status | Gap Details |
| --- | --- | --- | --- | --- |
| std_client | `common/tls/std_client.go` (4KB) | `sb-transport/src/tls.rs` (101KB) | ✅ | Standard TLS client |
| std_server | `common/tls/std_server.go` (8KB) | `sb-transport/src/tls.rs` | ✅ | Standard TLS server |
| utls_client | `common/tls/utls_client.go` (8KB) | `sb-tls/src/utls.rs` (28KB) | ◐ | Cipher suite/ALPN ordering only; rustls cannot match full ClientHello |
| reality_client | `common/tls/reality_client.go` (9KB) | `sb-tls/src/reality/` (7 files) | ✅ | Client uses uTLS-ordered config with REALITY verifier |
| reality_server | `common/tls/reality_server.go` (6KB) | `sb-tls/src/reality/` | ✅ | Full REALITY server support |
| ech | `common/tls/ech*.go` (4 files) | `sb-tls/src/ech/` (5 files) | ◐ | Parser/HPKE exist; rustls lacks ECH handshake (Go: go1.24+ gated) |
| acme | `common/tls/acme*.go` (3 files) | `sb-tls/src/acme.rs` (28KB) | ✅ | ACME certificate management |
| mkcert | `common/tls/mkcert.go` (2KB) | N/A (integrated) | ✅ | Certificate generation integrated |
| config | `common/tls/config.go` (1KB) | `sb-tls/src/standard.rs` (4KB) | ✅ | TLS configuration |

---

## DNS Transport Parity Matrix

| Go DNS Transport | Go Files | Rust File | Status | Gap Details |
| --- | --- | --- | --- | --- |
| udp | `dns/transport/udp.go` (5KB) | `transport/udp.rs` (19KB) | ✅ | UDP DNS |
| tcp | `dns/transport/tcp.go` (3KB) | `transport/tcp.rs` (9KB) | ✅ | TCP DNS |
| tls (DoT) | `dns/transport/tls.go` (4KB) | `transport/dot.rs` (9KB) | ✅ | DNS over TLS |
| https (DoH) | `dns/transport/https*.go` (2 files, 8KB) | `transport/doh.rs` (11KB) | ✅ | DNS over HTTPS |
| https (DoH3) | (Go: in quic/) | `transport/doh3.rs` (8KB) | ✅ | DNS over HTTP/3 |
| quic (DoQ) | `dns/transport/quic/` (2 files) | `transport/doq.rs` (5KB) | ✅ | DNS over QUIC |
| fakeip | `dns/transport/fakeip/` (3 files) | `fakeip.rs` (10KB) | ✅ | FakeIP pool |
| hosts | `dns/transport/hosts/` (5 files) | `hosts.rs` (12KB) | ✅ | Hosts file |
| local | `dns/transport/local/` (7 files) | `transport/local.rs` (8KB) | ✅ | System resolver |
| dhcp | `dns/transport/dhcp/` (2 files) | (passive monitoring) | ◐ | Passive only, no DHCP INFORM probe |
| resolved | `service/resolved/transport.go` (9KB) | `transport/resolved.rs` (20KB) | ✅ | D-Bus resolved DNS transport |
| enhanced_udp | N/A | `transport/enhanced_udp.rs` (9KB) | ➕ | Enhanced UDP DNS (Rust extension) |

---

## Config Schema Parity Matrix

| Go Type | Rust IR Type | Status | Notes |
| --- | --- | --- | --- |
| `option.Inbound` | `InboundIR` in `sb-config/src/ir/` | ✅ | Full parity |
| `option.Outbound` | `OutboundIR` in `sb-config/src/ir/` | ✅ | Full parity |
| `option.Service` | `ServiceIR` in `sb-config/src/ir/` | ✅ | Listen fields + TLS container aligned |
| `option.SSMAPIServiceOptions` | `ServiceIR` with `ty=Ssmapi` | ✅ | `servers` map + `cache_path` aligned |
| `option.DERPServiceOptions` | `ServiceIR` with `ty=Derp` | ✅ | All fields aligned |
| `option.ResolvedServiceOptions` | `ServiceIR` with `ty=Resolved` | ✅ | Listen fields aligned |
| `constant.TypeSSMAPI = "ssm-api"` | `ServiceType::Ssmapi` | ✅ | Serializes as `"ssm-api"` |
| `constant.TypeDERP = "derp"` | `ServiceType::Derp` | ✅ | Aligned |
| `constant.TypeResolved = "resolved"` | `ServiceType::Resolved` | ✅ | Aligned |
| `constant.TypeShadowsocksR` | `OutboundType::ShadowsocksR` | ⊘ | Go rejects; Rust accepts when feature enabled |
| `constant.TypeTailscale` (endpoint) | `EndpointType::Tailscale` | ❌ | Rust stub only |

---

## Detailed Gap Analysis

### 1) Tailscale Endpoint (Critical Gap)

**Go Implementation** (`protocol/tailscale/`):
- 4 files: `endpoint.go`, `dns_transport.go`, `protect_android.go`, `protect_nonandroid.go`
- Full `tsnet.Server` with gVisor netstack
- Control plane auth via Tailscale control URL
- DNS hooks with `LookupHook` integration
- Router/filter integration with `wgengine.ReconfigListener`
- State directory management with `filemanager`
- Accept routes, exit node, advertise routes configuration
- TCP+UDP data plane through netstack
- Network monitor integration via `netmon.RegisterInterfaceGetter`
- Platform interface for Android protect

**Rust Implementation** (`crates/sb-core/src/endpoint/tailscale.rs` - 38KB):
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
- Rust: `OutboundType::ShadowsocksR` implemented in `outbound/shadowsocksr/` (5 files)
- **Resolution**: Feature-gated with `legacy_shadowsocksr` (default OFF)

**Tailscale Outbound**:
- Go: No `tailscale` outbound exists; Tailscale is endpoint-only
- Rust: `OutboundType::Tailscale` implemented in `outbound/tailscale.rs` (21KB)
- **Resolution**: Feature-gated with `legacy_tailscale_outbound` (default OFF)

### 3) uTLS Integration (Partial)

**Go Implementation** (`common/tls/utls_client.go` - 8KB):
- Full `UTLSClientConfig` with fingerprint selection
- Supported fingerprints: Chrome, Firefox, Edge, Safari, 360, QQ, iOS, Android, random, randomized
- ECH support integration
- Fragment and record fragment support
- Wired into all TLS client paths

**Rust Implementation** (`crates/sb-tls/src/utls.rs` - 28KB):
- `UtlsFingerprint` enum with all fingerprints defined
- `UtlsConfig` struct with configuration
- Name→fingerprint parsing aligned with Go aliases
- Wired into TLS paths: Standard TLS, REALITY, ShadowTLS

**Impact**: Fingerprint selection is wired, but cannot match Go/uTLS on-wire fingerprints without different TLS stack.

### 4) ECH (Partial / Build-Gated in Go)

**Go Implementation** (`common/tls/ech*.go`):
- 4 files: `ech.go`, `ech_shared.go`, `ech_stub.go`, `ech_tag_stub.go`
- Enabled only on `go1.24` builds; otherwise returns "ECH requires go1.24 …"
- When enabled, integrates with stdlib `crypto/tls` ECH hooks

**Rust Implementation** (`crates/sb-tls/src/ech/` - 5 files):
- ECHConfigList parsing + HPKE primitives + CLI keygen exist
- **Missing** runtime TLS handshake integration (rustls 0.23 has no native ECH)

**Impact**: Config-level and crypto scaffolding exist, but runtime ECH parity is blocked by TLS library support.

### 5) DNS DHCP Transport (Partial Gap)

**Go Implementation** (`dns/transport/dhcp/`):
- 2 files: `dhcp.go`, `dhcp_shared.go`
- Active DHCP INFORM probe
- Interface discovery
- Server timeout and refresh handling

**Rust Implementation**:
- Passive `resolv.conf` monitoring only
- No DHCP INFORM probes
- No interface discovery

**Impact**: DHCP-discovered DNS servers may not be detected dynamically.

### 6) Experimental Features (De-scoped)

**Go `experimental/`** (6 subdirectories, 80+ files):
- `cachefile/` - persistent cache for rule sets (3 files)
- `clashapi/` - Clash API compatibility (19 files)
- `v2rayapi/` - V2Ray stats API (4 files)
- `libbox/` - mobile platform bindings (47 files)
- `locale/` - localization (2 files)
- `deprecated/` - deprecated feature warnings (3 files)

**Rust Status**: Intentionally **not ported** as Go-specific experimental features. However, Rust has **custom implementations**:
- Clash API → `services/clash_api.rs` (23KB, Rust-native)
- V2Ray API → `services/v2ray_api.rs` (16KB, Rust-native)
- Cache File → `services/cache_file.rs` (14KB, Rust-native)

---

## Summary Statistics

| Category | Aligned | Partial | Not Aligned | Feature-gated | Rust-only |
| --- | --- | --- | --- | --- | --- |
| Inbound Protocols | 18 | 0 | 0 | 0 | 1 |
| Outbound Protocols | 18 | 0 | 0 | 2 | 0 |
| Endpoints | 1 | 0 | 1 | 0 | 0 |
| Services (Go parity) | 3 | 0 | 0 | 0 | 6 |
| Transports | 10 | 0 | 0 | 0 | 9 |
| DNS Transports | 10 | 1 | 0 | 0 | 1 |
| TLS/Crypto | 6 | 2 | 0 | 0 | 0 |
| Config Schema | 9 | 0 | 1 | 1 | 0 |
| Go Directories | 12 | 2 | 1 | 0 | 0 |
| **Total** | **87** | **5** | **3** | **3** | **17** |

**Parity Rate**: ~90% aligned (87 aligned / 95 core items)
- 3 not aligned (Tailscale endpoint, Tailscale config, 1 DNS transport)
- 3 feature-gated (de-scoped legacy features)
- 17 Rust-only extensions

---

## Priority Remediation Order

### P0: Protocol Divergence Cleanup ✅ Completed

1. **ShadowsocksR**: Feature-gated with `legacy_shadowsocksr` (default OFF)
2. **Tailscale Outbound**: Feature-gated with `legacy_tailscale_outbound` (default OFF)

### P1: SSMAPI + Resolved Service Alignment ✅ Completed

1. ✅ SSMAPI: `update_users()`, `post_update()`, `TrafficManager` aligned
2. ✅ Resolved: D-Bus server + DNSRouter injection + NetworkMonitor callbacks

### P2: DNS DHCP Enhancement (Low priority, 1-2 days)

- [ ] Add active DHCP INFORM probe
- [ ] Add interface discovery
- [ ] Server timeout and refresh handling

### P3: TLS Fidelity (Blocked by rustls)

- [ ] Decide approach for full uTLS fingerprint parity
- [ ] Decide ECH runtime parity approach

### P4: Tailscale Stack Parity (Major undertaking - 2-4 weeks)

- [ ] Evaluate tsnet/FFI integration for netstack TCP/UDP and DNS hooks
- [ ] Evaluate `tailscale-control` pure Rust alternative
- [ ] Write decision document

---

## File Reference

### Go Reference (`go_fork_source/sing-box-1.12.12`)

| Directory | Files | Contents |
| --- | --- | --- |
| `protocol/` | 23 subdirs | Protocol implementations |
| `service/` | 3 subdirs | derp, resolved, ssmapi services |
| `transport/` | 11 subdirs | Transport implementations |
| `common/tls/` | 20 files | TLS implementations |
| `dns/transport/` | 5 subdirs | DNS transport implementations |
| `option/` | 47 files | Config type definitions |
| `constant/` | 22 files | Type constants and enums |
| `route/` | 7 files + rule/ | Router and rule engine |
| `adapter/` | 26 files | Adapter interfaces |
| `log/` | 10 files | Logging infrastructure |
| `experimental/` | 6 subdirs | Experimental features (de-scoped) |
| `cmd/` | CLI | Command-line interface |

### Rust Implementation (`crates/`)

| Crate | Files | Purpose |
| --- | --- | --- |
| `sb-adapters` | 109 | Protocol implementations (inbound/outbound/endpoint/service) |
| `sb-config` | 49 | Config parsing, validation, IR types |
| `sb-core` | 424 | Core runtime, router, DNS, services |
| `sb-tls` | 20 | TLS implementations (utls, reality, ech, acme) |
| `sb-transport` | 57 | Transport layer implementations |
| `sb-common` | 10 | Shared utilities |
| `sb-platform` | 20 | Platform-specific code |
| `sb-runtime` | 17 | Async runtime utilities |
| `sb-types` | 2 | Shared type definitions |
| `sb-metrics` | 9 | Metrics and telemetry |
| `sb-proto` | 9 | Protocol-specific types |
| `sb-api` | 29 | Admin API |
| `sb-subscribe` | 24 | Subscription management |
| `sb-security` | 5 | Security utilities |
| `sb-test-utils` | 3 | Test utilities |
| `sb-admin-contract` | 2 | Admin API contracts |

---

## Calibration Metadata

- **Date**: 2025-12-16
- **Go Reference Version**: sing-box-1.12.12
- **Rust Project**: singbox-rust
- **Methodology**: File-by-file directory comparison, protocol enumeration, service/transport/TLS/DNS mapping
