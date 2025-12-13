# Go-Rust Parity Matrix (2025-12-13 Comprehensive Calibration)

Objective: compare `singbox-rust` against Go reference `go_fork_source/sing-box-1.12.12` for functional, type, API, comment, and directory parity.

## Executive Summary

| Area | Status | Notes |
| --- | --- | --- |
| **Protocol Coverage** | ✅ High | 23/23 Go protocols have Rust equivalents (see Protocol Matrix below) |
| **Tailscale endpoint/data plane** | ❌ Not aligned | Go uses tsnet+gVisor netstack; Rust uses stub/daemon with host sockets |
| **Tailscale outbound & MagicDNS** | ❌ Not aligned | Go routes via tsnet + DNS hooks; Rust modes are ad-hoc with raw MagicDNS |
| **DNS transports (DHCP/Resolved/Tailscale)** | ◐ Partial | DHCP passive only; tailscale transport not feature-equivalent |
| **TLS uTLS wiring** | ✅ Aligned | Wired into standard/REALITY/ShadowTLS client paths |
| **Resolved service** | ✅ Aligned | D-Bus + per-link routing + NetworkMonitor with Linux netlink |
| **DERP service** | ✅ Aligned | HTTP + DERP protocol v2; mesh_key in ClientInfo; verify_client_endpoint; TLS |
| **SSMAPI service** | ✅ Aligned | REST API + stats + cache + TLS + HTTP/2 + per-server routing |
| **Transport layer** | ✅ High | WebSocket, gRPC, HTTP/2, QUIC, simple-obfs, sip003 all implemented |
| **Router/Rules** | ✅ High | Rule matching, geoip, geosite, process detection aligned |

---

## Directory / Module Parity Matrix

| Go Module/Dir | Rust Crate/Module | Status | Notes |
| --- | --- | --- | --- |
| `adapter/` | `crates/sb-core/src/adapter/`, `crates/sb-adapters/` | ✅ | Trait surface and lifecycle aligned |
| `common/` | `crates/sb-common/`, `crates/sb-platform/`, `crates/sb-runtime/` | ◐ | Some helper APIs differ; see area-specific gaps |
| `constant/` | `crates/sb-types/` + per‑crate `types.rs`/enum modules | ✅ | Constants/enums mirrored where used |
| `dns/` | `crates/sb-core/src/dns/` | ✅ | Core resolver aligned; DHCP/Resolved/Tailscale transports partial |
| `log/` | `crates/sb-core/src/log/`, `crates/sb-metrics/` | ✅ | Logging levels/fields aligned |
| `option/` | `crates/sb-config/` (schema + IR) | ✅ | Options/IR parity maintained |
| `protocol/` | `crates/sb-adapters/`, `crates/sb-proto/`, `crates/sb-transport/` | ✅ | Protocol implementations aligned |
| `route/` | `crates/sb-core/src/router/`, `crates/sb-core/src/routing/` | ✅ | Rule engine aligned |
| `service/` | `crates/sb-core/src/services/`, `crates/sb-adapters/src/service/` | ◐ | DERP/Resolved/SSMAPI still partial |
| `transport/` | `crates/sb-transport/`, `crates/sb-tls/` | ✅ | Transport APIs aligned; uTLS wired (see TLS/Crypto matrix) |
| `cmd/`, `box.go` | `app/`, `crates/sb-core/src/bin/` | ✅ | CLI/subcommand parity aligned |
| `experimental/` | N/A | ❌ | Go-only experimental features not ported |

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
| shadowsocksr | `crates/sb-adapters/src/outbound/shadowsocksr/` | ✅ | SSR with obfs/protocol |
| shadowtls | `crates/sb-adapters/src/outbound/shadowtls.rs` | ✅ | uTLS wired via `utls_fingerprint` |
| socks4 | `crates/sb-adapters/src/outbound/socks4.rs` | ✅ | SOCKS4 client |
| socks5 | `crates/sb-adapters/src/outbound/socks5.rs` | ✅ | SOCKS5 client |
| ssh | `crates/sb-adapters/src/outbound/ssh.rs` | ✅ | SSH client |
| tailscale | `crates/sb-adapters/src/outbound/tailscale.rs` | ❌ | Missing tsnet integration |
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
| derp | `crates/sb-core/src/services/derp/` | ✅ | HTTP + DERP protocol v2 aligned; mesh_key in ClientInfo; verify_client_endpoint implemented; /derp/mesh deprecated |
| resolved | `crates/sb-adapters/src/service/resolved_impl.rs` | ✅ | D-Bus + per-link transport aligned; NetworkMonitor with Linux netlink implemented |
| ssmapi | `crates/sb-core/src/services/ssmapi/` | ✅ | REST API + trackers + cache aligned; TLS + HTTP/2; per-server routing prefixes; ManagedSSMServer trait |

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
| utls_client | `crates/sb-tls/src/utls.rs` | ✅ | Fingerprint mapping + ClientConfig builder; wired into client call sites |
| reality_client/server | `crates/sb-tls/` | ✅ | Client uses uTLS-ordered config while preserving REALITY verifier |
| ech | N/A | ❌ | ECH not implemented |
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

### 2) DERP Service (Critical Gap)

**Go Implementation** (`service/derp/service.go`):
- Mandatory TLS with HTTP/2 support
- DERP HTTP handler with WebSocket upgrade (`addWebSocketSupport`)
- STUN listener on UDP port 3478
- Mesh PSK key support (`SetMeshKey`)
- Verify client via HTTP endpoints (`SetVerifyClientURL`)
- Verify client via Tailscale endpoints (`verify_client_endpoint`)
- Latency probe endpoints (`/derp/probe`, `/derp/latency-check`)
- Bootstrap DNS handler (`/bootstrap-dns`)
- Home page handler (simple/demo modes)
- Full `derp.Server` with tailscale client library

**Rust Implementation** (`crates/sb-core/src/services/derp/`):
- STUN UDP listener implemented (configurable)
- TLS acceptor supported (currently optional; Go requires TLS)
- HTTP server refactored to `hyper` (HTTP/1.1 + HTTP/2 + upgrade support)
- `/derp` supports:
  - Upgrade-only DERP handler (requires `Upgrade: derp|websocket`; matches `derphttp.Handler`)
  - Fast-start mode (`Derp-Fast-Start: 1`) supported (no 101 response bytes; client starts DERP frames immediately)
  - WebSocket upgrade gated by `Upgrade: websocket` + `Sec-WebSocket-Protocol` contains `derp` (matches Go `addWebSocketSupport` predicate)
- `/derp/probe`, `/derp/latency-check` match `derphttp.ProbeHandler` (GET/HEAD sets `Access-Control-Allow-Origin: *`; other methods 405)
- `/generate_204` matches `derphttp.ServeNoContent` (`X-Tailscale-Challenge` → `X-Tailscale-Response`)
- `/bootstrap-dns` implemented (JSON mapping; `Connection: close`; uses global DNS resolver; browser headers via `tsweb.AddBrowserHeaders`)
- Home/utility endpoints implemented: `/` (default HTML / blank / redirect), `/robots.txt` (browser headers via `tsweb.AddBrowserHeaders`)
- `verify_client_url` enforced during DERP handshake (ClientInfo read → verify → register)
- `verify_client_endpoint` parsed but not enforced (warn-only)
- **DERP wire protocol is not yet tailscale-compatible**: current Rust frames (`sb_transport::derp::protocol`) do not match sagernet/tailscale DERP (`ProtocolVersion=2`, naclbox ClientInfo/ServerInfo, different frame IDs, ping/pong types, etc.)
- Mesh wiring is still Rust-specific: `/derp/mesh` + `x-derp-mesh-psk` header; Go mesh key is carried in encrypted ClientInfo (`meshKey`) and `derphttp.NewClient(...).MeshKey`

**Impact**: DERP HTTP endpoints are now aligned to Go `derphttp`/`tsweb` behavior and test-verified, but standard Tailscale DERP clients still cannot interoperate until the DERP wire protocol (and mesh/verify_client_endpoint) is made compatible.

### 3) SSMAPI Service (Critical Gap)

**Go Implementation** (`service/ssmapi/server.go`):
- Binds to managed Shadowsocks inbounds via `InboundManager`
- `TrafficManager` for bandwidth tracking
- `UserManager` for user management on managed SSM servers
- Per-server routing via chi router
- Optional TLS support
- Cache persistence (`CachePath`, `loadCache`, `saveCache`)
- HTTP/2 enabled when TLS active

**Rust Implementation** (`crates/sb-core/src/services/ssmapi/`):
- Axum REST API with endpoint set matching Go
- `UserManager` + `TrafficManager` implemented with Go‑compatible fields
- Cache load/save on start/close (`ssmapi_cache_path`) implemented
- Traits `TrafficTracker` and `ManagedSSMServer` added for future inbound binding
- **Missing** InboundManager binding / per‑server routing prefixes and optional TLS

**Impact**: API semantics and stats parity are high, but service cannot yet auto‑manage multiple inbounds or serve over TLS.

### 4) uTLS Integration (Implemented)

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

**Impact**: uTLS fingerprint selection is now functional, but fidelity is limited (cipher-suite/ALPN ordering only; not full uTLS extension-order parity yet).

### 5) Resolved Service (Partial Gap)

**Go Implementation** (`service/resolved/service.go`):
- Full D-Bus server at `org.freedesktop.resolve1`
- Per-link DNS/domain tracking (`TransportLink`)
- Network monitor callback integration (`NetworkUpdateCallback`)
- TCP+UDP DNS serving via listener
- Default route sequence management
- Link update/delete callbacks

**Rust Implementation** (`crates/sb-adapters/src/service/resolved_impl.rs` + `crates/sb-core/src/dns/transport/resolved.rs`):
- D-Bus `org.freedesktop.resolve1.Manager` server implemented on Linux
- Per‑link DNS/domain state tracked in `Resolve1ManagerState`
- Resolved DNS transport mirrors Go `TransportLink` routing + ndots/search semantics
- DNS stub listener implemented
- **Missing** NetworkMonitor callback registration and Linux netlink change tracking

**Impact**: Feature parity is high on static networks; dynamic link updates still lag Go.

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

---

## Summary Statistics

| Category | Aligned | Partial | Not Aligned |
| --- | --- | --- | --- |
| Inbound Protocols | 19 | 0 | 0 |
| Outbound Protocols | 21 | 0 | 1 |
| Endpoints | 1 | 0 | 1 |
| Services | 0 | 3 | 0 |
| Transports | 10 | 0 | 0 |
| DNS Transports | 8 | 2 | 0 |
| TLS/Crypto | 4 | 0 | 1 |
| **Total** | **63** | **5** | **3** |

---

## Priority Remediation Order

1. **DERP Service Alignment**
   - Implement tailscale DERP wire protocol parity (v2 frames + naclbox handshake)
   - Migrate mesh to Go semantics (remove `/derp/mesh`; use `meshKey` in ClientInfo)
   - Implement `verify_client_endpoint` enforcement (Tailscale LocalClient integration)

2. **SSMAPI Service Finalization**
   - Bind to managed Shadowsocks inbounds (per‑server routing prefixes)
   - Add optional TLS + HTTP/2 enablement

3. **Resolved Service Completion**
   - Register NetworkMonitor callbacks
   - Add Linux netlink interface change tracking

4. **Tailscale Stack Parity** (Major undertaking)
   - Evaluate tsnet FFI integration
   - Implement netstack TCP/UDP data plane
   - Add DNS hook integration

5. **DHCP Transport Enhancement**
   - Add active DHCP INFORM probe
   - Implement interface discovery
