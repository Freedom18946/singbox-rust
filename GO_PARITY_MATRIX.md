# Go-Rust Parity Matrix (2025-12-13 Comprehensive Calibration)

Objective: compare `singbox-rust` against Go reference `go_fork_source/sing-box-1.12.12` for functional, type, API, comment, and directory parity.

## Status Legend

- ✅ **Aligned**: behavior/types/API/config match Go reference.
- ◐ **Partial**: implemented but missing/ diverging details; not yet interchangeable.
- ❌ **Not aligned**: stubbed, materially divergent, or Go feature is absent/disabled but Rust exposes it.

## Executive Summary

| Area | Status | Notes |
| --- | --- | --- |
| **Protocol Coverage** | ✅ High | All 23 Go `protocol/*` modules have Rust counterparts (see Protocol Matrix below) |
| **Tailscale endpoint/data plane** | ❌ Not aligned | Go uses tsnet+gVisor netstack; Rust uses stub/daemon with host sockets |
| **Tailscale outbound (Go has no outbound)** | ❌ Not aligned | Go exposes Tailscale as an **endpoint**; Rust also exposes a `tailscale` **outbound** (divergence; should be gated/de-scoped) |
| **DNS transports (DHCP/Resolved/Tailscale)** | ◐ Partial | DHCP passive only; tailscale transport not feature-equivalent |
| **TLS uTLS fidelity** | ◐ Partial | Wired, but rustls cannot reproduce Go/uTLS extension ordering and full ClientHello shape |
| **ECH (Go: go1.24+)** | ◐ Partial | Rust has config/parser/HPKE scaffolding but no rustls ECH handshake integration |
| **Resolved service** | ◐ Partial | D-Bus skeleton exists (Linux+feature gated) but query path/monitor parity is incomplete |
| **DERP service** | ◐ Partial | HTTP endpoints + TLS-required + `config_path` JSON key + NaCl box wire protocol + Go mesh model (`meshKey` in ClientInfo) aligned; remaining: `verify_client_endpoint` (de-scoped, requires Tailscale LocalClient) |
| **SSMAPI service** | ◐ Partial | Config type/schema + per-endpoint routing aligned; managed inbound binding + API/cache contract still diverge |
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
| `option/` | `crates/sb-config/` (schema + IR) | ◐ | Core coverage high; service schema/type IDs now aligned (see Gap #0) |
| `protocol/` | `crates/sb-adapters/`, `crates/sb-proto/`, `crates/sb-transport/` | ✅ | Protocol implementations aligned |
| `route/` | `crates/sb-core/src/router/`, `crates/sb-core/src/routing/` | ✅ | Rule engine aligned |
| `service/` | `crates/sb-core/src/services/`, `crates/sb-adapters/src/service/` | ◐ | DERP/Resolved partial; SSMAPI partial (see Service Matrix) |
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
| shadowsocksr | `crates/sb-adapters/src/outbound/shadowsocksr/` | ❌ | Go keeps options for compatibility but registry rejects (removed); Rust currently implements (divergence) |
| shadowtls | `crates/sb-adapters/src/outbound/shadowtls.rs` | ✅ | uTLS wired via `utls_fingerprint` |
| socks4 | `crates/sb-adapters/src/outbound/socks4.rs` | ✅ | SOCKS4 client |
| socks5 | `crates/sb-adapters/src/outbound/socks5.rs` | ✅ | SOCKS5 client |
| ssh | `crates/sb-adapters/src/outbound/ssh.rs` | ✅ | SSH client |
| tailscale | `crates/sb-adapters/src/outbound/tailscale.rs` | ❌ | Go does not provide a tailscale outbound (endpoint-only); Rust outbound is a divergence |
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
| derp | `crates/sb-core/src/services/derp/` | ◐ | TLS-required + `config_path` key JSON + tailscale DERP v2 (NaCl box ClientInfo/ServerInfo) + Go mesh model (`meshKey` in ClientInfo) aligned; `verify_client_endpoint` de-scoped (requires Tailscale LocalClient daemon) |
| resolved | `crates/sb-adapters/src/service/resolved_impl.rs`, `crates/sb-adapters/src/service/resolve1.rs` | ◐ | Linux+feature gated; DNS routing/monitor parity incomplete vs Go `adapter.DNSRouter` + netmon |
| ssmapi | `crates/sb-core/src/services/ssmapi/` | ◐ | Config type/schema + per-endpoint routing aligned; managed inbound binding + API response/caching + UpdateUsers parity still missing |

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

## Detailed Gap Analysis

### 0) Service Config Schema / Type IDs (✅ Aligned)

**Go Reference** (docs + options):
- Services use shared **Listen Fields**: `listen`, `listen_port`, etc. (e.g. `docs/configuration/shared/listen/`)
- `ssm-api` service type is **`"ssm-api"`** (Go constant `TypeSSMAPI = "ssm-api"`), and its `servers` is **endpoint→inbound tag** mapping
- DERP/Resolved/SSMAPI structures: `docs/configuration/service/derp.md`, `docs/configuration/service/resolved.md`, `docs/configuration/service/ssm-api.md`

**Rust Now**:
- Service IR uses shared Listen Fields + shared `tls` object in `crates/sb-config/src/ir/mod.rs`
- `ServiceType::Ssmapi` serializes as `"ssm-api"`; v2 validator also accepts legacy `"ssmapi"` as a compatibility alias (`crates/sb-config/src/validator/v2.rs`)
- v2 validator maps legacy Rust-only service fields (`*_listen`, `*_tls_*`, etc.) into Go-shaped fields for backward compatibility
- v2 schema accepts top-level `services` (`crates/sb-config/src/validator/v2_schema.json`)

**Impact**: Go service configs are now parseable and type-compatible; remaining gaps are service-runtime specific (DERP/SSMAPI/Resolved).

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
- `config_path` required (persistent server key)
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
- TLS acceptor is required (Go parity); missing `tls` or `config_path` errors during service build
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
- DERP wire protocol is now tailscale-compatible: `sb_transport::derp::protocol` matches sagernet/tailscale DERP v2 (`ProtocolVersion=2`, frame IDs, ping/pong) and implements NaCl box ClientInfo/ServerInfo handshake; server key persistence uses Go-compatible JSON (`{"PrivateKey":"privkey:<64hex>"}`)
- Mesh wiring is now Go-compatible: `meshKey` in ClientInfo is validated during handshake; server promotes client to mesh peer when keys match. `/derp/mesh` endpoint is deprecated but retained for backward compatibility.
- `verify_client_endpoint` is parsed but de-scoped (warn-only); full enforcement requires Tailscale LocalClient (Unix socket) integration.

**Impact**: DERP HTTP endpoints, wire protocol, and mesh semantics are aligned to Go (`derphttp`/`tsweb` + DERP v2 + `SetMeshKey`). `verify_client_endpoint` is de-scoped due to external Tailscale daemon dependency.

### 3) SSMAPI Service (Partial)

**Go Implementation** (`service/ssmapi/server.go`):
- Binds to managed Shadowsocks inbounds via `InboundManager`
- `TrafficManager` for bandwidth tracking
- `UserManager` for user management on managed SSM servers
- Per-server routing via chi router
- Optional TLS support + HTTP/2 enablement
- Cache persistence per endpoint (`CachePath`, `loadCache`, `saveCache`) including users + traffic
- HTTP/2 enabled when TLS active

**Rust Implementation** (`crates/sb-core/src/services/ssmapi/` + `crates/sb-config/src/ir/mod.rs`):
- HTTP server exists and some endpoints are implemented
- Config-level parity:
  - `type="ssm-api"` + Listen Fields + `tls` object supported
  - `servers` endpoint→inbound tag is parsed and used for `{endpoint}/server/v1/...` routing
- **API parity**: Go `GET /server/v1/users` returns `{"users":[UserObject...]}`; Rust now matches ✅
- **Cache model mismatch**: Go caches per-endpoint traffic + users; Rust cache is global and incomplete
- **Missing** `ManagedSSMServer.UpdateUsers` parity: Rust `UserManager` does not push user set to managed SS inbound

**Impact**: Config and routing are aligned, but service is not drop-in compatible until managed inbound binding + API response + cache format match Go.

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
- Enabled only on `go1.24` builds; otherwise returns “ECH requires go1.24 …”
- When enabled, integrates with stdlib `crypto/tls` ECH hooks

**Rust Implementation** (`crates/sb-tls/src/ech/`):
- ECHConfigList parsing + HPKE primitives + CLI keygen exist
- **Missing** runtime TLS handshake integration (rustls 0.23 has no native ECH)

**Impact**: Config-level and crypto scaffolding exist, but runtime ECH parity is blocked by TLS library support.

### 6) Resolved Service (Partial Gap)

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
- **Behavior gap**: Go forwards queries via `adapter.DNSRouter`; Rust service currently uses a system resolver for query handling

**Impact**: Feature parity is high on static networks; dynamic link updates still lag Go.

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

---

## Summary Statistics

| Category | Aligned | Partial | Not Aligned |
| --- | --- | --- | --- |
| Inbound Protocols | 19 | 0 | 0 |
| Outbound Protocols | 20 | 0 | 2 |
| Endpoints | 1 | 0 | 1 |
| Services | 0 | 3 | 0 |
| Transports | 10 | 0 | 0 |
| DNS Transports | 8 | 2 | 0 |
| TLS/Crypto | 3 | 2 | 0 |
| **Total** | **61** | **7** | **3** |

---

## Priority Remediation Order

1. **DERP Service Alignment**
   - ✅ Enforce TLS-required + `config_path` required behavior
   - ✅ Implement tailscale DERP wire protocol parity (v2 frames + NaCl box handshake)
   - ✅ Migrate mesh to Go semantics (`meshKey` in ClientInfo; `/derp/mesh` retained for backward compat)
   - ⊘ De-scoped: `verify_client_endpoint` requires Tailscale LocalClient daemon integration

2. **SSMAPI Service Alignment**
   - Implement Go `servers` endpoint→inbound binding, per-endpoint state/cache, and API response parity
   - Decide fate of Rust-only `tailscale` outbound and implemented `shadowsocksr` outbound (Go rejects)

3. **Resolved Service Completion**
   - Route DNS via configured router (Go `adapter.DNSRouter` equivalent)
   - Register NetworkMonitor callbacks + Linux netlink change tracking

4. **TLS Fidelity**
   - Decide approach for full uTLS fingerprint parity and ECH runtime parity (blocked by rustls limitations)

5. **Tailscale Stack Parity** (Major undertaking)
   - Evaluate tsnet/FFI integration for netstack TCP/UDP and DNS hooks

6. **DHCP Transport Enhancement**
   - Add active DHCP INFORM probe + interface discovery
