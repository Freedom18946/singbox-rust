<!--
  High-level architecture for singbox-rust.
  This document is intentionally verbose to serve as a newcomer-friendly guide.
-->

# singbox-rust Architecture

> TL;DR: Small, boring, testable components — **pragmatism over theory**.

**Last Updated**: 2025-10-09
**Status**: Production-ready (v0.2.0+)
**Feature Parity**: 99%+ with upstream sing-box

## Overview

singbox-rust is a complete Rust rewrite of sing-box, designed for high performance, memory safety, and cross-platform compatibility. The architecture follows a modular, trait-based design with clear separation of concerns.

## Core Principles

1. **Small, Testable Components**: Each module has a single, well-defined responsibility
2. **Trait-Based Abstractions**: Pluggable implementations via traits (TlsConnector, OutboundConnector, etc.)
3. **Zero-Cost Abstractions**: Feature flags enable/disable functionality without runtime overhead
4. **Never Break Userspace**: We add, we don't remove - backward compatibility is paramount
5. **Async-First**: Built on tokio with `#[async_trait]` throughout

## Crates

### Core Infrastructure

- **sb-core**
  Minimal platform-agnostic contracts and core functionality:
  - `net::Address` - Network address abstraction
  - `pipeline::{Inbound, Outbound}` - Protocol pipeline traits
  - `router::{Router, StaticRouter, engine::RuleRouter}` - Routing engine
  - `dns::*` - DNS resolution system
  - `metrics::*` - Prometheus metrics integration
  - `error::*` - Structured error handling

- **sb-tls** ⭐ **NEW** (Sprint 5)
  Comprehensive TLS infrastructure with anti-censorship protocols:
  - **Standard TLS**: Production-ready TLS 1.2/1.3 using rustls
  - **REALITY**: X25519-based TLS camouflage with fallback proxy
  - **ECH**: HPKE-encrypted SNI for privacy (RFC 9460)
  - **uTLS**: TLS fingerprint mimicry (future)
  - Unified `TlsConnector` trait for pluggable implementations

- **sb-adapters**
  Protocol implementations for inbound and outbound connections:
  - **Inbounds**: HTTP, SOCKS5, Mixed, TUN, Direct, VMess, VLESS, Trojan, Shadowsocks, TUIC, Hysteria v1/v2, Naive, ShadowTLS
  - **Outbounds**: Direct, Block, DNS, HTTP, SSH, Shadowsocks, VMess, VLESS, Trojan, TUIC, Hysteria v1/v2, ShadowTLS, Selector, URLTest
  - Feature flags: `in_*` (inbounds), `out_*` (outbounds)

- **sb-transport**
  Transport layer implementations:
  - TCP/UDP transports
  - V2Ray transports: WebSocket, HTTP/2, HTTPUpgrade, gRPC, Multiplex (yamux)
  - QUIC support for Hysteria/TUIC/DoQ
  - Circuit breaker and connection pooling

- **sb-config**
  Configuration parsing and validation:
  - JSON/YAML config support
  - Schema v2 validation (`v2_schema.json`)
  - V1→V2 migration tools
  - ConfigIR (Internal Representation) for runtime

- **sb-proto**
  Protocol-level implementations:
  - Shadowsocks 2022 AEAD
  - VMess encryption
  - VLESS protocol
  - Trojan protocol
  - Hysteria congestion control

### Infrastructure & Platform

- **sb-platform**
  Platform-specific functionality:
  - Process matching (native APIs on macOS/Windows/Linux)
  - TUN device management (cross-platform)
  - OS detection and capabilities

- **sb-metrics**
  Observability and monitoring:
  - Prometheus exporter
  - Cardinality monitoring (label explosion prevention)
  - Connection tracking
  - Performance metrics

- **sb-security**
  Security utilities:
  - Constant-time credential verification
  - Memory-safe secret handling (ZeroizeOnDrop)
  - Credential redaction in logs
  - JWT authentication provider

- **sb-api**
  External API interfaces:
  - V2Ray StatsService (gRPC)
  - Clash API endpoints (planned)
  - Admin API with JWT auth

- **sb-subscribe**
  Subscription management:
  - Remote subscription fetching
  - Node parsing and validation
  - Auto-update with caching

### Application

- **app**
  Main binary with CLI tools:
  - `run` - Start proxy server
  - `check` - Validate configuration
  - `version` - Show version info
  - `format` - Format config files
  - `generate` - Generate keypairs (REALITY, ECH, WireGuard, TLS, VAPID)
  - `geoip` - GeoIP database tools (list, lookup, export)
  - `geosite` - Geosite database tools (list, lookup, export)
  - `rule-set` - Rule-set management (compile, convert, merge, validate)
  - `tools` - Utilities (connect, fetch, sync-time)

## Data Flow

### Complete Request Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                         Application Layer                        │
│  ┌────────┐  config/env  ┌──────────┐  routes  ┌─────────────┐ │
│  │  app   │ ────────────▶│  Router  │ ────────▶│ Outbound    │ │
│  └────────┘              │  Engine  │          │ Selector    │ │
│      ▲                   └──────────┘          └─────────────┘ │
└──────┼──────────────────────┬────────────────────────┬──────────┘
       │                      │                        │
┌──────┼──────────────────────┼────────────────────────┼──────────┐
│      │                      │                        │           │
│      │  ┌──────────────┐    │  ┌─────────────────┐  │           │
│      └──│   Inbound    │────┘  │  TLS Transport  │──┘           │
│         │  (TUN/SOCKS) │       │  (REALITY/ECH)  │              │
│         └──────────────┘       └─────────────────┘              │
│              │                          │                        │
│              ▼                          ▼                        │
│         ┌─────────────────────────────────────────┐             │
│         │        Protocol Layer (sb-proto)        │             │
│         │  VMess │ VLESS │ Trojan │ Shadowsocks  │             │
│         └─────────────────────────────────────────┘             │
│                          │                                       │
│                          ▼                                       │
│         ┌─────────────────────────────────────────┐             │
│         │     Transport Layer (sb-transport)      │             │
│         │   TCP │ UDP │ QUIC │ WebSocket │ HTTP/2│             │
│         └─────────────────────────────────────────┘             │
└───────────────────────────────────────────────────────────────────┘
```

### Inbound Processing (Two Dimensions)

**Dimension 1: Local Entry Point** (Client Mode)
```
Local App → TUN/SOCKS5/HTTP Inbound → Router → Outbound → Remote Server
```

**Dimension 2: Remote Reception** (Server Mode)
```
Remote Client → Protocol Inbound (VMess/VLESS/Trojan Server) → Decrypt → Router → Direct Outbound → Target
```

## Router Engine

### Rule Matching

Rules are evaluated sequentially with first-match wins:

```rust
pub struct Rule {
    // Source matching
    pub inbound: Option<Vec<String>>,        // Match inbound tag
    pub source_ip_cidr: Option<Vec<IpNet>>,  // Match source IP
    pub source_port: Option<Vec<u16>>,       // Match source port

    // Destination matching
    pub domain: Option<Vec<String>>,         // Exact domain match
    pub domain_suffix: Option<Vec<String>>,  // Domain suffix match
    pub domain_keyword: Option<Vec<String>>, // Domain contains keyword
    pub ip_cidr: Option<Vec<IpNet>>,        // Destination IP CIDR
    pub port: Option<Vec<u16>>,             // Destination port

    // Protocol matching
    pub protocol: Option<Vec<String>>,       // tcp/udp
    pub network: Option<String>,             // tcp/udp

    // Sniffing data
    pub sniff_host: Option<Vec<String>>,     // Sniffed SNI/HTTP Host
    pub sniff_alpn: Option<Vec<String>>,     // Sniffed ALPN

    // Process matching (platform-specific)
    pub process_name: Option<Vec<String>>,   // Process name
    pub process_path: Option<Vec<String>>,   // Process executable path

    // Action
    pub outbound: String,                    // Target outbound tag
}
```

**No special cases.** Multiple domain suffixes become multiple `Rule`s.

### Sniffing Pipeline

Automatic protocol detection integrated with routing:

- **HTTP Host Sniffing**: Extract Host header from HTTP CONNECT
- **TLS SNI Sniffing**: Extract SNI from TLS ClientHello
- **QUIC ALPN Sniffing**: Extract ALPN from QUIC handshake

Sniffed data flows to router via `RouterInput::sniff_host` and `RouterInput::sniff_alpn`.

## TLS Architecture

### TlsConnector Trait Hierarchy

```
┌─────────────────────────────────────────┐
│         TlsConnector Trait              │
│  (Unified abstraction for all TLS)      │
└──────────┬──────────────────────────────┘
           │
     ┌─────┴──────┬─────────────┬──────────┐
     │            │             │          │
┌────▼────┐ ┌────▼────┐  ┌────▼────┐ ┌──▼──┐
│Standard │ │ REALITY │  │   ECH   │ │uTLS │
│   TLS   │ │  Client │  │ Client  │ │(TBD)│
└─────────┘ └─────────┘  └─────────┘ └─────┘
```

### TLS Implementation Details

1. **Standard TLS** (`sb-tls/src/standard.rs`)
   - rustls 0.23.x with WebPKI root verification
   - ALPN negotiation support
   - Client certificate authentication
   - Custom CA certificate support

2. **REALITY** (`sb-tls/src/reality/`)
   - X25519 key exchange with server public key
   - Auth data embedded in TLS ClientHello extension
   - Server-side auth verification with constant-time comparison
   - Fallback proxy for failed auth (e.g., www.microsoft.com)
   - E2E tests: `tests/reality_tls_e2e.rs`

3. **ECH** (`sb-tls/src/ech/`)
   - HPKE encryption: DHKEM-X25519-HKDF-SHA256 + CHACHA20POLY1305
   - ECHConfigList parsing and validation
   - SNI encryption in inner ClientHello
   - E2E tests: `tests/e2e/ech_handshake.rs`

## Feature Matrix

### Production-Ready Features (Full Implementation)

| Category | Feature | Crate | Status |
|----------|---------|-------|--------|
| **Inbounds** | TUN | sb-adapters | ✅ Full |
| | SOCKS5 | sb-adapters | ✅ Full |
| | Direct | sb-adapters | ✅ Full (TCP+UDP NAT) |
| | Hysteria v1 | sb-adapters | ✅ Full (QUIC, UDP) |
| | Hysteria2 | sb-adapters | ✅ Full (Salamander) |
| **Outbounds** | HTTP | sb-adapters | ✅ Full |
| | SSH | sb-adapters | ✅ Full (key auth) |
| | ShadowTLS | sb-adapters | ✅ Full |
| | Hysteria v1 | sb-adapters | ✅ Full (QUIC) |
| | Hysteria2 | sb-adapters | ✅ Full (Salamander) |
| | TUIC | sb-adapters | ✅ Full (UDP over stream) |
| **TLS** | Standard TLS | sb-tls | ✅ Full (rustls) |
| | REALITY | sb-tls | ✅ Full (X25519) |
| | ECH | sb-tls | ✅ Full (HPKE) |
| **Transport** | TCP/UDP | sb-transport | ✅ Full |
| | WebSocket | sb-transport | ✅ Full |
| | HTTP/2 | sb-transport | ✅ Full |
| | HTTPUpgrade | sb-transport | ✅ Full |
| | Multiplex | sb-transport | ✅ Full (yamux) |
| **APIs** | V2Ray Stats | sb-api | ✅ Full (gRPC) |

### Partial Implementations (Needs Work)

| Category | Feature | Gap |
|----------|---------|-----|
| HTTP Inbound | TLS support | Need sb-tls integration |
| Mixed Inbound | TLS support | Need sb-tls integration |
| VMess | Multiplex, TLS, UDP | Transport integration |
| VLESS | Multiplex, UDP | Transport integration |
| Trojan | Multiplex, UDP | Transport integration |
| Shadowsocks | Multiplex, UDP | Transport integration |

### Feature Flags

Enable features via Cargo.toml:

```toml
[dependencies]
sb-adapters = { path = "crates/sb-adapters", features = [
    "in_socks", "in_http", "in_tun",      # Inbounds
    "out_http", "out_direct", "out_ssh",   # Outbounds
] }
sb-tls = { path = "crates/sb-tls", features = ["reality", "ech"] }
sb-transport = { path = "crates/sb-transport", features = ["ws", "h2", "quic"] }
```

**Available feature sets**:
- `full` - All inbounds + outbounds + transports
- `tls` - REALITY + ECH + Standard TLS
- `quic` - QUIC-based protocols (Hysteria, TUIC, DoQ)
- `metrics` - Prometheus metrics collection

## Compatibility

### Backward Compatibility

- **Config Schema**: V1 (Go 1.12.4 Present) automatically migrated to V2
- **Type Aliases**: `EngineRouter` kept for legacy code
- **Deprecated Fields**: Accepted with warnings, not errors

### Upstream Compatibility

- **sing-box v1.13.0-alpha.19**: 99%+ CLI and config surface compatibility
- **Protocol Parity**: Full compatibility with Go implementation for all implemented protocols
- **Config Format**: Drop-in replacement for sing-box configs

## Testing Strategy

### Test Levels

1. **Unit Tests**: Per-crate in `crates/*/src/` with `#[cfg(test)]`
2. **Integration Tests**: Cross-crate in `tests/integration/`
3. **E2E Tests**: Full protocol stack in `tests/e2e/`
4. **CLI Tests**: Command-line interface in `app/tests/`

### Key Test Suites

- **TLS E2E**: `tests/reality_tls_e2e.rs`, `tests/e2e/ech_handshake.rs`
- **Protocol E2E**: `tests/e2e/hysteria_v1.rs`, `tests/e2e/tuic_outbound.rs`, `tests/e2e/ssh_outbound.rs`
- **Transport**: `tests/e2e/router_sniff_sni_alpn.rs`, `inbound_direct_udp.rs`
- **Config**: `tests/integration/test_schema_v2_integration.rs`

### Quality Gates

- All tests must pass: `cargo test --workspace --all-features`
- Zero clippy warnings: `cargo clippy --workspace -- -D warnings`
- Strict lib checks: `cargo clippy -p sb-core --lib -- -D warnings -W clippy::pedantic`
- No panics in library code: `-D clippy::panic -D clippy::unwrap_used -D clippy::expect_used`

## Readiness Signaling

We replaced port polling with **oneshot channel** (`serve_with_ready`), eliminating flakiness in CI:

```rust
let (ready_tx, ready_rx) = oneshot::channel();
let server = inbound.serve_with_ready(ready_tx);
ready_rx.await?; // Wait for server to be ready
// Proceed with client connections
```

## Performance

### Optimizations

- **Native Process Matching**: 149.4x faster on macOS, 20-50x on Windows (vs command-line tools)
- **Zero-Copy I/O**: `tokio::io::copy_bidirectional` for data relay
- **Connection Pooling**: SSH outbound maintains connection pool (default 5)
- **Cardinality Monitoring**: Prevents metric label explosion (10K series limit)

### Benchmarks

Run benchmarks with:

```bash
cargo bench -p sb-core         # Core benchmarks
cargo bench -p sb-tls          # TLS handshake benchmarks
cargo bench -p sb-transport    # Transport benchmarks
```

**Expected Performance** (on reference hardware):
- REALITY handshake: ~1-2ms overhead
- ECH handshake: ~2-3ms overhead
- Standard TLS: ~0.5-1ms
- Router decision: <10μs per rule
- Process matching: 14μs (macOS native), 2091μs (command-line fallback)

## Observability

### Metrics

Prometheus metrics exposed at `/metrics` (configurable):

- `sb_connections_total{protocol, direction}` - Connection counts
- `sb_traffic_bytes{protocol, direction}` - Bandwidth usage
- `sb_latency_seconds{protocol}` - Connection latency
- `sb_errors_total{protocol, error_type}` - Error counts
- `sb_udp_nat_sessions` - Active UDP NAT sessions
- `sb_prefetch_queue_depth` - Subscription prefetch queue

Enable metrics with `metrics` feature flag.

### Logging

Structured logging via `tracing`:

```bash
RUST_LOG=info cargo run              # Info level
RUST_LOG=sb_tls=debug cargo run      # Debug TLS operations
RUST_LOG=sb_core::router=trace       # Trace routing decisions
```

JSON output with `APP_LOG_JSON=1`.

## Security Considerations

### Production Checklist

- [ ] Enable TLS certificate verification (disable `skip_cert_verify` only for testing)
- [ ] Use strong, randomly generated keys for REALITY (X25519)
- [ ] Rotate ECH config periodically
- [ ] Store private keys securely (not in config files)
- [ ] Enable JWT authentication for admin API
- [ ] Configure rate limiting for public endpoints
- [ ] Use constant-time credential verification (built-in via sb-security)
- [ ] Redact sensitive data in logs (built-in via sb-security)

### Threat Model

**REALITY protects against**:
- ✅ Active probing (fallback to real server)
- ✅ DPI fingerprinting (TLS looks legitimate)
- ✅ SNI-based censorship (uses real domains)

**ECH protects against**:
- ✅ SNI snooping (encrypted in ClientHello)
- ✅ Passive observation of target domains
- ✅ Censorship based on SNI patterns

**Standard TLS protects against**:
- ✅ Passive eavesdropping
- ✅ Man-in-the-middle attacks (with cert verification)
- ✅ Downgrade attacks (TLS 1.2+ only)

## Related Documentation

- **Feature Status**: `GO_PARITY_MATRIX.md` - Detailed parity matrix with upstream
- **Roadmap**: `NEXT_STEPS.md` - Sprint planning and priorities
- **TLS Details**: `docs/TLS.md` - TLS infrastructure deep dive
- **CLI Tools**: `docs/CLI_TOOLS.md` - Command-line interface documentation
- **Config Reference**: `crates/sb-config/src/validator/v2_schema.json` - JSON schema
- **Development Guide**: `docs/DEVELOPMENT.md` - Quality gates and dev workflow
- **Operations Guide**: `docs/OPS.md` - Deployment and monitoring

## Version Information

- **singbox-rust**: v0.2.0+
- **Rust MSRV**: 1.90
- **tokio**: 1.x
- **rustls**: 0.23.x
- **Feature Parity**: 99%+ with sing-box v1.13.0-alpha.19

Last Updated: 2025-10-09

---

> _Never break userspace_ — we add, we don't remove.
