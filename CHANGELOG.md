# Changelog

All notable changes to singbox-rust will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `generate uuid` subcommand for V4 UUID generation (L15.1.1)
- `generate rand` subcommand with `--base64`/`--hex` flags (L15.1.2)
- ECH keypair PEM encoding compatible with Go sing-box format (L15.1.3)
- AdGuard DNS filter rule-set conversion (`rule-set convert --type adguard`) (L15.1.4)
- `rule-set format --write` flag for in-place formatting (L15.1.5)
- Chrome certificate store mode (L15.1.6)
- Criterion benchmark suite formalization with baseline JSON (L16.1.1)
- Go vs Rust throughput comparison framework (L16.1.2)
- Feature-gate matrix expanded to 40+ combinations (L16.1.4)
- Memory usage benchmark script (L16.2.1)
- Hot reload stability test (100x SIGHUP) (L16.2.2)
- Signal handling and resource leak detection tests (L16.2.3)
- CI/CD pipeline: lint, test, parity check, boundary check (L17.1.1)
- Multi-platform release builds (6 targets) (L17.1.2)
- Docker production image with health check (L17.1.3)
- Security audit checklist and `cargo deny` integration (L17.2.3)
- User documentation: configuration reference, migration guide, troubleshooting (L17.2.2)
- 7-day canary stability framework (L17.3.2)

### Changed
- PX-015 (Linux resolved validation) deferred with CI placeholder workflow (L15.2.3)

## [0.1.0] - 2026-02-12

### Added

#### Architecture (L1)
- Rust workspace with 8 crates: sb-types, sb-config, sb-core, sb-adapters, sb-tls, sb-transport, sb-runtime, app
- Port-trait architecture: OutboundConnector, InboundHandler, DnsPort, AdminPort, etc.
- Feature-gate system for modular builds
- Architecture boundary enforcement via check-boundaries.sh

#### Protocol Parity (L2)
- 10 outbound protocols: Direct, SOCKS5, HTTP, Shadowsocks, VMess, VLESS, Trojan, Hysteria2, TUIC, WireGuard
- 8 inbound protocols: SOCKS5, HTTP, Mixed, Shadowsocks, VMess, Trojan, Naive, TUN
- DNS resolvers: UDP, DoH, DoT, DoQ, DoH3, DHCP, systemd-resolved, Tailscale
- Rule-set: SRS binary format v1-v3, JSON source, remote HTTP with caching
- Router: domain/IP/port/process matching, logical rules, rule-set references
- Transport: WebSocket, HTTP/2, gRPC, QUIC, multiplex (smux/yamux/h2mux)
- 208/209 Go features implemented (99.52% parity)

#### Interop Testing (L5-L7)
- 77 interop-lab test cases (68 strict, 8 env_limited, 1 smoke)
- Protocol x fault matrix: 6 protocols x 4 fault types = 24 cell coverage
- WebSocket/TLS round-trip delay injection and trend reporting
- GUI startup/switch/reconnect replay testing
- E2E capstone test suite

#### CI Governance (L8-L11)
- Interop-lab smoke and nightly CI workflows
- Configurable trend gates with JSONL history tracking
- Regression detection across test runs

#### Migration Governance (L12)
- IssueCode::Deprecated detection in validator
- Deprecation directory and migration diagnostics
- Working group migration assistance tooling

#### Service Security (L13)
- Clash API and SSMAPI authentication middleware
- Non-localhost binding warnings
- ServiceStatus fault isolation
- Health API endpoint (/services/health)

#### TLS Advanced (L14)
- Certificate store modes: System, Mozilla, None
- Certificate file hot reload with file watcher
- TLS fragment configuration wiring
- TLS capability matrix and trend templates

### Known Limitations
- PX-015: Linux systemd-resolved validation requires real Linux environment (deferred)
- Chrome certificate store mode uses webpki-roots (Chrome/Mozilla roots highly overlap)

[Unreleased]: https://github.com/nicekid1/singbox-rust/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/nicekid1/singbox-rust/releases/tag/v0.1.0
