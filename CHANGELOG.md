# Changelog

All notable changes to singbox-rust will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] - RC Preparation (Phase 8)

### Parity Recalibration (2026-01-07) 🎯

**88% Go-Rust Parity** - Full calibration against `sing-box-1.12.14`

- **Total Items Compared**: 209
- **Fully Aligned**: 183 (88%)
- **Partial Alignment**: 15
- **De-scoped**: 4 (Tailscale endpoint, ShadowsocksR, libbox/locale)
- **Rust-only Extensions**: 4
- **Notes**: Parity build remains feature-gated; TLS uTLS/ECH and WireGuard endpoint limitations documented

#### Changed
- Updated parity docs and baselines to 1.12.14

---

### Parity Calibration Milestone (2025-12-24) 🎯

**92% Go-Rust Parity Achieved** - Full calibration against `sing-box-1.12.12` (历史基线)

- **Total Items Compared**: 190 (expanded from 169)
- **Fully Aligned**: 175 (92%)
- **Partial Alignment**: 5 (TLS uTLS/ECH library limitations)
- **De-scoped**: 4 (Tailscale endpoint, ShadowsocksR)
- **Rust-only Extensions**: 6 (NTP, DNS Forwarder, Circuit Breaker, etc.)
- **Tests Passed**: 295 across 10 crates

#### Added
- **Comprehensive Parity Matrix**: Expanded `GO_PARITY_MATRIX.md` to 190 items
- **Router/Rules Binary Parity**: Fixed SRS Item IDs and added missing fields
- **Documentation**: Updated TLS and Tailscale limitation docs

#### Fixed
- `sb-core/src/router/ruleset/mod.rs`: Missing closing brace for `DefaultRule` struct

---

### Protocol Coverage Milestone 🎉

**100% Go sing-box 1.12.12 Parity Achieved (2025-11-23, 历史基线)**

- **Inbound Protocols**: 17/17 complete (100%)
  - Latest additions: AnyTLS (2025-11-15), Hysteria v1 (2025-11-12), ShadowTLS (2025-11-12), TUIC (2025-11-12), Hysteria2 (2025-11-12), Naive (2025-11-12), Direct (2025-11-11)
- **Outbound Protocols**: 19/19 complete (100%)
  - Latest additions: AnyTLS (2025-11-19), WireGuard MVP (2025-11-15), Hysteria v1 (2025-11-12), Tor (2025-11-12), Direct/Block (2025-11-12), ShadowTLS (2025-11-12), SSH (2025-11-12)
- **Services**: DERP mesh networking complete (2025-11-22)
  - TLS support with rustls acceptor
  - PSK authentication for mesh peers
  - Per-IP rate limiting (sliding window)
  - Comprehensive Prometheus metrics
  - Cross-server packet relay (21 tests passing)
- **Endpoints**: WireGuard userspace endpoint MVP (2025-11-20)
  - boringtun + TUN device management
  - Feature-gated implementation
- **Documentation**: Migration guide published (2025-11-23)
  - Complete Go \u2192 Rust migration reference
  - Protocol comparison matrix
  - Configuration compatibility guide
  - Performance baselines

### Added (Parity WS6/WS2)

- NTP service via config block (feature-gated):
  - Added `ntp` to IR (`enabled`, `server`, `server_port`, `interval_ms`, `timeout_ms`).
  - Config→IR parsing and IR→view rendering (`interval` shown as `XmYs`).
  - Runtime supervisor spawns/stops background NTP task on start/reload when `service_ntp` feature is enabled.
  - App feature `service_ntp` forwards to `sb-core/service_ntp`.
- DNS config wiring (minimal path, env-bridge):
  - `app run` consumes top-level `dns.servers` and `dns.strategy`, derives resolver env vars without overriding user-set env:
    - DoH: `SB_DNS_MODE=doh`, `SB_DNS_DOH_URL=https://...`
    - UDP: `SB_DNS_MODE=udp`, `SB_DNS_UDP_SERVER=host:53`
    - DoT: `SB_DNS_MODE=dot`, `SB_DNS_DOT_ADDR=host:853`
    - DoQ (best-effort): `SB_DNS_MODE=doq`, optional `SB_DNS_DOQ_ADDR`, `SB_DNS_DOQ_SERVER_NAME`
    - Strategy mapping: `ipv4_only/prefer_ipv4`→`SB_DNS_QTYPE=a`,`SB_DNS_HE_ORDER=A_FIRST`; `ipv6_only/prefer_ipv6` similarly
  - Builds `SB_DNS_POOL` tokens for advanced pool resolver (non-blocking for unsupported schemes).
  - DNS stub (`DNS_STUB=1` or `--dns-from-env`) remains available and is skipped when config-driven DNS is applied.

### Changed (WS2 complete)
- DNS IR → Resolver (direct injection):
  - Added typed `dns` IR in sb-config with `servers`, `rules`, `default`.
  - Built IR-driven resolver in sb-core (supports UDP/DoH/DoT, system) and registered it in a global handle for router use.
  - Wired router DNS integration to prefer the IR-built resolver; falls back to env handle if absent.
  - Rules are mapped into the DNS rule engine using in-memory Rule-Set (suffix/keyword/exact → upstream tag with priority).
  - Supervisor sets/updates global DNS resolver on start/reload based on IR.
  - Added DoQ upstream support in IR builder (feature `dns_doq`).
  - Extended DNS IR with timeout/TTL/fakeip/pool knobs; applied to resolver/upstreams (best-effort via direct parameters/env compatibility).

### Added (Phase 8 - RC Packaging)
- **Release Artifacts**:
  - Man page generation via `app man --out dist/man/app.1` (feature: `manpage`)
  - Shell completions for bash/zsh/fish/powershell/elvish via `app gen-completions --all`
  - Version metadata JSON with commit SHA, build date, enabled features
  - Binary checksums (SHA256) for integrity verification
  - Build instructions and platform matrix documentation
- **Go/Rust Parity Tests**:
  - Route vector replay tests covering direct, blackhole, selector, geoip scenarios
  - Check command parity tests for valid/invalid/malformed configs
  - Deterministic output verification for stable contracts
- **Performance Smoke Tests** (marked `#[ignore]` for local validation):
  - 1000-iteration route explain stability test (no panics/leaks)
  - Large config (1000 rules) check and explain tests (no OOM/timeout)
- **Enhanced Security Checks**:
  - `cargo-deny` integration (licenses, advisories, bans, sources)
  - `cargo-audit` integration (RustSec advisory database)
  - Enhanced no-unwrap guard with WARN-level `unwrap_or` scanning
  - Security audit report documenting known issues and risk acceptance
- **Documentation Enhancements**:
  - `docs/ROUTE_EXPLAIN.md` - Complete routing decision inspector guide with field reference
  - `docs/CLI_EXIT_CODES.md` - Updated to clarify standard 3-code system (0/1/2)
  - `README.md` - Added "Essential CLI Examples" quick start section with 4 key commands
  - `dist/SECURITY_AUDIT.md` - Phase 8 security audit and risk acceptance report
  - `dist/BUILD_INSTRUCTIONS.md` - Release build matrix and cross-compilation guide

### Added (Earlier Phases)
- **CLI Tools**: `check`, `route`, `format`, `merge` commands with JSON/YAML support
- **Route Explain**: `--explain` and `--with-trace` flags for routing decision inspection
- **Schema Validation**: v2 schema validation with `--schema-v2-validate`
- **SARIF Output**: `check --format sarif` for IDE/CI integration
- **Shell Completions**: Generation for Bash/Zsh/Fish (if enabled)
- **Manpage**: Man page generation (if feature enabled)
- **Quality Guards**: 
  - `scripts/tools/validation/guard-no-unwrap.sh` - forbids naked unwrap/panic in core crates
  - Integrated into `ci-acceptance.sh`
- **Test Coverage**:
  - Route explain stability tests (`route_parity.rs`)
  - DNS failure path tests (invalid labels, nonexistent domains)
  - Pipeline failure propagation tests
  - Check SARIF output validation
- **Documentation**:
  - `docs/CLI_EXIT_CODES.md` - CLI exit code reference
  - `docs/ROUTE_EXPLAIN.md` - Route explain field reference
  - `docs/PHASE_8_RC_PREP.md` - RC preparation guide

### Changed
- **Toolchain Lock**: Official build toolchain locked to **Rust 1.90** (stable, no nightly features)
- **Feature Gates**: Default build does NOT enable REALITY/ECH/DSL/experimental features (opt-in via feature flags)
- **CLI Improvements**:
  - Fixed `gen-completions --all` to work without requiring `--shell` flag
  - Made `--shell` optional when using `--all` (resolves argument parsing ambiguity)
- **Core Library Hardening**: sb-core/sb-transport/sb-adapters use only safe error handling
  - No naked `.unwrap()` or `.expect()` in hot paths
  - All `unsafe` blocks documented with SAFETY comments
- **SARIF Output**: Improved ptr→region mapping with minimal location info
- **Exit Codes**: Standardized all CLI commands to 0/1/2 system (success/operational error/validation error)

### Fixed
- **CLI**: Shell completion generation with `--all` flag now works correctly (no longer requires `--shell`)
- DNS query packet validation for labels > 63 chars
- Error propagation in pipeline serve failures
- SARIF location region format for better IDE integration

### Security
- **No-Unwrap Guard**: 
  - Automated detection of panic-prone patterns in core libraries (unwrap, expect, panic, todo, unimplemented)
  - Enhanced with WARN-level scanning for `unwrap_or` variants (informational, does not fail builds)
  - Enforced in CI for sb-core, sb-transport, sb-adapters
- **Supply Chain Audit**:
  - Integrated `cargo-deny` (licenses, advisories, bans, sources)
  - Integrated `cargo-audit` (RustSec advisory database)
- **Known Issues** (Documented in `dist/SECURITY_AUDIT.md`, all LOW severity, deferred):
  - `atty` unmaintained (RUSTSEC-2021-0145) - migration to `std::io::IsTerminal` planned
  - `idna` Punycode handling (RUSTSEC-2024-0421) - hickory-dns migration planned
  - `trust-dns` unmaintained (RUSTSEC-2025-0017) - hickory-dns migration planned
  - `protobuf` recursion crash (RUSTSEC-2024-0437) - upgrade path available
- **License Compliance**: All dependencies verified to use approved OSS licenses (MIT, Apache-2.0, BSD, ISC, etc.)
- **Minimal Attack Surface**: Safe error handling patterns enforced across codebase

### Features (Opt-In)
- `acceptance` - Full feature set for acceptance testing
- `router` - Routing engine with explain capabilities
- `dns` - DNS resolution with multiple backends
- `tls` - TLS/REALITY/ECH support
- `metrics` - Prometheus metrics export
- `schema-v2` - Typed schema validation

**Note**: REALITY, ECH, DSL features are available but not enabled by default.

### Development
- CI acceptance suite with timeout guards
- Route test vectors for regression testing
- Failure path unit tests for error handling validation
- Documentation aligned with implementation

## [0.1.0] - Initial Development

### Added
- Initial Rust implementation of sing-box proxy
- Core routing engine
- DNS resolution system
- Multiple protocol adapters (shadowsocks, trojan, vmess, vless, etc.)
- Configuration validation
- Metrics collection
- Admin API

---

## Version Numbering

- **Major**: Breaking API/config changes
- **Minor**: New features, backward compatible
- **Patch**: Bug fixes, no new features

## RC Candidate Notes

This RC candidate is ready for:
- ✅ Functional testing against Go implementation
- ✅ Performance benchmarking
- ✅ Security audit (with cargo-deny/audit)
- ✅ Documentation review
- ⏳ Production deployment (pending final validation)

### Known Limitations
- ~~Full parity with Go version~~ \u2705 **ACHIEVED**: 100% protocol coverage as of 2025-11-23 (see `GO_PARITY_MATRIX.md`)
- Tailscale endpoint blocked due to Go build constraints on macOS ARM64 (see `docs/TAILSCALE_RESEARCH.md` for details and alternatives)
- Some advanced DSL/experimental features require explicit feature flags for opt-in security
- Performance tuning ongoing for extreme high-throughput scenarios (\u003e10Gbps)


### Upgrade Notes
- Configuration format is stable (v2 schema)
- Migration from v1 available via `--migrate` flag
- Binary artifacts include checksums for verification
