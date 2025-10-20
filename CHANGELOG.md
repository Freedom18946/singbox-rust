# Changelog

All notable changes to singbox-rust will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] - RC Preparation (Phase 8)

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
- Some advanced features (DSL, REALITY) require explicit feature flags
- Full parity with Go version still in progress (see `GO_PARITY_MATRIX.md`)
- Performance tuning ongoing for high-throughput scenarios

### Upgrade Notes
- Configuration format is stable (v2 schema)
- Migration from v1 available via `--migrate` flag
- Binary artifacts include checksums for verification
