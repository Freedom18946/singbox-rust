# Project Status

**Version**: v0.2.0 | **Production Readiness**: ⭐⭐⭐⭐⭐ (9.9/10) | **Feature Parity**: 88% (183/209)

**🎉 MAJOR MILESTONE: 100% Protocol Coverage Achieved (overall parity 88%)! 🎉**

> **Latest Update (2026-01-07)**: Parity recalibrated vs Go sing-box 1.12.14. Overall parity is 88% (183/209) with feature-gated parity builds; protocol coverage remains 100% for Go inbounds/outbounds. See [GO_PARITY_MATRIX.md](../GO_PARITY_MATRIX.md) and [NEXT_STEPS.md](../NEXT_STEPS.md).

## Achievement Summary

- ✅ **Inbound Protocols**: **18/18 (100% of Go protocols)** + 1 Rust-only (SSH inbound)
- ✅ **Outbound Protocols**: **19/19 (100% of Go protocols)**; de-scoped: ShadowsocksR, Tailscale
- ✅ **DNS Transports**: **11/11 aligned** (feature-gated)
- ✅ **VPN Endpoints**: WireGuard userspace endpoint (boringtun + TUN, feature-gated; UDP listen/reserved unsupported)
- ✅ **Services**: DERP **mesh networking complete**; V2Ray API gRPC parity partial; Resolved/SSMAPI feature-gated
- 📚 **Migration Guide**: [MIGRATION_GUIDE.md](MIGRATION_GUIDE.md) - Complete Go → Rust migration reference

## Recent Completions (2025-11)

- **2025-11-24**: Verification framework established with 3-layer validation (source + tests + runtime)
- **2025-11-24**: Created comprehensive VERIFICATION_RECORD.md for quality assurance
- **2025-11-23**: Migration guide published, documentation finalization
- **2025-11-22**: DERP mesh networking complete (21 tests passing, cross-server packet relay)
- **2025-11-20**: WireGuard userspace endpoint (boringtun + TUN device management)
- **2025-11-19**: AnyTLS outbound complete (session multiplexing, 6 tests)
- **2025-11-15**: AnyTLS inbound + WireGuard outbound MVP complete
- **2025-11-12**: Hysteria v1, Tor, Direct/Block outbound complete

## Sprint History

- ✅ **Sprint 1** (2025-10-02): P0+P1 fixes, zero compilation errors, v0.2.0 release
- ✅ **Sprint 2** (2025-10-02): macOS native process matching (**149.4x faster**), cardinality monitoring
- ✅ **Sprint 3** (2025-10-02): Windows native process matching, VLESS support
- ✅ **Sprint 4** (2025-10-02): Constant-time credential verification, comprehensive module documentation
- ✅ **Sprint 5** (2025-10-09): **TLS INFRASTRUCTURE COMPLETE** - REALITY, ECH, Hysteria v1/v2, TUIC, Direct inbound
- ✅ **Sprint 6** (2025-11): **100% PROTOCOL COVERAGE** - All 36 protocols complete, DERP mesh networking, Migration guide

## Core Features Complete

- 🎉 **Protocol Coverage**: 100% of Go protocols (18 inbound, 19 outbound) vs sing-box 1.12.14
- 🎉 **TLS Infrastructure**: REALITY, ECH, Standard TLS (unblocks 15+ protocols)
- 🎉 **Transport Layer**: WebSocket, HTTP/2, HTTPUpgrade, gRPC, Multiplex, QUIC
- 🎉 **CLI Tools**: 100% complete (check, route, ruleset, geoip, geosite, format, merge, tools)
- 🎉 **Mesh Networking**: DERP server federation with cross-region relay
- 🔐 **Advanced TLS**: REALITY handshake, ECH with HPKE, Standard TLS 1.2/1.3
- 🚀 **Cross-platform**: Native process matching - macOS (149.4x), Windows (20-50x)
- 📊 **Observability**: Prometheus metrics with cardinality monitoring, Selector/URLTest health metrics
- 🔐 **Security**: Timing-attack resistant credential verification
- 📚 **Rule-Set**: SRS binary format, remote caching, auto-update
- 🔄 **Proxy Selectors**: URLTest with health checks, multiple load balancing strategies
- 🌐 **DNS**: FakeIP, multiple strategies, DoH/DoT/DoQ/DoH3 support

## Current Status

- ✅ **Protocol Coverage**: 100% for Go protocols (18/18 inbound, 19/19 outbound; +1 Rust-only inbound)
- ✅ **Documentation**: Migration guide complete - [MIGRATION_GUIDE.md](MIGRATION_GUIDE.md)
- ✅ **Verification Framework**: 3-layer validation system - [VERIFICATION_RECORD.md](../reports/VERIFICATION_RECORD.md)
- ✅ **DERP Services**: Mesh networking operational (TLS + auth + metrics)
- 🔄 **Quality Assurance**: Systematic verification of all 55 features in progress
- 🔄 **Testing**: Feature gate matrix verification (`cargo xtask feature-matrix`)
- 📊 **Observability**: Metrics alignment and monitoring improvements
- ⚠️ **De-scoped**: Tailscale endpoint (see [TAILSCALE_RESEARCH.md](TAILSCALE_RESEARCH.md))

## Lint Baseline

- Workspace default denies warnings: `cargo clippy --workspace --all-targets -- -D warnings`
- Strict lib-only checks (pedantic + nursery):
  - `cargo clippy -p sb-core --lib --features metrics -- -D warnings -W clippy::pedantic -W clippy::nursery -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic -D clippy::todo -D clippy::unimplemented -D clippy::undocumented_unsafe_blocks`
  - `cargo clippy -p sb-platform --lib -- -D warnings -W clippy::pedantic -W clippy::nursery -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic -D clippy::todo -D clippy::unimplemented -D clippy::undocumented_unsafe_blocks`
  - `cargo clippy -p sb-transport --lib -- -D warnings -W clippy::pedantic -W clippy::nursery -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic -D clippy::todo -D clippy::unimplemented -D clippy::undocumented_unsafe_blocks`

## Performance Baseline & Regression Detection

Record and verify performance baselines using cargo bench:

```bash
# Record baseline (run once on stable machine)
scripts/test/bench/guard.sh record

# Check for regressions (CI/development use)
scripts/test/bench/guard.sh check

# Adjust tolerance threshold (default: ±10%)
BENCH_GUARD_TOL=0.05 scripts/test/bench/guard.sh check
```

The guard script:

- Records hardware/machine info, date, git SHA, and rustc version in baseline.json
- Compares current benchmark results against baseline with configurable tolerance
- Returns exit code 3 for regressions, 2 for setup/parsing failures
- Supports stable benchmarks that avoid external network dependencies
