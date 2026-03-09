# Project Status

**Version**: v0.2.0 | **Current Focus**: Phase 4 evidence review | **Acceptance Closure**: `UNVERIFIED (slim snapshot)`

> Capability facts (tri-state + evidence) are maintained in **[capabilities.md](capabilities.md)** and generated from `reports/capabilities.json`.

> **Latest Update (2026-03-09)**: active status docs now distinguish capability facts from closure claims. Missing local batch artifacts are treated as `UNVERIFIED (slim snapshot)` until a self-contained evidence manifest exists.
> **L18 Policy Shift (effective 2026-02-24)**: `gui/canary` are mandatory blocking gates; `docker` defaults to non-blocking in local mode (`--require-docker 0`) and can be switched to blocking for CI/certify mode (`--require-docker 1`).
> **L17 Baseline (historical)**: `scripts/l17_capstone.sh --profile fast` completed with `overall=PASS_STRICT`; optional environment gates were recorded as `SKIP` for L17 only.

## Achievement Summary

- ✅ **Inbound Protocols**: documented matrix covers 18/18 Go inbounds + 1 Rust-only (SSH inbound)
- ✅ **Outbound Protocols**: documented matrix covers 19/19 Go outbounds; de-scoped: ShadowsocksR, Tailscale
- ✅ **DNS Transports**: **11/11 aligned** (feature-gated)
- ✅ **VPN Endpoints**: WireGuard userspace endpoint (boringtun + TUN, feature-gated; UDP listen/reserved unsupported)
- ⚠️ **TUN/redirect/tproxy tri-state**: see
  [`tun.macos.tun2socks`](capabilities.md#capability-tun-macos-tun2socks),
  [`inbound.redirect`](capabilities.md#capability-inbound-redirect),
  [`inbound.tproxy`](capabilities.md#capability-inbound-tproxy)
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
- ✅ **Sprint 5** (2025-10-09): TLS infrastructure milestone (REALITY + ECH path landed; detailed state tracked in `capabilities`)
- ✅ **Sprint 6** (2025-11): protocol-scope milestone recorded for the then-current Go baseline, plus DERP mesh networking and migration guide work

## Core Features Complete

- 🎉 **Protocol Scope**: matrix currently documents 18 inbound and 19 outbound Go protocol types vs sing-box 1.12.14
- 🎉 **TLS Infrastructure**: REALITY, Standard TLS, ECH path (tri-state tracked in `capabilities`)
- 🎉 **Transport Layer**: WebSocket, HTTP/2, HTTPUpgrade, gRPC, Multiplex, QUIC
- 🎉 **CLI Tools**: 100% complete (check, route, ruleset, geoip, geosite, format, merge, tools)
- 🎉 **Mesh Networking**: DERP server federation with cross-region relay
- 🔐 **Advanced TLS**: REALITY handshake, Standard TLS 1.2/1.3, ECH TCP=`implemented_unverified`, QUIC ECH=`scaffold_stub`, uTLS=`implemented_unverified`
- 🚀 **Cross-platform**: Native process matching - macOS (149.4x), Windows (20-50x)
- 📊 **Observability**: Prometheus metrics with cardinality monitoring, Selector/URLTest health metrics
- 🔐 **Security**: Timing-attack resistant credential verification
- 📚 **Rule-Set**: SRS binary format, remote caching, auto-update
- 🔄 **Proxy Selectors**: URLTest with health checks, multiple load balancing strategies
- 🌐 **DNS**: FakeIP, multiple strategies, DoH/DoT/DoQ/DoH3 support

## Current Status

- ✅ **L18 Design-to-Implementation**: L18 script/workflow/report contracts landed (`scripts/l18/*.sh`, `reports/L18_REPLACEMENT_CERTIFICATION.md`, `l18-certification-macos.yml`)
- ✅ **L18 Daily Convergence**: same fixed configuration reached 3 consecutive PASS rounds (`capstone_daily_convergence_v7_timeout120`)
- ✅ **L18 Fixed-Profile Harness**: added `scripts/l18/run_capstone_fixed_profile.sh` and CI baseline lock for nightly/certify (parity prebuild + fixed env)
- 🔄 **L18 Phase 4**: evidence model, boundary containment, and harness semantics are being corrected before any long-run recovery decision
- ✅ **Protocol Coverage**: 100% for Go protocols (18/18 inbound, 19/19 outbound; +1 Rust-only inbound)
- ✅ **Documentation**: Migration guide complete - [MIGRATION_GUIDE.md](MIGRATION_GUIDE.md)
- ✅ **Verification Framework**: 3-layer validation system - [VERIFICATION_RECORD.md](../reports/VERIFICATION_RECORD.md)
- ✅ **DERP Services**: Mesh networking operational (TLS + auth + metrics)
- 🔄 **Quality Assurance**: Systematic verification of all 55 features in progress
- 🔄 **Testing**: Feature gate matrix verification (`cargo xtask feature-matrix`)
- 📊 **Observability**: Metrics alignment and monitoring improvements
- ⚠️ **De-scoped**: Tailscale endpoint (see [TAILSCALE_RESEARCH.md](TAILSCALE_RESEARCH.md))

### L18 Next Actions (updated 2026-03-09)

1. Split closure claims from capability facts in `reports/capabilities.json`.
2. Make claim guard hard-fail on unsupported closure language in active docs.
3. Move runtime startup to explicit registry construction and versioned boundary policy.
4. Update L18 harness taxonomy, evidence manifest, dynamic ports, and leak assertions.
5. Only after the above pass, run a new `daily` smoke to evaluate `nightly` recovery.

## Parity Build

To build with the parity-focused feature set, use the `parity` feature flag:

```bash
cargo build -p app --features parity --release
```

This enables all parity-critical features:
- **Router**: Full routing engine with rule evaluation
- **Adapters**: All inbound/outbound protocol adapters
- **DNS**: UDP, DoH, DoT, DoQ, DoH3, DHCP, Resolved, Tailscale transports
- **Services**: NTP, Resolved, SSMAPI, DERP
- **APIs**: Clash API, V2Ray API

> **Note**: Default builds use stub registrations for unconfigured adapters. Use `--features parity` to enable full protocol implementations.

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
