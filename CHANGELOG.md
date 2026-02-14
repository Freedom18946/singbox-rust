# Changelog

All notable changes to singbox-rust will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Release packaging script `scripts/package_release.sh` with unified artifact layout (`bin/`, `config/`, `docs/`) and checksum output (L17.2.1).
- Deployment config template `deployments/config-template.json` for release artifacts (L17.2.1).
- GUI smoke framework `scripts/gui_smoke_test.sh` with report and artifact generation (L17.3.1).
- Canary framework `scripts/canary_7day.sh` with JSONL sampling and summary generation (L17.3.2).
- Top-level docs entry points: `docs/configuration.md`, `docs/migration-from-go.md`, `docs/troubleshooting.md` (L17.2.2).

### Changed
- CI gate hardened: clippy now runs with `--workspace --all-features --all-targets -D warnings` (L17.1.1).
- Release workflow now packages artifacts via `scripts/package_release.sh` and names outputs as `singbox-rust-{version}-{os}-{arch}` (L17.1.2, L17.2.1).
- Docker runtime chain updated: non-root runtime, `/services/health` healthcheck, and explicit `<50MB` image-size validation command in deployment flow (L17.1.3).
- `deny.toml` rewritten for `cargo-deny 0.18.x` compatibility and current advisory tracking policy (L17.2.3).

## [0.1.0] - 2026-02-12

### Added

#### Architecture (L1)
- Rust workspace with modular crates and explicit boundary constraints.
- Port-trait architecture for connector/inbound/service abstractions.
- Architecture boundary enforcement via `check-boundaries.sh`.

#### Protocol & Feature Parity (L2-L14)
- Go parity closure to 208/209 items (99.52%) with one deferred Linux runtime validation item (`PX-015`).
- Core protocol, routing, DNS, migration governance, service security, and TLS advanced capabilities delivered.

#### Quality & Baseline (L15-L16)
- CLI parity additions (`generate uuid`, `generate rand`, ECH keypair, AdGuard conversion, format write mode).
- Benchmark baseline outputs, feature matrix, long-run stability tests, and bench regression gate.

### Known Limitations
- `PX-015`: Linux `systemd-resolved` runtime validation requires real Linux environment evidence.
- Chrome certificate store mode currently maps to `webpki-roots` equivalence.

## Contributing

- Contribution guide: `docs/04-development/contributing/getting-started.md`
- Pull request process: `docs/04-development/contributing/pull-requests.md`

[Unreleased]: https://github.com/nicekid1/singbox-rust/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/nicekid1/singbox-rust/releases/tag/v0.1.0
