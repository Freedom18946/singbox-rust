# Changelog

All notable changes to this project will be documented in this file.

## GA (General Availability) - 2025-01-XX

### 🎉 Major Milestones
- **Full E2E compatibility with Go sing-box**: All route/check/version/dns/selector/bench JSON outputs are field-for-field compatible
- **Production-ready performance baselines**: Automated regression detection with ±8% latency and ±5% throughput tolerance
- **Complete license compliance**: Third-party dependency audit with automated SBOM generation
- **Robust config migration**: Full v1→v2 schema migration with graceful unknown field handling
- **Release quality gates**: Preflight verification with digest validation and consistent toolchain verification

### ✨ New Features
- Performance baseline recording and regression guard system (`scripts/bench-guard.sh`)
- Comprehensive license inventory with third-party dependency tracking (`LICENSES/THIRD-PARTY.md`)
- Enhanced config compatibility matrix with 6 comprehensive test variants (3×v1 + 3×v2)
- Version command now includes license information and build metadata
- Release workflow with preflight dependency verification and artifact integrity checking

### 🔧 Migration Guide
- **v1→v2 Config Migration**: Run `check --migrate --write-normalized your-config.yml`
  - Unknown fields now generate warnings (not errors) with `--allow-unknown`
  - Schema validation maintains backward compatibility
- **Performance Monitoring**: Use `scripts/bench-guard.sh --record` to establish baseline, then `--check` for regression detection
- **License Compliance**: All executables now embed license information accessible via `--version`

### 🧪 Testing & Quality
- E2E test coverage with differential analysis against Go reference implementation
- Config compatibility matrix with comprehensive v1/v2 migration testing
- Performance regression detection with statistical tolerance thresholds
- Preflight checks ensure release consistency and artifact integrity

## Unreleased

### 🔐 Security & Authentication (PROMPTS #30-31)
- **JWT Authentication Provider**: Production-ready JWT validation with RS256/ES256/HS256 support, JWKS caching with rotation, and clock skew tolerance
- **Security utilities crate** (`sb-security`): Credential redaction, memory-safe secret handling with ZeroizeOnDrop
- **Enhanced cargo-deny policies**: Stricter vulnerability detection, license compliance, and supply chain security
- **Log redaction system**: Automatic credential sanitization in application logs

### 🧪 E2E Testing Enhancement (PROMPT #32)
- **Offline E2E pipeline** via `xtask` utility: Comprehensive testing covering version→check→run→route→metrics→admin flows
- **Authentication test scenarios**: Success (200), failure (401), and rate limiting (429) validation
- **CI integration**: New `e2e-offline` job with admin debug features testing
- **Offline configuration**: `examples/e2e/minimal.yaml` for deterministic testing without external dependencies

### 📚 Documentation & Contracts (PROMPT #33)
- **Admin API contract specification**: Complete endpoint documentation with authentication examples
- **Security documentation**: Enhanced SECURITY.md with threat model and procedures
- **E2E testing documentation**: Usage guidelines and configuration examples

### 🔧 Infrastructure Improvements
- Add e2e compatibility replay (P21) with optional Go reference.
- Unify error mapping to SbError in sb-adapters/sb-api (P22).
- Add Loom and Miri smoke tests (P23) and CI jobs.
- Add dev-only benches and bench script exporting CSV (P24).
- Add release draft workflow building cross-platform artifacts (P25).
- Documentation refactor completed; see docs/COOKBOOK.md for migration notes and runnable snippets (P27).
- Add preflight gating script and CI job for RC quality (P35).
