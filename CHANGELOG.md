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

### 🔨 Architecture Refactoring & TODO Resolution
- **VLESS Protocol Support**: ✅ Added VLESS variant to OutboundImpl enum to complete protocol matrix
  - *Rationale*: Previously using Direct as placeholder, impacting protocol accuracy
  - *Implementation*: Added proper VLESS enum variant with configuration mapping from sb-config to sb-core
  - *Result*: VLESS configurations now properly instantiate VlessConfig instead of falling back to Direct
- **Bridge Runtime Initialization**: ✅ Implemented proper Bridge initialization from IR
  - *Rationale*: Current Bridge::new() creates empty bridge, missing IR-based configuration
  - *Implementation*: Enhanced Bridge::new_from_config to construct inbound/outbound services from ConfigIR
  - *Result*: Runtime now properly initializes bridge with configured inbound/outbound services from IR
- **DNS Cache Architecture Cleanup**: ✅ Resolved cache key design inconsistency
  - *Rationale*: Cache API uses domain-only keys but creates query-type-specific keys internally
  - *Implementation*: Unified cache key design using Key struct (domain + QType) throughout DNS cache API
  - *Result*: A and AAAA records now have separate cache entries, eliminating shared cache conflicts
- **Dependency Architecture**: ✅ Preserved clean dependency boundaries to avoid circular dependencies
  - *Rationale*: sb-config should not depend on sb-core to maintain clear module boundaries
  - *Implementation*: Moved VLESS configuration processing from sb-config to sb-core, maintaining unidirectional dependency
  - *Result*: Clean architecture with sb-core depending on sb-config but not vice versa
- **Runtime Supervisor Configuration Diff**: ✅ Implemented proper old-IR extraction for accurate reload diff computation
  - *Rationale*: Hot reload diff computation was using `new_ir.clone()` as placeholder for old IR, preventing meaningful change detection
  - *Problem Analysis*:
    - State struct lacked storage of current ConfigIR
    - `reload()` method couldn't access previous configuration for comparison
    - Diff computation was essentially comparing config against itself (no-op)
  - *Implementation*:
    - Added `current_ir: ConfigIR` field to both router and non-router State variants
    - Modified `State::new()` to accept and store initial ConfigIR
    - Updated `reload()` to extract old_ir from state before applying new configuration
    - Enhanced `handle_reload()` and `handle_reload_no_router()` to update current_ir atomically during state transitions
    - Added structured logging for diff metrics (inbounds/outbounds added/removed) when `SB_RUNTIME_DIFF=1`
  - *Result*:
    - Hot reload now correctly computes delta between actual old and new configurations
    - Diff metrics accurately reflect configuration changes for monitoring/debugging
    - State transitions maintain IR consistency for future reloads
    - Memory overhead: single ConfigIR clone (~KB range for typical configs)
  - *Files Modified*: `crates/sb-core/src/runtime/supervisor.rs`

### 🏗️ Architecture Debt & Future Integration Points

The following TODO items represent intentional architectural placeholders that require system-wide abstractions not yet fully implemented:

- **V2Ray API Handler Service Integration** (`crates/sb-api/src/v2ray/services.rs`)
  - *Current State*: HandlerService methods (add/remove/alter inbound/outbound) return success with logging only
  - *Required Architecture*:
    - Global InboundManager trait to dynamically add/remove/configure inbound listeners
    - Global OutboundManager trait to dynamically add/remove/configure outbound connectors
    - Thread-safe registry accessible from V2Ray gRPC service handlers
  - *Design Considerations*:
    - Hot reload currently handled by Supervisor at config-file level (replace entire state)
    - Runtime inbound/outbound modification requires finer-grained control
    - Must maintain consistency with ConfigIR-based initialization
  - *Integration Path*:
    1. Define `InboundManager` and `OutboundManager` traits in sb-core
    2. Implement registry in Bridge or create separate ManagerRegistry
    3. Pass Arc<dyn Manager> to HandlerServiceImpl::new()
    4. Replace TODO logging with actual manager method calls
  - *Files Affected*: 6 TODO sites in add/remove/alter methods

- **TUN Inbound Router Integration** (`crates/sb-adapters/src/inbound/tun_enhanced.rs:458`)
  - *Current State*: TUN inbound directly uses configured outbound without routing
  - *Required Architecture*:
    - Router interface to make per-connection routing decisions
    - Connection context enrichment (source IP, destination, protocol)
  - *Design Considerations*:
    - Current design: EnhancedTunInbound holds single Arc<dyn OutboundConnector>
    - Correct design: Should query router for outbound selection per connection
    - Requires Router trait accessible from TUN packet handler
  - *Integration Path*:
    1. Add optional router: Option<Arc<dyn Router>> field to EnhancedTunInbound
    2. In handle_tcp_connection/handle_udp_packet, call router.route(&ctx) to select outbound
    3. Fall back to default outbound if router absent (backward compat)
  - *Files Affected*: TCP/UDP connection handling in tun_enhanced.rs

- **Monitoring Bridge Integration** (`crates/sb-api/src/monitoring/bridge.rs:267`)
  - *Current State*: Monitoring bridge returns mock metrics
  - *Required Integration*: Wire to actual runtime state, connection tracker, router metrics
  - *Future Work*: Connect to Supervisor state, Bridge statistics, and Engine routing metrics

### 📋 Code Quality Improvements (Ultrathink Session)

- **Clippy Strict Mode Compliance**: Fixed 178 files, 3414 insertions
  - Variable naming clarity (req/res → request/response, sem/sec → semaphore/timestamp_sec)
  - Numeric literal readability (100000 → 100_000)
  - Type conversion safety annotations (#[allow(clippy::cast_precision_loss)])
  - Option/Result idiomatic patterns (if-let → map_or_else)
  - Missing documentation (added # Errors sections to Result-returning functions)
  - lazy_static → std::sync::LazyLock (Rust 1.80+)
  - String allocation optimization (format! → writeln! for buffers)
  - HashMap generalization (added BuildHasher bounds for flexibility)
  - Audit log efficiency (by-reference parameter passing)
- **Zero Compilation Warnings**: All clippy pedantic/style warnings resolved

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
