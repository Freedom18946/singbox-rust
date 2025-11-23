# Test Coverage Report

Last Updated: 2025-11-21

## Overview

This document tracks test coverage for protocol adapters, DNS transports, VPN endpoints/services, and other core functionality.

**Updates (2025-11-21)**
- Added endpoint/service lifecycle coverage: `app/tests/wireguard_endpoint_test.rs`, `app/tests/wireguard_endpoint_e2e.rs`, `app/tests/service_instantiation_e2e.rs`
- Adapter parity now reaches 17/17 inbounds and 19/19 outbounds (AnyTLS/WireGuard included)

## DNS Transport Tests

### Transport Layer (`crates/sb-core/tests/dns_transport_tests.rs`)

| Transport | Construction | Basic Query | Real Network | Status |
|-----------|--------------|-------------|--------------|--------|
| UDP | ✅ | ✅ | ✅ (ignored) | Complete |
| TCP | ◐ | ◐ | ⚠ | Partial (via UDP upstream) |
| DoT (DNS-over-TLS) | ✅ | ⚠ | ⚠ | Construction only |
| DoH (DNS-over-HTTPS) | ✅ | ⚠ | ⚠ | Construction only |
| DoQ (DNS-over-QUIC) | ✅ | ⚠ | ⚠ | Construction only |
| **DoH3 (DNS-over-HTTP/3)** | ✅ | ✅ | ✅ (ignored) | **Complete** ✨ |

### Upstream Layer (`crates/sb-core/tests/dns_upstream_tests.rs`)

| Upstream | Construction | Query | Health Check | ECS Support | Real Network | Status |
|----------|--------------|-------|--------------|-------------|--------------|--------|
| UDP | ✅ | ✅ | ⚠ | ✅ | ✅ (ignored) | Complete |
| DoT | ✅ | ⚠ | ⚠ | ⚠ | ⚠ | Construction only |
| DoH | ✅ | ⚠ | ⚠ | ⚠ | ⚠ | Construction only |
| DoQ | ✅ | ⚠ | ⚠ | ⚠ | ⚠ | Construction only |
| **DoH3** | ✅ | ✅ | ✅ (ignored) | ✅ | ✅ (ignored) | **Complete** ✨ |

### Config Builder (`crates/sb-core/tests/dns_config_builder_tests.rs`)

| URL Scheme | Parsing | Server IR | TLS Options | Status |
|------------|---------|-----------|-------------|--------|
| `udp://` | ✅ | ⚠ | N/A | Partial |
| `dot://` / `tls://` | ✅ | ⚠ | ⚠ | Partial |
| `https://` (DoH) | ✅ | ⚠ | ⚠ | Partial |
| `doq://` / `quic://` | ✅ | ⚠ | ⚠ | Partial |
| **`doh3://` / `h3://`** | ✅ | ✅ | ✅ | **Complete** ✨ |
| `system` | ✅ | ⚠ | N/A | Partial |

**Special Tests:**
- ✅ DoH vs DoH3 consistency test (ignored, requires network)
- ✅ Default port/path handling for DoH3
- ✅ URL scheme differentiation (https:// for DoH, doh3://h3:// for DoH3)

## Adapter Tests

### Adapter Registry Tests (`crates/sb-adapters/tests/`)

#### Registry Smoke Tests (`adapter_registry_smoke.rs`) - ✅ **New** (2025-11-11)

Basic tests to verify the adapter registration system compiles and runs correctly:
- `test_register_all_is_safe` - Verifies registration can be called multiple times safely
- `test_adapter_module_exists` - Verifies the module compiles
- `test_*_feature_enabled` - Verifies feature gates work for each adapter type
- `test_documented_inbound_count` - Documents expected inbound count (17 types)
- `test_documented_outbound_count` - Documents expected outbound count (19 types)

**Status:** ✅ All tests passing

### Endpoint / Service Lifecycle

- `app/tests/wireguard_endpoint_test.rs` — IR round-trip + feature-gated stub verification
- `app/tests/wireguard_endpoint_e2e.rs` — Userspace WireGuard endpoint happy paths (config parse, PSK, dual-stack, lifecycle)
- `app/tests/service_instantiation_e2e.rs` — Ensures services from IR are built via Bridge and surface friendly stub errors

### Trait Architecture Mismatches (Resolved)

**Status: Resolved** ✅

Outbound adapters that previously diverged from the core traits now have wrappers registered in `sb-adapters/src/register.rs`:
- **HTTP** / **SOCKS** outbound connectors use dedicated wrappers to satisfy the adapter trait contract
- **DNS** outbound is implemented and feature-gated (`adapter-dns`)
- Shadowsocks/Trojan/VMess/VLESS continue to use the wrapper pattern introduced earlier
- **TUIC** (`out_tuic`) - Uses proper trait via wrapper
- **Hysteria2** (`out_hysteria2`) - Uses proper trait via wrapper

**Solution Pattern:**
The resolved adapters (Shadowsocks/Trojan/VMess/VLESS) follow the TUIC/Hysteria2 pattern:
1. Use `sb_core::outbound::*Outbound` types that implement `OutboundTcp`
2. Create wrapper that implements `sb_core::adapter::OutboundConnector`
3. Wrapper's `connect()` method returns error directing to use switchboard registry
4. Return both TCP connector (wrapper) and UDP factory (actual outbound)

The adapter registry's TCP connector is a placeholder; real connections go through the switchboard registry which uses the `OutboundTcp` trait.

### Inbound Adapters (`crates/sb-adapters/tests/`)

| Adapter | Basic | E2E | UDP Support | Integration | Status |
|---------|-------|-----|-------------|-------------|--------|
| HTTP | ✅ | ✅ | N/A | `http_connect.rs`, `http_tls.rs` | Complete |
| SOCKS | ✅ | ✅ | ✅ | `socks_connect.rs`, `socks_udp_*.rs` | Complete |
| Mixed | ⚠ | ⚠ | ⚠ | Via scaffold test | Minimal |
| Shadowsocks | ⚠ | ⚠ | ⚠ | None | **Missing** ⚠ |
| VMess | ⚠ | ⚠ | ⚠ | `vmess_unit.rs` (unit only) | Minimal |
| VLESS | ⚠ | ⚠ | ⚠ | `.disabled` files | **Disabled** ⚠ |
| Trojan | ⚠ | ⚠ | ⚠ | None | **Missing** ⚠ |
| Naive | ⚠ | ⚠ | N/A | Stub only | Stub |
| ShadowTLS | ✅ | ⚠ | ⚠ | `shadowtls_smoke.rs` | Smoke only |
| Hysteria | ⚠ | ⚠ | ⚠ | Stub only | Stub |
| Hysteria2 | ✅ | ⚠ | ⚠ | `hysteria2_smoke.rs` | Smoke only |
| TUIC | ✅ | ✅ | ⚠ | `tuic_integration.rs` | Partial |
| AnyTLS | ⚠ | ⚠ | ⚠ | Stub only | Stub |
| TUN | ⚠ | ⚠ | N/A | `tun_process_integration.rs` | Minimal |
| Redirect | ⚠ | ⚠ | N/A | None | **Missing** ⚠ |
| TProxy | ⚠ | ⚠ | N/A | None | **Missing** ⚠ |

### Outbound Adapters (`crates/sb-adapters/tests/`)

| Adapter | Basic | Connection | UDP Support | Integration | Status |
|---------|-------|------------|-------------|-------------|--------|
| Direct | ⚠ | ⚠ | ⚠ | Via scaffold | Minimal |
| Block | ⚠ | ⚠ | ⚠ | None | **Missing** ⚠ |
| HTTP | ✅ | ✅ | N/A | `http_connect.rs` | Complete |
| SOCKS | ✅ | ✅ | ✅ | `socks_connect.rs`, `socks_udp_*.rs` | Complete |
| Shadowsocks | ⚠ | ⚠ | ⚠ | None | **Missing** ⚠ |
| Trojan | ⚠ | ⚠ | ⚠ | None | **Missing** ⚠ |
| VMess | ⚠ | ⚠ | ⚠ | `vmess_unit.rs` (unit only) | Minimal |
| VLESS | ⚠ | ⚠ | ⚠ | `.disabled` files | **Disabled** ⚠ |
| SSH | ⚠ | ⚠ | N/A | None | **Missing** ⚠ |
| ShadowTLS | ⚠ | ⚠ | N/A | None | **Missing** ⚠ |
| TUIC | ✅ | ✅ | ✅ | `tuic_integration.rs` | Complete |
| Hysteria2 | ✅ | ⚠ | ⚠ | `hysteria2_smoke.rs` | Smoke only |
| **DNS** | ⚠ | ⚠ | ⚠ | None (new) | **To be added** |
| Tor | ⚠ | ⚠ | N/A | Stub only | Stub |
| AnyTLS | ⚠ | ⚠ | ⚠ | Stub only | Stub |
| WireGuard | ⚠ | ⚠ | ⚠ | Stub only | Stub |
| Hysteria (v1) | ⚠ | ⚠ | ⚠ | Stub only | Stub |

### E2E and Integration Tests

| Test Suite | File | Coverage | Status |
|------------|------|----------|--------|
| Proxy Flow | `e2e_proxy_flow.rs` | SOCKS + HTTP chain | Complete |
| Retry/Backoff | `retry_backoff.rs` | Connection retry | Complete |
| UDP Proxy | `socks_udp_e2e_*.rs` | SOCKS UDP relay | Complete |

## Feature Gate Tests

**Script:** `scripts/test_feature_gates.sh` → wraps `cargo xtask feature-matrix`

Matrix coverage (32 cases, `cargo run -p xtask -- feature-matrix`):
- App presets（minimal/router/observe/full）
- sb-core DNS transports（udp/doh/dot/doq/doh3 + TLS）
- QUIC/高级出站（tuic/hysteria2/shadowtls/wireguard）
- sb-adapters 主力 adapter（http/socks/shadowsocks/vmess/vless/trojan/naive/shadowtls/hysteria/hysteria2/tuic/wireguard/dns）
- Mixed cases（DNS + adapters）

**Status:** ✅ 已实现并运行（最新矩阵全部通过；失败时脚本会列出具体组合）

## Test Statistics

### DNS Tests
- **Total DNS Transports:** 6 (UDP, TCP, DoT, DoH, DoQ, DoH3)
- **Fully Tested:** 2 (UDP, **DoH3**)
- **Partially Tested:** 4 (TCP, DoT, DoH, DoQ)
- **Coverage:** 33% full, 67% partial

### Adapter Tests
- **Total Inbound Adapters:** 17
- **Fully Tested:** 2 (HTTP, SOCKS)
- **Partially Tested:** 4 (TUIC, Hysteria2, ShadowTLS, TUN)
- **Missing Tests:** 11
- **Coverage:** 12% full, 24% partial

- **Total Outbound Adapters:** 16
- **Fully Tested:** 3 (HTTP, SOCKS, TUIC)
- **Partially Tested:** 2 (VMess, Hysteria2)
- **Missing Tests:** 11
- **Coverage:** 19% full, 13% partial

## Priority Gaps

### High Priority (Core Protocols)
1. **Shadowsocks** - No integration tests (common protocol)
2. **Trojan** - No integration tests (common protocol)
3. **VLESS** - Tests disabled, need re-enabling
4. **VMess** - Only unit tests, need integration tests
5. **DNS Outbound** - New feature, needs basic tests

### Medium Priority (Platform-specific)
1. **Redirect/TProxy** - Linux-only, no tests
2. **TUN** - Minimal test coverage

### Low Priority (Stubs/Advanced)
1. Naive, Hysteria v1, AnyTLS, Tor, WireGuard - All stubs

## Recommendations

1. **Immediate Actions:**
   - Run feature gate test script
   - Add Shadowsocks integration test
   - Add Trojan integration test
   - Add DNS outbound basic test

2. **Short Term:**
   - Re-enable VLESS tests
   - Expand VMess test coverage
   - Add DoT/DoH/DoQ upstream query tests

3. **Long Term:**
   - Add platform-specific tests (Redirect/TProxy on Linux)
   - Expand TUN test coverage
   - Add performance benchmarks for DoH3 vs DoH

## New in This Update (2025-11-10)

✨ **DoH3 (DNS-over-HTTP/3) Test Coverage:**
- Transport layer construction and query tests
- Upstream layer with query, health check, and ECS support
- Config builder with URL parsing (doh3://, h3://)
- TLS options (CA paths/PEM, SNI, skip_verify)
- Real network tests (ignored by default)
- Consistency tests comparing DoH vs DoH3

✨ **Feature Gate Test Script:**
- Created `scripts/test_feature_gates.sh` (现在调用 `cargo xtask feature-matrix`)
- `cargo xtask feature-matrix` 覆盖 32 组 app/sb-core/sb-adapters 组合，包括 CLI 预设、DNS 传输、QUIC 出站和主力 adapter
- Validates no compilation regressions（失败用例会在矩阵汇总中列出）

✨ **Adapter Registry Fixes (2025-11-11):**
- Fixed trait architecture mismatch for 4 encrypted protocol outbounds:
  - Shadowsocks, Trojan, VMess, VLESS now use wrapper pattern
  - Follow TUIC/Hysteria2 architecture with `OutboundTcp` trait
  - Properly integrated with switchboard registry
- HTTP/SOCKS/DNS outbounds remain pending (require different approach)
- All adapter registry smoke tests passing (12 tests)

## Running the Tests

```bash
# Run DNS transport tests
cargo test --package sb-core --test dns_transport_tests

# Run DNS upstream tests
cargo test --package sb-core --test dns_upstream_tests

# Run DNS config builder tests
cargo test --package sb-core --test dns_config_builder_tests

# Run feature gate tests (32-case matrix)
cargo xtask feature-matrix
# or legacy wrapper
./scripts/test_feature_gates.sh

# Run adapter tests
cargo test --package sb-adapters

# Run all tests
cargo test --workspace

# Run ignored tests (require network)
cargo test --package sb-core -- --ignored
```

## CI Integration

**Status:** ⏳ Pending

**Recommended CI Matrix:**
- Default features
- Minimal features (dns_udp only)
- All DNS features
- All adapter features
- Full feature set

**Test Commands:**
```yaml
- cargo test --workspace --no-default-features
- cargo test --workspace --features dns_doh3
- cargo test --workspace --all-features
- ./scripts/test_feature_gates.sh
```
