# Test Coverage Report

## Overview
**Date**: 2026-02-02
**Status**: High protocol integration coverage (some suites feature-gated or temporarily disabled)
**Parity**: 88% (aligned with Go reference)

This document tracks the test coverage for the `singbox-rust` project, focusing on protocol integration, core routing logic, and service components.

---

## 1. Protocol Integration Tests (sb-adapters + workspace tests)

All core protocols have dedicated integration tests covering:
- Configuration parsing
- Connector/Server initialization
- Data transmission (Client <-> Server)
- Protocol-specific features (IV checks, users, etc.)

| Protocol | Test File | Tests | Status | Notes |
|----------|-----------|-------|--------|-------|
| **Shadowsocks** | `shadowsocks_integration.rs` | 14 | ✅ 13 pass, 1 ignored | Ignored test checks replay protection (requires mock time) |
| **Trojan** | `trojan_integration.rs` | 16 | ✅ 15 pass, 1 ignored | Ignored test checks timeout (requires rustls CryptoProvider) |
| **DNS** | `dns_outbound_integration.rs` | 15 | ✅ 14 pass, 1 ignored | Ignored test checks system resolver (env dependent) |
| **VLESS** | `vless_integration.rs` | 17 | ✅ 17 pass | Full coverage including flow control & encryption |
| **VMess** | `tests/vmess_websocket_integration.rs` | 4 | ✅ Config/transport wiring | WebSocket + TCP config coverage; no live server required |
| **TUIC** | `crates/sb-adapters/tests/tuic_integration.rs` | 10 | ⚠️ Disabled | Guarded by `#[cfg(disabled_test_temporarily)]` + `feature = "tuic"` |
| **Hysteria2** | `crates/sb-core/tests/hysteria2_integration.rs` | 12 | ✅ Feature-gated | Requires `feature = "out_hysteria2"`; config/behavior checks only |

---

## 2. Core Routing & Rule Tests (sb-core)

Routing logic is functionality verified, but some tests depend on external database files.

| Component | Test File | Status | Notes |
|-----------|-----------|--------|-------|
| **Router** | `router.rs` | ✅ Pass | Basic routing logic |
| **GeoIP Rules** | `router_geoip_rules_integration.rs` | ⚠️ Ignored | Requires `geoip.db` (MMDB format) |
| **GeoIP DB** | `router_geoip_integration.rs` | ⚠️ Ignored | Requires `geoip.db` (MMDB format) |
| **GeoSite** | `router_geosite_integration.rs` | ⚠️ Ignored | Requires `geosite.db` (Protobuf format) |

### Environment Requirements
To run GeoIP/GeoSite tests:
1. Download `geoip.db` (MMDB) and `geosite.db` (v2fly/dat format).
2. Place them in the expected test paths (or update test config).
3. Run with `cargo test --ignored`.

---

## 3. Structural & Unit Tests

| Crate | Focus | Status |
|-------|-------|--------|
| `sb-common` | Utilities, JSON parsing | ✅ Pass |
| `sb-types` | Configuration types | ✅ Pass |
| `sb-transport` | Network primitives | ✅ Pass |
| `sb-tls` | TLS wrappers (ECH, uTLS) | ✅ Pass |

---

## 4. Known Gaps & Future Work

1.  **TUIC Integration**: Test suite exists but is disabled by `#[cfg(disabled_test_temporarily)]`; re-enable after updating TUIC test harness.
2.  **Geo-Test Data**: Add small valid MMDB/Protobuf fixtures to the repo to enable GeoIP/GeoSite tests in CI without external downloads.
