# Test Coverage Report

This report tracks current test entry points and known coverage gaps. It is a gap tracker, not a parity-closure proof.

## Current Snapshot

- Feature matrix snapshot: `reports/feature_matrix_report.txt`
- Latest recorded matrix result: `46/46` pass
- This file should be read together with:
  - `agents-only/reference/ACCEPTANCE-CRITERIA.md`
  - `agents-only/reference/GO_PARITY_MATRIX.md`

## Scope

This document focuses on three questions:

- which test targets currently exist
- which important paths are only partially covered
- which older coverage claims are no longer trustworthy

It does not attempt to compute a single repository-wide percentage.

## Current Verified Test Entry Points

### Registry / Wiring

- `crates/sb-adapters/tests/adapter_registry_smoke.rs`
- `app/tests/adapter_instantiation_e2e.rs`
- `app/tests/service_instantiation_e2e.rs`
- `app/tests/wireguard_endpoint_test.rs`
- `app/tests/wireguard_endpoint_e2e.rs`

### Protocol Integration Targets

Current feature-gated integration suites that exist in the tree:

```bash
cargo test -p sb-adapters --features adapter-shadowsocks --test shadowsocks_integration
cargo test -p sb-adapters --features adapter-trojan --test trojan_integration
cargo test -p sb-adapters --features adapter-vless --test vless_integration
```

### DNS Outbound / App E2E

Current app-side DNS outbound test target:

```bash
cargo test -p app --features net_e2e --test dns_outbound_e2e
```

### DNS Transport / Config

- `crates/sb-core/tests/dns_transport_tests.rs`
- `crates/sb-core/tests/dns_upstream_tests.rs`
- `crates/sb-core/tests/dns_config_builder_tests.rs`

## Coverage Guidance

### Well-covered or actively exercised paths

- adapter registration smoke
- app-level adapter and service instantiation
- WireGuard endpoint lifecycle paths
- DNS transport/config builder coverage
- feature matrix compilation coverage

### Partially covered paths

- protocol runtime behavior that requires external network or elevated permissions
- Linux-only redirect / tproxy paths
- TUN runtime paths that depend on platform-specific wiring
- behavior-level parity for uTLS / ECH / accepted-limitation capabilities

### Important caveats

- Feature-matrix green status is compile/feature coverage, not end-to-end parity proof.
- Historical versions of this report contained inconsistent totals and outdated “missing test” claims. Those summary percentages have been removed.
- The existence of a test target does not imply full behavior verification across all supported platforms.

## Recommended Read Order

1. `reports/feature_matrix_report.txt`
2. this file
3. `agents-only/reference/ACCEPTANCE-CRITERIA.md`
4. `agents-only/reference/GO_PARITY_MATRIX.md`

---

**Last updated**: 2026-03-21
