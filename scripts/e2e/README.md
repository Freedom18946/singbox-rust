# E2E Tests

End-to-end integration tests for singbox-rust.

## Overview

This directory contains comprehensive E2E tests organized by subsystem:
- DNS resolution and caching
- Router configuration and rules
- UDP relay and protocols
- SOCKS5 protocol testing
- Proxy health and connection pooling
- TLS/transport layer

## Main Scripts

### `run.sh`
Main E2E test runner - executes all E2E tests.

```bash
./scripts/e2e/run.sh
```

### `clean.sh`
Clean up E2E test artifacts and temporary files.

```bash
./scripts/e2e/clean.sh
```

### `diff.sh`
Compare E2E test results between runs.

```bash
./scripts/e2e/diff.sh
```

### `smoke.sh`
Quick smoke test for basic functionality.

```bash
./scripts/e2e/smoke.sh
```

Exit codes:
- 0: All tests passed
- 1: Some tests failed
- 77: Skipped (GO_SINGBOX_BIN not available)

## Test Categories

### DNS Tests (`dns/`)

- `backends.sh` - Test different DNS backends (UDP, DoT, DoH)
- `cache.sh` - DNS caching functionality
- `cache-v2.sh` - DNS cache v2 implementation
- `dualstack.sh` - IPv4/IPv6 dual-stack DNS

### Router Tests (`router/`)

- `integration.sh` - Full router integration
- `json-bridge.sh` - JSON configuration bridge
- `proxy.sh` - Proxy routing logic
- `rules.sh` - Rule-based routing

### UDP Tests (`udp/`)

- `echo.sh` - UDP echo server testing
- `metrics.sh` - UDP metrics collection
- `shadowsocks.sh` - Shadowsocks UDP relay
- `socks5-echo.sh` - SOCKS5 UDP echo

### SOCKS5 Tests (`socks5/`)

- `udp-roundtrip.sh` - UDP roundtrip testing
- `udp-upstream.sh` - UDP upstream relay

### Proxy Tests (`proxy/`)

- `health.sh` - Proxy health checking
- `pool.sh` - Connection pool management

### Other Tests

- `tls-smoke.sh` - TLS handshake smoke test
- `dial-metrics.sh` - Dial metrics collection
- `subs.sh` - Subscription management

## Test Environment

Tests use the `.e2e/` directory for runtime artifacts:

```
.e2e/
├── logs/              Test logs
├── reports/           Test reports
├── pids/              Process IDs
├── visualizations/    Test visualizations
├── artifacts/         Test artifacts
└── archives/          Archived results
```

## Environment Variables

- `GO_SINGBOX_BIN` - Path to Go sing-box binary for comparison tests
- `RUST_BACKTRACE` - Enable Rust backtraces (default: 1)
- `ECHO_ADDR` - UDP echo server address (default: 127.0.0.1:19000)

## Running Tests

### Run All E2E Tests

```bash
./scripts/e2e/run.sh
```

### Run Specific Category

```bash
# DNS tests only
./scripts/e2e/dns/backends.sh
./scripts/e2e/dns/cache.sh

# Router tests
./scripts/e2e/router/integration.sh
```

### Run with Cleanup

```bash
./scripts/e2e/clean.sh && ./scripts/e2e/run.sh
```

### Compare with Go Implementation

```bash
export GO_SINGBOX_BIN=/path/to/sing-box
./scripts/e2e/run.sh
```

## Test Patterns

### Standard Test Structure

```bash
#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

# Setup
mkdir -p .e2e/{logs,pids}

# Build
cargo build -q --bins

# Test logic
run_test() {
    # Test implementation
}

# Cleanup
cleanup() {
    set +e
    # Kill processes
    # Remove temp files
}
trap cleanup EXIT

# Execute
run_test
echo "✓ Test passed"
```

### Using Test Utilities

```bash
# Source metrics library
source "${ROOT}/scripts/lib/metrics.sh"

# Fetch and validate metrics
METRICS=$(fetch_metrics "127.0.0.1:9090")
COUNT=$(metric_sum "$METRICS" "dns_queries_total")
```

## Writing New Tests

1. Choose appropriate subdirectory
2. Name file descriptively: `feature-name.sh`
3. Include usage documentation
4. Use standard project root detection
5. Source required libraries from `scripts/lib/`
6. Implement cleanup trap
7. Return appropriate exit codes
8. Log to `.e2e/logs/`

## Debugging Failed Tests

```bash
# Check test logs
tail -f .e2e/logs/*.log

# Check running processes
cat .e2e/pids/*.pid | xargs ps

# Cleanup stuck tests
./scripts/e2e/clean.sh

# Run single test with verbose output
RUST_BACKTRACE=full ./scripts/e2e/dns/backends.sh
```

## CI Integration

E2E tests run in GitHub Actions:

```yaml
- name: Run E2E Tests
  run: ./scripts/e2e/run.sh
```

## Dependencies

- `cargo` - Build binaries
- `curl` - HTTP requests
- `jq` - JSON processing
- `nc` / `netcat` - Network testing
- Optional: `dig` for DNS testing
- Optional: Go sing-box for comparison tests
