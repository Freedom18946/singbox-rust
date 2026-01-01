# Test Suite Organization

This directory contains integration tests for the singbox-rust application.

## Directory Structure

```
app/tests/
├── common/              # Shared test utilities (not run as tests)
│   ├── mod.rs          # Module exports
│   ├── workspace.rs    # Binary location helpers
│   ├── http.rs         # HTTP client helpers
│   └── fixtures.rs     # Test data loading utilities
├── fixtures/            # Test data files
│   ├── auth/           # Authentication test data (JWT keys, etc.)
│   │   ├── jwks.json
│   │   ├── expired.jwt
│   │   ├── invalid.jwt
│   │   └── apikey.env
│   └── geo/            # GeoIP/GeoSite test data
│       ├── legacy/
│       ├── corrupt/
│       └── missing/
├── golden/              # Golden file test data (expected outputs)
│   ├── version_output.json
│   ├── check_good_output.json
│   ├── check_bad_output.json
│   ├── explain_tcp_output.json
│   └── ...
├── data/                # Routing test vectors
│   ├── route_min.json
│   ├── ok.json
│   ├── bad.json
│   └── route_vectors/
├── cli/                 # CLI test files (trycmd)
│   ├── *.trycmd        # CLI test specifications
│   └── fixtures/       # CLI-specific fixtures
│       ├── minimal_good.json
│       ├── invalid_config.json
│       ├── merge_*.json
│       └── pems/
└── *.rs                 # Integration test files
```

## Test Organization

### Test File Naming Conventions

Test files follow these naming patterns:

- `*_unit.rs` - Unit tests (currently rare in integration tests directory)
- `*_integration.rs` - Integration tests (cross-module functionality)
- `*_e2e.rs` - End-to-end tests (require external services or network)
- `*_contract.rs` - Contract tests (API/CLI interface contracts)
- `*_stress.rs` - Stress/performance tests (long-running)

Examples:
- `p0_dns_integration.rs` - DNS integration with P0 protocols
- `admin_http_contract.rs` - Admin HTTP API contract tests
- `multiplex_vmess_e2e.rs` - VMess multiplexing end-to-end tests

### Feature Gates

Tests are gated by cargo features to control which tests run in different environments:

#### `admin_tests`
Admin API and debug endpoint tests. Requires network binding capabilities.

**Usage:**
```bash
cargo test --features admin_tests
```

**Purpose:** Tests that require binding to network ports (admin HTTP server, etc.)

#### `net_e2e`
Network end-to-end tests. May require external services or Docker containers.

**Usage:**
```bash
cargo test --features net_e2e
```

**Purpose:** Full end-to-end network protocol tests (DNS, proxies, etc.)

#### `long_tests`
Long-running stress and endurance tests. May run for minutes or hours.

**Usage:**
```bash
cargo test --features long_tests --release -- --ignored --test-threads=1
```

**Purpose:** Performance benchmarks, stress tests, resource leak detection

### Running Tests

**Run all tests (default features):**
```bash
cargo test
```

**Run specific test file:**
```bash
cargo test --test p0_dns_integration
```

**Run with all features:**
```bash
cargo test --all-features
```

**Run admin tests only:**
```bash
cargo test --features admin_tests
```

**Run e2e tests:**
```bash
cargo test --features net_e2e
```

**Run stress tests:**
```bash
cargo test --features long_tests --release -- --ignored --test-threads=1
```

## Using Common Test Utilities

### Workspace Binary Location

To locate binaries built by cargo:

```rust
#[path = "../common/mod.rs"]
mod common;

use common::workspace::workspace_bin;

#[test]
fn test_something() {
    let check_bin = workspace_bin("check");
    // Use the binary...
}
```

### HTTP Helpers

For simple HTTP testing:

```rust
use common::http::{get, post_json};

let response = get("127.0.0.1:8080", "/health");
assert!(response.contains("200 OK"));

let body = r#"{"key": "value"}"#;
let response = post_json("127.0.0.1:8080", "/api/endpoint", body);
```

### Fixture Loading

To load test data files:

```rust
use common::fixtures::{load_fixture, fixture_path};

// Load as string (from app/tests/fixtures/)
let jwks = load_fixture("auth/jwks.json");

// Get path for std::fs operations
let path = fixture_path("geo/legacy/config.yaml");
```

**Available fixtures:**
- `fixtures/auth/` - JWT keys, API keys, authentication tokens
  - `jwks.json` - JSON Web Key Set
  - `expired.jwt`, `invalid.jwt` - Test JWT tokens
  - `apikey.env` - Environment file with API keys
- `fixtures/geo/` - GeoIP/GeoSite test configurations
  - `legacy/config.yaml` - Legacy format configuration
  - `corrupt/config.yaml` - Intentionally corrupted data
  - `missing/config.yaml` - Missing required fields

### Mock SOCKS5 Server

For UDP/SOCKS5 testing (across crates):

```rust
use sb_test_utils::socks5::start_mock_socks5;

#[tokio::test]
async fn test_with_socks5() {
    let (tcp_addr, udp_addr) = start_mock_socks5().await.unwrap();
    // Use the mock server...
}
```

## Test Data Management

### Fixtures Directory (`app/tests/fixtures/`)

Organized by functionality:

- **auth/** - Authentication and authorization test data
  - JWT keys, tokens, API keys
  - Valid and invalid credentials for testing auth flows

- **geo/** - Geographic routing test data
  - GeoIP/GeoSite database configurations
  - Legacy, corrupt, and minimal test cases

### Golden Files (`app/tests/golden/`)

Expected output files for golden tests (snapshot testing):

- `version_output.json` - Expected output from `version --json`
- `check_good_output.json` - Expected output from `check` on valid config
- `check_bad_output.json` - Expected output from `check` on invalid config
- `explain_tcp_output.json` - Expected output from `route-explain --protocol tcp`
- `explain_udp_output.json` - Expected output from `route-explain --protocol udp`
- `config_*.json` - Test configuration files

### CLI Fixtures (`app/tests/cli/fixtures/`)

Test data specific to CLI command testing:

- `minimal_good.json` - Minimal valid configuration
- `invalid_config.json` - Invalid configuration for error testing
- `merge_*.json` - Configuration files for merge testing
- `pems/` - TLS certificates and keys for testing

### Routing Test Vectors (`app/tests/data/`)

Test vectors for routing logic validation:

- `route_min.json` - Minimal routing configuration
- `ok.json`, `bad.json`, `warn.json` - Test cases with different severities
- `route_vectors/` - Complex routing test scenarios
  - `direct.json` - Direct routing tests
  - `selector.json` - Selector routing tests

### Golden File Tests

Golden file tests compare actual output against expected output stored in files.

Location: `app/tests/golden/`

Example structure:
```
golden/
├── version_output.json          # Expected output from `version --json`
├── check_good_output.json       # Expected output from `check` on valid config
├── check_bad_output.json        # Expected output from `check` on invalid config
└── explain_tcp_output.json      # Expected output from `route-explain`
```

## Adding New Tests

### 1. Choose the Right Location

- **Integration test:** `app/tests/feature_integration.rs`
- **E2E test:** `app/tests/protocol_e2e.rs`
- **Contract test:** `app/tests/api_contract.rs`

### 2. Add Feature Gates if Needed

```rust
#![cfg(feature = "net_e2e")]

#[test]
fn my_e2e_test() {
    // Test code
}
```

### 3. Use Common Utilities

Import from `common/` module to avoid code duplication:

```rust
#[path = "../common/mod.rs"]
mod common;

use common::workspace::{workspace_bin, run_check};
use common::http::get;
```

### 4. Document the Test

Add a doc comment explaining:
- What the test verifies
- Any prerequisites (external services, etc.)
- Expected behavior

```rust
/// Test DNS resolution through REALITY outbound.
///
/// Verifies that DNS queries can be correctly routed through
/// REALITY proxies with proper TLS fingerprinting.
#[test]
#[cfg(feature = "net_e2e")]
fn test_dns_via_reality() {
    // Test implementation
}
```

## CI Integration

### GitHub Actions

Tests run in CI with different feature combinations:

```yaml
- name: Run integration tests
  run: cargo test --features "admin_tests net_e2e"

- name: Run stress tests
  run: cargo test --features long_tests --release -- --ignored
```

### Test Matrix

CI runs tests across:
- Multiple Rust versions (MSRV 1.90+)
- Multiple platforms (Linux, macOS, Windows)
- Multiple feature combinations

## Troubleshooting

### Permission Denied Errors

Some tests (especially `admin_tests`) require network binding. On sandboxed systems (macOS, CI), these may fail with `PermissionDenied`. Tests should gracefully skip when permissions are denied:

```rust
let listener = match TcpListener::bind("127.0.0.1:0") {
    Ok(l) => l,
    Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
        eprintln!("Skipping test due to PermissionDenied: {}", e);
        return;
    }
    Err(e) => panic!("Unexpected error: {}", e),
};
```

### Flaky Tests

If tests are flaky:
1. Check for race conditions
2. Add appropriate timeouts
3. Use `tokio::time::pause()` for time-dependent tests
4. Ensure proper cleanup in teardown

### Test Timeouts

For long-running operations:

```rust
#[tokio::test]
#[timeout(std::time::Duration::from_secs(30))]
async fn my_test() {
    // Will fail if takes longer than 30 seconds
}
```

## Code Quality Standards

### Lints

Tests follow the same lint rules as production code:
- `#![deny(clippy::unwrap_used)]` - Use proper error handling
- `#![deny(clippy::expect_used)]` - Avoid expect in tests where possible
- `#![deny(clippy::panic)]` - Use assertions instead

### Error Handling

Prefer `Result` return types:

```rust
#[test]
fn my_test() -> anyhow::Result<()> {
    let value = something_that_might_fail()?;
    assert_eq!(value, expected);
    Ok(())
}
```

### Assertions

Use descriptive assertion messages:

```rust
assert!(
    result.is_ok(),
    "Expected successful validation, got error: {:?}",
    result.unwrap_err()
);
```

## Resources

- [Rust Testing Book](https://doc.rust-lang.org/book/ch11-00-testing.html)
- [Cargo Test Documentation](https://doc.rust-lang.org/cargo/commands/cargo-test.html)
- [Integration Testing Guide](https://doc.rust-lang.org/rust-by-example/testing/integration_testing.html)

## Maintenance

This test suite is actively maintained. When adding new features:

1. **Add tests first** (TDD approach recommended)
2. **Update this README** if adding new patterns or conventions
3. **Keep tests fast** - move slow tests to `long_tests` feature
4. **Document edge cases** - explain why tests exist

---

Last updated: 2026-01-01
