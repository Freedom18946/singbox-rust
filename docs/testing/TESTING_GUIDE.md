# Testing Guide for singbox-rust

This guide provides comprehensive information on testing the singbox-rust project, including how to run tests, add new tests, and understand test coverage.

## Table of Contents

- [Overview](#overview)
- [Test Structure](#test-structure)
- [Running Tests](#running-tests)
- [Test Categories](#test-categories)
- [Adding New Tests](#adding-new-tests)
- [Mock Servers and Test Fixtures](#mock-servers-and-test-fixtures)
- [Debugging Tests](#debugging-tests)
- [Coverage and Metrics](#coverage-and-metrics)

## Overview

The singbox-rust project uses a multi-layered testing strategy:

1. **Unit Tests**: Test individual functions and modules in isolation
2. **Integration Tests**: Test interactions between components
3. **E2E Tests**: Test complete workflows with real protocol implementations
4. **Contract Tests**: Verify CLI output matches Go sing-box behavior
5. **Performance Tests**: Benchmark throughput and latency

## Test Structure

```
singbox-rust/
├── app/tests/           # Application-level integration tests
│   ├── adapter_*.rs     # Adapter instantiation and registration tests
│   ├── cli_*.rs         # CLI command tests
│   ├── *_e2e.rs         # End-to-end protocol tests
│   └── route_*.rs       # Routing and rule engine tests
├── crates/*/tests/      # Crate-specific integration tests
├── xtests/              # Cross-cutting end-to-end tests
│   ├── tests/           # E2E test suites
│   └── benches/         # Performance benchmarks
└── scripts/             # Parity and validation scripts
    ├── *_parity.sh      # Go vs Rust comparison scripts
    └── test_*.sh        # Test automation scripts
```

## Running Tests

### All Tests

```bash
# Run all tests in the workspace
cargo test --workspace

# Run tests with output
cargo test --workspace -- --nocapture

# Run tests in parallel (default) or serially
cargo test --workspace -- --test-threads=1
```

### Specific Test Suites

```bash
# Unit tests only (library tests)
cargo test --lib

# Integration tests in app
cargo test -p app --test '*'

# Specific integration test file
cargo test -p app --test adapter_instantiation_e2e

# E2E tests
cargo test -p xtests

# DNS-specific tests
cargo test --package sb-core --lib dns

# Adapter tests with specific features
cargo test -p sb-adapters --features adapter-shadowsocks
```

### Feature Combinations

```bash
# Test with all features
cargo test --workspace --all-features

# Test without default features
cargo test --workspace --no-default-features

# Test specific feature combination
cargo test -p sb-core --features "dns_doh,dns_dot,dns_doq"

# Run feature gate matrix (all combinations)
cargo run -p xtask -- feature-matrix
```

### Contract and Parity Tests

```bash
# Route explain parity (Rust vs Go)
./scripts/route_explain_compare.sh

# GeoIP/GeoSite parity
./scripts/geodata_parity.sh

# Ruleset CLI parity
./scripts/ruleset_parity.sh

# Prefetch parity
./scripts/prefetch_parity.sh

# All parity tests
./scripts/test_feature_gates.sh
```

### Performance Benchmarks

```bash
# Run all benchmarks
cargo bench -p xtests

# Specific benchmark
cargo bench -p xtests --bench adapter_throughput

# Benchmark with baseline comparison
cargo bench -p xtests -- --save-baseline main
cargo bench -p xtests -- --baseline main
```

## Test Categories

### 1. Unit Tests

**Location**: `src/` directories within each crate (inline `#[cfg(test)]` modules)

**Purpose**: Test individual functions, structs, and modules in isolation

**Example**:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_domain() {
        let result = parse_domain("example.com");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "example.com");
    }
}
```

### 2. Integration Tests

**Location**: `app/tests/`, `crates/*/tests/`

**Purpose**: Test component interactions and adapter registry

**Example Test Files**:
- `app/tests/adapter_instantiation_e2e.rs` - Protocol adapter tests
- `app/tests/dns_outbound_e2e.rs` - DNS outbound functionality
- `app/tests/cli_tools_adapter_test.rs` - CLI tool integration

### 3. End-to-End Tests

**Location**: `xtests/tests/`

**Purpose**: Test complete workflows with real network traffic (mocked or local)

**Example Workflow**:
1. Start mock server (or local test server)
2. Configure inbound + outbound adapters
3. Send test traffic through the tunnel
4. Verify data integrity and metrics
5. Clean up resources

### 4. Contract Tests

**Location**: `scripts/*_parity.sh`

**Purpose**: Verify Rust implementation matches Go sing-box behavior

**Coverage**:
- CLI command output (stdout, stderr, exit codes)
- JSON structure equivalence
- Route explain results
- GeoIP/GeoSite matching
- Ruleset operations

### 5. Stress Tests

**Location**: `xtests/tests/stress/`

**Purpose**: Validate stability under load

**Scenarios**:
- 1000+ concurrent connections
- Memory leak detection (long-running)
- Connection pool exhaustion
- Rapid hot-reload cycles

## Adding New Tests

### Integration Test Template

Create `app/tests/my_feature_test.rs`:

```rust
//! Integration tests for my new feature

use anyhow::Result;

#[tokio::test]
async fn test_feature_basic_functionality() -> Result<()> {
    // Setup
    let config = create_test_config();
    
    // Exercise
    let result = my_feature_function(&config).await?;
    
    // Verify
    assert_eq!(result.status, "success");
    assert!(result.value > 0);
    
    Ok(())
}

#[tokio::test]
async fn test_feature_error_handling() -> Result<()> {
    let invalid_config = create_invalid_config();
    
    let result = my_feature_function(&invalid_config).await;
    
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("expected error message"));
    
    Ok(())
}

// Helper functions
fn create_test_config() -> Config {
    // Return test configuration
    Config::default()
}
```

### E2E Test Template

Create `xtests/tests/protocol_e2e.rs`:

```rust
//! End-to-end tests for protocol implementation

use tokio::net::TcpListener;
use std::sync::Arc;

#[tokio::test]
async fn test_protocol_connection_success() -> anyhow::Result<()> {
    // 1. Start mock server
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let server_addr = listener.local_addr()?;
    
    let server_handle = tokio::spawn(async move {
        // Mock server logic
        run_mock_server(listener).await
    });
    
    // 2. Configure adapter
    let config = create_adapter_config(server_addr);
    let adapter = build_adapter(&config).await?;
    
    // 3. Send test traffic
    let test_data = b"Hello, World!";
    let response = adapter.send(test_data).await?;
    
    // 4. Verify
    assert_eq!(response, test_data);
    
    // 5. Cleanup
    server_handle.abort();
    
    Ok(())
}

async fn run_mock_server(listener: TcpListener) {
    // Implementation
}
```

### Adding to Test Matrix

For protocol tests, add to `app/tests/protocol_integration_matrix_test.rs`:

```rust
#[test]
fn test_my_protocol_inbound_registration() {
    sb_adapters::register_all();
    
    let ir = InboundIR {
        ty: InboundType::MyProtocol,
        name: "test-my-protocol".to_string(),
        listen: Some("127.0.0.1:8080".to_string()),
        // ... protocol-specific fields
        ..Default::default()
    };
    
    let result = to_inbound_param(&ir);
    assert!(result.is_ok());
}
```

## Mock Servers and Test Fixtures

### Creating Mock Servers

Use `tokio::net` for simple protocol mocks:

```rust
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn echo_server(addr: &str) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    
    loop {
        let (mut socket, _) = listener.accept().await?;
        
        tokio::spawn(async move {
            let mut buf = vec![0; 1024];
            
            loop {
                let n = match socket.read(&mut buf).await {
                    Ok(n) if n == 0 => return,
                    Ok(n) => n,
                    Err(_) => return,
                };
                
                if socket.write_all(&buf[0..n]).await.is_err() {
                    return;
                }
            }
        });
    }
}
```

### Test Fixtures

Store test configurations in `app/tests/data/`:

```
app/tests/data/
├── configs/
│   ├── basic_socks.json
│   ├── multi_outbound.json
│   └── dns_rules.json
├── rulesets/
│   ├── test_domain.srs
│   └── test_ip.srs
└── fixtures/
    ├── sample_requests.txt
    └── expected_responses.json
```

Load in tests:

```rust
fn load_test_config(name: &str) -> String {
    std::fs::read_to_string(
        format!("tests/data/configs/{}.json", name)
    ).expect("Failed to load test config")
}
```

## Debugging Tests

### Enable Logging

```bash
# Run with trace-level logs
RUST_LOG=trace cargo test -- --nocapture

# Specific module logs
RUST_LOG=sb_core::dns=debug cargo test dns_tests

# Multiple modules
RUST_LOG=sb_core=debug,sb_adapters=trace cargo test
```

### Run Single Test

```bash
# Run one specific test
cargo test test_shadowsocks_registration -- --exact --nocapture

# Show test names without running
cargo test -- --list
```

### Use `dbg!()` and `println!()`

```rust
#[test]
fn debug_example() {
    let value = compute_something();
    dbg!(&value);  // Prints with file:line info
    
    println!("Value: {:?}", value);  // Regular output
    
    assert_eq!(value, expected);
}
```

### Ignore Flaky Tests Temporarily

```rust
#[test]
#[ignore = "flaky test, needs investigation"]
fn sometimes_fails() {
    // Test code
}
```

Run ignored tests explicitly:
```bash
cargo test -- --ignored
```

## Coverage and Metrics

### Generate Coverage Report

Using `cargo-tarpaulin`:

```bash
# Install
cargo install cargo-tarpaulin

# Generate HTML report
cargo tarpaulin --out Html --output-dir coverage/

# Generate lcov for CI
cargo tarpaulin --out Lcov
```

### Coverage Goals

- **sb-core**: ≥80% line coverage
- **sb-adapters**: ≥75% line coverage
- **sb-config**: ≥70% line coverage
- **Critical paths** (DNS, routing, adapter registry): ≥90%

### Test Metrics

Track in CI/CD:

- Total test count
- Pass rate (should be 100%)
- Test execution time
- Flaky test rate (should be <1%)
- Coverage percentage

### Go Parity Metrics

Compare with Go sing-box:

- CLI command compatibility: 100%
- Protocol coverage: 36/36 protocols
- DNS transport coverage: 11/12 transports
- Configuration compatibility: all standard configs

## Best Practices

1. **Test Isolation**: Each test should be independent and not rely on global state
2. **Cleanup**: Always clean up resources (connections, temp files, spawned tasks)
3. **Determinism**: Avoid flaky tests by not relying on timing or random values
4. **Meaningful Assertions**: Use `assert_eq!` with clear expected values
5. **Error Context**: Use `anyhow::Context` to add context to errors
6. **Async Tests**: Always use `#[tokio::test]` for async tests
7. **Feature Gates**: Test with and without optional features

## Continuous Integration

CI runs the following on every PR:

```bash
# Formatting check
cargo fmt --all -- --check

# Linting
cargo clippy --workspace --all-targets -- -D warnings

# All tests
cargo test --workspace --all-features

# Feature matrix
cargo run -p xtask -- feature-matrix

# Go parity tests
./scripts/route_explain_compare.sh
./scripts/geodata_parity.sh
```

## Troubleshooting

### Tests Hang

- Check for missing `.await` in async code
- Verify timeouts are set appropriately
- Look for deadlocks in concurrent code

### Tests Fail Intermittently

- Remove timing dependencies
- Use channels/barriers for synchronization
- Check for race conditions

### Coverage Not Captured

- Ensure `#[cfg(test)]` is used correctly
- Check that test functions are marked with `#[test]`
- Verify feature gates aren't excluding code

## Resources

- [Rust Testing Documentation](https://doc.rust-lang.org/book/ch11-00-testing.html)
- [tokio Testing Guide](https://tokio.rs/tokio/topics/testing)
- [Project Test Coverage](../TEST_COVERAGE.md)
- [Go Parity Matrix](../../GO_PARITY_MATRIX.md)

## Contact

For questions about testing:
- Check existing test examples in `app/tests/`
- Review NEXT_STEPS.md for current testing priorities
- See GO_PARITY_MATRIX.md for protocol coverage status
