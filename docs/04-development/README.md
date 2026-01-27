# Development Guide

Contributing to singbox-rust: architecture, code style, testing, and build system.

---

## 📖 Documentation Sections

### Architecture

- **[Overview](architecture/overview.md)** - System architecture and design principles
- **[Router Engine](architecture/router-engine.md)** - Routing system internals
- **[TLS Infrastructure](architecture/tls-infrastructure.md)** - TLS/REALITY/ECH implementation
- **[Transport Layer](architecture/transport-layer.md)** - WebSocket, HTTP/2, gRPC, QUIC
- **[Data Flow](architecture/data-flow.md)** - Request flow and processing pipeline

### Contributing

- **[Getting Started](contributing/getting-started.md)** - Dev environment setup
- **[Code Style](contributing/code-style.md)** - Rust conventions and patterns
- **[Testing Guide](contributing/testing-guide.md)** - Writing tests
- **[Documentation](contributing/documentation.md)** - Docs contribution guide
- **[Pull Requests](contributing/pull-requests.md)** - PR workflow and review process

### Build System

- **[Overview](build-system/overview.md)** - Cargo workspace and build configuration
- **[Feature Flags](build-system/feature-flags.md)** - Available features and combinations
- **[Cross Compilation](build-system/cross-compilation.md)** - Building for different targets
- **[CI Matrix](build-system/ci-matrix.md)** - CI/CD scripts and tasks

### Quality Gates

- **[Linting](quality-gates/linting.md)** - Clippy rules and enforcement
- **[Testing](quality-gates/testing.md)** - Unit, integration, E2E tests
- **[Benchmarking](quality-gates/benchmarking.md)** - Performance regression detection
- **[Stress Testing](quality-gates/stress-testing.md)** - Load and stress testing

### Protocol Implementation

- **[Implementation Guide](protocols/implementation-guide.md)** - Adding new protocols
- **[Adapter Bridge](protocols/adapter-bridge.md)** - Inbound/outbound adapter interface
- **[Upstream Compatibility](protocols/upstream-compat.md)** - Maintaining parity with sing-box

### Related References

- **[Transport Defaults](transport-defaults.md)** - Outbound transport defaults and conflicts
- **[Project Structure Navigation](../../PROJECT_STRUCTURE_NAVIGATION.md)** - Authoritative project layout
- **[API Reference](../05-api-reference/README.md)** - Admin HTTP API, V2Ray gRPC API
- **[Operations Guide](../03-operations/README.md)** - Runtime ops and deployment
- **[Migration Guide](../MIGRATION_GUIDE.md)** - Go → Rust migration notes
- **[Testing Guide](../testing/TESTING_GUIDE.md)** - Test strategy and execution

---

## Quick Start for Contributors

### 1. Clone and Setup

```bash
# Clone repository
git clone https://github.com/your-repo/singbox-rust.git
cd singbox-rust

# Check Rust version (MSRV: 1.90)
rustc --version

# Build workspace
cargo build --workspace

# Run tests
cargo test --workspace
```

### 2. Development Workflow

```bash
# 1. Create feature branch
git checkout -b feature/my-awesome-feature

# 2. Make changes and test
cargo check
cargo test
cargo clippy -- -D warnings

# 3. Format code
cargo fmt

# 4. Run full CI locally
bash scripts/ci/local.sh

# 5. Commit and push
git commit -m "feat: add awesome feature"
git push origin feature/my-awesome-feature

# 6. Create Pull Request
```

### 3. Quality Checks

```bash
# Workspace clippy (all warnings as errors)
cargo clippy --workspace --all-targets -- -D warnings

# Strict lib checks (pedantic + nursery)
cargo clippy -p sb-core --lib --features metrics -- \
  -D warnings \
  -W clippy::pedantic \
  -W clippy::nursery \
  -D clippy::unwrap_used \
  -D clippy::expect_used \
  -D clippy::panic

# Run all tests
cargo test --workspace --all-features

# Run benchmarks
cargo bench -p sb-core

# Coverage report
scripts/test/cov.sh
open target/coverage/index.html
```

---

## Architecture Overview

### Crate Structure

```
crates/
├── sb-core/           # Core abstractions and routing
├── sb-tls/            # TLS infrastructure (REALITY, ECH)
├── sb-transport/      # Transport layers (WS, H2, gRPC, QUIC)
├── sb-adapters/       # Protocol implementations
├── sb-config/         # Configuration parsing
├── sb-proto/          # Protocol codecs
├── sb-platform/       # Platform-specific (process matching, TUN)
├── sb-metrics/        # Prometheus metrics
├── sb-security/       # Security utilities
├── sb-api/            # External APIs (gRPC, HTTP)
├── sb-subscribe/      # Subscription management
└── sb-runtime/        # Async runtime utilities
```

### Key Design Principles

1. **Small, Testable Components**: Each module has single responsibility
2. **Trait-Based Abstractions**: Pluggable implementations
3. **Zero-Cost Abstractions**: Feature flags for optional functionality
4. **Never Break Userspace**: Backward compatibility is paramount
5. **Async-First**: Built on tokio with async_trait

See [Project Structure Navigation](../../PROJECT_STRUCTURE_NAVIGATION.md) and [Transport Strategy](../TRANSPORT_STRATEGY.md).

---

## Coding Standards

### Rust Conventions

```rust
// ✅ Good: Explicit error handling
fn connect(&self) -> Result<Stream, Error> {
    let stream = TcpStream::connect(&self.addr)
        .await
        .map_err(|e| Error::Io(e))?;
    Ok(stream)
}

// ❌ Bad: unwrap() in library code
fn connect(&self) -> Stream {
    TcpStream::connect(&self.addr).await.unwrap()  // Never do this!
}
```

**Key rules**:

- No `unwrap()`, `expect()`, or `panic!()` in library code (binaries OK)
- Document all public APIs with rustdoc
- Use `#[must_use]` for important return values
- Prefer `thiserror` for error types
- Use `tracing` for logging, not `println!()`

Code style guidance is currently captured in lint rules and inline examples; a dedicated style guide is planned.

### Testing Standards

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_router_direct_match() {
        let router = Router::new(config);
        let result = router.route("google.com", 443);
        assert_eq!(result.outbound, "proxy");
    }

    #[tokio::test]
    async fn test_outbound_connect() {
        let outbound = DirectOutbound::new();
        let stream = outbound.connect("1.1.1.1:443").await;
        assert!(stream.is_ok());
    }
}
```

**Test categories**:

- **Unit tests**: In `#[cfg(test)]` modules
- **Integration tests**: In `tests/` directory
- **E2E tests**: Full protocol stack tests
- **Benchmarks**: In `benches/` directory

See [Testing Guide](contributing/testing-guide.md).

---

## Build System

### Feature Flags

Enable/disable functionality at compile time:

```toml
# Build with specific features
cargo build -p app --features "acceptance,metrics,router"

# Build with all features
cargo build -p app --all-features

# Build minimal binary
cargo build -p app --no-default-features --features "router"
```

**Common feature categories**:

- **Inbounds**: `in_socks`, `in_http`, `in_tun`, `in_vmess`, etc.
- **Outbounds**: `out_direct`, `out_shadowsocks`, `out_vmess`, etc.
- **Transports**: `transport_ws`, `transport_h2`, `transport_quic`
- **TLS**: `tls_reality`, `tls_ech`
- **Observability**: `metrics`, `tracing`

See [Feature Flags](build-system/feature-flags.md).

### Cross Compilation

Build for different platforms:

```bash
# Linux x86_64
cargo build --target x86_64-unknown-linux-gnu --release

# Linux aarch64
cargo build --target aarch64-unknown-linux-gnu --release

# macOS Apple Silicon
cargo build --target aarch64-apple-darwin --release

# Windows
cargo build --target x86_64-pc-windows-msvc --release

# MUSL (static linking)
cargo build --target x86_64-unknown-linux-musl --release
```

See [Cross Compilation](build-system/cross-compilation.md).

---

## Quality Gates

### Pre-commit Checks

Run before every commit:

```bash
# Format code
cargo fmt --all

# Check compilation
cargo check --workspace

# Run clippy
cargo clippy --workspace -- -D warnings

# Run tests
cargo test --workspace
```

### CI Pipeline

GitHub Actions CI runs:

1. **Lint**: `cargo fmt --check`, `cargo clippy`
2. **Test**: Unit + integration tests on Linux/macOS/Windows
3. **Build**: Release builds for all targets
4. **Bench**: Performance regression detection
5. **Coverage**: Code coverage reporting
6. **Security**: `cargo audit`, `cargo deny`

See [CI Matrix](build-system/ci-matrix.md).

### Performance Baseline

Prevent performance regressions:

```bash
# Record baseline
scripts/test/bench/guard.sh record

# Check for regressions (CI)
scripts/test/bench/guard.sh check

# Adjust tolerance
BENCH_GUARD_TOL=0.05 scripts/test/bench/guard.sh check
```

Exit codes:

- `0`: No regression
- `2`: Setup/parsing failure
- `3`: Performance regression detected

---

## Protocol Implementation

### Adding a New Protocol

1. **Create adapter** in `crates/sb-adapters/src/{inbound,outbound}/`
2. **Implement traits**: `InboundAdapter` or `OutboundAdapter`
3. **Add feature flag** in `Cargo.toml`
4. **Write tests**: Unit, integration, E2E
5. **Update documentation**: User guide + examples
6. **Add CI tests**: Enable in CI matrix

```rust
// crates/sb-adapters/src/outbound/my_protocol.rs

use async_trait::async_trait;
use sb_core::{OutboundAdapter, Address, Stream};

pub struct MyProtocolOutbound {
    server: String,
    port: u16,
}

#[async_trait]
impl OutboundAdapter for MyProtocolOutbound {
    async fn connect(&self, addr: &Address) -> Result<Stream> {
        // 1. Connect to server
        let tcp = TcpStream::connect((&self.server, self.port)).await?;

        // 2. Perform protocol handshake
        let stream = my_protocol_handshake(tcp, addr).await?;

        // 3. Return established stream
        Ok(Box::pin(stream))
    }
}
```

See [Protocol Implementation Guide](protocols/implementation-guide.md).

---

## Documentation

### Writing Docs

All documentation is in `docs/` using Markdown:

```bash
# Add new doc
vim docs/01-user-guide/protocols/my-protocol.md

# Update index
vim docs/01-user-guide/README.md

# Check links
markdown-link-check docs/**/*.md

# Preview locally (if using mdBook)
mdbook serve
```

**Doc standards**:

- Use code examples for every feature
- Include troubleshooting section
- Add "Related Documentation" links
- Keep examples up-to-date

See [Documentation Guide](contributing/documentation.md).

### API Documentation

Generate rustdoc:

```bash
# Generate docs
cargo doc --workspace --all-features --no-deps

# Open in browser
cargo doc --open

# Check for missing docs
cargo doc --workspace -- -D missing_docs
```

---

## Release Process

1. **Update version** in `Cargo.toml` files
2. **Update CHANGELOG.md** with release notes
3. **Run full test suite**:
   ```bash
   cargo test --workspace --all-features
   bash scripts/ci/local.sh
   ```
4. **Create git tag**: `git tag v0.3.0`
5. **Push tag**: `git push origin v0.3.0`
6. **CI builds release binaries** automatically
7. **Create GitHub Release** with changelog

---

## Troubleshooting Development Issues

### Compilation Errors

**Issue**: `error: cannot find function unwrap in this scope`
**Solution**: Don't use `unwrap()` in library code - use `?` operator

**Issue**: `error: feature 'metrics' not enabled`
**Solution**: Build with `--features metrics` or `--all-features`

### Test Failures

**Issue**: E2E test timeout
**Solution**: Increase test timeout or use `serve_with_ready()` for proper synchronization

**Issue**: Port already in use
**Solution**: Use `find_available_port()` or run tests serially with `--test-threads=1`

### Performance Issues

**Issue**: Benchmark shows regression
**Solution**: Profile with `perf` or `cargo flamegraph`, identify hot paths

---

## Getting Help

- **Architecture Questions**: Read [Architecture docs](architecture/overview.md)
- **Code Review**: Submit PR for feedback
- **Discussions**: [GitHub Discussions](https://github.com/your-repo/discussions)
- **Chat**: [Discord/Matrix](https://your-chat-link) (if available)

---

## Related Documentation

- **[Architecture Overview](architecture/overview.md)** - System design
- **[Contributing Guide](contributing/getting-started.md)** - Contribution workflow
- **[Testing Guide](contributing/testing-guide.md)** - Test strategies
- **[User Guide](../01-user-guide/)** - End-user documentation
