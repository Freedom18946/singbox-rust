# Code Examples / 代码示例

Rust code examples demonstrating how to use and integrate singbox-rust components.

展示如何使用和集成 singbox-rust 组件的 Rust 代码示例。

---

## 📁 Directory Structure

```
code-examples/
├── network/        # TCP/UDP networking examples
├── dns/            # DNS resolution examples
├── proxy/          # Proxy protocol implementations
└── testing/        # Testing utilities and scenarios
```

---

## 🌐 Network Examples

**Directory**: `network/`

### tcp_connect.rs

Demonstrates direct TCP connection using singbox-rust outbound.

```bash
# Connect to example.com:80
cargo run --example tcp_connect -- example.com 80

# Connect to custom host/port
cargo run --example tcp_connect -- google.com 443
```

**Key Concepts**:

- `DirectOutbound` usage
- `TcpConnectRequest` configuration
- Connection timeout handling
- System dialer integration

---

### udp_echo.rs

UDP echo server example for testing UDP relay functionality.

```bash
# Run UDP echo server
cargo run --example udp_echo
```

**Use Cases**:

- Testing UDP relay
- SOCKS5 UDP associate testing
- Network debugging

---

### udp_blast.rs

UDP stress testing tool for performance benchmarking.

```bash
# Stress test UDP connection
cargo run --example udp_blast
```

**Features**:

- High-frequency UDP packet sending
- Performance metrics
- Throughput testing

---

## 🔍 DNS Examples

**Directory**: `dns/`

### dns_lookup.rs

Basic DNS resolution example using singbox-rust DNS subsystem.

```bash
# Run DNS lookup example
cargo run --example dns_lookup
```

**Key Concepts**:

- DNS resolver configuration
- Async DNS queries
- DoH/DoT/DoQ support
- DNS caching

**Environment Variables**:

```bash
# Enable DoH
SB_DNS_ENABLE=1 SB_DNS_MODE=doh cargo run --example dns_lookup

# Enable DoT
SB_DNS_ENABLE=1 SB_DNS_MODE=dot cargo run --example dns_lookup
```

---

## 🔌 Proxy Examples

**Directory**: `proxy/`

### http_inbound_demo.rs

Complete HTTP inbound server implementation.

```bash
# Run HTTP proxy server
RUST_LOG=info cargo run --example http_inbound_demo
```

**Features**:

- HTTP CONNECT method handling
- Connection lifecycle management
- Error handling patterns
- Logging integration

**Test**:

```bash
curl -x http://127.0.0.1:8080 https://example.com
```

---

### socks5_udp_probe.rs

SOCKS5 UDP relay testing utility.

```bash
# Test SOCKS5 UDP associate
SB_SOCKS_UDP_ENABLE=1 cargo run -p sb-adapters --example socks5_udp_probe -- \
  127.0.0.1:11080 127.0.0.1:19090 example.com
```

**Arguments**:

1. SOCKS5 server address
2. Target UDP address
3. Test domain

**Use Cases**:

- SOCKS5 UDP relay verification
- NAT behavior testing
- UDP performance testing

---

## 🧪 Testing Scenarios

**Directory**: `testing/scenarios/`

### loopback.smoke.json

Basic loopback smoke test configuration.

**Purpose**: Verify basic functionality in CI/CD pipelines.

---

### vars.ci.json

Environment variables for CI environments.

**Contents**: CI-specific settings and timeouts.

---

### vars.dev.json

Development environment variable presets.

**Contents**: Development-friendly settings with verbose logging.

---

## 🔧 Building & Running

### Run Individual Examples

```bash
# Network examples
cargo run --example tcp_connect -- HOST PORT
cargo run --example udp_echo
cargo run --example udp_blast

# DNS example
cargo run --example dns_lookup

# Proxy examples
cargo run --example http_inbound_demo
cargo run -p sb-adapters --example socks5_udp_probe -- ARGS
```

### With Logging

```bash
RUST_LOG=debug cargo run --example EXAMPLE_NAME
RUST_LOG=sb_core=trace,app=debug cargo run --example EXAMPLE_NAME
```

### With Feature Flags

Some examples require specific features:

```bash
# DNS with DoQ support
cargo run --features 'sb-core/dns_doq' --example dns_lookup

# Full adapter features
cargo run -p sb-adapters --all-features --example socks5_udp_probe
```

---

## 📚 Learning Path

### Beginner

1. **Start with TCP**: `tcp_connect.rs` - Learn basic outbound usage
2. **Explore UDP**: `udp_echo.rs` - Understand UDP handling
3. **DNS Basics**: `dns_lookup.rs` - DNS resolution patterns

### Intermediate

4. **Proxy Servers**: `http_inbound_demo.rs` - Inbound implementation
5. **SOCKS5 UDP**: `socks5_udp_probe.rs` - UDP relay testing

### Advanced

6. **Integration**: Combine examples into custom applications
7. **Testing**: Use scenarios for automated testing
8. **Performance**: Benchmark with `udp_blast.rs`

---

## 🎓 Key Concepts Demonstrated

### Async/Await Patterns

All examples use Tokio async runtime:

```rust
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Async code here
}
```

### Error Handling

Examples demonstrate proper error handling:

```rust
use anyhow::Result;

async fn example() -> Result<()> {
    // Error propagation with ?
    let result = operation().await?;
    Ok(())
}
```

### Tracing/Logging

Integration with `tracing` crate:

```rust
use tracing::{info, debug, error};

info!("Starting operation");
debug!(target = %addr, "Connecting");
```

### Configuration

Examples show various configuration patterns:

- Environment variables
- Command-line arguments
- Programmatic configuration

---

## 💡 Tips

1. **Enable Logging**: Always use `RUST_LOG` during development
2. **Read the Code**: Examples are heavily commented
3. **Experiment**: Modify examples to learn different behaviors
4. **Error Messages**: Pay attention to error messages for debugging

---

## 🔗 Related Documentation

- [Architecture](../../docs/ARCHITECTURE.md)
- [Development Guide](../../docs/DEVELOPMENT.md)
- [API Documentation](../../docs/05-api-reference/)

---

## 🐛 Troubleshooting

### Example Won't Compile

1. Check if required feature flags are enabled
2. Verify correct package (`-p app` vs `-p sb-adapters`)
3. Update dependencies: `cargo update`

### Runtime Errors

1. Enable logging: `RUST_LOG=debug`
2. Check network connectivity
3. Verify port availability
4. Review environment variables

### Permission Errors

Some examples (especially UDP) may require:

- Firewall exceptions
- Port binding permissions
- Root/admin access (for raw sockets)

---

**Note**: These examples are for learning and testing. Production code should include additional error handling, validation, and security measures.
