# Multiplex Usage Guide

This guide explains how to use the multiplexing feature in singbox-rust to improve connection efficiency and performance.

## Overview

Multiplexing (mux) allows multiple logical streams to share a single underlying TCP connection, significantly reducing:
- Connection establishment overhead
- Network resource usage
- Server-side connection limits impact

singbox-rust implements multiplexing using the **yamux** protocol, which is compatible with the Go version of sing-box.

## Key Benefits

1. **Reduced Latency**: No need to establish new TCP connections for each request
2. **Connection Pooling**: Reuse existing connections efficiently
3. **Server Resource Savings**: Fewer connections to manage on the server side
4. **NAT Traversal**: Better behavior with restrictive NAT/firewalls
5. **Concurrent Streams**: Handle multiple requests simultaneously over one connection

## Architecture

### Without Multiplex
```
Client Request 1 → TCP Conn 1 → Server
Client Request 2 → TCP Conn 2 → Server
Client Request 3 → TCP Conn 3 → Server
```

### With Multiplex
```
Client Request 1 ┐
Client Request 2 ├→ TCP Conn → yamux → Server
Client Request 3 ┘
```

### Layer Stack
```
┌──────────────────────────────────────┐
│  Application Protocol                │
│  (Shadowsocks, Trojan, VLESS, VMess) │
└──────────────────────────────────────┘
              ↓
┌──────────────────────────────────────┐
│      Multiplex Layer (yamux)         │
│  - Stream multiplexing               │
│  - Flow control                      │
│  - Connection pooling                │
└──────────────────────────────────────┘
              ↓
┌──────────────────────────────────────┐
│      Transport Layer (TCP/TLS)       │
└──────────────────────────────────────┘
```

## Configuration

### MultiplexConfig Structure

```rust
pub struct MultiplexConfig {
    /// Enable multiplexing
    pub enabled: bool,

    /// Protocol (currently only "yamux" supported)
    pub protocol: String,

    /// Maximum number of multiplexed connections to maintain
    pub max_connections: usize,

    /// Maximum number of streams per connection
    pub max_streams: usize,

    /// Enable padding for traffic obfuscation
    pub padding: bool,

    /// Brutal congestion control settings (optional)
    pub brutal: Option<BrutalConfig>,
}
```

### Default Configuration

```rust
MultiplexConfig {
    enabled: true,
    protocol: "yamux".to_string(),
    max_connections: 4,
    max_streams: 16,
    padding: false,
    brutal: None,
}
```

## Protocol-Specific Usage

### 1. Shadowsocks + Multiplex

**Client Configuration:**
```rust
use sb_adapters::outbound::shadowsocks::{ShadowsocksConfig, ShadowsocksConnector};
use sb_transport::multiplex::MultiplexConfig;

let config = ShadowsocksConfig {
    server: "127.0.0.1:8388".to_string(),
    method: "aes-256-gcm".to_string(),
    password: "your-password".to_string(),
    connect_timeout_sec: Some(30),

    multiplex: Some(MultiplexConfig {
        enabled: true,
        protocol: "yamux".to_string(),
        max_connections: 4,
        max_streams: 16,
        padding: false,
        brutal: None,
    }),
};

let connector = ShadowsocksConnector::new(config)?;
```

**Server Configuration:**
```rust
use sb_adapters::inbound::shadowsocks::ShadowsocksInboundConfig;
use sb_transport::multiplex::MultiplexServerConfig;

let config = ShadowsocksInboundConfig {
    listen: "0.0.0.0:8388".parse()?,
    method: "aes-256-gcm".to_string(),
    password: "your-password".to_string(),
    router: Arc::new(router_handle),

    multiplex: Some(MultiplexServerConfig {
        enabled: true,
        protocol: "yamux".to_string(),
        max_connections: 4,
        max_streams: 16,
        padding: false,
        brutal: None,
    }),
};
```

**Implementation** (crates/sb-adapters/src/outbound/shadowsocks.rs:97):
```rust
// Create multiplex dialer if configured
let multiplex_dialer = if let Some(mux_config) = config.multiplex.clone() {
    let tcp_dialer = Box::new(sb_transport::TcpDialer) as Box<dyn sb_transport::Dialer>;
    Some(std::sync::Arc::new(
        sb_transport::multiplex::MultiplexDialer::new(mux_config, tcp_dialer)
    ))
} else {
    None
};
```

### 2. Trojan + Multiplex

**Note**: Trojan multiplex support is configured but the full implementation is pending architectural changes. The protocol flow needs to be: TCP → TLS → Multiplex → Trojan.

**Configuration:**
```rust
use sb_adapters::outbound::trojan::{TrojanConfig, TrojanConnector};

let config = TrojanConfig {
    server: "example.com:443".to_string(),
    password: "your-password".to_string(),
    sni: Some("example.com".to_string()),
    skip_cert_verify: false,

    multiplex: Some(MultiplexConfig {
        enabled: true,
        protocol: "yamux".to_string(),
        max_connections: 4,
        max_streams: 16,
        padding: false,
        brutal: None,
    }),

    #[cfg(feature = "tls_reality")]
    reality: None,
};

let connector = TrojanConnector::new(config);
```

**Current Status** (crates/sb-adapters/src/outbound/trojan.rs:282):
```rust
if config.multiplex.is_some() {
    tracing::warn!(
        "Multiplex configuration present but not yet fully implemented for Trojan outbound"
    );
}
```

### 3. VLESS + Multiplex

**Client Configuration:**
```rust
use sb_adapters::outbound::vless::{VlessConfig, VlessConnector, FlowControl, Encryption};

let config = VlessConfig {
    server_addr: "127.0.0.1:443".parse()?,
    uuid: Uuid::new_v4(),
    flow: FlowControl::None,
    encryption: Encryption::None,
    timeout: Some(30),

    multiplex: Some(MultiplexConfig {
        enabled: true,
        protocol: "yamux".to_string(),
        max_connections: 4,
        max_streams: 16,
        padding: false,
        brutal: None,
    }),

    #[cfg(feature = "tls_reality")]
    reality: None,

    ..Default::default()
};

let connector = VlessConnector::new(config);
```

**Implementation** (crates/sb-adapters/src/outbound/vless.rs:206):
```rust
let boxed_stream: BoxedStream = if let Some(ref mux_dialer) = self.multiplex_dialer {
    tracing::debug!("Using multiplex dialer for VLESS connection");

    let stream = tokio::time::timeout(
        timeout,
        mux_dialer.connect(
            &self.config.server_addr.ip().to_string(),
            self.config.server_addr.port()
        ),
    )
    .await?
    .map_err(|e| AdapterError::Other(format!("Multiplex dial failed: {}", e)))?;

    stream
} else {
    // Direct TCP connection
    let tcp_stream = tokio::time::timeout(
        timeout,
        tokio::net::TcpStream::connect(self.config.server_addr),
    ).await??;

    Box::new(tcp_stream)
};
```

### 4. VMess + Multiplex

**Client Configuration:**
```rust
use sb_adapters::outbound::vmess::{VmessConfig, VmessConnector, VmessAuth, Security};

let config = VmessConfig {
    server_addr: "127.0.0.1:443".parse()?,
    auth: VmessAuth {
        uuid: Uuid::new_v4(),
        alter_id: 0,
        security: Security::Auto,
        additional_data: None,
    },

    multiplex: Some(MultiplexConfig {
        enabled: true,
        protocol: "yamux".to_string(),
        max_connections: 4,
        max_streams: 16,
        padding: false,
        brutal: None,
    }),

    tls: None,
    ..Default::default()
};

let connector = VmessConnector::new(config);
```

**Implementation** (crates/sb-adapters/src/outbound/vmess.rs:157):
```rust
let multiplex_dialer = if let Some(mux_config) = config.multiplex.clone() {
    let tcp_dialer = Box::new(sb_transport::TcpDialer) as Box<dyn sb_transport::Dialer>;
    Some(std::sync::Arc::new(
        sb_transport::multiplex::MultiplexDialer::new(mux_config, tcp_dialer)
    ))
} else {
    None
};
```

## Advanced Configuration

### Connection Limits

```rust
MultiplexConfig {
    enabled: true,
    protocol: "yamux".to_string(),

    // Maintain up to 8 multiplexed connections
    max_connections: 8,

    // Allow up to 32 streams per connection
    max_streams: 32,

    padding: false,
    brutal: None,
}
```

**Tradeoffs:**
- **Higher max_connections**: More resilience to connection failures, but more overhead
- **Higher max_streams**: Better concurrency, but more per-connection overhead
- **Recommended**: 4-8 connections, 8-32 streams for most use cases

### Padding for Obfuscation

```rust
MultiplexConfig {
    enabled: true,
    protocol: "yamux".to_string(),
    max_connections: 4,
    max_streams: 16,

    // Enable traffic padding
    padding: true,

    brutal: None,
}
```

**Purpose**: Padding adds random data to obscure traffic patterns from network analysis.

**Tradeoffs:**
- **Pros**: Better resistance to traffic analysis
- **Cons**: Increased bandwidth usage (~5-15%)

### Brutal Congestion Control

```rust
pub struct BrutalConfig {
    /// Upload bandwidth in Mbps
    pub up_mbps: u32,
    /// Download bandwidth in Mbps
    pub down_mbps: u32,
}

MultiplexConfig {
    enabled: true,
    protocol: "yamux".to_string(),
    max_connections: 4,
    max_streams: 16,
    padding: false,

    brutal: Some(BrutalConfig {
        up_mbps: 100,    // 100 Mbps upload
        down_mbps: 100,  // 100 Mbps download
    }),
}
```

**Purpose**: Aggressive congestion control for high-throughput scenarios.

**Use Cases:**
- High-bandwidth applications
- Low-latency requirements
- Controlled network environments

## Multiplex + TLS

Combining multiplex with TLS provides both security and efficiency.

### Layer Stack
```
Application Protocol (VMess, Shadowsocks, etc.)
              ↓
     Multiplex (yamux)
              ↓
         TLS 1.3
              ↓
            TCP
```

### Configuration Example

```rust
let config = VmessConfig {
    server_addr: "example.com:443".parse()?,
    auth: VmessAuth { ... },

    // TLS configuration
    tls: Some(TlsConfig {
        enabled: true,
        server_name: Some("example.com".to_string()),
        insecure: false,
        ..Default::default()
    }),

    // Multiplex configuration
    multiplex: Some(MultiplexConfig {
        enabled: true,
        protocol: "yamux".to_string(),
        max_connections: 4,
        max_streams: 16,
        padding: false,
        brutal: None,
    }),

    ..Default::default()
};
```

**Benefits:**
- Encrypted multiplexed streams
- Single TLS handshake for multiple streams
- Reduced TLS overhead

## Performance Optimization

### Tuning Parameters

**For Low-Latency Applications:**
```rust
MultiplexConfig {
    enabled: true,
    protocol: "yamux".to_string(),
    max_connections: 2,   // Fewer connections
    max_streams: 8,       // Moderate streams
    padding: false,       // No padding overhead
    brutal: None,
}
```

**For High-Throughput Applications:**
```rust
MultiplexConfig {
    enabled: true,
    protocol: "yamux".to_string(),
    max_connections: 8,   // More connections for parallelism
    max_streams: 32,      // Many concurrent streams
    padding: false,
    brutal: Some(BrutalConfig {
        up_mbps: 1000,
        down_mbps: 1000,
    }),
}
```

**For Censorship Resistance:**
```rust
MultiplexConfig {
    enabled: true,
    protocol: "yamux".to_string(),
    max_connections: 4,
    max_streams: 16,
    padding: true,        // Enable padding
    brutal: None,
}
```

### Connection Pooling Strategy

The `MultiplexDialer` automatically manages connection pools:

1. **Connection Reuse**: Existing connections are reused when available
2. **Load Balancing**: Streams are distributed across connections
3. **Connection Limits**: New connections created up to `max_connections`
4. **Stream Limits**: Streams rejected if `max_streams` exceeded

## Troubleshooting

### Common Issues

**1. Multiplex Connection Failed**
```
Error: Multiplex dial failed: connection refused
```
**Solution**: Ensure server has multiplex enabled and accessible.

**2. Stream Limit Exceeded**
```
Error: Maximum streams exceeded
```
**Solution**: Increase `max_streams` or reduce concurrent request rate.

**3. Connection Pool Exhausted**
```
Error: All multiplex connections busy
```
**Solution**: Increase `max_connections` to allow more pooled connections.

**4. Trojan Multiplex Not Working**
```
Warning: Multiplex configuration present but not yet fully implemented for Trojan outbound
```
**Status**: Architectural work in progress. See trojan.rs:282 for details.

### Debug Logging

Enable multiplex debug logging:
```bash
RUST_LOG=sb_transport::multiplex=debug,sb_adapters=debug cargo run
```

Example output:
```
DEBUG sb_transport::multiplex: Using multiplex dialer for VLESS connection
DEBUG sb_transport::multiplex: Reusing existing connection [1/4]
DEBUG sb_transport::multiplex: Opening new stream [5/16]
```

## Testing

### E2E Tests

See test files:
- `app/tests/multiplex_shadowsocks_e2e.rs` - Shadowsocks multiplex tests
- `app/tests/multiplex_trojan_e2e.rs` - Trojan multiplex tests
- `app/tests/multiplex_vless_e2e.rs` - VLESS multiplex tests
- `app/tests/multiplex_vmess_e2e.rs` - VMess multiplex tests

### Manual Testing

**Test Concurrent Streams:**
```bash
# Terminal 1: Start server
cargo run --bin singbox-rust -- server \
    --protocol shadowsocks \
    --method aes-256-gcm \
    --password test-password \
    --multiplex-enabled

# Terminal 2-5: Make concurrent requests
for i in {1..10}; do
    curl --proxy socks5h://localhost:1080 https://example.com &
done
```

### Performance Benchmark

```rust
use std::time::Instant;

async fn benchmark_multiplex() {
    let connector = ShadowsocksConnector::new(config)?;

    let start = Instant::now();

    // Create 100 concurrent streams
    let handles: Vec<_> = (0..100)
        .map(|_| {
            let connector = connector.clone();
            tokio::spawn(async move {
                connector.dial(target, DialOpts::default()).await
            })
        })
        .collect();

    for handle in handles {
        handle.await??;
    }

    let elapsed = start.elapsed();
    println!("100 streams in {:?}", elapsed);
}
```

## Comparison with Go sing-box

### Compatibility

singbox-rust's multiplex implementation is **wire-compatible** with Go sing-box:
- Same yamux protocol
- Compatible configuration format
- Interoperable client/server

### Differences

| Feature | Go sing-box | singbox-rust | Status |
|---------|-------------|--------------|--------|
| yamux protocol | ✅ | ✅ | Full parity |
| Connection pooling | ✅ | ✅ | Full parity |
| Padding support | ✅ | ✅ | Full parity |
| Brutal CC | ✅ | ⚠️ | Configured, testing pending |
| Trojan multiplex | ✅ | ⚠️ | Partial (arch work needed) |

## Best Practices

1. **Always enable multiplex for production** - improves efficiency
2. **Tune max_streams based on workload** - 8-32 for most cases
3. **Use padding in censored regions** - adds obfuscation
4. **Combine with TLS** - provides both security and efficiency
5. **Monitor connection pool usage** - adjust max_connections as needed
6. **Test under load** - verify performance characteristics

## Future Enhancements

- **QUIC multiplexing**: UDP-based multiplex for better performance
- **H2 multiplexing**: HTTP/2 as multiplex protocol
- **Dynamic tuning**: Automatic parameter adjustment based on load
- **Connection migration**: Seamless connection switching

## References

- **yamux Protocol**: [hashicorp/yamux](https://github.com/hashicorp/yamux)
- **sing-box Multiplex**: [SagerNet/sing-box](https://github.com/SagerNet/sing-box)
- **Implementation**: `crates/sb-transport/src/multiplex.rs`

## Feature Flags

- `multiplex` - Enable multiplex support (default enabled)
- `brutal` - Enable Brutal congestion control (optional)
