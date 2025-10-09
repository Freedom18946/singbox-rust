# REALITY TLS Transport Integration

This document describes the REALITY TLS integration in the `sb-transport` crate.

## Overview

REALITY is an anti-censorship protocol that bypasses SNI whitelisting and DPI (Deep Packet Inspection) by:
- Stealing TLS certificates from real target websites
- Using SNI forgery to appear as legitimate traffic
- Authenticating with X25519 key exchange
- Falling back to real target on authentication failure

## Architecture

The REALITY integration follows the existing transport layer pattern:

```
┌─────────────────────────────────────────────────────────┐
│                    Application Layer                     │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│              RealityDialer<TcpDialer>                    │
│  (sb-transport: Dialer trait implementation)             │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│                  RealityConnector                        │
│     (sb-tls: TlsConnector trait implementation)          │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│                    TCP Connection                        │
└─────────────────────────────────────────────────────────┘
```

## Components

### RealityDialer

The `RealityDialer` is a wrapper around any `Dialer` implementation that adds REALITY TLS support.

**Location**: `crates/sb-transport/src/tls.rs`

**Key Features**:
- Wraps any underlying dialer (typically `TcpDialer`)
- Delegates to `RealityConnector` from `sb-tls` for handshake
- Converts between `sb-tls::TlsIoStream` and `sb-transport::IoStream`
- Supports environment variable configuration

### RealityStreamAdapter

An internal adapter that converts between trait objects:
- Input: `Box<dyn sb_tls::TlsStream>`
- Output: `Box<dyn sb_transport::AsyncReadWrite>`

Both traits have identical bounds (`AsyncRead + AsyncWrite + Unpin + Send`), so this is purely a type conversion wrapper.

## Usage

### Basic Usage

```rust
use sb_transport::{RealityDialer, TcpDialer, Dialer};
use sb_tls::RealityClientConfig;

// Create configuration
let config = RealityClientConfig {
    target: "www.apple.com".to_string(),
    server_name: "www.apple.com".to_string(),
    public_key: "0123456789abcdef...".to_string(),
    short_id: Some("01ab".to_string()),
    fingerprint: "chrome".to_string(),
    alpn: vec!["h2".to_string()],
};

// Create dialer
let dialer = RealityDialer::new(TcpDialer, config)?;

// Connect
let stream = dialer.connect("proxy.example.com", 443).await?;
```

### Environment Variable Configuration

```bash
export SB_REALITY_TARGET="www.apple.com"
export SB_REALITY_PUBLIC_KEY="0123456789abcdef..."
export SB_REALITY_SHORT_ID="01ab"
export SB_REALITY_FINGERPRINT="chrome"
```

```rust
use sb_transport::{RealityDialer, TcpDialer};

let dialer = RealityDialer::from_env(TcpDialer)?;
let stream = dialer.connect("proxy.example.com", 443).await?;
```

## Configuration

### Required Fields

- `target`: Target domain for SNI forgery (e.g., "www.apple.com")
- `server_name`: Server name for TLS handshake (usually same as target)
- `public_key`: Server's X25519 public key (64-character hex string)

### Optional Fields

- `short_id`: Client identifier (hex string)
- `fingerprint`: Browser fingerprint to emulate ("chrome", "firefox", "safari")
- `alpn`: ALPN protocols (e.g., ["h2", "http/1.1"])

## Feature Flags

The REALITY integration requires the `transport_reality` feature:

```toml
[dependencies]
sb-transport = { path = "../sb-transport", features = ["transport_reality"] }
```

This feature automatically enables:
- `transport_tls`: Base TLS support
- `sb-tls`: TLS abstraction layer with REALITY implementation

## Testing

Run REALITY integration tests:

```bash
cargo test -p sb-transport --test reality_integration --features transport_reality
```

Run the example:

```bash
cargo run --example reality_dialer --features transport_reality -p sb-transport
```

## Implementation Details

### Connection Flow

1. **TCP Connection**: Underlying dialer establishes TCP connection
2. **REALITY Handshake**:
   - Client generates ephemeral X25519 keypair
   - Derives shared secret with server's public key
   - Embeds authentication data in TLS ClientHello
   - Uses forged SNI (target domain)
3. **Server Verification**:
   - Server validates authentication data
   - Success: Issues temporary certificate, proxies traffic
   - Failure: Proxies to real target (fallback mode)
4. **Stream Wrapping**: TLS stream is wrapped in adapter for type conversion

### Type Conversion

The `RealityStreamAdapter` handles conversion between:
- `sb_tls::TlsIoStream` = `Box<dyn TlsStream>`
- `sb_transport::IoStream` = `Box<dyn AsyncReadWrite>`

Both traits require `AsyncRead + AsyncWrite + Unpin + Send`, so the adapter simply forwards all I/O operations.

### Error Handling

Errors are converted to `DialError::Tls` with descriptive messages:
- Configuration validation errors
- Handshake failures
- Authentication failures

## Security Considerations

### Authentication

REALITY uses X25519 key exchange for authentication:
- Client and server derive shared secret
- Authentication hash prevents unauthorized access
- Short ID allows multiple client configurations

### Anti-Detection

REALITY is designed to be undetectable:
- Uses real target domain certificates
- Falls back to real target on auth failure
- Emulates browser TLS fingerprints
- No distinguishable traffic patterns

### Configuration Security

- Public keys must be 64-character hex strings (32 bytes)
- Short IDs should be unique per client
- Target domains should be popular, legitimate sites
- Fingerprints should match common browsers

## Limitations

1. **Server Required**: REALITY requires a compatible server implementation
2. **Target Availability**: Target domain must be accessible and serve TLS
3. **Certificate Validity**: Target certificates must be valid
4. **No Inbound Support**: Currently only client (outbound) is implemented

## Future Enhancements

- [ ] REALITY server (inbound) support in transport layer
- [ ] Connection pooling for REALITY connections
- [ ] Metrics and observability
- [ ] Performance optimizations
- [ ] Additional browser fingerprints

## References

- REALITY Protocol: [sing-box documentation](https://sing-box.sagernet.org/)
- X25519 Key Exchange: [RFC 7748](https://tools.ietf.org/html/rfc7748)
- TLS 1.3: [RFC 8446](https://tools.ietf.org/html/rfc8446)

## Related Files

- `crates/sb-transport/src/tls.rs`: REALITY dialer implementation
- `crates/sb-tls/src/reality/`: REALITY protocol implementation
- `crates/sb-transport/tests/reality_integration.rs`: Integration tests
- `crates/sb-transport/examples/reality_dialer.rs`: Usage example
