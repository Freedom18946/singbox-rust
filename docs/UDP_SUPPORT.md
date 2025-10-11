# UDP Support Guide

This guide explains UDP relay support in singbox-rust, covering implementation, configuration, and usage for Shadowsocks, Trojan, and VLESS protocols.

## Overview

UDP relay allows proxy protocols (primarily designed for TCP) to also handle UDP traffic. This is essential for applications like:
- DNS queries
- VoIP (Voice over IP)
- Online gaming
- Live streaming
- QUIC-based protocols (HTTP/3)

singbox-rust implements UDP relay for three major protocols:
- **Shadowsocks** - Full UDP relay with AEAD encryption
- **Trojan** - UDP ASSOCIATE over TLS connection
- **VLESS** - Stateless UDP relay with UUID authentication

## Architecture

### TCP vs UDP Relay

**TCP Relay** (Standard):
```
Client → Proxy Server → Destination
   TCP        TCP         TCP
```

**UDP Relay**:
```
Client → Proxy Server → Destination
   UDP   TCP (control)   UDP
              UDP (data)
```

### Protocol Stack

```
┌──────────────────────────────────────┐
│       Application (DNS, Gaming)      │
└──────────────────────────────────────┘
              ↓
┌──────────────────────────────────────┐
│      UDP Relay Layer                 │
│  - Packet encoding/decoding          │
│  - Address encapsulation             │
│  - Encryption (for Shadowsocks)      │
└──────────────────────────────────────┘
              ↓
┌──────────────────────────────────────┐
│      Transport Layer (UDP/TCP)       │
└──────────────────────────────────────┘
```

## Protocol-Specific Implementation

### 1. Shadowsocks UDP Relay

Shadowsocks UDP uses AEAD encryption for all packets, providing security for UDP traffic.

#### Packet Format
```
┌─────────────┬──────────────────────────────────┐
│  Salt       │  Encrypted(ATYP + ADDR + PORT   │
│  (12 bytes) │           + PAYLOAD)             │
└─────────────┴──────────────────────────────────┘
```

#### Encryption Methods
- **aes-256-gcm** - AES-256 with Galois/Counter Mode
- **chacha20-poly1305** - ChaCha20 stream cipher with Poly1305 MAC

#### Configuration

```rust
use sb_adapters::outbound::shadowsocks::{ShadowsocksConfig, ShadowsocksConnector};
use sb_adapters::traits::Target;

let config = ShadowsocksConfig {
    server: "127.0.0.1:8388".to_string(),
    method: "aes-256-gcm".to_string(),
    password: "your-password".to_string(),
    connect_timeout_sec: Some(30),
    multiplex: None,
    tag: None,
};

let connector = ShadowsocksConnector::new(config)?;

// Create UDP relay
let target = Target::udp("8.8.8.8", 53);  // DNS server
let udp_socket = connector.udp_relay_dial(target.clone()).await?;

// Set target for subsequent operations
udp_socket.set_target(target).await;

// Send DNS query
let query = build_dns_query("example.com");
udp_socket.send_to(&query).await?;

// Receive response
let mut buffer = vec![0u8; 4096];
let len = udp_socket.recv_from(&mut buffer).await?;
let response = &buffer[..len];
```

#### Implementation (crates/sb-adapters/src/outbound/shadowsocks.rs:155)

```rust
pub async fn udp_relay_dial(&self, target: Target) -> Result<Box<dyn OutboundDatagram>> {
    // Parse server address
    let server_addr: SocketAddr = self.config.server.parse()?;

    // Create local UDP socket
    let local_socket = UdpSocket::bind("0.0.0.0:0").await?;

    // Connect to server
    local_socket.connect(server_addr).await?;

    // Create UDP socket wrapper
    let udp_socket = ShadowsocksUdpSocket::new(
        Arc::new(local_socket),
        self.cipher_method.clone(),
        self.key.clone(),
        server_addr,
    )?;

    Ok(Box::new(udp_socket))
}
```

#### Packet Encoding (crates/sb-adapters/src/outbound/shadowsocks.rs:657)

```rust
fn encrypt_packet(&self, data: &[u8], target: &Target) -> Result<Vec<u8>> {
    // Generate random salt
    let salt_len = self.cipher_method.nonce_size();
    let mut salt = vec![0u8; salt_len];
    rand::thread_rng().fill_bytes(&mut salt);

    // Build payload: address + port + data
    let mut payload = self.encode_target_address(target)?;
    payload.extend_from_slice(data);

    // Encrypt payload with AEAD
    let ciphertext = match &self.cipher_method {
        CipherMethod::Aes256Gcm => {
            let cipher = Aes256Gcm::new(GenericArray::from_slice(&self.key));
            let nonce_array = Nonce::from_slice(&salt);
            cipher.encrypt(nonce_array, payload.as_ref())?
        }
        CipherMethod::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
            let nonce_array = ChaNonce::from_slice(&salt);
            cipher.encrypt(nonce_array, payload.as_ref())?
        }
    };

    // Combine: salt + ciphertext (includes tag)
    let mut packet = Vec::with_capacity(salt.len() + ciphertext.len());
    packet.extend_from_slice(&salt);
    packet.extend_from_slice(&ciphertext);

    Ok(packet)
}
```

### 2. Trojan UDP Relay

Trojan UDP relay uses a TCP control connection for the UDP ASSOCIATE command, while actual UDP data flows directly.

#### Protocol Flow

1. **Establish TCP/TLS connection** to Trojan server
2. **Send UDP ASSOCIATE command** (CMD=0x03)
3. **Create local UDP socket** for data transfer
4. **Encode/decode UDP packets** with Trojan format

#### Packet Format
```
┌──────┬──────┬───────────┬──────┬──────────┐
│ CMD  │ ATYP │ DST.ADDR  │ PORT │ PAYLOAD  │
│ 0x03 │  1B  │  Variable │  2B  │ Variable │
└──────┴──────┴───────────┴──────┴──────────┘
```

#### Configuration

```rust
use sb_adapters::outbound::trojan::{TrojanConfig, TrojanConnector};

let config = TrojanConfig {
    server: "example.com:443".to_string(),
    password: "your-trojan-password".to_string(),
    sni: Some("example.com".to_string()),
    skip_cert_verify: false,
    connect_timeout_sec: Some(30),
    #[cfg(feature = "tls_reality")]
    reality: None,
    multiplex: None,
    tag: None,
};

let connector = TrojanConnector::new(config);

// Create UDP relay
let target = Target::udp("8.8.8.8", 53);
let udp_socket = connector.udp_relay_dial(target.clone()).await?;

// Set target and use
udp_socket.set_target(target).await;
udp_socket.send_to(&dns_query).await?;
```

#### Implementation (crates/sb-adapters/src/outbound/trojan.rs:172)

```rust
pub async fn udp_relay_dial(&self, target: Target) -> Result<Box<dyn OutboundDatagram>> {
    let config = self._config.as_ref().unwrap();

    // Step 1: Establish TCP connection for UDP ASSOCIATE
    let tcp_stream = tokio::net::TcpStream::connect(&config.server).await?;

    // Step 2: Perform TLS handshake
    let mut tls_stream = self.perform_standard_tls_handshake(tcp_stream, config).await?;

    // Step 3: Send UDP ASSOCIATE command (CMD=0x03)
    let mut request = Vec::new();

    // Password hash (SHA224)
    let mut hasher = Sha224::new();
    hasher.update(config.password.as_bytes());
    let password_hash = hasher.finalize();
    request.extend_from_slice(&hex::encode(password_hash).as_bytes());
    request.extend_from_slice(b"\r\n");

    // Command: UDP ASSOCIATE (0x03)
    request.push(0x03);

    // Address encoding...
    request.extend_from_slice(&server_addr.to_be_bytes());
    request.extend_from_slice(b"\r\n");

    // Send request
    tls_stream.write_all(&request).await?;

    // Step 4: Create UDP socket
    let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;
    udp_socket.connect(server_addr).await?;

    Ok(Box::new(TrojanUdpSocket::new(
        Arc::new(udp_socket),
        config.password.clone(),
    )?))
}
```

#### Packet Encoding (crates/sb-adapters/src/outbound/trojan.rs:400)

```rust
fn encode_packet(&self, data: &[u8], target: &Target) -> Result<Vec<u8>> {
    let mut packet = Vec::new();

    // CMD: UDP (0x03)
    packet.push(0x03);

    // Address type and address
    if let Ok(ip) = target.host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(ipv4) => {
                packet.push(0x01); // IPv4
                packet.extend_from_slice(&ipv4.octets());
            }
            IpAddr::V6(ipv6) => {
                packet.push(0x04); // IPv6
                packet.extend_from_slice(&ipv6.octets());
            }
        }
    } else {
        // Domain name
        packet.push(0x03); // Domain
        packet.push(target.host.len() as u8);
        packet.extend_from_slice(target.host.as_bytes());
    }

    // Port
    packet.extend_from_slice(&target.port.to_be_bytes());

    // Payload
    packet.extend_from_slice(data);

    Ok(packet)
}
```

### 3. VLESS UDP Relay

VLESS provides stateless UDP relay with minimal overhead.

#### Packet Format
```
┌──────┬──────┬──────┬──────┬───────────┬──────┬──────────┐
│ VER  │ UUID │ CMD  │ ATYP │ DST.ADDR  │ PORT │ PAYLOAD  │
│ 0x00 │  16B │ 0x02 │  1B  │  Variable │  2B  │ Variable │
└──────┴──────┴──────┴──────┴───────────┴──────┴──────────┘
```

**Address Types (ATYP)**:
- `0x01` - IPv4 (4 bytes)
- `0x02` - Domain (length byte + domain)
- `0x03` - IPv6 (16 bytes)

#### Configuration

```rust
use sb_adapters::outbound::vless::{VlessConfig, VlessConnector, FlowControl, Encryption};
use uuid::Uuid;

let config = VlessConfig {
    server_addr: "127.0.0.1:443".parse()?,
    uuid: Uuid::new_v4(),
    flow: FlowControl::None,
    encryption: Encryption::None,
    timeout: Some(30),
    tcp_fast_open: false,
    multiplex: None,
    #[cfg(feature = "tls_reality")]
    reality: None,
    #[cfg(feature = "transport_ech")]
    ech: None,
    headers: Default::default(),
};

let connector = VlessConnector::new(config);

// Create UDP relay
let target = Target::udp("8.8.8.8", 53);
let udp_socket = connector.udp_relay_dial(target.clone()).await?;

// Set target and use
udp_socket.set_target(target).await;
udp_socket.send_to(&dns_query).await?;
```

#### Implementation (crates/sb-adapters/src/outbound/vless.rs:174)

```rust
pub async fn udp_relay_dial(&self, target: Target) -> Result<Box<dyn OutboundDatagram>> {
    // Create local UDP socket
    let local_socket = UdpSocket::bind("0.0.0.0:0").await?;

    // Connect to VLESS server
    local_socket.connect(self.config.server_addr).await?;

    // Create VLESS UDP socket wrapper
    let vless_udp = VlessUdpSocket::new(
        Arc::new(local_socket),
        self.config.uuid,
    )?;

    Ok(Box::new(vless_udp))
}
```

#### Packet Encoding (crates/sb-adapters/src/outbound/vless.rs:385)

```rust
fn encode_packet(&self, data: &[u8], target: &Target) -> Result<Vec<u8>> {
    let mut packet = Vec::new();

    // VLESS version (1 byte)
    packet.push(0x00);

    // UUID (16 bytes)
    packet.extend_from_slice(self.uuid.as_bytes());

    // CMD: UDP (0x02)
    packet.push(0x02);

    // Address type and address
    if let Ok(ip) = target.host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(ipv4) => {
                packet.push(0x01); // IPv4
                packet.extend_from_slice(&ipv4.octets());
            }
            std::net::IpAddr::V6(ipv6) => {
                packet.push(0x03); // IPv6
                packet.extend_from_slice(&ipv6.octets());
            }
        }
    } else {
        // Domain name
        packet.push(0x02); // Domain
        packet.push(target.host.len() as u8);
        packet.extend_from_slice(target.host.as_bytes());
    }

    // Port (2 bytes, big endian)
    packet.extend_from_slice(&target.port.to_be_bytes());

    // Payload
    packet.extend_from_slice(data);

    Ok(packet)
}
```

## OutboundDatagram Trait

All UDP socket implementations use the `OutboundDatagram` trait for unified interface.

### Trait Definition (crates/sb-adapters/src/traits.rs:221)

```rust
#[async_trait]
pub trait OutboundDatagram: Send + Sync + Debug {
    /// Send data to the remote target
    async fn send_to(&self, payload: &[u8]) -> Result<usize>;

    /// Receive data from the remote target
    async fn recv_from(&self, buf: &mut [u8]) -> Result<usize>;

    /// Close the datagram connection
    async fn close(&self) -> Result<()> {
        Ok(())
    }
}
```

### Usage Example

```rust
async fn send_dns_query(udp_socket: Box<dyn OutboundDatagram>) -> Result<Vec<u8>> {
    // Build DNS query
    let query = build_dns_query("example.com");

    // Send query
    udp_socket.send_to(&query).await?;

    // Receive response
    let mut buffer = vec![0u8; 4096];
    let len = udp_socket.recv_from(&mut buffer).await?;

    Ok(buffer[..len].to_vec())
}
```

## Common Use Cases

### 1. DNS Queries

```rust
async fn dns_lookup(connector: &ShadowsocksConnector, domain: &str) -> Result<Vec<IpAddr>> {
    let target = Target::udp("8.8.8.8", 53);  // Google DNS
    let udp_socket = connector.udp_relay_dial(target.clone()).await?;
    udp_socket.set_target(target).await;

    // Build DNS query packet
    let query = build_dns_query(domain);

    // Send and receive
    udp_socket.send_to(&query).await?;
    let mut response = vec![0u8; 512];
    let len = udp_socket.recv_from(&mut response).await?;

    // Parse DNS response
    parse_dns_response(&response[..len])
}
```

### 2. QUIC/HTTP3

```rust
async fn http3_request(connector: &VlessConnector, url: &str) -> Result<Response> {
    // Parse URL to get host and port
    let (host, port) = parse_url(url)?;

    let target = Target::udp(host, port);
    let udp_socket = connector.udp_relay_dial(target.clone()).await?;
    udp_socket.set_target(target).await;

    // Establish QUIC connection
    let quic_conn = quinn::Endpoint::new_with_abstract_socket(udp_socket)?;

    // Make HTTP/3 request
    let response = quic_conn.connect(host, port).await?
        .request(url).await?;

    Ok(response)
}
```

### 3. Online Gaming

```rust
async fn game_connection(connector: &TrojanConnector, server: &str) -> Result<()> {
    let (host, port) = parse_server_address(server)?;

    let target = Target::udp(host, port);
    let udp_socket = connector.udp_relay_dial(target.clone()).await?;
    udp_socket.set_target(target).await;

    // Game packet loop
    loop {
        // Send game state update
        let packet = build_game_packet();
        udp_socket.send_to(&packet).await?;

        // Receive server update
        let mut buffer = vec![0u8; 4096];
        let len = udp_socket.recv_from(&mut buffer).await?;
        handle_server_update(&buffer[..len])?;

        tokio::time::sleep(Duration::from_millis(16)).await;  // 60 FPS
    }
}
```

## Performance Considerations

### MTU and Packet Size

**Typical MTU values:**
- **Ethernet**: 1500 bytes
- **Internet**: 1400 bytes (safe value)
- **VPN/Tunnel**: 1280-1400 bytes

**Recommendation**: Keep UDP packets under 1400 bytes to avoid fragmentation.

```rust
const MAX_UDP_PACKET_SIZE: usize = 1400;

let data = &payload[..MAX_UDP_PACKET_SIZE.min(payload.len())];
udp_socket.send_to(data).await?;
```

### Encryption Overhead

| Protocol | Overhead | Notes |
|----------|----------|-------|
| Shadowsocks (AES-256-GCM) | ~28 bytes | 12B salt + 16B tag |
| Shadowsocks (ChaCha20-Poly1305) | ~28 bytes | 12B nonce + 16B tag |
| Trojan | ~10-20 bytes | CMD + address encoding |
| VLESS | ~20-30 bytes | Version + UUID + CMD + address |

### Throughput

Typical UDP relay throughput (on modern hardware):
- **Shadowsocks UDP**: 500-800 Mbps
- **Trojan UDP**: 400-600 Mbps (TLS overhead)
- **VLESS UDP**: 600-900 Mbps (minimal overhead)

## Troubleshooting

### Common Issues

**1. UDP Packets Not Received**
```
Error: Timeout waiting for UDP response
```
**Possible causes:**
- Server doesn't support UDP relay
- Firewall blocking UDP packets
- Packet size exceeds MTU

**Solutions:**
- Verify server configuration
- Check firewall rules
- Reduce packet size

**2. DNS Resolution Fails**
```
Error: DNS query timeout
```
**Solutions:**
- Try different DNS server (e.g., 1.1.1.1)
- Increase timeout value
- Check network connectivity

**3. Encryption/Decryption Error (Shadowsocks)**
```
Error: AES-GCM decryption failed
```
**Possible causes:**
- Incorrect password
- Mismatched encryption method
- Packet corruption

**Solutions:**
- Verify password matches server
- Ensure same encryption method on client/server
- Check network stability

### Debug Logging

Enable UDP relay debug logging:
```bash
RUST_LOG=sb_adapters::outbound=debug cargo run
```

Example output:
```
DEBUG sb_adapters::outbound::shadowsocks: Creating Shadowsocks UDP relay
TRACE sb_adapters::outbound::shadowsocks: Shadowsocks UDP packet sent: 75 bytes
TRACE sb_adapters::outbound::shadowsocks: Shadowsocks UDP packet received: 64 bytes
```

## Testing

### E2E Tests

See: `app/tests/udp_relay_e2e.rs`

Tests cover:
- Single packet send/receive
- Large packet handling (1400 bytes)
- Multiple sequential packets
- Concurrent UDP connections

### Manual Testing

**Test DNS over Shadowsocks UDP:**
```bash
# Start Shadowsocks server with UDP support
ss-server -s 0.0.0.0 -p 8388 -k password -m aes-256-gcm -U

# Test DNS query through relay
dig @127.0.0.1 -p 1053 example.com

# Check logs for UDP relay activity
```

## Comparison with Go sing-box

### Feature Parity

| Feature | Go sing-box | singbox-rust | Status |
|---------|-------------|--------------|--------|
| Shadowsocks UDP | ✅ | ✅ | **Full parity** |
| Trojan UDP | ✅ | ✅ | **Full parity** |
| VLESS UDP | ✅ | ✅ | **Full parity** |
| VMess UDP | ✅ | ❌ | **Not implemented** |
| Packet encryption | ✅ | ✅ | **Full parity** |
| Address encoding | ✅ | ✅ | **Full parity** |

### Differences

**singbox-rust advantages:**
- More explicit error handling
- Type-safe packet encoding
- Better test coverage

**Go sing-box advantages:**
- VMess UDP support (not yet in singbox-rust)
- More mature UDP relay optimizations

## Best Practices

1. **Always test UDP relay** before production deployment
2. **Keep packets under MTU** to avoid fragmentation
3. **Use appropriate encryption** (prefer ChaCha20 for mobile)
4. **Monitor packet loss** and adjust timeouts accordingly
5. **Consider QUIC** for modern applications needing UDP
6. **Handle timeouts gracefully** - UDP is unreliable by nature

## Future Enhancements

- **VMess UDP support**: Planned for future sprint
- **UDP over QUIC**: Better performance and reliability
- **FEC (Forward Error Correction)**: Improved packet loss handling
- **Connection tracking**: Better NAT traversal

## References

- **Shadowsocks UDP**: [Shadowsocks Protocol](https://shadowsocks.org/en/wiki/Protocol.html)
- **Trojan UDP**: [Trojan Protocol](https://trojan-gfw.github.io/trojan/protocol)
- **VLESS Protocol**: [Project X Documentation](https://xtls.github.io/)
- **AEAD Encryption**: [RFC 5116](https://datatracker.ietf.org/doc/html/rfc5116)

## Feature Flags

- `adapter-shadowsocks` - Enable Shadowsocks UDP relay
- `adapter-trojan` - Enable Trojan UDP relay
- `adapter-vless` - Enable VLESS UDP relay
