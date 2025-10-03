# sb-tls: TLS Abstraction & Anti-Censorship Layer

This crate provides TLS abstractions and anti-censorship protocols for singbox-rust.

## Features

- **`reality`** (default): REALITY anti-censorship protocol
- **`utls`**: uTLS fingerprint mimicry (TODO)
- **`ech`**: Encrypted Client Hello (TODO)

## Modules

### Standard TLS

Standard TLS 1.3 connector using rustls:

```rust
use sb_tls::{StandardTlsConnector, TlsConnector};

let connector = StandardTlsConnector::new()?;
let tls_stream = connector.connect(tcp_stream, "example.com").await?;
```

### REALITY Protocol

REALITY is an anti-censorship protocol that bypasses SNI whitelisting:

#### Client

```rust
use sb_tls::reality::{RealityClientConfig, RealityConnector};

let config = RealityClientConfig {
    target: "www.apple.com".to_string(),
    server_name: "www.apple.com".to_string(),
    public_key: "0123...abcdef".to_string(),  // Server's public key (64 hex chars)
    short_id: Some("01ab".to_string()),       // Optional client ID (0-16 hex chars)
    fingerprint: "chrome".to_string(),
    alpn: vec!["h2".to_string()],
};

let connector = RealityConnector::new(config)?;
let tls_stream = connector.connect(tcp_stream, "www.apple.com").await?;
```

#### Server

```rust
use sb_tls::reality::{RealityServerConfig, RealityAcceptor};

let config = RealityServerConfig {
    target: "www.apple.com:443".to_string(),    // Real target to proxy to
    server_names: vec!["proxy.example.com".to_string()],
    private_key: "0123...abcdef".to_string(),  // Server's private key (64 hex chars)
    short_ids: vec!["01ab".to_string()],       // Accepted client IDs
    handshake_timeout: 5,
    enable_fallback: true,                      // Fallback to target on auth failure
};

let acceptor = RealityAcceptor::new(config)?;
let connection = acceptor.accept(tcp_stream).await?;

match connection.handle().await? {
    Some(proxy_stream) => {
        // Authenticated connection - proxy traffic
    }
    None => {
        // Fallback connection - already proxied to target
    }
}
```

#### Key Generation

```rust
use sb_tls::reality::generate_keypair;

let (private_key, public_key) = generate_keypair();
println!("Private key (keep secret): {}", private_key);
println!("Public key (share with clients): {}", public_key);
```

## How REALITY Works

### Anti-Censorship Mechanism

REALITY bypasses SNI whitelisting by:

1. **Certificate Stealing**: Proxies TLS handshake to a real target website (e.g., apple.com) to "steal" their certificate chain
2. **SNI Forgery**: Uses the target domain's SNI, appearing as legitimate traffic
3. **Authentication**: Uses X25519 ECDH key exchange for client authentication
4. **Fallback**: If authentication fails, proxies to the real target website (anti-detection)

### Client Side

1. Connects with forged SNI (e.g., "www.apple.com")
2. Embeds authentication data in TLS ClientHello extensions
3. Receives either:
   - Temporary trusted certificate (authenticated proxy)
   - Real target certificate (fallback/crawler mode)

### Server Side

1. Receives TLS ClientHello with embedded auth data
2. Validates authentication using shared secret (X25519 ECDH)
3. If valid: issues temporary certificate and establishes proxy
4. If invalid: proxies to real target website (disguise)

### Security Model

- **X25519 Key Exchange**: Public/private key pairs for authentication
- **Short ID**: Identifies different clients (0-16 hex chars)
- **Target Domain**: Real website to impersonate (e.g., apple.com, microsoft.com)
- **Fallback**: Transparent proxy to real target on auth failure

## Implementation Status

### ✅ Completed

- [x] TLS abstraction layer (`TlsConnector` trait)
- [x] Standard TLS connector (rustls)
- [x] REALITY configuration structs
- [x] X25519 authentication framework
- [x] REALITY client connector (framework)
- [x] REALITY server acceptor (framework)
- [x] Configuration validation
- [x] Key generation utilities

### 🚧 TODO (Full Implementation)

- [ ] Custom ClientHello generation with REALITY extensions
- [ ] Certificate type detection (temporary vs real)
- [ ] Actual X25519 ECDH (currently placeholder)
- [ ] Target certificate stealing mechanism
- [ ] TLS fingerprint emulation (uTLS)
- [ ] Encrypted Client Hello (ECH)

### Implementation Notes

The current implementation provides the **framework and architecture** for REALITY:

1. **Configuration**: Full config structs with validation
2. **Authentication**: X25519 key management (placeholder crypto)
3. **Client/Server**: Connection flow and handshake structure
4. **Fallback**: Fallback mechanism architecture

For **production use**, the following needs implementation:

1. **Custom TLS Library**: rustls doesn't allow ClientHello modification
   - Option 1: Fork rustls and add hooks for ClientHello modification
   - Option 2: Use boring-sys (BoringSSL) for low-level TLS control
   - Option 3: Implement custom TLS 1.3 handshake

2. **Proper X25519**: Current implementation is placeholder
   - Replace with proper ECDH using ring or x25519-dalek StaticSecret

3. **Certificate Handling**: Implement certificate stealing from target
   - Connect to real target
   - Extract certificate chain
   - Present to client (fallback mode)

## References

- [REALITY Whitepaper](https://github.com/XTLS/REALITY)
- [Xray-core REALITY Implementation](https://github.com/XTLS/Xray-core/tree/main/transport/internet/reality)
- [sing-box REALITY](https://sing-box.sagernet.org/configuration/shared/tls/#reality)

## License

Same as parent project.
