# sb-tls: TLS Abstraction & Anti-Censorship Layer

This crate provides TLS abstractions and anti-censorship protocols for singbox-rust.

## Features

- **`reality`** (default): REALITY anti-censorship protocol
- **`utls`**: uTLS-style fingerprinting (best-effort cipher suite/ALPN ordering via rustls)
- **`ech`**: Encrypted Client Hello (config + HPKE implemented; handshake integration pending)
- **`acme`**: ACME helpers for certificate management (feature-gated)

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

### ✅ Implemented

- [x] TLS abstraction layer (`TlsConnector` trait)
- [x] Standard TLS connector (rustls)
- [x] REALITY configuration structs + validation
- [x] REALITY ClientHello extension injection + server-side parsing
- [x] X25519 key exchange + auth hash computation
- [x] REALITY server auth: derive `session_data` from ClientHello random
- [x] REALITY temporary certificate verification (HMAC) + WebPKI fallback
- [x] REALITY client connector (with custom cert verifier hook)
- [x] REALITY server acceptor (temporary HMAC cert + fallback relay)
- [x] REALITY target chain capture/replay (intermediates) + leaf template (CN/SAN/validity)
- [x] uTLS fingerprint catalog + rustls ClientConfig builder (cipher suites + ALPN)
- [x] ECH config structs, ECHConfigList parser, HPKE primitives (see `crates/sb-tls/src/ech/README.md`)
- [x] Key generation utilities (REALITY + ECH)
- [x] ECH client handshake integration via rustls (TLS 1.3 only)

### ⚠️ Partial / Pending

- [ ] REALITY full leaf cloning (byte-for-byte target leaf/extension parity)
- [ ] uTLS full ClientHello/extension ordering parity (rustls limitation)
- [ ] QUIC ECH alignment + E2E coverage

### Implementation Notes

The current implementation provides **end-to-end wiring** for REALITY, uTLS, and ECH **configuration**, with a few protocol-critical gaps:

1. **REALITY Leaf Cloning**: target chain capture/replay is implemented, but the leaf is not byte-for-byte identical to the target (public key + extensions differ).
2. **uTLS Parity**: rustls cannot fully control ClientHello extension order/grease; current behavior is best-effort.
3. **ECH Integration**: rustls ECH client wiring is integrated (TLS 1.3 only); QUIC ECH is still pending.

## References

- [REALITY Whitepaper](https://github.com/XTLS/REALITY)
- [Xray-core REALITY Implementation](https://github.com/XTLS/Xray-core/tree/main/transport/internet/reality)
- [sing-box REALITY](https://sing-box.sagernet.org/configuration/shared/tls/#reality)

## License

Same as parent project.
