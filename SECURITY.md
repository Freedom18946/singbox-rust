# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability, please report it privately.
**Do not** file a public GitHub issue.

## Threat Model

### Assets Protected
- **Cryptographic Keys**: TLS certificates, authentication credentials
- **User Data**: Routing information, DNS queries, connection metadata
- **System Resources**: Memory, file descriptors, network connections
- **Configuration**: Authentication settings, routing rules, upstream endpoints

### Attack Vectors
- Network-based attacks (MITM, traffic analysis)
- Memory corruption and resource exhaustion
- Credential theft from logs or memory dumps
- Dependency vulnerabilities

## Security Primitives (`sb-security` crate)

### Credential Redaction

`sb-security::redact` provides automatic credential redaction for logging:

```rust
use sb_security::{redact_token, redact_key, redact_credential};

// Tokens: first 4 + last 4 characters visible
redact_token("Bearer eyJhbG...signature"); // "Bear********ture"

// Keys: type and length only
redact_key("-----BEGIN RSA PRIVATE KEY-----\n..."); // "RSA-[KEY:1234]"

// Credentials: first 2 characters only
redact_credential("super_secret"); // "su**********"
```

### Constant-Time Credential Verification

`sb-security::credentials` uses the `subtle` crate for timing-attack resistant comparisons:

```rust
use sb_security::verify_credentials;

let valid = verify_credentials(
    Some("admin"), Some("secret"),
    "admin", "secret"
);
```

### Secure Key Loading

`sb-security::key_loading` supports loading secrets from multiple sources with `ZeroizeOnDrop`:

```rust
use sb_security::{KeySource, SecretLoader};

let mut loader = SecretLoader::new();

// From environment variable (recommended for production)
let secret = loader.load(&KeySource::env("API_KEY"))?;

// From file (verifies Unix permissions)
let secret = loader.load(&KeySource::file("/run/secrets/key"))?;
```

Key files are validated for restrictive permissions (0600) on Unix systems.

### Memory Safety
- Sensitive data uses `zeroize` (`ZeroizeOnDrop`) for automatic cleanup on drop
- Cryptographic comparisons use `subtle::ConstantTimeEq`

## TLS

- Default backend: rustls (TLS 1.2/1.3)
- Certificate validation enforced by default
- Custom CA bundles supported via `sb-tls`

## Dependency Auditing

The project uses `cargo-deny` with configuration in `deny.toml`:

```bash
# Via project tooling
tools/deny/check.sh

# Or directly
cargo deny check advisories
cargo deny check licenses
cargo deny check bans
```

## Runtime Hardening

- Rate limiting on inbound connections (`sb-core::net::tcp_rate_limit`)
- Connection limits and timeouts configurable per inbound
- Admin endpoints require authentication (`app::admin_debug::auth`)

---

*Last updated: 2026-03-21*
