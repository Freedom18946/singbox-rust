# Security Policy

This document outlines the security policies, threat model, and best practices for SingBox-Rust.

## Supported Versions

We provide security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Threat Model

### Assets Protected
- **Cryptographic Keys**: JWT signing keys, API keys, TLS certificates
- **User Data**: Routing information, DNS queries, connection metadata
- **System Resources**: Memory, file descriptors, network connections
- **Configuration**: Authentication settings, routing rules, upstream endpoints

### Threat Actors
- **External Attackers**: Attempting to intercept or manipulate traffic
- **Insider Threats**: Users with access to configuration or logs
- **Supply Chain Attacks**: Compromised dependencies or build tools
- **Local System Compromise**: Unauthorized access to the host system

### Attack Vectors
- Network-based attacks (MITM, traffic analysis)
- Configuration injection and privilege escalation
- Memory corruption and resource exhaustion
- Credential theft from logs or memory dumps
- Dependency vulnerabilities and supply chain compromise

## Key Management

### Supported Key Sources
SingBox-Rust supports secure key loading through multiple sources, in order of security preference:

1. **Environment Variables** (Recommended for production)
   ```toml
   [auth.jwt]
   source = "env"
   name = "JWT_SIGNING_KEY"
   ```

2. **File-based Keys** (Secure for containerized deployments)
   ```toml
   [auth.jwt]
   source = "file"
   path = "/run/secrets/jwt_key"
   ```

3. **Inline Configuration** (⚠️ NOT recommended for production)
   ```toml
   [auth.jwt]
   source = "inline"
   value = "your-secret-here"  # Only for development/testing
   ```

### Key Security Requirements

#### File Permissions
- Key files MUST have restrictive permissions (0600 or similar)
- Key files MUST NOT be world-readable or group-readable
- The application will reject keys with insecure file permissions

#### Environment Variables
- Use dedicated secret management systems (Kubernetes Secrets, HashiCorp Vault, etc.)
- Avoid setting secrets in shell history or process environment
- Rotate keys regularly (recommended: every 90 days)

#### Key Format Validation
- JWT keys support RS256, ES256, and HS256 algorithms
- RSA keys must be at least 2048 bits
- ECDSA keys must use P-256 curve or stronger
- All keys are validated during loading

### Key Rotation Procedures

1. **Generate New Key**
   ```bash
   # For RSA keys
   openssl genpkey -algorithm RSA -out new_key.pem -pkcs8 -aes256

   # For ECDSA keys
   openssl genpkey -algorithm EC -out new_key.pem -pkcs8 -aes256 \
     -pkeyopt ec_paramgen_curve:P-256
   ```

2. **Update Configuration**
   - Add new key to JWKS endpoint or configuration
   - Update key ID references in configuration
   - Deploy configuration changes

3. **Rotate Keys**
   - Keep old key active for grace period (24-48 hours)
   - Monitor for authentication errors
   - Remove old key after grace period

## Logging Security

### Automatic Credential Redaction
SingBox-Rust includes built-in credential redaction to prevent sensitive information from appearing in logs:

```rust
use sb_security::{redact_token, redact_key, redact_credential};

// Tokens show first 4 and last 4 characters
let token = "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature";
info!("Auth token: {}", redact_token(token));
// Logs: "Auth token: Bear********ture"

// Keys show only type and length
let key = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...";
info!("Loaded key: {}", redact_key(key));
// Logs: "Loaded key: RSA-[KEY:1234]"

// Credentials are heavily redacted
let password = "super_secret_password";
info!("Credential: {}", redact_credential(password));
// Logs: "Credential: su**********"
```

### Safe Logging Practices
- **Never log**: Raw secrets, private keys, passwords, JWT tokens
- **Always redact**: Authorization headers, API keys, user credentials
- **Log safely**: Redacted versions, metadata (length, type), error context

### Log Storage Security
- Store logs in secure, access-controlled locations
- Implement log retention policies (recommend: 30-90 days)
- Use encrypted storage for log archives
- Monitor log access and implement audit trails

## Dependency Security

### Supply Chain Protection
We use `cargo-deny` to enforce security policies:

```bash
# Check for known vulnerabilities
cargo deny check advisories

# Verify license compliance
cargo deny check licenses

# Detect supply chain issues
cargo deny check bans
```

### Security Policies
- **Vulnerabilities**: All HIGH and CRITICAL severity vulnerabilities are blocked
- **Unmaintained Crates**: Unmaintained dependencies are blocked in production
- **License Compliance**: Only approved licenses (MIT, Apache-2.0, BSD variants)
- **Multiple Versions**: Flagged for review to reduce attack surface

### Approved Licenses
- MIT
- Apache-2.0
- BSD-3-Clause
- BSD-2-Clause
- ISC
- Unicode-DFS-2016

## Runtime Security

### Memory Safety
- **Secure Allocation**: Sensitive data uses `zeroize` for automatic cleanup
- **Constant-Time Operations**: Cryptographic comparisons use `subtle` crate
- **Bounds Checking**: All array/slice access is bounds-checked
- **No `unsafe` Code**: Forbidden except in vetted dependencies

### Resource Limits
```toml
# Example configuration limits
[security]
max_connections = 10000
max_memory_mb = 512
max_file_descriptors = 1024
request_timeout_seconds = 30
```

### Network Security
- TLS 1.2+ required for all encrypted connections
- Certificate validation enforced by default
- Support for custom CA bundles and certificate pinning
- Rate limiting on admin endpoints

## Incident Response

### Security Contact
For security vulnerabilities, please email: security@singbox.example.com

**DO NOT** file public GitHub issues for security vulnerabilities.

### Response Timeline
- **Acknowledgment**: Within 24 hours
- **Initial Assessment**: Within 72 hours
- **Fix Development**: Based on severity (Critical: 7 days, High: 14 days)
- **Public Disclosure**: 90 days after fix release (coordinated disclosure)

### Severity Classification
- **Critical**: Remote code execution, authentication bypass
- **High**: Privilege escalation, data exposure
- **Medium**: Information disclosure, denial of service
- **Low**: Configuration issues, non-security bugs

### Emergency Procedures

#### If You Suspect a Compromise
1. **Immediate Actions**
   - Rotate all cryptographic keys
   - Check logs for suspicious activity
   - Isolate affected systems

2. **Assessment**
   - Determine scope of potential compromise
   - Identify affected secrets and keys
   - Review access logs and network traffic

3. **Recovery**
   - Generate new secrets and keys
   - Update all dependent systems
   - Monitor for continued suspicious activity

4. **Reporting**
   - Document incident timeline
   - Report to security team
   - Update security procedures if needed

#### Key Compromise Response
```bash
# 1. Generate new keys immediately
openssl genpkey -algorithm RSA -out emergency_key.pem -pkcs8 -aes256

# 2. Update JWKS endpoint
curl -X POST https://your-jwks-endpoint/rotate \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"emergency_rotation": true}'

# 3. Revoke compromised keys
curl -X DELETE https://your-jwks-endpoint/keys/$COMPROMISED_KEY_ID \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

## Security Auditing

### Code Review Requirements
- All security-sensitive code requires peer review
- Cryptographic implementations require expert review
- External security audits recommended annually

### Security Testing
```bash
# Run security-focused tests
cargo test --features security-tests

# Check for vulnerabilities
cargo audit

# Verify secure compilation
cargo deny check

# Test with sanitizers
RUSTFLAGS="-Z sanitizer=address" cargo test
```

### Monitoring and Alerting
- Monitor authentication failures and rate limiting
- Alert on suspicious configuration changes
- Track key rotation and expiration events
- Log all administrative actions

## Compliance and Standards

### Industry Standards
- Follows OWASP Application Security Guidelines
- Implements NIST Cybersecurity Framework principles
- Compliant with modern TLS best practices

### Security Features
- **Authentication**: Multi-factor support, key-based auth
- **Authorization**: Role-based access control, principle of least privilege
- **Encryption**: TLS 1.2+, strong cipher suites
- **Integrity**: Configuration validation, secure defaults
- **Availability**: Rate limiting, resource controls

---

## Quick Security Checklist

### Deployment Security
- [ ] Use environment variables or secure files for secrets
- [ ] Verify file permissions on key files (0600)
- [ ] Enable TLS for all network connections
- [ ] Configure appropriate rate limits
- [ ] Set up log monitoring and alerting
- [ ] Run `cargo deny check` before deployment
- [ ] Implement key rotation procedures
- [ ] Test incident response procedures

### Configuration Security
- [ ] Disable inline secrets in production
- [ ] Use strong, randomly generated keys
- [ ] Configure appropriate session timeouts
- [ ] Enable request ID tracking
- [ ] Set conservative resource limits
- [ ] Validate all external dependencies

### Operational Security
- [ ] Regular security updates
- [ ] Monitor for security advisories
- [ ] Backup and test key recovery procedures
- [ ] Conduct regular security reviews
- [ ] Train team on security procedures
- [ ] Maintain incident response documentation

---

*Last updated: 2025-09-28*
*Next review: 2025-12-28*