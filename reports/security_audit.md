# Security Audit Report

**Project**: singbox-rust
**Date**: 2026-02-12
**Auditor**: Automated + Manual Review

## 1. Dependency Audit

### cargo audit
- **Status**: To be verified
- **Command**: `cargo audit`
- **Criteria**: No HIGH or CRITICAL advisories

### cargo deny (licenses)
- **Status**: To be verified
- **Command**: `cargo deny check licenses`
- **Criteria**: All dependencies use permissive licenses

## 2. Secret Handling

### Password/Token Logging
- **Check**: Passwords, tokens, and secrets must not appear in info/warn log output
- **Method**: `grep -rn "password\|secret\|token\|api.key" --include="*.rs" | grep -i "info!\|warn!\|debug!\|trace!"`
- **Exclusions**: Debug-level logging of sanitized values is acceptable
- **Status**: To be verified

### Configuration Secrets
- **Check**: Configuration parsing must not log raw secret values
- **Locations to verify**:
  - `sb-config/src/` — config parsing
  - `sb-core/src/` — runtime config application
  - `app/src/` — CLI output

## 3. TLS Security

### Minimum TLS Version
- **Check**: Default TLS version >= 1.2
- **Implementation**: `rustls` defaults to TLS 1.2+ (TLS 1.0/1.1 not supported)
- **Verification**: `rustls` crate features include `tls12` but not `tls10`/`tls11`
- **Status**: PASS (by design — rustls does not support < TLS 1.2)

### Cipher Suites
- **Check**: No insecure cipher suites (RC4, DES, export ciphers)
- **Implementation**: `rustls` only supports modern AEAD ciphers (AES-GCM, ChaCha20-Poly1305)
- **Status**: PASS (by design — rustls enforces secure ciphers)

## 4. Authentication Security

### Timing-Safe Comparison
- **Check**: Auth middleware uses constant-time comparison for tokens/passwords
- **Implementation**: `subtle::ConstantTimeEq` used in auth middleware
- **Location**: `app/src/` auth-related modules
- **Status**: To be verified

### API Authentication
- **Clash API**: Bearer token authentication via middleware
- **SSMAPI**: Authentication middleware with token validation
- **Non-localhost Warning**: Warning emitted when API binds to non-127.0.0.1

## 5. Input Validation

### Configuration Validation
- **Check**: All user-supplied configuration is validated before use
- **Implementation**: `sb-config` validator with JSON schema
- **Status**: PASS (validator covers all top-level fields)

### Command Injection
- **Check**: No shell command construction from user input
- **Method**: Review all `Command::new()` usages
- **Status**: To be verified

## 6. Summary

| Category | Status | Notes |
|----------|--------|-------|
| Dependency audit | PENDING | Run `cargo audit` |
| License compliance | PENDING | Run `cargo deny check` |
| Secret logging | PENDING | Grep verification needed |
| TLS >= 1.2 | PASS | rustls enforces this |
| Secure ciphers | PASS | rustls enforces this |
| Timing-safe auth | PENDING | Code review needed |
| Input validation | PASS | Schema validator |
| Command injection | PENDING | Code review needed |

## Actions Required

1. Run `cargo audit` and resolve any HIGH/CRITICAL advisories
2. Run `cargo deny check` and resolve any license issues
3. Verify no secret values in info/warn logs (manual grep)
4. Verify timing-safe comparison in auth middleware (code review)
5. Review all `Command::new()` for injection risks
