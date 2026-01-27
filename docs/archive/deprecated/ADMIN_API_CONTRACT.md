# Admin API Contract

This document defines the unified JSON response contract for admin endpoints and CLI tools using the `sb-admin-contract` crate.

## Overview

All admin endpoints and CLI tools with `--format json` option use a unified response envelope from the `sb-admin-contract` crate to ensure consistency across the entire API surface.

## Response Envelope Structure

### ResponseEnvelope&lt;T&gt;

All JSON responses follow this envelope format:

```rust
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ResponseEnvelope<T> {
    pub ok: bool,
    pub data: Option<T>,
    pub error: Option<ErrorBody>,
    pub request_id: Option<String>,
}
```

**Field Descriptions:**
- `ok`: Boolean indicating success (`true`) or failure (`false`)
- `data`: Response payload when `ok = true` (omitted when `None`)
- `error`: Error details when `ok = false` (omitted when `None`)
- `request_id`: Unique request identifier (omitted when `None`)

### ErrorBody

Error details structure:

```rust
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ErrorBody {
    pub kind: ErrorKind,
    pub msg: String,
    pub ptr: Option<String>,
    pub hint: Option<String>,
}
```

**Field Descriptions:**
- `kind`: Standardized error category (see ErrorKind below)
- `msg`: Human-readable error message
- `ptr`: Optional JSON pointer to the problematic field (e.g., "/config/timeout")
- `hint`: Optional suggestion for resolution

### ErrorKind

Standardized error categories:

```rust
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "value", rename_all = "camelCase")]
pub enum ErrorKind {
    NotFound,           // Resource not found
    Conflict,           // Resource conflict (e.g., duplicate key)
    State,              // Invalid state transition
    Auth,               // Authentication/authorization failure
    RateLimit,          // Rate limit exceeded
    Io,                 // I/O error
    Decode,             // Parsing/decoding error
    Timeout,            // Operation timeout
    Internal,           // Internal server error
    Other(String),      // Other error with custom category
}
```

## Request ID Generation

Request IDs are automatically generated for each request using the format: `req-{timestamp}-{counter}`

Clients can provide their own request ID via the `X-Request-Id` or `Request-Id` headers.

## Example Responses

### Success Response

```json
{
  "ok": true,
  "data": {
    "depth": 42,
    "high_watermark": 128,
    "enq": 1024,
    "drop": 0,
    "done": 982,
    "fail": 0,
    "retry": 0
  },
  "requestId": "req-a1b2c-001"
}
```

### Error Response

```json
{
  "ok": false,
  "error": {
    "kind": "notFound",
    "msg": "Resource not found: cache-123",
    "hint": "Check if the cache ID exists"
  },
  "requestId": "req-a1b2c-002"
}
```

### Complex Error with Pointer

```json
{
  "ok": false,
  "error": {
    "kind": "decode",
    "msg": "Invalid timeout value",
    "ptr": "/config/timeout_ms",
    "hint": "Timeout must be a positive integer"
  },
  "requestId": "req-a1b2c-003"
}
```

## CLI Integration

CLI tools support both legacy and unified output formats:

### Legacy Format (--json flag)
```bash
$ prefetch stats --json
{"depth":0,"high_watermark":0,"enq":0,"drop":0,"done":0,"fail":0,"retry":0}
```

### Unified Format (--format json)
```bash
$ prefetch stats --format json
{"ok":true,"data":{"depth":0,"high_watermark":0,"enq":0,"drop":0,"done":0,"fail":0,"retry":0},"requestId":"req-a1b2c-004"}
```

## Auth Error Mapping

The authentication system has been standardized to use `ErrorKind::Auth` for all authentication failures. This section documents the specific error mappings and response formats.

### Authentication Provider Types

The system supports multiple authentication methods:

- **None**: No authentication required
- **API Key**: Bearer token or HMAC-SHA256 signature verification
- **JWT**: JSON Web Token authentication (placeholder implementation)
- **mTLS**: Mutual TLS authentication (handled at transport layer)

### Authentication Error Types

All authentication errors are mapped to `ErrorKind::Auth` with specific error messages and hints:

#### Missing Credentials

```json
{
  "ok": false,
  "error": {
    "kind": "auth",
    "msg": "Authorization header required",
    "hint": "Include Authorization header with valid credentials"
  },
  "requestId": "req-1234567890abcdef-001a"
}
```

#### Invalid Credentials

```json
{
  "ok": false,
  "error": {
    "kind": "auth",
    "msg": "Invalid Bearer token",
    "hint": "Check your authentication credentials and try again"
  },
  "requestId": "req-1234567890abcdef-001b"
}
```

#### Expired Credentials

```json
{
  "ok": false,
  "error": {
    "kind": "auth",
    "msg": "Authentication timestamp outside 5-minute window",
    "hint": "Refresh your authentication token and try again"
  },
  "requestId": "req-1234567890abcdef-001c"
}
```

#### HMAC Authentication Errors

```json
{
  "ok": false,
  "error": {
    "kind": "auth",
    "msg": "HMAC authentication format must be keyId:timestamp:signature",
    "hint": "Check your authentication credentials and try again"
  },
  "requestId": "req-1234567890abcdef-001d"
}
```

#### mTLS Authentication

For mTLS authentication, a special non-JSON response is returned:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: mtls realm="sb-admin"
Content-Type: text/plain

mTLS authentication required: valid client certificate needed
```

### Request ID Integration

All authentication errors include a `request_id` field for tracing and debugging:

- **Auto-generated**: Format `req-{timestamp}-{random}` if no client ID provided
- **Client-provided**: Via `X-Request-Id` or `Request-Id` headers
- **Consistency**: Same request ID used throughout the request lifecycle

### Feature Flag Support

Authentication behavior depends on the `auth` feature flag:

- **When enabled**: Uses the new modular authentication system with contract-compliant errors
- **When disabled**: Falls back to simple authentication with basic error responses

### Security Considerations

- **Constant-time comparison**: HMAC signatures use constant-time comparison to prevent timing attacks
- **Time window validation**: HMAC timestamps are validated within a 5-minute window
- **Error message consistency**: Authentication errors use consistent language to avoid information leakage

## Admin Endpoints

All admin debug endpoints (`/__health`, `/__config`, `/__metrics`, etc.) can optionally use the unified envelope format when the `admin_envelope` feature is enabled.

Legacy endpoints continue to work for backward compatibility.

## Field Naming Convention

- **Response envelope fields**: camelCase (`requestId`, `errorBody`)
- **Data payload fields**: Depends on the specific endpoint (may use snake_case for compatibility)
- **Error fields**: camelCase (`errorKind`, `msg`, `ptr`, `hint`)

## Implementation Notes

1. **Feature gating**: The contract is available via the `admin_envelope` feature flag
2. **Backward compatibility**: Legacy response formats are preserved
3. **Request ID injection**: Automatic generation with client override support
4. **Error standardization**: Consistent error categories across all endpoints
5. **Serialization**: Uses serde with camelCase field renaming

## Validation

All envelope responses can be validated against the contract types to ensure consistency and catch regressions.

## See Also

- [`sb-admin-contract` crate source](../../../crates/sb-admin-contract/src/lib.rs)
- [Admin API documentation](admin_api.md)
- [Admin HTTP documentation](ADMIN_HTTP.md)
