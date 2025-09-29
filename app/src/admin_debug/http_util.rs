use percent_encoding::percent_decode_str;
use sb_admin_contract::{ErrorBody, ErrorKind, ResponseEnvelope};
use serde::Serialize;
use std::collections::HashMap;
use tokio::io::AsyncWriteExt;

// Request ID generation
pub fn generate_request_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(1);

    let count = COUNTER.fetch_add(1, Ordering::SeqCst);
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    format!("req-{:x}-{:x}", timestamp & 0xfffff, count & 0xfff)
}

// Extract request ID from headers or generate one
pub fn get_or_generate_request_id(headers: &HashMap<String, String>) -> String {
    headers
        .get("x-request-id")
        .or_else(|| headers.get("request-id"))
        .and_then(|id| {
            if id.trim().is_empty() {
                None
            } else {
                Some(id.clone())
            }
        })
        .unwrap_or_else(generate_request_id)
}

pub fn parse_query(q: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    for kv in q.split('&') {
        if let Some((k, v)) = kv.split_once('=') {
            m.insert(url_decode(k), url_decode(v));
        }
    }
    m
}

pub fn url_decode(s: &str) -> String {
    percent_decode_str(s).decode_utf8_lossy().to_string()
}

pub async fn respond(
    sock: &mut (impl AsyncWriteExt + Unpin),
    code: u16,
    ctype: &str,
    body: &str,
) -> std::io::Result<()> {
    let status = match code {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        501 => "Not Implemented",
        _ => "OK",
    };
    let hdr = format!(
        "HTTP/1.1 {code} {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.as_bytes().len()
    );
    sock.write_all(hdr.as_bytes()).await?;
    sock.write_all(body.as_bytes()).await?;
    Ok(())
}

pub async fn respond_json_ok(
    sock: &mut (impl AsyncWriteExt + Unpin),
    body: &impl Serialize,
) -> std::io::Result<()> {
    let json = serde_json::to_vec(body).unwrap_or_else(|_| b"{}".to_vec());
    respond(
        sock,
        200,
        "application/json",
        std::str::from_utf8(&json).unwrap(),
    )
    .await
}

// Legacy JsonError for backward compatibility
#[derive(Serialize)]
struct JsonError<'a> {
    error: &'a str,
    detail: &'a str,
}

// Type aliases for sb-admin-contract types
pub type AdminResponse<T> = ResponseEnvelope<T>;
pub type AdminError = ErrorBody;

// Convenience constructors for common error types
pub fn admin_error_io(msg: impl Into<String>) -> AdminError {
    ErrorBody {
        kind: ErrorKind::Io,
        msg: msg.into(),
        ptr: None,
        hint: None,
    }
}

pub fn admin_error_parse(msg: impl Into<String>) -> AdminError {
    ErrorBody {
        kind: ErrorKind::Decode,
        msg: msg.into(),
        ptr: None,
        hint: None,
    }
}

pub fn admin_error_not_found(msg: impl Into<String>) -> AdminError {
    ErrorBody {
        kind: ErrorKind::NotFound,
        msg: msg.into(),
        ptr: None,
        hint: None,
    }
}

pub fn admin_error_conflict(msg: impl Into<String>) -> AdminError {
    ErrorBody {
        kind: ErrorKind::Conflict,
        msg: msg.into(),
        ptr: None,
        hint: None,
    }
}

pub fn admin_error_state(msg: impl Into<String>) -> AdminError {
    ErrorBody {
        kind: ErrorKind::State,
        msg: msg.into(),
        ptr: None,
        hint: None,
    }
}

pub fn admin_error_with_ptr(mut error: AdminError, ptr: impl Into<String>) -> AdminError {
    error.ptr = Some(ptr.into());
    error
}

pub fn admin_error_with_hint(mut error: AdminError, hint: impl Into<String>) -> AdminError {
    error.hint = Some(hint.into());
    error
}

// Legacy JSON error response (for backward compatibility)
pub async fn respond_json_error(
    sock: &mut (impl AsyncWriteExt + Unpin),
    code: u16,
    msg: &str,
    hint: Option<&str>,
) -> std::io::Result<()> {
    let detail = hint.unwrap_or(msg);
    let payload = JsonError { error: msg, detail };
    let json = serde_json::to_string(&payload)
        .unwrap_or_else(|_| "{\"error\":\"unknown\",\"detail\":\"unknown\"}".into());
    respond(sock, code, "application/json", &json).await
}

// New unified admin response functions
pub async fn respond_admin_success<T: Serialize>(
    sock: &mut (impl AsyncWriteExt + Unpin),
    data: T,
) -> std::io::Result<()> {
    respond_admin_success_with_request_id(sock, data, generate_request_id()).await
}

pub async fn respond_admin_success_with_request_id<T: Serialize>(
    sock: &mut (impl AsyncWriteExt + Unpin),
    data: T,
    request_id: String,
) -> std::io::Result<()> {
    let response = ResponseEnvelope::ok(data).with_request_id(request_id);
    let json = serde_json::to_string(&response).unwrap_or_else(|_| {
        r#"{"ok":false,"error":{"kind":"io","msg":"serialization failed"}}"#.into()
    });
    respond(sock, 200, "application/json", &json).await
}

pub async fn respond_admin_error(
    sock: &mut (impl AsyncWriteExt + Unpin),
    code: u16,
    error: AdminError,
) -> std::io::Result<()> {
    respond_admin_error_with_request_id(sock, code, error, generate_request_id()).await
}

pub async fn respond_admin_error_with_request_id(
    sock: &mut (impl AsyncWriteExt + Unpin),
    code: u16,
    error: AdminError,
    request_id: String,
) -> std::io::Result<()> {
    let response: AdminResponse<()> =
        ResponseEnvelope::err(error.kind, error.msg).with_request_id(request_id);
    let json = serde_json::to_string(&response).unwrap_or_else(|_| {
        r#"{"ok":false,"error":{"kind":"io","msg":"serialization failed"}}"#.into()
    });
    respond(sock, code, "application/json", &json).await
}

// Convenience function for common error patterns
pub async fn respond_admin_parse_error(
    sock: &mut (impl AsyncWriteExt + Unpin),
    msg: impl Into<String>,
    ptr: Option<impl Into<String>>,
    hint: Option<impl Into<String>>,
) -> std::io::Result<()> {
    let mut error = admin_error_parse(msg);
    if let Some(p) = ptr {
        error = admin_error_with_ptr(error, p);
    }
    if let Some(h) = hint {
        error = admin_error_with_hint(error, h);
    }
    respond_admin_error(sock, 400, error).await
}

pub async fn respond_admin_not_found(
    sock: &mut (impl AsyncWriteExt + Unpin),
    resource: impl Into<String>,
    hint: Option<impl Into<String>>,
) -> std::io::Result<()> {
    let mut error = admin_error_not_found(format!("Resource not found: {}", resource.into()));
    if let Some(h) = hint {
        error = admin_error_with_hint(error, h);
    }
    respond_admin_error(sock, 404, error).await
}

pub async fn respond_admin_conflict(
    sock: &mut (impl AsyncWriteExt + Unpin),
    msg: impl Into<String>,
    ptr: Option<impl Into<String>>,
) -> std::io::Result<()> {
    let mut error = admin_error_conflict(msg);
    if let Some(p) = ptr {
        error = admin_error_with_ptr(error, p);
    }
    respond_admin_error(sock, 409, error).await
}

/// Maximum allowed size for base64 inline content (512KB)
pub const MAX_INLINE_BYTES: usize = 512 * 1024;

/// Validate base64 content size before decoding (estimation only)
pub fn validate_inline_size_estimate(b64_content: &str) -> Result<(), &'static str> {
    let est = estimate_b64_decoded_size(b64_content);
    if est <= MAX_INLINE_BYTES {
        Ok(())
    } else {
        Err("inline content too large")
    }
}

/// More robust Base64 size estimation (ignores whitespace and considers padding)
fn estimate_b64_decoded_size(b64: &str) -> usize {
    // 去掉空白
    let len = b64
        .as_bytes()
        .iter()
        .filter(|b| !b" \n\r\t".contains(b))
        .count();
    // 非法字符不要在此处拒绝，让解码报错；这里只做 rough estimate
    // Base64 4 chars -> 3 bytes，考虑填充
    let padding = b64.chars().rev().take_while(|&c| c == '=').count();
    if len == 0 {
        return 0;
    }
    // 向下取整的估算，但不小于0
    // 公式： decoded = (len/4)*3 - padding
    let blocks = len / 4;
    blocks.saturating_mul(3).saturating_sub(padding)
}

/// Validate actual decoded content size
pub fn validate_decoded_size(decoded_bytes: &[u8]) -> Result<(), &'static str> {
    if decoded_bytes.len() > MAX_INLINE_BYTES {
        Err("inline content too large")
    } else {
        Ok(())
    }
}

/// Validate format parameter
pub fn validate_format(format: &str) -> Result<(), &'static str> {
    match format {
        "clash" | "singbox" => Ok(()),
        _ => Err("invalid format"),
    }
}

/// Get supported patch kinds dynamically from core
pub fn supported_patch_kinds() -> &'static [String] {
    use std::sync::OnceLock;
    static KINDS: OnceLock<Vec<String>> = OnceLock::new();

    KINDS.get_or_init(|| {
        #[cfg(feature = "sbcore_rules_tool")]
        {
            let json = sb_core::router::analyze_fix::supported_patch_kinds_json();
            // Parse the JSON to extract kinds array
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&json) {
                if let Some(kinds_array) = value.get("kinds").and_then(|k| k.as_array()) {
                    return kinds_array
                        .iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect();
                }
            }
        }

        // Fallback to empty list if core feature not available or parsing fails
        vec![]
    })
}

/// Check if networking is allowed via environment variable
pub fn is_networking_allowed() -> bool {
    match std::env::var("SB_ADMIN_ALLOW_NET") {
        Ok(val) => val != "0" && !val.is_empty(),
        Err(_) => true, // Default to allowed if not set
    }
}

/// Validate URL for security (only allow http/https schemes)
pub fn validate_url_scheme(url: &str) -> Result<(), &'static str> {
    if url.starts_with("http://") || url.starts_with("https://") {
        Ok(())
    } else {
        Err("invalid URL scheme")
    }
}

/// Get supported kinds as a comma-separated string for error messages
pub fn supported_patch_kinds_hint() -> String {
    let kinds = supported_patch_kinds();
    if kinds.is_empty() {
        "none available (sbcore_rules_tool feature required)".to_string()
    } else {
        kinds.join(", ")
    }
}

/// Validate kinds parameter
pub fn validate_kinds(kinds_str: &str) -> Result<Vec<String>, String> {
    if kinds_str.trim().is_empty() {
        return Ok(vec![]);
    }

    let supported = supported_patch_kinds();
    let requested: Vec<String> = kinds_str.split(',').map(|s| s.trim().to_string()).collect();
    let mut invalid = Vec::new();

    for kind in &requested {
        if !supported.iter().any(|s| s.as_str() == kind) {
            invalid.push(kind.clone());
        }
    }

    if invalid.is_empty() {
        Ok(requested)
    } else {
        Err(format!(
            "unsupported kinds: {:?}; supported: [{}]",
            invalid,
            supported
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))
    }
}
