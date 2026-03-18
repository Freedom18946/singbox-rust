//! Provider content parsing for proxy subscriptions and rule sets.
//! 提供者内容解析，用于代理订阅和规则集。
//!
//! Supports:
//! - **Proxy providers**: base64-encoded URI lists, JSON arrays of `OutboundIR`, plain-text URI lists
//! - **Rule providers**: plain text (one rule per line), JSON arrays
//!
//! 支持：
//! - **代理提供者**：base64 编码的 URI 列表、`OutboundIR` JSON 数组、纯文本 URI 列表
//! - **规则提供者**：纯文本（每行一条规则）、JSON 数组

use crate::model::SubsError;
use base64::Engine as _;
use sb_config::ir::{OutboundIR, OutboundType};

// ────────────────────── Proxy provider parsing ──────────────────────

/// Attempt to parse provider content as a list of outbound proxy configs.
/// 尝试将提供者内容解析为出站代理配置列表。
///
/// Detection order:
/// 1. JSON array of `OutboundIR` objects (sing-box native format)
/// 2. Base64-encoded content → decode → re-try JSON or URI lines
/// 3. Plain-text proxy URI lines (ss://, vmess://, trojan://, vless://, etc.)
pub fn parse_proxy_content(content: &str) -> Result<Vec<OutboundIR>, SubsError> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    // Attempt 1: JSON array
    if trimmed.starts_with('[') {
        if let Ok(outbounds) = serde_json::from_str::<Vec<OutboundIR>>(trimmed) {
            return Ok(outbounds);
        }
        // Could be a JSON array of something else — fall through
    }

    // Attempt 2: JSON object with "outbounds" key (sing-box config snippet)
    if trimmed.starts_with('{') {
        if let Ok(obj) = serde_json::from_str::<serde_json::Value>(trimmed) {
            if let Some(arr) = obj.get("outbounds").and_then(|v| v.as_array()) {
                let json_str = serde_json::to_string(arr)
                    .map_err(|e| SubsError::Parse(format!("re-serialize outbounds: {e}")))?;
                if let Ok(outbounds) = serde_json::from_str::<Vec<OutboundIR>>(&json_str) {
                    return Ok(outbounds);
                }
            }
        }
    }

    // Attempt 3: base64 decode → re-try
    if looks_like_base64(trimmed) {
        if let Ok(decoded) = base64_decode(trimmed) {
            if let Ok(decoded_str) = String::from_utf8(decoded) {
                let inner = decoded_str.trim();
                // Decoded JSON?
                if inner.starts_with('[') || inner.starts_with('{') {
                    if let Ok(result) = parse_proxy_content(inner) {
                        return Ok(result);
                    }
                }
                // Decoded URI list
                let uris = parse_proxy_uri_lines(inner);
                if !uris.is_empty() {
                    return Ok(uris);
                }
            }
        }
    }

    // Attempt 4: plain-text URI lines
    let uris = parse_proxy_uri_lines(trimmed);
    if !uris.is_empty() {
        return Ok(uris);
    }

    Err(SubsError::Parse(
        "unable to parse provider content as proxy list".into(),
    ))
}

/// Parse plain-text proxy URI lines (one URI per line).
/// 解析纯文本代理 URI 行（每行一个 URI）。
///
/// Recognizes: `ss://`, `vmess://`, `vless://`, `trojan://`, `hysteria2://`, `hy2://`
fn parse_proxy_uri_lines(text: &str) -> Vec<OutboundIR> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            parse_proxy_uri(line)
        })
        .collect()
}

/// Parse a single proxy URI into an OutboundIR.
/// 将单个代理 URI 解析为 OutboundIR。
///
/// Currently supports the most common formats:
/// - `ss://` (Shadowsocks — SIP002 and legacy)
/// - `vmess://` (V2Ray base64 JSON)
/// - `vless://` (VLESS standard URI)
/// - `trojan://` (Trojan standard URI)
/// - `hysteria2://` / `hy2://` (Hysteria2 URI)
fn parse_proxy_uri(uri: &str) -> Option<OutboundIR> {
    if let Some(rest) = uri.strip_prefix("ss://") {
        return parse_ss_uri(rest);
    }
    if let Some(rest) = uri.strip_prefix("vmess://") {
        return parse_vmess_uri(rest);
    }
    if let Some(rest) = uri.strip_prefix("vless://") {
        return parse_standard_uri(rest, OutboundType::Vless);
    }
    if let Some(rest) = uri.strip_prefix("trojan://") {
        return parse_standard_uri(rest, OutboundType::Trojan);
    }
    if let Some(rest) = uri.strip_prefix("hysteria2://") {
        return parse_standard_uri(rest, OutboundType::Hysteria2);
    }
    if let Some(rest) = uri.strip_prefix("hy2://") {
        return parse_standard_uri(rest, OutboundType::Hysteria2);
    }
    None
}

/// Parse Shadowsocks SIP002 URI: `ss://base64(method:password)@host:port#tag`
fn parse_ss_uri(rest: &str) -> Option<OutboundIR> {
    // Split off fragment (tag)
    let (main, tag) = match rest.rsplit_once('#') {
        Some((m, t)) => (m, url_decode(t)),
        None => (rest, String::from("ss-proxy")),
    };

    // SIP002: base64userinfo@host:port
    if let Some((userinfo_b64, hostport)) = main.rsplit_once('@') {
        let userinfo = String::from_utf8(base64_decode(userinfo_b64).ok()?).ok()?;
        let (method, password) = userinfo.split_once(':')?;
        let (host, port) = parse_host_port(hostport)?;

        return Some(OutboundIR {
            ty: OutboundType::Shadowsocks,
            name: Some(tag),
            server: Some(host),
            port: Some(port),
            method: Some(method.to_string()),
            password: Some(password.to_string()),
            ..Default::default()
        });
    }

    // Legacy: base64(method:password@host:port)
    let decoded = String::from_utf8(base64_decode(main).ok()?).ok()?;
    let (userinfo, hostport) = decoded.rsplit_once('@')?;
    let (method, password) = userinfo.split_once(':')?;
    let (host, port) = parse_host_port(hostport)?;

    Some(OutboundIR {
        ty: OutboundType::Shadowsocks,
        name: Some(tag),
        server: Some(host),
        port: Some(port),
        method: Some(method.to_string()),
        password: Some(password.to_string()),
        ..Default::default()
    })
}

/// Parse VMess URI: `vmess://base64(json)`
fn parse_vmess_uri(rest: &str) -> Option<OutboundIR> {
    let decoded = String::from_utf8(base64_decode(rest.trim()).ok()?).ok()?;
    let obj: serde_json::Value = serde_json::from_str(&decoded).ok()?;

    let server = obj.get("add")?.as_str()?.to_string();
    let port: u16 = match obj.get("port")? {
        serde_json::Value::Number(n) => n.as_u64()? as u16,
        serde_json::Value::String(s) => s.parse().ok()?,
        _ => return None,
    };
    let uuid = obj.get("id")?.as_str()?.to_string();
    let tag = obj
        .get("ps")
        .and_then(|v| v.as_str())
        .unwrap_or("vmess-proxy")
        .to_string();

    Some(OutboundIR {
        ty: OutboundType::Vmess,
        name: Some(tag),
        server: Some(server),
        port: Some(port),
        uuid: Some(uuid),
        ..Default::default()
    })
}

/// Parse standard URI format: `user_info@host:port?params#tag`
/// Used for VLESS, Trojan, Hysteria2.
fn parse_standard_uri(rest: &str, ty: OutboundType) -> Option<OutboundIR> {
    let (main, tag) = match rest.rsplit_once('#') {
        Some((m, t)) => (m, url_decode(t)),
        None => (rest, format!("{}-proxy", ty.ty_str())),
    };

    let (user_host, _query) = match main.split_once('?') {
        Some((uh, q)) => (uh, Some(q)),
        None => (main, None),
    };

    let (userinfo, hostport) = user_host.rsplit_once('@')?;
    let (host, port) = parse_host_port(hostport)?;

    let mut ir = OutboundIR {
        ty,
        name: Some(tag),
        server: Some(host),
        port: Some(port),
        ..Default::default()
    };

    // For VLESS / VMess: userinfo is UUID
    // For Trojan: userinfo is password
    match ir.ty {
        OutboundType::Vless | OutboundType::Vmess => {
            ir.uuid = Some(userinfo.to_string());
        }
        OutboundType::Trojan => {
            ir.password = Some(userinfo.to_string());
        }
        _ => {
            // For others (Hysteria2 etc.), store as password
            ir.password = Some(userinfo.to_string());
        }
    }

    Some(ir)
}

// ────────────────────── Rule provider parsing ──────────────────────

/// Parse rule provider content into a list of rule strings.
/// 将规则提供者内容解析为规则字符串列表。
///
/// Supports:
/// - Plain text: one rule per line (comments `#` and empty lines skipped)
/// - JSON array of strings
/// - Base64-encoded content (decoded and re-parsed)
pub fn parse_rule_content(content: &str) -> Result<Vec<String>, SubsError> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    // JSON array of strings
    if trimmed.starts_with('[') {
        if let Ok(rules) = serde_json::from_str::<Vec<String>>(trimmed) {
            return Ok(rules);
        }
    }

    // Base64 decode attempt
    if looks_like_base64(trimmed) {
        if let Ok(decoded) = base64_decode(trimmed) {
            if let Ok(decoded_str) = String::from_utf8(decoded) {
                let result = parse_rule_lines(&decoded_str);
                if !result.is_empty() {
                    return Ok(result);
                }
            }
        }
    }

    // Plain text lines
    let rules = parse_rule_lines(trimmed);
    Ok(rules)
}

/// Parse rule lines from plain text.
fn parse_rule_lines(text: &str) -> Vec<String> {
    text.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect()
}

// ────────────────────── Utilities ──────────────────────

/// Heuristic: does this look like base64-encoded content?
/// Checks that it's mostly alphanumeric/+/=/- and doesn't contain typical
/// plaintext patterns (newlines with non-base64 chars).
fn looks_like_base64(s: &str) -> bool {
    // If it contains newlines with proxy URIs or rule syntax, it's not base64
    if s.contains("://") && s.contains('\n') {
        return false;
    }
    // Must be mostly base64 characters
    let clean = s.replace(['\n', '\r', ' '], "");
    if clean.is_empty() {
        return false;
    }
    let base64_chars = clean
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=' || *c == '-' || *c == '_')
        .count();
    base64_chars as f64 / clean.len() as f64 > 0.9
}

/// Decode base64 (standard or URL-safe, with or without padding).
fn base64_decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let clean: String = input.chars().filter(|c| !c.is_whitespace()).collect();

    // Try standard base64 first, then URL-safe
    base64::engine::general_purpose::STANDARD
        .decode(&clean)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(&clean))
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(&clean))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&clean))
}

/// Parse `host:port` or `[ipv6]:port`.
fn parse_host_port(s: &str) -> Option<(String, u16)> {
    // IPv6: [::1]:443
    if let Some(rest) = s.strip_prefix('[') {
        let (ip6, port_str) = rest.split_once("]:")?;
        let port: u16 = port_str.parse().ok()?;
        return Some((ip6.to_string(), port));
    }
    // IPv4 / hostname: host:port
    let (host, port_str) = s.rsplit_once(':')?;
    let port: u16 = port_str.parse().ok()?;
    Some((host.to_string(), port))
}

/// Simple percent-decoding for URI fragments.
fn url_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let h = chars.next().unwrap_or(b'0');
            let l = chars.next().unwrap_or(b'0');
            let val =
                u8::from_str_radix(&format!("{}{}", h as char, l as char), 16).unwrap_or(b'?');
            result.push(val as char);
        } else if b == b'+' {
            result.push(' ');
        } else {
            result.push(b as char);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── proxy URI parsing ──

    #[test]
    fn test_parse_ss_sip002() {
        // method:password = aes-256-gcm:test123
        let b64 = base64::engine::general_purpose::STANDARD.encode("aes-256-gcm:test123");
        let uri = format!("ss://{}@1.2.3.4:8388#my-ss", b64);
        let result = parse_proxy_uri(&uri).unwrap();
        assert_eq!(result.ty, OutboundType::Shadowsocks);
        assert_eq!(result.server.as_deref(), Some("1.2.3.4"));
        assert_eq!(result.port, Some(8388));
        assert_eq!(result.method.as_deref(), Some("aes-256-gcm"));
        assert_eq!(result.password.as_deref(), Some("test123"));
        assert_eq!(result.name.as_deref(), Some("my-ss"));
    }

    #[test]
    fn test_parse_vmess_uri() {
        let json = r#"{"v":"2","ps":"test-vmess","add":"example.com","port":443,"id":"uuid-here","aid":0,"net":"tcp","type":"none"}"#;
        let b64 = base64::engine::general_purpose::STANDARD.encode(json);
        let uri = format!("vmess://{}", b64);
        let result = parse_proxy_uri(&uri).unwrap();
        assert_eq!(result.ty, OutboundType::Vmess);
        assert_eq!(result.server.as_deref(), Some("example.com"));
        assert_eq!(result.port, Some(443));
        assert_eq!(result.uuid.as_deref(), Some("uuid-here"));
        assert_eq!(result.name.as_deref(), Some("test-vmess"));
    }

    #[test]
    fn test_parse_trojan_uri() {
        let uri = "trojan://mypassword@example.com:443?sni=example.com#my-trojan";
        let result = parse_proxy_uri(uri).unwrap();
        assert_eq!(result.ty, OutboundType::Trojan);
        assert_eq!(result.server.as_deref(), Some("example.com"));
        assert_eq!(result.port, Some(443));
        assert_eq!(result.password.as_deref(), Some("mypassword"));
        assert_eq!(result.name.as_deref(), Some("my-trojan"));
    }

    #[test]
    fn test_parse_vless_uri() {
        let uri = "vless://some-uuid@example.com:443?encryption=none#my-vless";
        let result = parse_proxy_uri(uri).unwrap();
        assert_eq!(result.ty, OutboundType::Vless);
        assert_eq!(result.server.as_deref(), Some("example.com"));
        assert_eq!(result.port, Some(443));
        assert_eq!(result.uuid.as_deref(), Some("some-uuid"));
        assert_eq!(result.name.as_deref(), Some("my-vless"));
    }

    // ── proxy content parsing ──

    #[test]
    fn test_parse_proxy_content_json_array() {
        let json = r#"[{"ty":"shadowsocks","server":"1.2.3.4","port":8388,"method":"aes-256-gcm"}]"#;
        let result = parse_proxy_content(json).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].ty, OutboundType::Shadowsocks);
    }

    #[test]
    fn test_parse_proxy_content_base64_uri_list() {
        let uris = "trojan://pass@example.com:443#node1\ntrojan://pass@example.com:444#node2\n";
        let b64 = base64::engine::general_purpose::STANDARD.encode(uris);
        let result = parse_proxy_content(&b64).unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_parse_proxy_content_plain_uri_list() {
        let content = "trojan://pass@example.com:443#node1\ntrojan://pass2@example.com:444#node2\n";
        let result = parse_proxy_content(content).unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_parse_proxy_content_empty() {
        assert!(parse_proxy_content("").unwrap().is_empty());
        assert!(parse_proxy_content("  \n  ").unwrap().is_empty());
    }

    // ── rule content parsing ──

    #[test]
    fn test_parse_rule_content_plain_text() {
        let content = "DOMAIN,example.com\nDOMAIN-SUFFIX,google.com\n# comment\n\nIP-CIDR,1.2.3.0/24";
        let rules = parse_rule_content(content).unwrap();
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0], "DOMAIN,example.com");
        assert_eq!(rules[1], "DOMAIN-SUFFIX,google.com");
        assert_eq!(rules[2], "IP-CIDR,1.2.3.0/24");
    }

    #[test]
    fn test_parse_rule_content_json_array() {
        let json = r#"["DOMAIN,example.com","IP-CIDR,1.2.3.0/24"]"#;
        let rules = parse_rule_content(json).unwrap();
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn test_parse_rule_content_empty() {
        assert!(parse_rule_content("").unwrap().is_empty());
    }

    // ── utilities ──

    #[test]
    fn test_parse_host_port() {
        assert_eq!(
            parse_host_port("example.com:443"),
            Some(("example.com".into(), 443))
        );
        assert_eq!(
            parse_host_port("[::1]:8080"),
            Some(("::1".into(), 8080))
        );
        assert!(parse_host_port("noport").is_none());
    }

    #[test]
    fn test_url_decode() {
        assert_eq!(url_decode("hello%20world"), "hello world");
        assert_eq!(url_decode("no+spaces"), "no spaces");
        assert_eq!(url_decode("plain"), "plain");
    }

    #[test]
    fn test_looks_like_base64() {
        assert!(looks_like_base64("dHJvamFuOi8vcGFzc0BleGFtcGxlLmNvbTo0NDM="));
        assert!(!looks_like_base64(
            "trojan://pass@example.com:443\nvless://uuid@host:443"
        ));
        assert!(!looks_like_base64(""));
    }
}
