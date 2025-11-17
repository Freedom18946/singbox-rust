//! Simple sensitive data redaction utilities for logging.
//!
//! Intent: provide a lightweight, opt-in API to scrub secrets before they
//! appear in logs. Prefer structured logs and avoid logging secrets entirely.
use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    // key=value patterns (querystrings, form bodies, env-style)
    static ref KV_RE: Regex = Regex::new(
        r#"(?i)\b(password|token|secret|api[_-]?key|authorization|cookie)=([^&\s;]+)"#
    ).unwrap();

    // JSON-style fields: "key": "value"
    static ref JSON_RE: Regex = Regex::new(
        r#"(?i)"(password|token|secret|api[_-]?key|authorization|cookie)"\s*:\s*"([^"]*)""#
    ).unwrap();

    // Basic auth in URLs: https://user:pass@host
    static ref URL_AUTH_RE: Regex = Regex::new(
        r#"(?i)\b(https?://)([^:@/]+):([^@/]+)@"#
    ).unwrap();

    // Bearer tokens
    static ref BEARER_RE: Regex = Regex::new(
        r#"(?i)\bBearer\s+[A-Za-z0-9._\-]+"#
    ).unwrap();
}

/// Redact common secret patterns from a free-form text.
#[must_use]
pub fn redact_str(input: &str) -> String {
    let mut s = input.to_string();
    // key=value
    s = KV_RE
        .replace_all(&s, |caps: &regex::Captures| format!("{}=***", &caps[1]))
        .into_owned();
    // JSON fields
    s = JSON_RE
        .replace_all(&s, |caps: &regex::Captures| {
            format!("\"{}\": \"***\"", &caps[1])
        })
        .into_owned();
    // URL basic auth
    s = URL_AUTH_RE
        .replace_all(&s, |caps: &regex::Captures| {
            format!("{}{}:{}@", &caps[1], &caps[2], "***")
        })
        .into_owned();
    // Bearer
    s = BEARER_RE.replace_all(&s, "Bearer ***").into_owned();
    s
}

/// Redact a value when the key suggests sensitivity.
#[must_use]
pub fn redact_kv(key: &str, value: &str) -> String {
    let k = key.to_ascii_lowercase();
    if [
        "password",
        "passwd",
        "token",
        "secret",
        "api_key",
        "apikey",
        "authorization",
        "cookie",
        "key",
    ]
    .iter()
    .any(|&x| k.contains(x))
    {
        return "***".to_string();
    }
    value.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_kv_pairs() {
        let s = "password=hunter2&token=abc.def&name=alice";
        let r = redact_str(s);
        assert!(r.contains("password=***"));
        assert!(r.contains("token=***"));
        assert!(r.contains("name=alice"));
    }

    #[test]
    fn redact_json_fields() {
        let s = r#"{"token":"abcd","user":"bob"}"#;
        let r = redact_str(s);
        assert!(r.contains("\"token\": \"***\""));
        assert!(r.contains("\"user\": \"bob\""));
    }

    #[test]
    fn redact_url_basic_auth() {
        let s = "https://user:pass@example.com/path";
        let r = redact_str(s);
        assert!(r.contains("https://user:***@example.com"));
    }

    #[test]
    fn redact_bearer() {
        let s = "Authorization: Bearer abc.xyz";
        let r = redact_str(s);
        assert!(r.contains("Bearer ***"));
    }
}
