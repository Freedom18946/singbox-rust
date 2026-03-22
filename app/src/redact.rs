#![allow(dead_code)]

//! Simple sensitive data redaction utilities for logging.
//!
//! Intent: provide a lightweight, opt-in API to scrub secrets before they
//! appear in logs. Prefer structured logs and avoid logging secrets entirely.
use regex::Regex;

#[allow(clippy::struct_field_names)]
#[derive(Debug)]
pub struct Redactor {
    kv_re: Regex,
    json_re: Regex,
    url_auth_re: Regex,
    bearer_re: Regex,
}

impl Redactor {
    /// Build a reusable redactor instance for the process runtime.
    ///
    /// # Errors
    ///
    /// Returns the regex compilation error if one of the built-in redaction
    /// patterns is invalid.
    pub fn new() -> Result<Self, regex::Error> {
        Ok(Self {
            kv_re: Regex::new(
                r"(?i)\b(password|token|secret|api[_-]?key|authorization|cookie)=([^&\s;]+)",
            )?,
            json_re: Regex::new(
                r#"(?i)"(password|token|secret|api[_-]?key|authorization|cookie)"\s*:\s*"([^"]*)""#,
            )?,
            url_auth_re: Regex::new(r"(?i)\b(https?://)([^:@/]+):([^@/]+)@")?,
            bearer_re: Regex::new(r"(?i)\bBearer\s+[A-Za-z0-9._\-]+")?,
        })
    }

    /// Redact common secret patterns from a free-form text.
    #[must_use]
    pub fn redact_str(&self, input: &str) -> String {
        let mut s = input.to_string();
        s = self
            .kv_re
            .replace_all(&s, |caps: &regex::Captures| {
                let redacted = redact_kv(&caps[1], &caps[2]);
                format!("{}={}", &caps[1], redacted)
            })
            .into_owned();
        s = self
            .json_re
            .replace_all(&s, |caps: &regex::Captures| {
                let redacted = redact_kv(&caps[1], &caps[2]);
                format!("\"{}\": \"{}\"", &caps[1], redacted)
            })
            .into_owned();
        s = self
            .url_auth_re
            .replace_all(&s, |caps: &regex::Captures| {
                format!("{}{}:{}@", &caps[1], &caps[2], "***")
            })
            .into_owned();
        self.bearer_re.replace_all(&s, "Bearer ***").into_owned()
    }
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

    fn redactor() -> Redactor {
        Redactor::new().expect("test regexes compile")
    }

    #[test]
    fn redact_kv_pairs() {
        let s = "password=hunter2&token=abc.def&name=alice";
        let r = redactor().redact_str(s);
        assert!(r.contains("password=***"));
        assert!(r.contains("token=***"));
        assert!(r.contains("name=alice"));
    }

    #[test]
    fn redact_json_fields() {
        let s = r#"{"token":"abcd","user":"bob"}"#;
        let r = redactor().redact_str(s);
        assert!(r.contains("\"token\": \"***\""));
        assert!(r.contains("\"user\":\"bob\""));
    }

    #[test]
    fn redact_url_basic_auth() {
        let s = "https://user:pass@example.com/path";
        let r = redactor().redact_str(s);
        assert!(r.contains("https://user:***@example.com"));
    }

    #[test]
    fn redact_bearer() {
        let s = "Authorization: Bearer abc.xyz";
        let r = redactor().redact_str(s);
        assert!(r.contains("Bearer ***"));
    }
}
