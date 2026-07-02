//! R140: RULE-SET/GEOSITE Provider cache (in-memory read-only).
//! [Chinese] R140: RULE-SET/GEOSITE Provider 缓存（内存只读）。

use base64::Engine as _;
use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct MemoryProvider {
    map: HashMap<String, String>,
    hits: u64,
    misses: u64,
}

impl MemoryProvider {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put_text(&mut self, name: &str, text: &str) {
        self.map.insert(name.to_string(), text.to_string());
    }

    pub fn put_b64(&mut self, name: &str, b64: &str) {
        let text = decode_b64_text(b64).unwrap_or_else(|| b64.to_string());
        self.put_text(name, &text);
    }

    pub fn get(&mut self, name: &str) -> Option<&str> {
        if let Some(value) = self.map.get(name) {
            self.hits += 1;
            Some(value)
        } else {
            self.misses += 1;
            None
        }
    }

    pub fn stats(&self) -> (u64, u64) {
        (self.hits, self.misses)
    }
}

/// Expand `provider:NAME` lines from the in-memory provider cache.
/// [Chinese] 从内存 provider 缓存展开 `provider:NAME` 行。
pub fn parse_with_providers(text: &str, provider: &mut MemoryProvider) -> String {
    let mut out = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(name) = trimmed.strip_prefix("provider:").map(str::trim) {
            if let Some(body) = provider.get(name) {
                out.extend(
                    body.lines()
                        .map(str::trim)
                        .filter(|rule| !rule.is_empty() && !rule.starts_with('#'))
                        .map(str::to_string),
                );
            } else {
                out.push(line.to_string());
            }
        } else {
            out.push(line.to_string());
        }
    }
    out.join("\n")
}

fn decode_b64_text(input: &str) -> Option<String> {
    let clean: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(&clean)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(&clean))
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(&clean))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&clean))
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_text_provider_lines() {
        let mut provider = MemoryProvider::new();
        provider.put_text(
            "ADBLOCK",
            "# comment\nDOMAIN,ads.example.com\n\nDOMAIN-SUFFIX,track.example.org\n",
        );

        let expanded = parse_with_providers(
            "DOMAIN,keep.example,DIRECT\nprovider:ADBLOCK\nMATCH,DIRECT",
            &mut provider,
        );

        assert_eq!(
            expanded,
            "DOMAIN,keep.example,DIRECT\nDOMAIN,ads.example.com\nDOMAIN-SUFFIX,track.example.org\nMATCH,DIRECT"
        );
        assert_eq!(provider.stats(), (1, 0));
    }

    #[test]
    fn decodes_base64_provider_body() {
        let body = "DOMAIN,ads.example.com\n";
        let b64 = base64::engine::general_purpose::STANDARD.encode(body);
        let mut provider = MemoryProvider::new();
        provider.put_b64("ADBLOCK", &b64);

        let expanded = parse_with_providers("provider:ADBLOCK", &mut provider);

        assert_eq!(expanded, "DOMAIN,ads.example.com");
        assert_eq!(provider.stats(), (1, 0));
    }

    #[test]
    fn missing_provider_keeps_reference_and_records_miss() {
        let mut provider = MemoryProvider::new();

        let expanded = parse_with_providers("provider:MISSING", &mut provider);

        assert_eq!(expanded, "provider:MISSING");
        assert_eq!(provider.stats(), (0, 1));
    }
}
