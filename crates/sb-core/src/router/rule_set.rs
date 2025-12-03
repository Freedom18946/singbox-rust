use crate::router::ruleset::{
    binary,
    matcher::{MatchContext, RuleMatcher},
    RuleSetFormat, RuleSetSource,
};
use parking_lot::RwLock;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

/// Database for managing and matching RuleSets
#[derive(Debug, Default)]
pub struct RuleSetDb {
    /// List of (tag, matcher) pairs
    matchers: RwLock<Vec<(String, RuleMatcher)>>,
}

impl RuleSetDb {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a rule set from a file path (synchronous)
    pub fn add_rule_set(&self, tag: String, path: &str, format_str: &str) -> Result<(), String> {
        let path_buf = PathBuf::from(path);
        if !path_buf.exists() {
            return Err(format!("RuleSet file not found: {}", path));
        }

        // Determine format
        let format = match format_str {
            "binary" => RuleSetFormat::Binary,
            "source" | "json" | "headless" => RuleSetFormat::Source,
            _ => {
                if path.ends_with(".srs") {
                    RuleSetFormat::Binary
                } else {
                    RuleSetFormat::Source
                }
            }
        };

        // Read file synchronously
        let data = std::fs::read(&path_buf).map_err(|e| format!("Failed to read file: {}", e))?;

        // Parse
        let ruleset = match format {
            RuleSetFormat::Binary => binary::parse_binary(&data, RuleSetSource::Local(path_buf))
                .map_err(|e| e.to_string())?,
            RuleSetFormat::Source => binary::parse_json(&data, RuleSetSource::Local(path_buf))
                .map_err(|e| e.to_string())?,
        };

        let matcher = RuleMatcher::new(Arc::new(ruleset));
        self.matchers.write().push((tag, matcher));
        Ok(())
    }

    /// Match a host against all rule sets and collect matching tags
    pub fn match_host(&self, host: &str, matched_tags: &mut Vec<String>) {
        let matchers = self.matchers.read();
        let ctx = MatchContext {
            domain: Some(host.to_string()),
            destination_ip: None,
            destination_port: 0, // Port not available in simple host match
            network: None,
            process_name: None,
            process_path: None,
            source_ip: None,
            source_port: None,
        };

        for (tag, matcher) in matchers.iter() {
            if matcher.matches(&ctx) {
                matched_tags.push(tag.clone());
            }
        }
    }

    /// Match an IP against all rule sets and collect matching tags
    pub fn match_ip(&self, ip: IpAddr, matched_tags: &mut Vec<String>) {
        let matchers = self.matchers.read();
        let ctx = MatchContext {
            domain: None,
            destination_ip: Some(ip),
            destination_port: 0,
            network: None,
            process_name: None,
            process_path: None,
            source_ip: None,
            source_port: None,
        };

        for (tag, matcher) in matchers.iter() {
            if matcher.matches(&ctx) {
                matched_tags.push(tag.clone());
            }
        }
    }
}
