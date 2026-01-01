use crate::router::ruleset::{
    binary,
    matcher::{MatchContext, RuleMatcher},
    RuleSetFormat, RuleSetSource,
};
use anyhow::Result;
use parking_lot::RwLock;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

/// Lifecycle stages for rule-set initialization (Go-parity)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleSetStage {
    /// Initialize resources (pre-start)
    Initialize,
    /// Start/load rule-sets (main startup)
    Start,
    /// Post-start configuration
    PostStart,
}

/// Database for managing and matching RuleSets (Go-parity lifecycle)
#[derive(Debug, Default)]
pub struct RuleSetDb {
    /// List of (tag, matcher) pairs
    matchers: RwLock<Vec<(String, RuleMatcher)>>,
    /// Pending rule-sets to load (tag, path, format)
    pending: RwLock<Vec<(String, String, String)>>,
    /// Current lifecycle stage
    stage: RwLock<Option<RuleSetStage>>,
    /// Load errors (accumulated during Start stage)
    errors: RwLock<Vec<(String, String)>>,
}

impl RuleSetDb {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue a rule-set for loading during Start stage
    pub fn queue_rule_set(&self, tag: String, path: String, format: String) {
        self.pending.write().push((tag, path, format));
    }

    /// Start lifecycle: Initialize, Start, or PostStart
    pub async fn start(&self, stage: RuleSetStage) -> Result<()> {
        *self.stage.write() = Some(stage);
        
        match stage {
            RuleSetStage::Initialize => {
                tracing::debug!(target: "sb_core::router", "RuleSetDb initializing");
            }
            RuleSetStage::Start => {
                self.load_all_pending().await?;
            }
            RuleSetStage::PostStart => {
                tracing::debug!(target: "sb_core::router", "RuleSetDb post-start");
            }
        }
        Ok(())
    }

    /// Load all pending rule-sets concurrently
    async fn load_all_pending(&self) -> Result<()> {
        let pending: Vec<_> = self.pending.write().drain(..).collect();
        
        if pending.is_empty() {
            return Ok(());
        }
        
        tracing::info!(target: "sb_core::router", "Loading {} rule-sets", pending.len());
        
        // Load concurrently using spawn_blocking for I/O
        let tasks: Vec<_> = pending
            .into_iter()
            .map(|(tag, path, format)| {
                let tag_clone = tag.clone();
                tokio::task::spawn_blocking(move || {
                    Self::load_rule_set_sync(&tag, &path, &format)
                        .map(|m| (tag, m))
                        .map_err(|e| (tag_clone, e))
                })
            })
            .collect();
        
        let mut loaded = Vec::new();
        let mut errors = Vec::new();
        
        for task in tasks {
            match task.await {
                Ok(Ok((tag, matcher))) => {
                    tracing::debug!(target: "sb_core::router", "Loaded rule-set: {}", tag);
                    loaded.push((tag, matcher));
                }
                Ok(Err((tag, err))) => {
                    tracing::error!(target: "sb_core::router", "Failed to load rule-set {}: {}", tag, err);
                    errors.push((tag, err));
                }
                Err(join_err) => {
                    tracing::error!(target: "sb_core::router", "Task join error: {}", join_err);
                }
            }
        }
        
        // Store loaded matchers
        self.matchers.write().extend(loaded);
        self.errors.write().extend(errors);
        
        Ok(())
    }

    /// Synchronous rule-set loading (for spawn_blocking)
    fn load_rule_set_sync(_tag: &str, path: &str, format_str: &str) -> Result<RuleMatcher, String> {
        let path_buf = PathBuf::from(path);
        if !path_buf.exists() {
            return Err(format!("RuleSet file not found: {}", path));
        }

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

        let data = std::fs::read(&path_buf).map_err(|e| format!("Failed to read file: {}", e))?;

        let ruleset = match format {
            RuleSetFormat::Binary => binary::parse_binary(&data, RuleSetSource::Local(path_buf))
                .map_err(|e| e.to_string())?,
            RuleSetFormat::Source => binary::parse_json(&data, RuleSetSource::Local(path_buf))
                .map_err(|e| e.to_string())?,
        };

        Ok(RuleMatcher::new(Arc::new(ruleset)))
    }

    /// Cleanup: Close all rule-sets and clear errors
    pub async fn cleanup(&self) {
        self.matchers.write().clear();
        self.pending.write().clear();
        self.errors.write().clear();
        *self.stage.write() = None;
        tracing::debug!(target: "sb_core::router", "RuleSetDb cleaned up");
    }

    /// Get load errors from Start stage
    pub fn get_errors(&self) -> Vec<(String, String)> {
        self.errors.read().clone()
    }

    /// Current lifecycle stage
    pub fn current_stage(&self) -> Option<RuleSetStage> {
        *self.stage.read()
    }

    /// Add a rule set from a file path (synchronous, legacy API)
    pub fn add_rule_set(&self, tag: String, path: &str, format_str: &str) -> Result<(), String> {
        let matcher = Self::load_rule_set_sync(&tag, path, format_str)?;
        self.matchers.write().push((tag, matcher));
        Ok(())
    }

    /// Match a host against all rule sets and collect matching tags
    pub fn match_host(&self, host: &str, matched_tags: &mut Vec<String>) {
        let matchers = self.matchers.read();
        let ctx = MatchContext {
            domain: Some(host.to_string()),
            destination_ip: None,
            destination_port: 0,
            network: None,
            process_name: None,
            process_path: None,
            source_ip: None,
            clash_mode: None,
            source_port: None,
            query_type: None,
            geosite_codes: Vec::new(),
            geoip_code: None,
            inbound_tag: None,
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
            query_type: None,
            clash_mode: None,
            inbound_tag: None,
            geosite_codes: Vec::new(),
            geoip_code: None,
        };

        for (tag, matcher) in matchers.iter() {
            if matcher.matches(&ctx) {
                matched_tags.push(tag.clone());
            }
        }
    }

    /// Get number of loaded rule-sets
    pub fn len(&self) -> usize {
        self.matchers.read().len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.matchers.read().is_empty()
    }
}
