#![cfg_attr(
    any(test),
    allow(dead_code, unused_imports, unused_variables, unused_must_use)
)]
use ipnet::IpNet;
use once_cell::sync::OnceCell;
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use std::sync::RwLock;

static EXPLAIN_INDEX: OnceCell<RwLock<ExplainIndex>> = OnceCell::new();

fn global_index() -> &'static RwLock<ExplainIndex> {
    EXPLAIN_INDEX.get_or_init(|| RwLock::new(ExplainIndex::default()))
}

pub fn get_index() -> ExplainIndex {
    global_index().read().map(|g| g.clone()).unwrap_or_default()
}

pub fn set_index(idx: ExplainIndex) {
    if let Ok(mut guard) = global_index().write() {
        *guard = idx;
    }
}

#[derive(Clone)]
pub struct CidrRule {
    pub net: IpNet,
    pub to: String,
    pub when: serde_json::Value,
}

#[derive(Clone)]
pub struct SuffixRule {
    pub suffix: String,
    pub to: String,
    pub when: serde_json::Value,
}

#[derive(Clone)]
pub struct ExactRule {
    pub host: String,
    pub to: String,
    pub when: serde_json::Value,
}

#[derive(Clone)]
pub struct GeoRule {
    pub cc: String,
    pub to: String,
    pub when: serde_json::Value,
}

#[derive(Clone, Default)]
pub struct ExplainIndex {
    pub cidr: Vec<CidrRule>,
    pub suffix: Vec<SuffixRule>,
    pub exact: Vec<ExactRule>,
    pub geo: Vec<GeoRule>,
    pub ov_exact: Vec<ExactRule>,
    pub ov_suffix: Vec<SuffixRule>,
    pub ov_default: Option<String>,
}

impl ExplainIndex {
    pub fn from_rules_json(view: &serde_json::Value) -> Self {
        let mut idx = ExplainIndex::default();
        if let Some(arr) = view.get("cidr").and_then(|v| v.as_array()) {
            for r in arr {
                if let (Some(net), Some(to)) = (
                    r.get("net").and_then(|v| v.as_str()),
                    r.get("to").and_then(|v| v.as_str()),
                ) {
                    if let Ok(net) = net.parse::<IpNet>() {
                        idx.cidr.push(CidrRule {
                            net,
                            to: to.to_string(),
                            when: r
                                .get("when")
                                .cloned()
                                .unwrap_or_else(|| serde_json::json!({})),
                        });
                    }
                }
            }
        }

        if let Some(arr) = view.get("suffix").and_then(|v| v.as_array()) {
            for r in arr {
                if let (Some(suffix), Some(to)) = (
                    r.get("suffix").and_then(|v| v.as_str()),
                    r.get("to").and_then(|v| v.as_str()),
                ) {
                    idx.suffix.push(SuffixRule {
                        suffix: suffix.to_string(),
                        to: to.to_string(),
                        when: r
                            .get("when")
                            .cloned()
                            .unwrap_or_else(|| serde_json::json!({})),
                    });
                }
            }
        }

        if let Some(arr) = view.get("exact").and_then(|v| v.as_array()) {
            for r in arr {
                if let (Some(host), Some(to)) = (
                    r.get("host").and_then(|v| v.as_str()),
                    r.get("to").and_then(|v| v.as_str()),
                ) {
                    idx.exact.push(ExactRule {
                        host: host.to_string(),
                        to: to.to_string(),
                        when: r
                            .get("when")
                            .cloned()
                            .unwrap_or_else(|| serde_json::json!({})),
                    });
                }
            }
        }

        if let Some(arr) = view.get("geo").and_then(|v| v.as_array()) {
            for r in arr {
                if let (Some(cc), Some(to)) = (
                    r.get("cc").and_then(|v| v.as_str()),
                    r.get("to").and_then(|v| v.as_str()),
                ) {
                    idx.geo.push(GeoRule {
                        cc: cc.to_string(),
                        to: to.to_string(),
                        when: r
                            .get("when")
                            .cloned()
                            .unwrap_or_else(|| serde_json::json!({})),
                    });
                }
            }
        }

        if let Some(arr) = view.get("ov_exact").and_then(|v| v.as_array()) {
            for r in arr {
                if let (Some(host), Some(to)) = (
                    r.get("host").and_then(|v| v.as_str()),
                    r.get("to").and_then(|v| v.as_str()),
                ) {
                    idx.ov_exact.push(ExactRule {
                        host: host.to_string(),
                        to: to.to_string(),
                        when: r
                            .get("when")
                            .cloned()
                            .unwrap_or_else(|| serde_json::json!({})),
                    });
                }
            }
        }

        if let Some(arr) = view.get("ov_suffix").and_then(|v| v.as_array()) {
            for r in arr {
                if let (Some(suffix), Some(to)) = (
                    r.get("suffix").and_then(|v| v.as_str()),
                    r.get("to").and_then(|v| v.as_str()),
                ) {
                    idx.ov_suffix.push(SuffixRule {
                        suffix: suffix.to_string(),
                        to: to.to_string(),
                        when: r
                            .get("when")
                            .cloned()
                            .unwrap_or_else(|| serde_json::json!({})),
                    });
                }
            }
        }

        if let Some(def) = view.get("ov_default").and_then(|v| v.as_str()) {
            if !def.is_empty() {
                idx.ov_default = Some(def.to_string());
            }
        }

        idx
    }

    pub fn is_empty(&self) -> bool {
        self.cidr.is_empty()
            && self.suffix.is_empty()
            && self.exact.is_empty()
            && self.geo.is_empty()
            && self.ov_exact.is_empty()
            && self.ov_suffix.is_empty()
            && self.ov_default.is_none()
    }

    pub fn match_override_exact(&self, host: &str) -> Option<(&ExactRule, String)> {
        self.ov_exact
            .iter()
            .find(|r| r.host.eq_ignore_ascii_case(host))
            .map(|r| (r, format!("override:exact:{host}")))
    }

    pub fn match_override_suffix(&self, host: &str) -> Option<(&SuffixRule, String)> {
        self.ov_suffix
            .iter()
            .find(|r| host.ends_with(r.suffix.as_str()))
            .map(|r| (r, format!("override:suffix:*.{}", r.suffix)))
    }

    pub fn match_cidr(&self, ip: Option<IpAddr>) -> Option<(&CidrRule, String)> {
        let ip = ip?;
        self.cidr.iter().find(|r| r.net.contains(&ip)).map(|r| {
            (
                r,
                format!("cidr:{}/{}", r.net.network(), r.net.prefix_len()),
            )
        })
    }

    pub fn match_geo_cc(&self, cc: &str) -> Option<(&GeoRule, String)> {
        self.geo
            .iter()
            .find(|r| r.cc.eq_ignore_ascii_case(cc))
            .map(|r| (r, format!("geo:{cc}")))
    }

    pub fn match_suffix(&self, host: &str) -> Option<(&SuffixRule, String)> {
        self.suffix
            .iter()
            .find(|r| host.ends_with(r.suffix.as_str()))
            .map(|r| (r, format!("suffix:*.{}", r.suffix)))
    }

    pub fn match_exact(&self, host: &str) -> Option<(&ExactRule, String)> {
        self.exact
            .iter()
            .find(|r| r.host.eq_ignore_ascii_case(host))
            .map(|r| (r, format!("exact:{host}")))
    }
}

pub fn snapshot_digest(idx: &ExplainIndex) -> String {
    let cidr: Vec<_> = idx
        .cidr
        .iter()
        .map(|r| {
            serde_json::json!({
                "net": r.net.to_string(),
                "to": r.to.clone(),
                "when": r.when.clone(),
            })
        })
        .collect();
    let suffix: Vec<_> = idx
        .suffix
        .iter()
        .map(|r| {
            serde_json::json!({
                "suffix": r.suffix.clone(),
                "to": r.to.clone(),
                "when": r.when.clone(),
            })
        })
        .collect();
    let exact: Vec<_> = idx
        .exact
        .iter()
        .map(|r| {
            serde_json::json!({
                "host": r.host.clone(),
                "to": r.to.clone(),
                "when": r.when.clone(),
            })
        })
        .collect();
    let geo: Vec<_> = idx
        .geo
        .iter()
        .map(|r| {
            serde_json::json!({
                "cc": r.cc.clone(),
                "to": r.to.clone(),
                "when": r.when.clone(),
            })
        })
        .collect();
    let ov_exact: Vec<_> = idx
        .ov_exact
        .iter()
        .map(|r| {
            serde_json::json!({
                "host": r.host.clone(),
                "to": r.to.clone(),
                "when": r.when.clone(),
            })
        })
        .collect();
    let ov_suffix: Vec<_> = idx
        .ov_suffix
        .iter()
        .map(|r| {
            serde_json::json!({
                "suffix": r.suffix.clone(),
                "to": r.to.clone(),
                "when": r.when.clone(),
            })
        })
        .collect();
    let payload = serde_json::json!({
        "cidr": cidr,
        "suffix": suffix,
        "exact": exact,
        "geo": geo,
        "ov_exact": ov_exact,
        "ov_suffix": ov_suffix,
        "ov_default": idx.ov_default.clone(),
    });
    let mut hasher = Sha256::new();
    if let Ok(bytes) = serde_json::to_vec(&payload) {
        hasher.update(bytes);
    }
    format!("{:x}", hasher.finalize())
}

pub fn rebuild_periodic(handle: crate::router::RouterHandle) {
    let interval_ms = std::env::var("SB_EXPLAIN_REBUILD_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|ms| *ms > 0);

    let Some(ms) = interval_ms else { return };

    std::thread::spawn(move || loop {
        match handle.export_rules_json() {
            Ok(rules) => {
                if let Err(err) = super::explain_bridge::rebuild_index(&rules) {
                    tracing::warn!(target: "explain", "rebuild_index failed: {err}");
                }
            }
            Err(err) => {
                tracing::warn!(target: "explain", "export_rules_json failed: {err}");
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(ms));
    });
}
