#![cfg_attr(not(feature = "router"), allow(dead_code))]

//! Router facade.
//!
//! Minimal builds get compile-time shims; router-enabled builds use `sb_core`
//! directly from call sites.

// Router functionality is provided through direct sb_core imports in other modules

// No-router compatibility shims keep minimal builds compiling while routing
// commands remain gated behind the `router` feature.
#[cfg(not(feature = "router"))]
pub mod coverage {
    pub const fn reset() {
        // No-op when router is disabled
    }

    #[must_use]
    pub fn snapshot() -> serde_json::Value {
        serde_json::json!({})
    }
}

#[cfg(not(feature = "router"))]
pub mod analyze_fix {
    #[must_use]
    pub fn supported_patch_kinds_json() -> String {
        r#"{"error": "router feature not enabled"}"#.to_string()
    }
}

#[cfg(not(feature = "router"))]
pub mod preview {
    use anyhow::Result;

    /// # Errors
    /// Returns an error if the router feature is not enabled.
    pub fn build_index_from_rules(_rules: &str) -> Result<()> {
        anyhow::bail!("app built without `router` feature")
    }

    /// # Errors
    /// Returns an error if the router feature is not enabled.
    pub fn build_index_from_rules_plus(_rules: &str, _cwd: Option<&std::path::Path>) -> Result<()> {
        anyhow::bail!("app built without `router` feature")
    }

    /// # Errors
    /// Returns an error if the router feature is not enabled.
    pub fn preview_decide_http(_idx: &(), _target: &str) -> Result<PreviewResult> {
        anyhow::bail!("app built without `router` feature")
    }

    /// # Errors
    /// Returns an error if the router feature is not enabled.
    pub fn preview_decide_udp(_idx: &(), _target: &str) -> Result<PreviewResult> {
        anyhow::bail!("app built without `router` feature")
    }

    #[must_use]
    pub const fn derive_compare_targets(_a: &str, _b: &str, _limit: Option<usize>) -> Vec<String> {
        Vec::new()
    }

    #[must_use]
    pub const fn derive_targets(_dsl: &str, _limit: Option<usize>) -> Vec<String> {
        Vec::new()
    }

    #[must_use]
    pub fn analyze_dsl(_dsl: &str) -> AnalysisResult {
        AnalysisResult::default()
    }

    #[must_use]
    pub fn analysis_to_json(_analysis: &AnalysisResult) -> String {
        r#"{"error": "router feature not enabled"}"#.to_string()
    }

    #[derive(Default)]
    pub struct PreviewResult {
        pub decision: String,
        pub reason: String,
        pub reason_kind: String,
    }

    #[derive(Default)]
    pub struct AnalysisResult {
        // Empty placeholder struct
    }
}

#[cfg(not(feature = "router"))]
pub mod minijson {
    pub enum Val {
        Str(&'static str),
    }

    #[must_use]
    pub fn obj(_items: &[(&str, Val)]) -> String {
        r#"{"error": "router feature not enabled"}"#.to_string()
    }
}

#[cfg(not(feature = "router"))]
pub mod dsl_plus {
    use anyhow::Result;

    /// # Errors
    /// Returns an error if the router feature is not enabled.
    pub fn expand_dsl_plus(_text: &str, _cwd: Option<&std::path::Path>) -> Result<String> {
        anyhow::bail!("app built without `router` feature")
    }
}

#[cfg(not(feature = "router"))]
pub mod explain {
    use anyhow::Result;

    /// # Errors
    /// Returns an error if the router feature is not enabled.
    pub fn explain_decision(_query: &ExplainQuery) -> Result<ExplainResult> {
        anyhow::bail!("app built without `router` feature")
    }

    #[derive(Default)]
    pub struct ExplainQuery {
        pub host: String,
        pub port: u16,
    }

    #[derive(Default)]
    pub struct ExplainResult {
        pub decision: String,
        pub reason: String,
        pub reason_kind: String,
    }
}

#[cfg(not(feature = "router"))]
pub mod engine {
    #[allow(unused_imports)]
    use anyhow::Result;

    pub struct RouterHandle;

    impl RouterHandle {
        #[must_use]
        pub const fn from_env() -> Self {
            Self
        }
    }
}

#[cfg(not(feature = "router"))]
pub mod analyze {
    #[derive(Default)]
    pub struct Report {
        // Empty placeholder
    }

    #[must_use]
    pub fn analyze(_text: &str) -> Report {
        Report::default()
    }
}

#[cfg(not(feature = "router"))]
pub mod explain_index {
    pub const fn rebuild_periodic(
        _router: crate::router::engine::RouterHandle,
        _interval: std::time::Duration,
    ) {
        // No-op
    }

    #[must_use]
    pub fn snapshot_digest(_idx: &()) -> String {
        "no-router".to_string()
    }
}

#[cfg(not(feature = "router"))]
pub mod patch_plan {
    use anyhow::Result;

    /// # Errors
    /// Returns an error if the router feature is not enabled.
    pub fn build_plan(_old: &str, _new: &str, _ctx: Option<&str>) -> Result<()> {
        anyhow::bail!("app built without `router` feature")
    }
}

#[cfg(not(feature = "router"))]
#[must_use]
pub fn rules_normalize(rules: &str) -> String {
    rules.to_string() // Pass-through when router disabled
}

#[cfg(not(feature = "router"))]
#[must_use]
pub const fn router_captured_rules() -> Option<Vec<String>> {
    None
}

#[cfg(not(feature = "router"))]
pub const fn get_index() {}

#[cfg(not(feature = "router"))]
pub struct Router;

#[cfg(not(feature = "router"))]
pub struct RouterHandle;

#[cfg(not(feature = "router"))]
pub mod routing {
    #[allow(unused_imports)]
    use anyhow::Result;

    pub mod explain {
        #[allow(unused_imports)]
        use anyhow::Result;

        pub struct ExplainEngine;

        impl ExplainEngine {
            /// # Errors
            /// Returns an error if the router feature is not enabled.
            pub fn from_config(_cfg: &sb_config::Config) -> Result<Self> {
                anyhow::bail!("app built without `router` feature")
            }

            #[must_use]
            pub fn explain(&self, _dest: &str, _with_trace: bool) -> ExplainResult {
                ExplainResult::default()
            }
        }

        #[derive(Default)]
        pub struct ExplainResult {
            pub dest: String,
            pub matched_rule: String,
            pub chain: Vec<String>,
            pub outbound: String,
            pub trace: Option<super::trace::Trace>,
        }
    }

    pub mod trace {
        #[derive(Default)]
        pub struct Trace {
            // Empty placeholder
        }
    }
}
