//! Router facade module
//!
//! When the `router` feature is enabled, re-exports `sb_core::router` functionality.
//! When disabled, provides safe placeholder functions that return appropriate errors.

// Router functionality is provided through direct sb_core imports in other modules

// Safe placeholders when router feature is not enabled
#[cfg(not(feature = "router"))]
#[allow(dead_code)] // Scaffolding placeholders for when router is disabled
pub mod coverage {
    pub fn reset() {
        // No-op when router is disabled
    }

    pub fn snapshot() -> serde_json::Value {
        serde_json::json!({})
    }
}

#[cfg(not(feature = "router"))]
#[allow(dead_code)] // Scaffolding placeholders
pub mod analyze_fix {
    pub fn supported_patch_kinds_json() -> String {
        r#"{"error": "router feature not enabled"}"#.to_string()
    }
}

#[cfg(not(feature = "router"))]
#[allow(dead_code)] // Scaffolding placeholders
pub mod preview {
    use anyhow::Result;

    pub fn build_index_from_rules(_rules: &str) -> Result<()> {
        anyhow::bail!("app built without `router` feature")
    }

    pub fn build_index_from_rules_plus(_rules: &str, _cwd: Option<&std::path::Path>) -> Result<()> {
        anyhow::bail!("app built without `router` feature")
    }

    pub fn preview_decide_http(_idx: &(), _target: &str) -> Result<PreviewResult> {
        anyhow::bail!("app built without `router` feature")
    }

    pub fn preview_decide_udp(_idx: &(), _target: &str) -> Result<PreviewResult> {
        anyhow::bail!("app built without `router` feature")
    }

    pub fn derive_compare_targets(_a: &str, _b: &str, _limit: Option<usize>) -> Vec<String> {
        vec![]
    }

    pub fn derive_targets(_dsl: &str, _limit: Option<usize>) -> Vec<String> {
        vec![]
    }

    pub fn analyze_dsl(_dsl: &str) -> AnalysisResult {
        AnalysisResult::default()
    }

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
    #[allow(dead_code)]
    pub enum Val {
        Str(&'static str),
    }

    #[allow(dead_code)]
    pub fn obj(_items: &[(&str, Val)]) -> String {
        r#"{"error": "router feature not enabled"}"#.to_string()
    }
}

#[cfg(not(feature = "router"))]
pub mod dsl_plus {
    use anyhow::Result;

    #[allow(dead_code)]
    pub fn expand_dsl_plus(_text: &str, _cwd: Option<&std::path::Path>) -> Result<String> {
        anyhow::bail!("app built without `router` feature")
    }
}

#[cfg(not(feature = "router"))]
pub mod explain {
    use anyhow::Result;

    #[allow(dead_code)]
    pub fn explain_decision(_query: &ExplainQuery) -> Result<ExplainResult> {
        anyhow::bail!("app built without `router` feature")
    }

    #[derive(Default)]
    #[allow(dead_code)]
    pub struct ExplainQuery {
        pub host: String,
        pub port: u16,
    }

    #[derive(Default)]
    #[allow(dead_code)]
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

    #[allow(dead_code)]
    pub struct RouterHandle;

    impl RouterHandle {
        #[allow(dead_code)]
        pub fn from_env() -> Self {
            RouterHandle
        }
    }
}

#[cfg(not(feature = "router"))]
pub mod analyze {
    #[derive(Default)]
    #[allow(dead_code)]
    pub struct Report {
        // Empty placeholder
    }

    #[allow(dead_code)]
    pub fn analyze(_text: &str) -> Report {
        Report::default()
    }
}

#[cfg(not(feature = "router"))]
pub mod explain_index {
    #[allow(dead_code)]
    pub fn rebuild_periodic(_router: super::engine::RouterHandle, _interval: std::time::Duration) {
        // No-op
    }

    #[allow(dead_code)]
    pub fn snapshot_digest(_idx: &()) -> String {
        "no-router".to_string()
    }
}

#[cfg(not(feature = "router"))]
pub mod patch_plan {
    use anyhow::Result;

    #[allow(dead_code)]
    pub fn build_plan(_old: &str, _new: &str, _ctx: Option<&str>) -> Result<()> {
        anyhow::bail!("app built without `router` feature")
    }
}

#[cfg(not(feature = "router"))]
#[allow(dead_code)] // Scaffolding placeholder
pub fn rules_normalize(_rules: &str) -> String {
    _rules.to_string() // Pass-through when router disabled
}

#[cfg(not(feature = "router"))]
#[allow(dead_code)] // Scaffolding placeholder
pub fn router_captured_rules() -> Option<Vec<String>> {
    None
}

#[cfg(not(feature = "router"))]
#[allow(dead_code)] // Scaffolding placeholder
pub fn get_index() {}

#[cfg(not(feature = "router"))]
#[allow(dead_code)] // Scaffolding placeholder
pub struct Router;

#[cfg(not(feature = "router"))]
#[allow(dead_code)] // Scaffolding placeholder
pub struct RouterHandle;

// Provide routing module placeholder when router feature is disabled
#[cfg(not(feature = "router"))]
#[allow(dead_code)] // Scaffolding placeholders
pub mod routing {
    #[allow(unused_imports)]
    use anyhow::Result;

    pub mod explain {
        #[allow(unused_imports)]
        use anyhow::Result;

        #[allow(dead_code)]
        pub struct ExplainEngine;

        impl ExplainEngine {
            #[allow(dead_code)]
            pub fn from_config(_cfg: &sb_config::Config) -> Result<Self> {
                anyhow::bail!("app built without `router` feature")
            }

            #[allow(dead_code)]
            pub fn explain(&self, _dest: &str, _with_trace: bool) -> ExplainResult {
                ExplainResult::default()
            }
        }

        #[derive(Default)]
        #[allow(dead_code)]
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
        #[allow(dead_code)]
        pub struct Trace {
            // Empty placeholder
        }
    }
}
