#[cfg(feature = "subs_bindings")]
pub mod bindings;
#[cfg(feature = "subs_full")]
pub mod convert_full;
#[cfg(any(feature = "subs_view", feature = "subs_hash"))]
pub mod convert_view;
#[cfg(feature = "subs_diff")]
pub mod diff_full;
#[cfg(feature = "subs_http")]
pub mod http;
#[cfg(feature = "subs_lint")]
pub mod lint;
#[cfg(any(feature = "subs_lint_patch", feature = "subs_lint"))]
pub mod lint_fix;
pub mod model;
#[cfg(feature = "subs_clash")]
pub mod parse_clash;
#[cfg(feature = "subs_singbox")]
pub mod parse_singbox;
#[cfg(feature = "subs_preview_plan")]
pub mod preview_plan;
#[cfg(feature = "subs_ruleset_cache")]
pub mod providers;

/// 只读合并辅助计数（可后续接 metrics）
#[derive(Default, Debug, Clone)]
pub struct MergeStats {
    pub applied_ruleset: usize,
    pub applied_geosite: usize,
    pub skipped_unknown: usize,
}

#[cfg(test)]
fn _hash_for_test(s: &str) -> String {
    #[cfg(feature = "subs_hash")]
    {
        format!("{}", blake3::hash(s.as_bytes()).to_hex())
    }
    #[cfg(not(feature = "subs_hash"))]
    {
        "disabled".to_string()
    }
}
