use crate::analyze::registry::AnalyzeRegistry;
#[cfg(feature = "sbcore_rules_tool")]
use anyhow::{Context, Result};
#[cfg(feature = "sbcore_rules_tool")]
use sb_core::router::analyze_fix::CliPatch;
#[cfg(feature = "sbcore_rules_tool")]
use serde_json::json;
#[cfg(feature = "sbcore_rules_tool")]
use serde_json::Value;

#[cfg(feature = "sbcore_rules_tool")]
fn get_text_file(v: &Value) -> Result<(String, Option<String>)> {
    let text = v
        .get("text")
        .and_then(|x| x.as_str())
        .context("missing field: text")?
        .to_string();
    let file = v
        .get("file")
        .and_then(|x| x.as_str())
        .map(std::string::ToString::to_string);
    Ok((text, file))
}

#[cfg(feature = "sbcore_rules_tool")]
fn patch_json(patch: Option<CliPatch>) -> Value {
    match patch {
        Some(patch) => json!({
            "noop": false,
            "patch": {
                "text": patch.patch_text,
                "file": patch.file,
            }
        }),
        None => json!({
            "noop": true,
            "patch": {
                "text": "",
                "file": null,
            }
        }),
    }
}

#[cfg(feature = "sbcore_rules_tool")]
fn portrange_merge(input: &Value) -> Result<Value> {
    let (text, file) = get_text_file(input)?;
    let report = sb_core::router::analyze::analyze(&text);
    Ok(patch_json(
        sb_core::router::analyze_fix::build_portrange_merge_patch(&report, &text, file.as_deref()),
    ))
}

#[cfg(feature = "sbcore_rules_tool")]
fn suffix_shadow_cleanup(input: &Value) -> Result<Value> {
    let (text, file) = get_text_file(input)?;
    let report = sb_core::router::analyze::analyze(&text);
    Ok(patch_json(
        sb_core::router::analyze_fix::build_suffix_shadow_cleanup_patch(&report, file.as_deref()),
    ))
}

#[cfg(feature = "sbcore_rules_tool")]
fn port_aggregate(input: &Value) -> Result<Value> {
    let (text, file) = get_text_file(input)?;
    Ok(patch_json(
        sb_core::router::analyze_fix::build_port_aggregate_patch(&text, file.as_deref()),
    ))
}

#[cfg(feature = "sbcore_rules_tool")]
fn lint_autofix(input: &Value) -> Result<Value> {
    let (text, file) = get_text_file(input)?;
    let report = sb_core::router::analyze::analyze(&text);
    Ok(patch_json(
        sb_core::router::analyze_fix::build_lint_autofix_patch(&report, &text, file.as_deref()),
    ))
}

pub fn register_core_adapters(registry: &AnalyzeRegistry) {
    #[cfg(feature = "sbcore_rules_tool")]
    {
        registry.register("portrange_merge", portrange_merge as _);
        registry.register("suffix_shadow_cleanup", suffix_shadow_cleanup as _);
        registry.register("port_aggregate", port_aggregate as _);
        registry.register("lint_autofix", lint_autofix as _);
    }

    #[cfg(not(feature = "sbcore_rules_tool"))]
    let _ = registry;
}
