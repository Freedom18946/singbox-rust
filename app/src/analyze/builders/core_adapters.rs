use anyhow::{Context, Result, bail};
use serde_json::Value;
use crate::analyze::builders::wrap_patch_text;
use crate::analyze::registry::register;

/// 将 sb_core 的功能适配为注册表 builder
/// 输入 JSON 约定:
/// {
///   "kind": "...",
///   "text": "<rules content>",
///   "file": "<optional filename>",
///   "report": {...}   // 可选，若未提供则由调用方自行分析
/// }

fn get_text_file(v: &Value) -> Result<(String, Option<String>)> {
    let text = v.get("text").and_then(|x| x.as_str())
        .context("missing field: text")?.to_string();
    let file = v.get("file").and_then(|x| x.as_str()).map(|s| s.to_string());
    Ok((text, file))
}

fn portrange_merge(input: &Value) -> Result<Value> {
    let (text, _file) = get_text_file(input)?;
    // 简化实现，返回模拟补丁
    let patch_text = format!("# Portrange merge patch for: {}\n# (placeholder implementation)", text.chars().take(50).collect::<String>());
    Ok(wrap_patch_text(patch_text))
}

fn suffix_shadow_cleanup(input: &Value) -> Result<Value> {
    let (text, _file) = get_text_file(input)?;
    // 简化实现，返回模拟补丁
    let patch_text = format!("# Suffix shadow cleanup patch for: {}\n# (placeholder implementation)", text.chars().take(50).collect::<String>());
    Ok(wrap_patch_text(patch_text))
}

fn port_aggregate(input: &Value) -> Result<Value> {
    let (text, _file) = get_text_file(input)?;
    // 简化实现，返回模拟补丁
    let patch_text = format!("# Port aggregate patch for: {}\n# (placeholder implementation)", text.chars().take(50).collect::<String>());
    Ok(wrap_patch_text(patch_text))
}

fn lint_autofix(input: &Value) -> Result<Value> {
    let (text, _file) = get_text_file(input)?;
    // 简化实现，返回模拟补丁
    let patch_text = format!("# Lint autofix patch for: {}\n# (placeholder implementation)", text.chars().take(50).collect::<String>());
    Ok(wrap_patch_text(patch_text))
}

pub fn register_core_adapters() {
    register("portrange_merge", portrange_merge as _);
    register("suffix_shadow_cleanup", suffix_shadow_cleanup as _);
    register("port_aggregate", port_aggregate as _);
    register("lint_autofix", lint_autofix as _);
}