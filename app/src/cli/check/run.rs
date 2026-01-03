//! Configuration Validation Engine / 配置校验引擎
//!
//! # Global Strategic Logic / 全局战略逻辑
//! This module implements the **Static Analysis Engine** for configuration files.
//! 本模块实现了配置文件的 **静态分析引擎**。
//!
//! ## Validation Workflow / 校验工作流
//! 1. **Parse / 解析**: Load JSON/YAML into a generic `Value` tree.
//! 2. **Schema Check / 模式检查**: Validate against the formal V2 schema (structure, types).
//! 3. **Logic Check / 逻辑检查**: Validate business rules (e.g., "rule must have an action").
//! 4. **Report / 报告**: Generate structured reports (Human/JSON/SARIF).
//!
//! ## Strategic Features / 战略特性
//! - **Fingerprinting / 指纹识别**: Calculates a stable hash of the normalized config to detect semantic changes.
//!   计算归一化配置的稳定哈希，以检测语义变化。
//! - **Semantic Diff / 语义差异**: Compares configurations logically rather than textually, ignoring formatting noise.
//!   在逻辑上而非文本上比较配置，忽略格式噪音。

use anyhow::{Context, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;

use super::args::CheckArgs;
use super::types::{push_err, push_warn, CheckIssue, CheckReport, IssueCode, IssueKind};
use crate::cli::GlobalArgs;
use crate::config_loader;
use crate::cli::output;
use crate::cli::Format;
use app::util;
use sb_config::compat as cfg_compat;
use sb_config::validator::v2;

/// Main check function
///
/// Exit codes:
/// - 0: Config is valid (no errors or warnings)
/// - 1: Config has warnings only (no errors)
/// - 2: Config has errors (with or without warnings)
pub fn run(global: &GlobalArgs, args: CheckArgs) -> Result<i32> {
    if !wants_extended_analysis(&args) {
        let entries = config_loader::collect_config_entries(&global.config, &global.config_directory)?;
        let cfg = config_loader::load_config(&entries)?;
        check_config(&cfg)?;
        return Ok(0);
    }

    let entries = config_loader::collect_config_entries(&global.config, &global.config_directory)?;
    let primary_path = match entries.as_slice() {
        [single] => single.path.clone(),
        _ => "merged".to_string(),
    };
    let mut raw = config_loader::load_merged_value(&entries)?;

    // Optional migration to v2 schema view
    if args.migrate {
        raw = cfg_compat::migrate_to_v2(&raw);
    }

    let mut issues: Vec<CheckIssue> = Vec::new();

    let mut minimized_raw: Option<Value> = None;
    if args.minimize || args.minimize_rules {
        let (minimized, action) = minimize_rules_value(&raw);
        minimized_raw = Some(minimized);
        let skipped = matches!(
            action,
            sb_config::minimize::MinimizeAction::SkippedByNegation
        );
        if skipped {
            push_warn(
                &mut issues,
                IssueCode::MinimizeSkippedByNegation,
                "/route/rules",
                "minimize skipped due to negation rules",
                None,
            );
            if args.format != "json" && args.format != "sarif" {
                eprintln!("MINIMIZE_SKIPPED: negation_present=true");
            }
        }
    }

    if args.minimize_rules {
        let out_json = minimized_raw.clone().unwrap_or_else(|| raw.clone());
        println!("{}", serde_json::to_string_pretty(&out_json)?);
        return Ok(0);
    }

    // Handle --print-fingerprint early return
    if args.print_fingerprint {
        let fingerprint = fingerprint_of(&raw);
        println!("{fingerprint}");
        return Ok(0);
    }

    // Schema v2 validation if enabled
    if args.schema_v2 || args.deny_unknown {
        // Determine if unknown fields should be warnings instead of errors
        let allow_unknown_validation = args.allow_unknown.is_some();
        let v2_issues = v2::validate_v2(&raw, allow_unknown_validation);
        // Convert v2 issues to CheckIssue format
        let allow_prefixes: Vec<String> = args
            .allow_unknown
            .as_ref()
            .map(|s| {
                s.split(',')
                    .map(|x| x.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        for issue_value in v2_issues {
            if let Some(mut converted_issue) = convert_v2_issue(&issue_value) {
                // Downgrade UnknownField to warning when allowed by prefix
                if converted_issue.code == IssueCode::UnknownField && !allow_prefixes.is_empty() {
                    let ptr = converted_issue.ptr.clone();
                    let allowed = allow_prefixes.iter().any(|p| ptr.starts_with(p));
                    if allowed {
                        converted_issue.kind = IssueKind::Warning;
                    }
                }
                issues.push(converted_issue);
            }
        }
    }

    // Schema dump if requested (early return)
    if args.schema && !args.schema_dump.is_empty() {
        match args.schema_dump.as_str() {
            "v1" => {
                println!("{}", serde_json::to_string_pretty(&schema_v1())?);
            }
            "v2" => {
                #[cfg(feature = "schema-v2")]
                {
                    let schema = sb_config::schema_v2::schema_v2()?;
                    println!("{}", serde_json::to_string_pretty(&schema)?);
                }
                #[cfg(not(feature = "schema-v2"))]
                {
                    eprintln!("schema v2 not available (build without feature)");
                    return Ok(2);
                }
            }
            _ => {}
        }
        return Ok(0);
    }

    // Config diff if requested (early return)
    if !args.diff_config.is_empty() {
        if args.diff_config.len() != 2 {
            eprintln!("--diff-config OLD NEW");
            return Ok(2);
        }
        return diff_configs(&args.diff_config[0], &args.diff_config[1], &args);
    }

    // Basic config validation
    validate_basic_config(&raw, &args, &mut issues)?;
    validate_geo_resources(&raw, &mut issues);

    // Generate report
    let ok = (issues.is_empty() || !args.strict)
        && !issues.iter().any(|i| matches!(i.kind, IssueKind::Error));

    let include_fingerprint = args.fingerprint || args.minimize;
    let fingerprint = if include_fingerprint {
        Some(fingerprint_of(&raw))
    } else {
        None
    };

    let canonical = if args.fingerprint {
        let mut norm = raw.clone();
        normalize_json(&mut norm);
        Some(norm)
    } else {
        None
    };

    let report = CheckReport {
        ok,
        file: primary_path.clone(),
        issues: issues.clone(),
        summary: serde_json::json!({
            "total_issues": issues.len(),
            "errors": issues.iter().filter(|i| matches!(i.kind, IssueKind::Error)).count(),
            "warnings": issues.iter().filter(|i| matches!(i.kind, IssueKind::Warning)).count(),
        }),
        fingerprint,
        canonical,
    };

    // Handle normalized/migrated output write if requested
    if args.write_normalized {
        let mut out_json = minimized_raw.unwrap_or_else(|| raw.clone());
        normalize_json(&mut out_json);
        // stamp schema_version when migrating or missing
        if out_json.get("schema_version").is_none() {
            if let Some(obj) = out_json.as_object_mut() {
                obj.insert("schema_version".into(), Value::from(2));
            }
        }
        let text = serde_json::to_string_pretty(&out_json)?;
        let out = if let Some(o) = &args.out {
            o.clone()
        } else {
            format!("{}.normalized.json", &primary_path)
        };
        util::write_atomic(&out, text.as_bytes()).with_context(|| format!("write {out}"))?;
    }

    // Output results (unified)
    let fmt = match args.format.as_str() {
        "json" => Format::Json,
        "sarif" => Format::Sarif,
        _ => Format::Human,
    };

    match fmt {
        Format::Sarif => {
            let sarif_text = to_sarif(&report);
            output::emit(
                Format::Sarif,
                || {
                    if ok {
                        "Config validation passed".to_string()
                    } else {
                        format!(
                            "{} issues ({} errors, {} warnings)",
                            issues.len(),
                            issues
                                .iter()
                                .filter(|i| matches!(i.kind, IssueKind::Error))
                                .count(),
                            issues
                                .iter()
                                .filter(|i| matches!(i.kind, IssueKind::Warning))
                                .count()
                        )
                    }
                },
                &serde_json::from_str::<serde_json::Value>(&sarif_text)
                    .unwrap_or_else(|_| serde_json::json!({})),
            );
        }
        _ => {
            output::emit(
                fmt,
                || {
                    if ok {
                        "Config validation passed".to_string()
                    } else {
                        let errs = issues
                            .iter()
                            .filter(|i| matches!(i.kind, IssueKind::Error))
                            .count();
                        let warns = issues.len().saturating_sub(errs);
                        format!("Validation failed: {errs} errors, {warns} warnings")
                    }
                },
                &report,
            );
        }
    }

    // Exit code: 0=ok, 1=warnings only (when !strict), 2=errors present
    let errors = issues.iter().any(|i| matches!(i.kind, IssueKind::Error));
    let warnings = issues.iter().any(|i| matches!(i.kind, IssueKind::Warning));
    let code = i32::from(errors) * 2 + i32::from(warnings);
    Ok(code)
}

fn wants_extended_analysis(args: &CheckArgs) -> bool {
    args.format != "text"
        || args.strict
        || args.schema
        || args.check_refs
        || args.deny_unknown
        || args.allow_unknown.is_some()
        || args.explain
        || args.enforce_apiversion
        || args.fingerprint
        || args.print_fingerprint
        || args.rules_dir.is_some()
        || args.normalize
        || args.autofix_plan
        || args.summary
        || args.explain_why
        || args.rule_graph
        || args.minimize_rules
        || args.apply_plan
        || args.with_rule_id
        || !args.diff_config.is_empty()
        || args.schema_v2
        || args.minimize
        || args.write_normalized
        || args.migrate
        || args.out.is_some()
}

pub(crate) fn check_config(cfg: &sb_config::Config) -> Result<()> {
    #[cfg(feature = "router")]
    {
        #[cfg(feature = "adapters")]
        sb_adapters::register_all();
        let cfg_ir = sb_config::present::to_ir(cfg)?;
        sb_core::runtime::Runtime::from_config_ir(&cfg_ir)
            .map_err(|e| anyhow::anyhow!("runtime init failed: {e}"))?;
        Ok(())
    }

    #[cfg(not(feature = "router"))]
    {
        cfg.build_registry_and_router()
    }
}

struct RuleMatch {
    action: String,
    conds: Vec<Option<HashSet<String>>>,
}

struct RuleDimension {
    keys: &'static [&'static str],
}

const RULE_DIMS: &[RuleDimension] = &[
    RuleDimension { keys: &["domain"] },
    RuleDimension {
        keys: &["domain_suffix"],
    },
    RuleDimension {
        keys: &["domain_keyword"],
    },
    RuleDimension {
        keys: &["domain_regex"],
    },
    RuleDimension { keys: &["geoip"] },
    RuleDimension { keys: &["geosite"] },
    RuleDimension {
        keys: &["ip_cidr", "ipcidr"],
    },
    RuleDimension {
        keys: &["source_ip_cidr"],
    },
    RuleDimension { keys: &["port"] },
    RuleDimension {
        keys: &["source_port"],
    },
    RuleDimension { keys: &["network"] },
    RuleDimension { keys: &["protocol"] },
    RuleDimension { keys: &["process"] },
];

fn minimize_rules_value(raw: &Value) -> (Value, sb_config::minimize::MinimizeAction) {
    let Some(rules) = rules_array(raw) else {
        return (raw.clone(), sb_config::minimize::MinimizeAction::Applied);
    };

    if rules.iter().any(rule_has_negation) {
        return (raw.clone(), sb_config::minimize::MinimizeAction::SkippedByNegation);
    }

    let mut kept: Vec<Value> = Vec::new();
    let mut kept_matches: Vec<Option<RuleMatch>> = Vec::new();

    for rule in rules {
        let candidate = build_rule_match(rule);
        let mut covered = false;
        if let Some(ref cand_match) = candidate {
            for prior in kept_matches.iter().flatten() {
                if rule_covers(prior, cand_match) {
                    covered = true;
                    break;
                }
            }
        }
        if covered {
            continue;
        }
        kept.push(rule.clone());
        kept_matches.push(candidate);
    }

    let mut out = raw.clone();
    if let Some(rules_mut) = rules_array_mut(&mut out) {
        *rules_mut = kept;
    }
    (out, sb_config::minimize::MinimizeAction::Applied)
}

fn rule_covers(earlier: &RuleMatch, later: &RuleMatch) -> bool {
    if earlier.action != later.action {
        return false;
    }
    for (earlier_dim, later_dim) in earlier.conds.iter().zip(later.conds.iter()) {
        match (earlier_dim, later_dim) {
            (None, _) => {}
            (Some(_), None) => return false,
            (Some(earlier_set), Some(later_set)) => {
                if !later_set.is_subset(earlier_set) {
                    return false;
                }
            }
        }
    }
    true
}

fn build_rule_match(rule: &Value) -> Option<RuleMatch> {
    let action = rule_action(rule)?;
    let mut conds = Vec::with_capacity(RULE_DIMS.len());
    for dim in RULE_DIMS {
        conds.push(extract_dim(rule, dim.keys));
    }
    Some(RuleMatch { action, conds })
}

fn rule_action(rule: &Value) -> Option<String> {
    if let Some(val) = rule.get("to").and_then(|v| v.as_str()) {
        return Some(val.to_string());
    }
    if let Some(val) = rule.get("outbound").and_then(|v| v.as_str()) {
        return Some(val.to_string());
    }
    None
}

fn extract_dim(rule: &Value, keys: &[&'static str]) -> Option<HashSet<String>> {
    let mut collected = Vec::new();
    for key in keys {
        if let Some(when_val) = rule.get("when").and_then(|v| v.get(*key)) {
            collect_values(when_val, &mut collected);
        }
        if let Some(rule_val) = rule.get(*key) {
            collect_values(rule_val, &mut collected);
        }
    }
    if collected.is_empty() {
        None
    } else {
        Some(collected.into_iter().collect())
    }
}

fn collect_values(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Array(items) => {
            for item in items {
                collect_values(item, out);
            }
        }
        Value::String(s) => out.push(s.clone()),
        Value::Number(n) => out.push(n.to_string()),
        Value::Bool(b) => out.push(b.to_string()),
        Value::Null => {}
        Value::Object(_) => out.push(value.to_string()),
    }
}

fn rule_has_negation(rule: &Value) -> bool {
    if let Some(when_obj) = rule.get("when").and_then(|v| v.as_object()) {
        if map_has_negation(when_obj) {
            return true;
        }
    }
    if let Some(rule_obj) = rule.as_object() {
        if map_has_negation(rule_obj) {
            return true;
        }
    }
    false
}

fn map_has_negation(map: &serde_json::Map<String, Value>) -> bool {
    map.iter()
        .filter(|(key, _)| key.starts_with("not_"))
        .any(|(_, value)| value_has_content(value))
}

fn value_has_content(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Array(items) => !items.is_empty(),
        Value::String(s) => !s.is_empty(),
        Value::Object(obj) => !obj.is_empty(),
        _ => true,
    }
}

fn rules_array(config: &Value) -> Option<&Vec<Value>> {
    if let Some(route) = config.get("route") {
        if let Some(rules) = route.get("rules").and_then(|v| v.as_array()) {
            return Some(rules);
        }
    }
    config.get("rules").and_then(|v| v.as_array())
}

fn rules_array_mut(config: &mut Value) -> Option<&mut Vec<Value>> {
    if let Value::Object(obj) = config {
        if obj.contains_key("route") {
            if let Some(Value::Object(route_obj)) = obj.get_mut("route") {
                if let Some(Value::Array(rules)) = route_obj.get_mut("rules") {
                    return Some(rules);
                }
            }
            return None;
        }
        if let Some(Value::Array(rules)) = obj.get_mut("rules") {
            return Some(rules);
        }
    }
    None
}

/// Basic config validation
fn validate_basic_config(
    config: &Value,
    args: &CheckArgs,
    issues: &mut Vec<CheckIssue>,
) -> Result<()> {
    // API version check
    if args.enforce_apiversion {
        let api_version = config.get("apiVersion").and_then(|x| x.as_str());
        let kind = config.get("kind").and_then(|x| x.as_str());

        if api_version.is_none() {
            push_warn(
                issues,
                IssueCode::SchemaMissingField,
                "/apiVersion",
                "missing apiVersion",
                Some("set to 'singbox/v1'"),
            );
        }

        if kind.is_none() {
            push_warn(
                issues,
                IssueCode::SchemaMissingField,
                "/kind",
                "missing kind",
                Some("set to 'Configuration'"),
            );
        }
    }

    // Basic structure validation
    if let Some(route) = config.get("route") {
        if let Some(rules) = route.get("rules") {
            if let Some(rules_array) = rules.as_array() {
                for (i, rule) in rules_array.iter().enumerate() {
                    validate_rule(rule, i, issues)?;
                }
            }
        }
    }

    Ok(())
}

#[allow(unused_variables)]
fn validate_geo_resources(config: &Value, issues: &mut Vec<CheckIssue>) {
    #[cfg(feature = "router")]
    {
        use sb_core::router::geo::{GeoIpDb, GeoSiteDb};
        use std::path::Path;

        if let Some(path) = config
            .pointer("/route/geoip/path")
            .and_then(|v| v.as_str())
        {
            if let Err(err) = GeoIpDb::load_from_file(Path::new(path)) {
                push_err(
                    issues,
                    IssueCode::TypeMismatch,
                    "/route/geoip/path",
                    &format!("geoip db load failed: {err}"),
                    None,
                );
            }
        }

        if let Some(path) = config
            .pointer("/route/geosite/path")
            .and_then(|v| v.as_str())
        {
            if let Err(err) = GeoSiteDb::load_from_file(Path::new(path)) {
                push_err(
                    issues,
                    IssueCode::TypeMismatch,
                    "/route/geosite/path",
                    &format!("geosite db load failed: {err}"),
                    None,
                );
            }
        }
    }
}

/// Basic rule validation
fn validate_rule(rule: &Value, index: usize, issues: &mut Vec<CheckIssue>) -> Result<()> {
    let ptr = format!("/route/rules/{index}");

    // Check if rule has at least one match condition
    let has_match = rule.get("domain").is_some()
        || rule.get("domain_suffix").is_some()
        || rule.get("domain_keyword").is_some()
        || rule.get("domain_regex").is_some()
        || rule.get("ip_cidr").is_some()
        || rule.get("source_ip_cidr").is_some()
        || rule.get("port").is_some()
        || rule.get("port_range").is_some()
        || rule.get("source_port").is_some()
        || rule.get("source_port_range").is_some()
        || rule.get("process_name").is_some()
        || rule.get("process_path").is_some()
        || rule.get("process").is_some()
        || rule.get("protocol").is_some()
        || rule.get("network").is_some()
        || rule.get("geoip").is_some()
        || rule.get("geosite").is_some();

    if !has_match {
        push_warn(
            issues,
            IssueCode::SchemaInvalid,
            &ptr,
            "rule has no match conditions",
            Some("add at least one match condition"),
        );
    }

    // Check if rule has an action (v1 `outbound` or v2 `to`)
    if rule.get("outbound").is_none() && rule.get("to").is_none() {
        push_err(
            issues,
            IssueCode::SchemaMissingField,
            &format!("{ptr}/outbound"),
            "rule missing outbound",
            Some("specify an outbound/to action"),
        );
    }

    Ok(())
}

/// Generate minimal v1 schema
fn schema_v1() -> Value {
    serde_json::json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "properties": {
            "apiVersion": {"type": "string"},
            "kind": {"type": "string"},
            "route": {
                "type": "object",
                "properties": {
                    "rules": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "outbound": {"type": "string"}
                            },
                            "required": ["outbound"]
                        }
                    }
                }
            }
        }
    })
}

/// Convert report to SARIF format
fn to_sarif(rep: &CheckReport) -> String {
    use serde_json::json;
    let results: Vec<Value> = rep
        .issues
        .iter()
        .map(|i| {
            let level = match i.kind {
                IssueKind::Error => "error",
                IssueKind::Warning => "warning",
            };
            let rule_id = format!("{:?}", i.code);

            // Create the basic result structure with minimal ptr→region mapping
            let mut result = json!({
                "ruleId": rule_id,
                "level": level,
                "message": { "text": i.msg },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": rep.file },
                        "region": {
                            "startLine": 1
                        }
                    },
                    "message": { "text": format!("ptr: {}", i.ptr) }
                }]
            });

            // Add hint as additional information if present
            if let Some(hint) = &i.hint {
                result["message"]["text"] = json!(format!("{} (hint: {})", i.msg, hint));
            }

            result
        })
        .collect();

    // Generate rules metadata from the issues
    let mut rules_map = std::collections::BTreeMap::new();
    for issue in &rep.issues {
        let rule_id = format!("{:?}", issue.code);
        if !rules_map.contains_key(&rule_id) {
            rules_map.insert(
                rule_id.clone(),
                json!({
                    "id": rule_id,
                    "shortDescription": { "text": format!("Check rule: {}", rule_id) },
                    "helpUri": "https://example.invalid/singbox-rust/check-rules"
                }),
            );
        }
    }
    let rules: Vec<Value> = rules_map.into_values().collect();

    let sarif = json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "singbox-rust-check",
                    "informationUri": "https://example.invalid/singbox-rust",
                    "rules": rules
                }
            },
            "results": results
        }]
    });
    serde_json::to_string_pretty(&sarif).unwrap_or_else(|_| "{}".to_string())
}

/// Normalize JSON for consistent fingerprinting (recursive key sorting, remove comments)
fn normalize_json(v: &mut Value) {
    normalize_json_with_path(v, "");
}

/// Normalize JSON with path tracking for array field detection
fn normalize_json_with_path(v: &mut Value, path: &str) {
    match v {
        Value::Object(map) => {
            // Remove comment keys
            map.retain(|k, _| !k.starts_with("//") && !k.starts_with('#'));

            // Recursively normalize values with updated path
            for (key, val) in map.iter_mut() {
                let new_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                normalize_json_with_path(val, &new_path);
            }

            // serde_json::Map maintains insertion order, so we need to create a new sorted map
            let sorted_pairs: std::collections::BTreeMap<String, Value> =
                map.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
            map.clear();
            for (k, v) in sorted_pairs {
                map.insert(k, v);
            }
        }
        Value::Array(arr) => {
            // First recursively normalize array items
            for (index, item) in arr.iter_mut().enumerate() {
                let new_path = format!("{path}[{index}]");
                normalize_json_with_path(item, &new_path);
            }

            // Check if this array should be sorted for stable fingerprinting
            if should_sort_array(path) {
                sort_array_for_fingerprint(arr);
            }
        }
        _ => {}
    }
}

/// Determine if an array at the given path should be sorted for fingerprint stability
fn should_sort_array(path: &str) -> bool {
    // Define collection-semantic array fields that should be sorted
    let sortable_paths = [
        "rules",
        "route.rules",
        "dns.servers",
        "geosite",
        "nodes",
        "inbounds",
        "outbounds",
    ];

    sortable_paths
        .iter()
        .any(|&pattern| path.ends_with(pattern) || path.contains(&format!(".{pattern}")))
}

/// Sort array items for consistent fingerprinting
fn sort_array_for_fingerprint(arr: &mut [Value]) {
    arr.sort_by(|a, b| {
        // Generate a stable sort key from the JSON value
        let key_a = json_sort_key(a);
        let key_b = json_sort_key(b);
        key_a.cmp(&key_b)
    });
}

/// Generate a sort key for JSON values
fn json_sort_key(v: &Value) -> String {
    match v {
        Value::Object(map) => {
            // For objects, create a key from important identifying fields
            if let Some(type_val) = map.get("type") {
                if let Some(name_val) = map.get("name") {
                    return format!(
                        "{}:{}",
                        type_val.as_str().unwrap_or(""),
                        name_val.as_str().unwrap_or("")
                    );
                }
                return type_val.as_str().unwrap_or("").to_string();
            }
            if let Some(outbound_val) = map.get("outbound") {
                return outbound_val.as_str().unwrap_or("").to_string();
            }
            if let Some(domain_suffix_val) = map.get("domain_suffix") {
                return domain_suffix_val.as_str().unwrap_or("").to_string();
            }
            // Fallback: use JSON string representation
            serde_json::to_string(v).unwrap_or_default()
        }
        Value::String(s) => s.clone(),
        _ => serde_json::to_string(v).unwrap_or_default(),
    }
}

/// Calculate SHA256-8 fingerprint of normalized config
fn fingerprint_of(v: &Value) -> String {
    let mut norm = v.clone();
    normalize_json(&mut norm);
    let serialized = serde_json::to_vec(&norm).unwrap_or_else(|_| b"{}".to_vec());
    let mut hasher = Sha256::new();
    hasher.update(&serialized);
    let result = hasher.finalize();
    // Return first 8 hex characters (32 bits)
    format!(
        "{:08x}",
        u32::from_be_bytes([result[0], result[1], result[2], result[3]])
    )
}

/// Convert v2 validator output to `CheckIssue` format
fn convert_v2_issue(v2_issue: &Value) -> Option<CheckIssue> {
    let kind_str = v2_issue.get("kind")?.as_str()?;
    let kind = match kind_str {
        "error" => IssueKind::Error,
        "warning" => IssueKind::Warning,
        _ => IssueKind::Warning,
    };

    let code_str = v2_issue.get("code")?.as_str()?;
    let code = match code_str {
        "UnknownField" => IssueCode::UnknownField,
        "MissingRequired" => IssueCode::MissingRequired,
        "TypeMismatch" => IssueCode::TypeMismatch,
        "Conflict" => IssueCode::Conflict,
        _ => IssueCode::SchemaInvalid,
    };

    let ptr = v2_issue.get("ptr")?.as_str()?.to_string();
    let msg = v2_issue.get("msg")?.as_str()?.to_string();
    let hint = v2_issue
        .get("hint")
        .and_then(|h| h.as_str())
        .map(std::string::ToString::to_string);

    Some(CheckIssue {
        kind,
        ptr,
        msg,
        code,
        hint,
        rule_id: None,
        key: None,
        members: None,
        tos: None,
        risk: None,
    })
}

/// Compare two configuration files and show differences
fn diff_configs(old_path: &str, new_path: &str, args: &CheckArgs) -> Result<i32> {
    // Load and parse both configs
    let old_config = load_config_file(old_path, args)?;
    let new_config = load_config_file(new_path, args)?;

    // Normalize both configs for comparison
    let mut old_normalized = old_config;
    let mut new_normalized = new_config;
    normalize_json_with_path(&mut old_normalized, "");
    normalize_json_with_path(&mut new_normalized, "");

    // Generate fingerprints
    let old_fingerprint = fingerprint_of(&old_normalized);
    let new_fingerprint = fingerprint_of(&new_normalized);

    if old_fingerprint == new_fingerprint {
        println!("Configs are identical (no differences found)");
        return Ok(0);
    }

    println!("Config differences detected:");
    println!(
        "Old: {} (fingerprint: {})",
        old_path,
        &old_fingerprint[..16]
    );
    println!(
        "New: {} (fingerprint: {})",
        new_path,
        &new_fingerprint[..16]
    );
    println!();

    // Compare key sections
    diff_section(
        &old_normalized,
        &new_normalized,
        "inbounds",
        "Inbound configurations",
    );
    diff_section(
        &old_normalized,
        &new_normalized,
        "outbounds",
        "Outbound configurations",
    );
    diff_section(
        &old_normalized,
        &new_normalized,
        "route",
        "Route configuration",
    );
    diff_section(&old_normalized, &new_normalized, "dns", "DNS configuration");
    diff_section(&old_normalized, &new_normalized, "log", "Log configuration");
    diff_section(
        &old_normalized,
        &new_normalized,
        "experimental",
        "Experimental features",
    );

    Ok(1) // Return 1 to indicate differences found
}

/// Load and parse a config file
fn load_config_file(path: &str, args: &CheckArgs) -> Result<Value> {
    let data = fs::read(path).with_context(|| format!("read config {path}"))?;
    let mut raw: Value = if path.ends_with(".yaml") || path.ends_with(".yml") {
        serde_yaml::from_slice(&data).with_context(|| "parse as yaml")?
    } else {
        serde_json::from_slice(&data).with_context(|| "parse as json")?
    };

    // Apply migration if requested
    if args.migrate {
        raw = cfg_compat::migrate_to_v2(&raw);
    }

    Ok(raw)
}

/// Compare a specific section of two configs
fn diff_section(old: &Value, new: &Value, section: &str, description: &str) {
    let old_section = old.get(section);
    let new_section = new.get(section);

    match (old_section, new_section) {
        (Some(old_val), Some(new_val)) => {
            if old_val != new_val {
                println!("{description}: MODIFIED");
                print_section_diff(old_val, new_val, section);
            }
        }
        (Some(_), None) => {
            println!("{description}: REMOVED");
        }
        (None, Some(_)) => {
            println!("{description}: ADDED");
        }
        (None, None) => {
            // Both missing, no difference
        }
    }
}

/// Print differences within a section
fn print_section_diff(old: &Value, new: &Value, section: &str) {
    match (old, new) {
        (Value::Object(old_map), Value::Object(new_map)) => {
            // Check for added/removed/modified keys
            let old_keys: std::collections::HashSet<_> = old_map.keys().collect();
            let new_keys: std::collections::HashSet<_> = new_map.keys().collect();

            for key in new_keys.difference(&old_keys) {
                println!("  + {section}.{key}");
            }

            for key in old_keys.difference(&new_keys) {
                println!("  - {section}.{key}");
            }

            for key in old_keys.intersection(&new_keys) {
                if old_map[*key] != new_map[*key] {
                    println!("  ~ {section}.{key}");
                }
            }
        }
        (Value::Array(old_arr), Value::Array(new_arr)) => {
            if old_arr.len() != new_arr.len() {
                println!(
                    "  {} length: {} -> {}",
                    section,
                    old_arr.len(),
                    new_arr.len()
                );
            }
            // Could add more detailed array comparison here
        }
        _ => {
            println!("  {section} value changed");
        }
    }
}
#[cfg(test)]
mod tests_schema_lock {
    use super::*;

    #[test]
    fn check_json_schema_locked() {
        let rep = CheckReport {
            ok: false,
            file: "demo.json".into(),
            issues: vec![CheckIssue {
                kind: IssueKind::Error,
                ptr: "/inbounds/0/port".into(),
                msg: "port must be integer".into(),
                code: IssueCode::TypeMismatch,
                hint: Some("1..65535".into()),
                rule_id: None,
                key: None,
                members: None,
                tos: None,
                risk: None,
            }],
            summary: serde_json::json!({"total_issues":1, "errors":1, "warnings":0}),
            fingerprint: Some("deadbeef".into()),
            canonical: None,
        };
        let s = serde_json::to_string_pretty(&rep).unwrap();
        // 锁定字段顺序/必需项（回归友好）：前三行严格匹配
        let lines: Vec<&str> = s.lines().collect();
        assert!(lines[0].contains('{'));
        assert!(lines[1].contains("\"ok\""));
        assert!(lines[2].contains("\"file\""));
        assert!(s.contains("\"issues\""));
        assert!(s.contains("\"summary\""));
    }

    #[test]
    fn check_sarif_schema_locked() {
        let rep = CheckReport {
            ok: false,
            file: "demo.json".into(),
            issues: vec![CheckIssue {
                kind: IssueKind::Warning,
                ptr: "/route/rules/0".into(),
                msg: "rule has no match conditions".into(),
                code: IssueCode::SchemaInvalid,
                hint: Some("add at least one match condition".into()),
                rule_id: None,
                key: None,
                members: None,
                tos: None,
                risk: None,
            }],
            summary: serde_json::json!({"total_issues":1, "errors":0, "warnings":1}),
            fingerprint: None,
            canonical: None,
        };
        let s = to_sarif(&rep);
        // 顶层键顺序和必需项
        assert!(s.contains("\"version\": \"2.1.0\""));
        assert!(s.contains("\"runs\""));
        assert!(s.contains("\"tool\""));
        assert!(s.contains("\"results\""));
        // result 基本字段
        assert!(s.contains("\"ruleId\""));
        assert!(s.contains("\"message\""));
        assert!(s.contains("\"locations\""));
    }
}
