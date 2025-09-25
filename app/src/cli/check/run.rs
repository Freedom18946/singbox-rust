use anyhow::{Context, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;

use super::args::CheckArgs;
use super::types::{push_err, push_warn, CheckIssue, CheckReport, IssueCode};
use sb_config::validator::v2;
use sb_config::compat as cfg_compat;

/// Main check function - returns exit code (0 = success, 1 = warnings, 2 = errors)
pub fn run(args: CheckArgs) -> Result<i32> {
    // Read and parse config file (support both JSON and YAML)
    let data = fs::read(&args.config).with_context(|| format!("read config {}", &args.config))?;
    let mut raw: Value = if args.config.ends_with(".yaml") || args.config.ends_with(".yml") {
        serde_yaml::from_slice(&data).with_context(|| "parse as yaml")?
    } else {
        serde_json::from_slice(&data).with_context(|| "parse as json")?
    };

    // Optional migration to v2 schema view
    if args.migrate {
        raw = cfg_compat::migrate_to_v2(&raw);
    }

    let mut issues: Vec<CheckIssue> = Vec::new();

    // Handle --print-fingerprint early return
    if args.print_fingerprint {
        let fingerprint = fingerprint_of(&raw);
        println!("{}", fingerprint);
        return Ok(0);
    }

    // Schema v2 validation if enabled
    if args.schema_v2 || args.deny_unknown {
        let v2_issues = v2::validate_v2(&raw);
        // Convert v2 issues to CheckIssue format
        let allow_prefixes: Vec<String> = args
            .allow_unknown
            .as_ref()
            .map(|s| s.split(',').map(|x| x.trim().to_string()).filter(|s| !s.is_empty()).collect())
            .unwrap_or_else(|| Vec::new());
        for issue_value in v2_issues {
            if let Some(mut converted_issue) = convert_v2_issue(&issue_value) {
                // Downgrade UnknownField to warning when allowed by prefix
                if converted_issue.code == IssueCode::UnknownField && !allow_prefixes.is_empty() {
                    let ptr = converted_issue.ptr.clone();
                    let allowed = allow_prefixes.iter().any(|p| ptr.starts_with(p));
                    if allowed {
                        converted_issue.kind = super::types::IssueKind::Warning;
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
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&sb_config::schema_v2::schema_v2())?
                    );
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
        // TODO: Implement config diff functionality
        eprintln!("Config diff functionality not yet implemented");
        return Ok(2);
    }

    // Basic config validation
    validate_basic_config(&raw, &args, &mut issues)?;

    // Generate report
    let ok = !issues
        .iter()
        .any(|i| matches!(i.kind, super::types::IssueKind::Error))
        && !(args.strict && !issues.is_empty());

    let fingerprint = if args.fingerprint {
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
        file: args.config.clone(),
        issues: issues.clone(),
        summary: serde_json::json!({
            "total_issues": issues.len(),
            "errors": issues.iter().filter(|i| matches!(i.kind, super::types::IssueKind::Error)).count(),
            "warnings": issues.iter().filter(|i| matches!(i.kind, super::types::IssueKind::Warning)).count(),
        }),
        fingerprint,
        canonical,
    };

    // Handle normalized/migrated output write if requested
    if args.write_normalized {
        let mut out_json = raw.clone();
        normalize_json(&mut out_json);
        // stamp schema_version when migrating or missing
        if out_json.get("schema_version").is_none() {
            if let Some(obj) = out_json.as_object_mut() { obj.insert("schema_version".into(), Value::from(2)); }
        }
        let text = serde_json::to_string_pretty(&out_json)?;
        let out = if let Some(o) = &args.out { o.clone() } else { format!("{}.normalized.json", &args.config) };
        sb_core::util::fs_atomic::write_atomic(&out, text.as_bytes())
            .with_context(|| format!("write {}", out))?;
    }

    // Output results
    match args.format.as_str() {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        "sarif" => {
            println!("{}", to_sarif(&report));
        }
        _ => {
            // Human-readable format
            if !issues.is_empty() {
                for issue in &issues {
                    let kind_str = match issue.kind {
                        super::types::IssueKind::Error => "ERROR",
                        super::types::IssueKind::Warning => "WARN",
                    };
                    if let Some(hint) = &issue.hint {
                        eprintln!(
                            "[{}][{:?}] {}: {}  (hint: {})",
                            kind_str, issue.code, issue.ptr, issue.msg, hint
                        );
                    } else {
                        eprintln!(
                            "[{}][{:?}] {}: {}",
                            kind_str, issue.code, issue.ptr, issue.msg
                        );
                    }
                }
            } else {
                println!("Config validation passed");
            }
        }
    }

    Ok(if ok { 0 } else { 1 })
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
                IssueCode::ApiVersionMissing,
                "/apiVersion",
                "missing apiVersion",
                Some("set to 'singbox/v1'"),
            );
        }

        if kind.is_none() {
            push_warn(
                issues,
                IssueCode::KindMissing,
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

/// Basic rule validation
fn validate_rule(rule: &Value, index: usize, issues: &mut Vec<CheckIssue>) -> Result<()> {
    let ptr = format!("/route/rules/{}", index);

    // Check if rule has at least one match condition
    let has_match = rule.get("domain").is_some()
        || rule.get("domain_suffix").is_some()
        || rule.get("domain_keyword").is_some()
        || rule.get("domain_regex").is_some()
        || rule.get("ip_cidr").is_some()
        || rule.get("source_ip_cidr").is_some()
        || rule.get("port").is_some()
        || rule.get("source_port").is_some();

    if !has_match {
        push_warn(
            issues,
            IssueCode::EmptyRuleMatch,
            &ptr,
            "rule has no match conditions",
            Some("add at least one match condition"),
        );
    }

    // Check if rule has an action
    if rule.get("outbound").is_none() {
        push_err(
            issues,
            IssueCode::MissingField,
            &format!("{}/outbound", ptr),
            "rule missing outbound",
            Some("specify an outbound"),
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
                super::types::IssueKind::Error => "error",
                super::types::IssueKind::Warning => "warning",
            };
            let rule_id = format!("{:?}", i.code);

            // Create the basic result structure
            let mut result = json!({
                "ruleId": rule_id,
                "level": level,
                "message": { "text": i.msg },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": rep.file },
                        "region": {
                            "message": { "text": i.ptr }
                        }
                    }
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
    serde_json::to_string_pretty(&sarif).unwrap()
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
            map.retain(|k, _| !k.starts_with("//") && !k.starts_with("#"));

            // Recursively normalize values with updated path
            for (key, val) in map.iter_mut() {
                let new_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{}.{}", path, key)
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
                let new_path = format!("{}[{}]", path, index);
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
        .any(|&pattern| path.ends_with(pattern) || path.contains(&format!(".{}", pattern)))
}

/// Sort array items for consistent fingerprinting
fn sort_array_for_fingerprint(arr: &mut Vec<Value>) {
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
    let serialized = serde_json::to_vec(&norm).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(&serialized);
    let result = hasher.finalize();
    // Return first 8 hex characters (32 bits)
    format!(
        "{:08x}",
        u32::from_be_bytes([result[0], result[1], result[2], result[3]])
    )
}

/// Convert v2 validator output to CheckIssue format
fn convert_v2_issue(v2_issue: &Value) -> Option<CheckIssue> {
    let kind_str = v2_issue.get("kind")?.as_str()?;
    let kind = match kind_str {
        "error" => super::types::IssueKind::Error,
        "warning" => super::types::IssueKind::Warning,
        _ => super::types::IssueKind::Warning,
    };

    let code_str = v2_issue.get("code")?.as_str()?;
    let code = match code_str {
        "UnknownField" => IssueCode::UnknownField,
        "MissingRequired" => IssueCode::MissingField,
        "TypeMismatch" => IssueCode::TypeMismatch,
        "Conflict" => IssueCode::MutualExclusive,
        _ => IssueCode::SchemaViolation,
    };

    let ptr = v2_issue.get("ptr")?.as_str()?.to_string();
    let msg = v2_issue.get("msg")?.as_str()?.to_string();
    let hint = v2_issue
        .get("hint")
        .and_then(|h| h.as_str())
        .map(|s| s.to_string());

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

#[cfg(test)]
mod tests_schema_lock {
    use super::*;

    #[test]
    fn check_json_schema_locked() {
        let rep = CheckReport {
            ok: false,
            file: "demo.json".into(),
            issues: vec![CheckIssue {
                kind: super::types::IssueKind::Error,
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
        assert!(lines[0].contains("{"));
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
                kind: super::types::IssueKind::Warning,
                ptr: "/route/rules/0".into(),
                msg: "rule has no match conditions".into(),
                code: IssueCode::EmptyRuleMatch,
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
