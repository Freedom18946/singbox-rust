use super::emit_issue;
use sb_types::IssueCode;
use serde_json::Value;

/// Validate root-level schema: load embedded schema, check `schema_version`, check unknown fields.
///
/// Returns `true` if validation should continue with domain passes, `false` if schema load failed
/// (caller should return `issues` as-is without running domain passes).
pub(super) fn validate_root_schema(
    doc: &Value,
    allow_unknown: bool,
    issues: &mut Vec<Value>,
) -> bool {
    let schema_text = include_str!("../v2_schema.json");
    let schema: Value = match serde_json::from_str(schema_text) {
        Ok(v) => v,
        Err(_) => {
            issues.push(emit_issue(
                "error",
                IssueCode::Conflict,
                "/",
                "schema load failed",
                "internal",
            ));
            return false;
        }
    };

    // schema_version check (must be 2)
    match doc.get("schema_version") {
        Some(v) => {
            if v.as_u64() != Some(2) {
                issues.push(emit_issue(
                    "error",
                    IssueCode::TypeMismatch,
                    "/schema_version",
                    "schema_version must be 2",
                    "set to 2",
                ));
            }
        }
        None => {
            issues.push(emit_issue(
                "warning",
                IssueCode::MissingRequired,
                "/schema_version",
                "missing schema_version (assuming v2)",
                "add: 2",
            ));
        }
    }

    // Root additionalProperties=false check
    if let (Some(obj), Some(props)) = (
        doc.as_object(),
        schema.get("properties").and_then(|p| p.as_object()),
    ) {
        for k in obj.keys() {
            // Allow $schema (Go optional field for JSON Schema tooling)
            if k == "$schema" {
                continue;
            }
            if !props.contains_key(k) {
                let kind = if allow_unknown { "warning" } else { "error" };
                issues.push(emit_issue(
                    kind,
                    IssueCode::UnknownField,
                    &format!("/{}", k),
                    "unknown field",
                    "remove it",
                ));
            }
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn schema_version_correct_no_issue() {
        let doc = json!({"schema_version": 2});
        let mut issues = Vec::new();
        let cont = validate_root_schema(&doc, false, &mut issues);
        assert!(cont);
        let version_issues: Vec<_> = issues
            .iter()
            .filter(|i| {
                i["ptr"]
                    .as_str()
                    .is_some_and(|p| p.contains("schema_version"))
            })
            .collect();
        assert!(
            version_issues.is_empty(),
            "schema_version=2 should produce no version issue, got: {:?}",
            version_issues
        );
    }

    #[test]
    fn schema_version_wrong_emits_type_mismatch() {
        let doc = json!({"schema_version": 99});
        let mut issues = Vec::new();
        let cont = validate_root_schema(&doc, false, &mut issues);
        assert!(cont);
        let found: Vec<_> = issues
            .iter()
            .filter(|i| {
                i["code"].as_str() == Some("TypeMismatch")
                    && i["ptr"].as_str() == Some("/schema_version")
            })
            .collect();
        assert_eq!(found.len(), 1, "wrong schema_version should emit TypeMismatch");
    }

    #[test]
    fn schema_version_missing_emits_warning() {
        let doc = json!({});
        let mut issues = Vec::new();
        let cont = validate_root_schema(&doc, false, &mut issues);
        assert!(cont);
        let found: Vec<_> = issues
            .iter()
            .filter(|i| {
                i["code"].as_str() == Some("MissingRequired")
                    && i["kind"].as_str() == Some("warning")
                    && i["ptr"].as_str() == Some("/schema_version")
            })
            .collect();
        assert_eq!(
            found.len(),
            1,
            "missing schema_version should emit MissingRequired warning"
        );
    }

    #[test]
    fn root_unknown_field_deny_emits_error() {
        let doc = json!({"schema_version": 2, "bogus_field": true});
        let mut issues = Vec::new();
        let cont = validate_root_schema(&doc, false, &mut issues);
        assert!(cont);
        let found: Vec<_> = issues
            .iter()
            .filter(|i| {
                i["code"].as_str() == Some("UnknownField")
                    && i["kind"].as_str() == Some("error")
                    && i["ptr"].as_str() == Some("/bogus_field")
            })
            .collect();
        assert_eq!(
            found.len(),
            1,
            "unknown field with allow_unknown=false should emit error"
        );
    }

    #[test]
    fn root_unknown_field_allow_emits_warning() {
        let doc = json!({"schema_version": 2, "bogus_field": true});
        let mut issues = Vec::new();
        let cont = validate_root_schema(&doc, true, &mut issues);
        assert!(cont);
        let found: Vec<_> = issues
            .iter()
            .filter(|i| {
                i["code"].as_str() == Some("UnknownField")
                    && i["kind"].as_str() == Some("warning")
                    && i["ptr"].as_str() == Some("/bogus_field")
            })
            .collect();
        assert_eq!(
            found.len(),
            1,
            "unknown field with allow_unknown=true should emit warning"
        );
    }

    #[test]
    fn dollar_schema_always_allowed() {
        let doc = json!({"schema_version": 2, "$schema": "http://json-schema.org/draft-07/schema#"});
        let mut issues = Vec::new();
        let cont = validate_root_schema(&doc, false, &mut issues);
        assert!(cont);
        let schema_issues: Vec<_> = issues
            .iter()
            .filter(|i| i["ptr"].as_str().is_some_and(|p| p.contains("$schema")))
            .collect();
        assert!(
            schema_issues.is_empty(),
            "$schema should be allowed even with allow_unknown=false, got: {:?}",
            schema_issues
        );
    }

    #[test]
    fn validate_root_schema_returns_true_on_success() {
        let doc = json!({"schema_version": 2});
        let mut issues = Vec::new();
        assert!(
            validate_root_schema(&doc, false, &mut issues),
            "should return true when schema loads successfully"
        );
    }

    // ───── WP-30ae pins ─────

    #[test]
    fn wp30ae_pin_schema_core_owner_is_schema_core_rs() {
        // Pin: root schema validation (schema load + schema_version check + root unknown field
        // check) is owned by schema_core.rs, not mod.rs.
        // Evidence: validate_root_schema is defined here and performs all three checks.
        let doc = json!({"schema_version": 99, "bogus": 1});
        let mut issues = Vec::new();
        let cont = validate_root_schema(&doc, false, &mut issues);
        assert!(cont);
        // Must produce both TypeMismatch (version) and UnknownField (bogus) from this module
        let has_type_mismatch = issues
            .iter()
            .any(|i| i["code"].as_str() == Some("TypeMismatch"));
        let has_unknown = issues
            .iter()
            .any(|i| i["code"].as_str() == Some("UnknownField"));
        assert!(
            has_type_mismatch && has_unknown,
            "schema_core.rs must own both schema_version check and root unknown field check"
        );
    }

    #[test]
    fn wp30ae_pin_validate_v2_delegates_root_schema() {
        // Pin: validate_v2() delegates root schema validation to schema_core.
        // Evidence: calling validate_v2() with wrong schema_version + unknown field produces
        // the same issues as calling validate_root_schema() directly.
        let doc = json!({"schema_version": 99, "bogus": 1});

        // Direct call
        let mut direct_issues = Vec::new();
        validate_root_schema(&doc, false, &mut direct_issues);

        // Through validate_v2
        let v2_issues = crate::validator::v2::validate_v2(&doc, false);

        // Every issue from direct call must appear in v2 output
        for di in &direct_issues {
            let code = di["code"].as_str().unwrap_or("");
            let ptr = di["ptr"].as_str().unwrap_or("");
            let found = v2_issues
                .iter()
                .any(|vi| vi["code"].as_str() == Some(code) && vi["ptr"].as_str() == Some(ptr));
            assert!(
                found,
                "validate_v2 must include schema_core issue code={} ptr={} (delegation pin)",
                code, ptr
            );
        }
    }
}
