#[cfg(any(feature = "router", feature = "sbcore_rules_tool"))]
use serde_json::json;

#[cfg(any(feature = "router", feature = "sbcore_rules_tool"))]
#[test]
fn register_builder_and_use() {
    // 直接使用 app::analyze::registry（无需 sb-core）
    let f = |v: &serde_json::Value| -> anyhow::Result<serde_json::Value> {
        Ok(json!({"ok":true,"data":v}))
    };
    let registry = app::analyze::registry::AnalyzeRegistry::default();
    registry.register("demo", f);
    let out = registry.build_by_kind("demo", &json!({"x":1})).unwrap();
    assert!(out["ok"].as_bool().unwrap());
    assert_eq!(out["data"]["x"].as_i64().unwrap(), 1);
}

#[cfg(feature = "sbcore_rules_tool")]
#[test]
fn default_registry_uses_real_core_patch_builder() {
    let registry = app::analyze::registry::AnalyzeRegistry::default();
    let out = registry
        .build_by_kind(
            "port_aggregate",
            &json!({
                "text": "port:80=direct\nport:443=direct\n",
                "file": "rules.conf"
            }),
        )
        .expect("registered core patch builder");

    let patch_text = out["patch"]["text"].as_str().expect("patch text");
    assert!(patch_text.contains("+portset:80,443=direct"));
    assert!(!patch_text.contains("placeholder implementation"));
    assert_eq!(out["noop"].as_bool(), Some(false));
}
