#[cfg(any(feature="router", feature="sbcore_rules_tool"))]
use serde_json::json;

#[cfg(any(feature="router", feature="sbcore_rules_tool"))]
#[test]
fn register_builder_and_use() {
    // 直接使用 app::analyze::registry（无需 sb-core）
    let f = |v: &serde_json::Value| -> anyhow::Result<serde_json::Value> {
        Ok(json!({"ok":true,"data":v}))
    };
    app::analyze::registry::register("demo", f);
    let out = app::analyze::registry::build_by_kind("demo", &json!({"x":1})).unwrap();
    assert!(out["ok"].as_bool().unwrap());
    assert_eq!(out["data"]["x"].as_i64().unwrap(), 1);
}