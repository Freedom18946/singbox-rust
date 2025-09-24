#[cfg(all(feature = "subs_preview_plan", feature = "subs_clash"))]
#[test]
fn preview_plan_produces_patch_and_applies() {
    let y = r#"
rules:
  - DOMAIN,example.com,DIRECT
  - DOMAIN,example.com,DIRECT
  - DST-PORT,8080-80,DIRECT
proxies:
  - { name: "A", type: "trojan" }
"#;
    let r = sb_subscribe::preview_plan::preview_plan_minijson(y, "clash", false, true, None, true)
        .unwrap();
    assert!(r.json.contains("\"ok\":true"));
    assert!(r.json.contains("\"patch\""));
    // 应用后应当出现 dsl_out
    assert!(r.json.contains("\"dsl_out\""));
    // 补丁包含删除/添加
    assert!(r.patch.contains("\n-") || r.patch.contains("\n+"));
}

#[cfg(all(feature = "subs_preview_plan", feature = "subs_clash"))]
#[test]
fn test_unknown_kinds() {
    let input = "rules:\n  - DOMAIN,example.com,DIRECT\n";
    let format = "clash";
    let result = sb_subscribe::preview_plan::preview_plan_minijson(
        input,
        format,
        false,
        false,
        Some("unknown_kind,portrange_merge"),
        false,
    );
    assert!(result.is_ok());
    let json = result.unwrap().json;
    assert!(json.contains("unknown_kinds"));
    assert!(json.contains("unknown_kind"));
}
