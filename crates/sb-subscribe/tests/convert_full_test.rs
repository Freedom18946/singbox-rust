#[cfg(feature = "subs_full")]
#[test]
fn full_contains_dsl_and_json() {
    let y = r#"
rules:
  - DOMAIN,example.com,DIRECT
  - DOMAIN-KEYWORD,shop,DIRECT
proxies:
  - { name: "tro-a", type: "trojan" }
  - { name: "ss2-b", type: "ss2022" }
"#;
    let j = sb_subscribe::convert_full::convert_full_minijson(y, "clash", false, true).unwrap();
    assert!(j.contains("\"ok\":true"));
    assert!(j.contains("\"dsl\""));
    assert!(j.contains("\"view\""));
    assert!(j.contains("\"bindings\""));
    assert!(j.contains("outbounds")); // bindings 子结构
}
