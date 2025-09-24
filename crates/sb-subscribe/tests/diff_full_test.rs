#[cfg(all(feature = "subs_diff", feature = "subs_clash"))]
#[test]
fn diff_full_basic() {
    let lhs = r#"
rules:
  - DOMAIN,example.com,DIRECT
proxies:
  - { name: "tro-a", type: "trojan" }
"#;
    let rhs = r#"
rules:
  - DOMAIN,example.com,PROXY
  - DOMAIN-KEYWORD,shop,DIRECT
proxies:
  - { name: "tro-a", type: "trojan" }
  - { name: "ss2-b", type: "ss2022" }
"#;
    let j = sb_subscribe::diff_full::diff_full_minijson(lhs, rhs, "clash", false, true).unwrap();
    assert!(j.contains("\"ok\":true"));
    assert!(j.contains("\"dsl_patch\""));
    assert!(j.contains("\"kinds_count_lhs\""));
    assert!(j.contains("\"kinds_count_rhs\""));
    // 补丁至少包含一次 '-' 或 '+'
    assert!(j.contains('-') || j.contains('+'));
}
