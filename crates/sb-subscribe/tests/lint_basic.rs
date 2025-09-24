#[cfg(all(feature = "subs_lint", feature = "subs_clash"))]
#[test]
fn lint_and_autofix() {
    let y = r#"
rules:
  - DOMAIN,example.com,DIRECT
  - DOMAIN,example.com,DIRECT
  - DOMAIN-SUFFIX,example.com,PROXYX
  - DST-PORT,8080-80,DIRECT
proxies:
  - { name: "proxyx", type: "trojan" }
"#;
    let r = sb_subscribe::lint::lint_minijson(y, "clash", false, true).unwrap();
    assert!(r.json.contains("\"ok\":true"));
    assert!(r.json.contains("\"dup_rule\""));
    assert!(r.json.contains("\"reversed_portrange\""));
    assert!(r.json.contains("\"unknown_outbound\"")); // PROXYX vs proxyx
    let patch = sb_subscribe::lint_fix::make_autofix_patch(&r.dsl);
    assert!(patch.contains("\n-")); // 删除重复
    assert!(patch.contains("\n+portrange:80-8080=")); // 反向区间修正
}
