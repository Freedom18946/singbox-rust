#[cfg(feature = "subs_clash")]
#[test]
fn view_contains_kinds_count() {
    let y = r#"
rules:
  - DOMAIN,example.com,DIRECT
proxies:
  - { name: "a", type: "ss" }
  - { name: "b", type: "ss" }
  - { name: "c", type: "trojan" }
"#;
    let p = sb_subscribe::parse_clash::parse(y).unwrap();
    let j = sb_subscribe::convert_view::view_minijson(&p);
    assert!(j.contains("\"kinds_count\""));
    assert!(j.contains("\"outbound_kinds_count\""));
    assert!(j.contains("\"ss\":2"));
    assert!(j.contains("\"trojan\":1"));
}

#[cfg(feature = "subs_clash")]
#[test]
fn view_contains_sample_rules() {
    let y = r#"
rules:
  - DOMAIN,example.com,DIRECT
  - DOMAIN,test.com,PROXY
proxies:
  - { name: "a", type: "ss" }
"#;
    let p = sb_subscribe::parse_clash::parse(y).unwrap();
    let j = sb_subscribe::convert_view::view_minijson(&p);

    assert!(j.contains("\"sample_rules\""));
    // Rules are normalized during parsing (e.g., "exact:example.com=direct")
    assert!(j.contains("example.com"));
    assert!(j.contains("test.com"));
}
