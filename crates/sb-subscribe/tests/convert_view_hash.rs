#[cfg(feature = "subs_clash")]
#[test]
fn view_contains_hashes() {
    let y = r#"
rules:
  - DOMAIN,example.com,DIRECT
proxies:
  - { name: "a", type: "ss" }
"#;
    let p = sb_subscribe::parse_clash::parse(y).unwrap();
    let j = sb_subscribe::convert_view::view_minijson(&p);
    assert!(j.contains("\"rules_hash\""));
    assert!(j.contains("\"outbounds_hash\""));
}
