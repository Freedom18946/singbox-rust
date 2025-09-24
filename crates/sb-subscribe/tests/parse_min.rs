#[cfg(feature = "subs_clash")]
#[test]
fn clash_map_min() {
    let y = r#"
rules:
  - DOMAIN-SUFFIX,example.com,DIRECT
proxies:
  - { name: "a", type: "ss" }
"#;
    let p = sb_subscribe::parse_clash::parse(y).unwrap();
    assert_eq!(p.rules.len(), 1);
    assert_eq!(p.outbounds.len(), 1);
}

#[cfg(feature = "subs_singbox")]
#[test]
fn sbox_map_min() {
    let j = r#"
{ "route": { "rules": [ { "outbound": "direct", "domain_suffix": ["example.com"] } ] },
  "outbounds": [ { "type": "direct", "tag": "direct" } ] }
"#;
    let p = sb_subscribe::parse_singbox::parse(j).unwrap();
    assert_eq!(p.rules.len(), 1);
    assert_eq!(p.outbounds.len(), 1);
}
