#[cfg(all(feature = "subs_clash", feature = "subs_http"))]
#[test]
fn merge_ruleset_geosite_inline() {
    use std::collections::HashMap;
    let main = r#"
rules:
  - RULE-SET,ADBLOCK,REJECT
  - GEOSITE,SHOP,DIRECT
proxies:
  - { name: "a", type: "ss" }
"#;
    let mut m = HashMap::new();
    // ADBLOCK 规则集：两条基础域名
    m.insert(
        "ruleset:ADBLOCK".to_string(),
        "DOMAIN,ads.example.com\nDOMAIN-SUFFIX,track.example.org\n".to_string(),
    );
    // geosite SHOP：两条后缀
    m.insert(
        "geosite:SHOP".to_string(),
        "shop.com\nmall.net\n".to_string(),
    );
    let p = sb_subscribe::parse_clash::parse_with_providers(main, false, &m).unwrap();
    let joined = p
        .rules
        .iter()
        .map(|r| r.line.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(joined.contains("exact:ads.example.com=reject"));
    assert!(joined.contains("suffix:track.example.org=reject"));
    assert!(joined.contains("suffix:shop.com=direct"));
    assert!(joined.contains("suffix:mall.net=direct"));
    assert!(p.outbounds.len() == 1);
}
