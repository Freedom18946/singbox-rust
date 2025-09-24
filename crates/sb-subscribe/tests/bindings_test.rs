#[cfg(feature = "subs_clash")]
#[test]
fn bindings_json() {
    let y = r#"
rules:
  - DOMAIN,example.com,DIRECT
proxies:
  - { name: "tro", type: "trojan" }
  - { name: "ss2", type: "ss2022" }
"#;
    let p = sb_subscribe::parse_clash::parse(y).unwrap();
    let j = sb_subscribe::bindings::bindings_minijson(&p);
    assert!(j.contains("\"name\":\"tro\""));
    assert!(j.contains("\"kind\":\"trojan\""));
    assert!(j.contains("\"name\":\"ss2\""));
    assert!(j.contains("\"kind\":\"ss2022\""));
}

// R135: Tests for subscription outbound binding enhancement (R134)
#[cfg(all(feature = "subs_clash", feature = "subs_bindings_dry"))]
#[tokio::test]
async fn bindings_dry_connect() {
    let y = r#"
rules:
  - DOMAIN,example.com,DIRECT
proxies:
  - { name: "direct", type: "direct" }
  - { name: "block", type: "block" }
  - { name: "trojan1", type: "trojan" }
"#;
    let p = sb_subscribe::parse_clash::parse(y).unwrap();

    // Test dry connect
    let result = sb_subscribe::bindings::dry_connect_test(&p, Some("test.example.com")).await;
    assert!(result.contains("\"dry_connect\""));
    assert!(result.contains("\"direct\""));
    assert!(result.contains("\"block\""));
    assert!(result.contains("\"trojan1\""));
    assert!(result.contains("\"status\""));
    assert!(result.contains("\"elapsed_ms\""));
}

#[cfg(all(feature = "subs_clash", feature = "subs_bindings_dry"))]
#[tokio::test]
async fn bindings_enhanced_with_connect() {
    let y = r#"
rules:
  - DOMAIN,example.com,DIRECT
proxies:
  - { name: "direct", type: "direct" }
  - { name: "ss1", type: "shadowsocks" }
"#;
    let p = sb_subscribe::parse_clash::parse(y).unwrap();

    // Test enhanced bindings with connect test
    let result =
        sb_subscribe::bindings::bindings_enhanced_minijson(&p, true, Some("localhost")).await;
    assert!(result.contains("\"outbounds\""));
    assert!(result.contains("\"test_status\""));
    assert!(result.contains("\"test_elapsed_ms\""));

    // Test enhanced bindings without connect test
    let result_no_test = sb_subscribe::bindings::bindings_enhanced_minijson(&p, false, None).await;
    assert!(result_no_test.contains("\"outbounds\""));
    assert!(!result_no_test.contains("\"test_status\""));
}
