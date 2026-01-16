#![cfg(feature = "router")]
use prost::Message;
use sb_core::router::geo::{Domain, GeoSite, GeoSiteDb, GeoSiteList, Type};
use sb_core::router::ruleset::binary;
use sb_core::router::ruleset::RuleSetFormat;
use sb_core::router::ruleset::{DefaultRule, DomainRule, Rule};

#[tokio::test]
async fn test_px007_geosite_protobuf_parity() {
    let dir = tempfile::tempdir().unwrap();
    let geosite_path = dir.path().join("geosite.db");

    // 1. Create a Protobuf GeoSite database
    let site = GeoSite {
        country_code: "TEST".to_string(), // Matches category "test"
        domain: vec![
            Domain {
                r#type: Type::Full as i32,
                value: "exact.example.com".to_string(),
            },
            Domain {
                r#type: Type::Domain as i32, // Suffix
                value: "suffix.example.com".to_string(),
            },
            Domain {
                r#type: Type::Plain as i32, // Keyword
                value: "keyword".to_string(),
            },
            Domain {
                r#type: Type::Regex as i32,
                value: "^regex.*com$".to_string(),
            },
        ],
    };
    let list = GeoSiteList { entry: vec![site] };
    let mut buf = Vec::new();
    list.encode(&mut buf).unwrap();
    std::fs::write(&geosite_path, buf).unwrap();

    // 2. Load it
    let geosite_db = GeoSiteDb::load_from_file(&geosite_path).unwrap();

    // 3. Verify matching
    assert!(geosite_db.match_domain("exact.example.com", "TEST"));
    assert!(geosite_db.match_domain("sub.suffix.example.com", "TEST")); // Suffix match
    assert!(geosite_db.match_domain("this-contains-keyword-here.com", "TEST")); // Keyword match
    assert!(geosite_db.match_domain("regex-test.com", "TEST")); // Regex match

    assert!(!geosite_db.match_domain("other.com", "TEST"));
    assert!(!geosite_db.match_domain("exact.example.com", "OTHER")); // Wrong category
}

#[tokio::test]
async fn test_px007_ruleset_srs_parity() {
    let dir = tempfile::tempdir().unwrap();
    let srs_path = dir.path().join("test.srs");

    // 1. Create a RuleSet with domain rules
    let rule = Rule::Default(DefaultRule {
        domain: vec![DomainRule::Exact("example.com".to_string())],
        ..Default::default()
    });

    // Write SRS (version 1)
    binary::write_to_file(&srs_path, &[rule], 1).await.unwrap();

    // 2. Load it
    let loaded_rs = binary::load_from_file(&srs_path, RuleSetFormat::Binary)
        .await
        .unwrap();
    assert_eq!(loaded_rs.rules.len(), 1);

    // Verify content
    match &loaded_rs.rules[0] {
        Rule::Default(r) => {
            assert_eq!(r.domain.len(), 1);
            match &r.domain[0] {
                DomainRule::Suffix(d) => assert_eq!(d, "example.com"),
                _ => panic!("Unexpected rule type: {:?}", r.domain[0]),
            }
        }
        _ => panic!("Unexpected rule type"),
    }
}
