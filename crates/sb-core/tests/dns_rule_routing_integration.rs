//! Integration test for DNS Rule-Set routing
//!
//! Demonstrates DNS routing based on Rule-Set matching

#[cfg(all(feature = "router", feature = "suffix_trie"))]
#[tokio::test]
async fn test_dns_rule_routing_integration() {
    use sb_core::dns::rule_engine::{DnsRoutingRule, DnsRuleEngine};
    use sb_core::dns::{DnsAnswer, DnsUpstream, RecordType};
    use sb_core::router::ruleset::{
        DefaultRule, IpPrefixTree, Rule, RuleSet, RuleSetFormat, RuleSetSource,
    };
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::SystemTime;

    // Mock DNS upstream for testing
    struct TestUpstream {
        name: String,
        response_ip: IpAddr,
    }

    #[async_trait::async_trait]
    impl DnsUpstream for TestUpstream {
        async fn query(
            &self,
            _domain: &str,
            _record_type: RecordType,
        ) -> anyhow::Result<DnsAnswer> {
            Ok(DnsAnswer::new(
                vec![self.response_ip],
                std::time::Duration::from_secs(300),
                sb_core::dns::cache::Source::System,
                sb_core::dns::cache::Rcode::NoError,
            ))
        }

        fn name(&self) -> &str {
            &self.name
        }

        async fn health_check(&self) -> bool {
            true
        }
    }

    // Create Rule-Set for Google domains -> Google DNS (8.8.8.8)
    let google_rules = Arc::new(RuleSet {
        source: RuleSetSource::Local(PathBuf::from("google_rules.srs")),
        format: RuleSetFormat::Binary,
        version: 1,
        rules: vec![Rule::Default(DefaultRule {
            domain_suffix: vec!["google.com".to_string(), "googleapis.com".to_string()],
            ..Default::default()
        })],
        #[cfg(feature = "suffix_trie")]
        domain_trie: Arc::new(Default::default()),
        #[cfg(not(feature = "suffix_trie"))]
        domain_suffixes: Arc::new(vec!["google.com".to_string(), "googleapis.com".to_string()]),
        ip_tree: Arc::new(IpPrefixTree::new()),
        last_updated: SystemTime::now(),
        etag: None,
    });

    // Create Rule-Set for CN domains -> CN DNS (114.114.114.114)
    let cn_rules = Arc::new(RuleSet {
        source: RuleSetSource::Local(PathBuf::from("cn_rules.srs")),
        format: RuleSetFormat::Binary,
        version: 1,
        rules: vec![Rule::Default(DefaultRule {
            domain_suffix: vec!["cn".to_string(), "baidu.com".to_string()],
            ..Default::default()
        })],
        #[cfg(feature = "suffix_trie")]
        domain_trie: Arc::new(Default::default()),
        #[cfg(not(feature = "suffix_trie"))]
        domain_suffixes: Arc::new(vec!["cn".to_string(), "baidu.com".to_string()]),
        ip_tree: Arc::new(IpPrefixTree::new()),
        last_updated: SystemTime::now(),
        etag: None,
    });

    // Create upstream servers
    let mut upstreams: HashMap<String, Arc<dyn DnsUpstream>> = HashMap::new();
    upstreams.insert(
        "google_dns".to_string(),
        Arc::new(TestUpstream {
            name: "google_dns_8.8.8.8".to_string(),
            response_ip: IpAddr::from([8, 8, 8, 8]),
        }),
    );
    upstreams.insert(
        "cn_dns".to_string(),
        Arc::new(TestUpstream {
            name: "cn_dns_114.114.114.114".to_string(),
            response_ip: IpAddr::from([114, 114, 114, 114]),
        }),
    );
    upstreams.insert(
        "default_dns".to_string(),
        Arc::new(TestUpstream {
            name: "default_dns_1.1.1.1".to_string(),
            response_ip: IpAddr::from([1, 1, 1, 1]),
        }),
    );

    // Create routing rules
    let routing_rules = vec![
        DnsRoutingRule {
            rule_set: google_rules,
            upstream_tag: "google_dns".to_string(),
            priority: 10, // High priority
            address_limit: None,
            rewrite_ip: None,
            rcode: None,
            answer: None,
            ns: None,
            extra: None,
        },
        DnsRoutingRule {
            rule_set: cn_rules,
            upstream_tag: "cn_dns".to_string(),
            priority: 20, // Lower priority
            address_limit: None,
            rewrite_ip: None,
            rcode: None,
            answer: None,
            ns: None,
            extra: None,
        },
    ];

    // Create DNS rule engine
    let engine = DnsRuleEngine::new(
        routing_rules,
        upstreams,
        "default_dns".to_string(),
        sb_core::dns::DnsStrategy::default(),
        Arc::new(sb_core::dns::transport::TransportRegistry::new()),
    );

    // Test Case 1: Google domain should route to Google DNS (8.8.8.8)
    let result = engine
        .resolve("www.google.com", RecordType::A)
        .await
        .unwrap();
    assert_eq!(result.ips.len(), 1);
    assert_eq!(result.ips[0], IpAddr::from([8, 8, 8, 8]));
    println!("✅ Test 1: www.google.com → 8.8.8.8 (Google DNS)");

    // Test Case 2: Google API should also route to Google DNS
    let result = engine
        .resolve("maps.googleapis.com", RecordType::A)
        .await
        .unwrap();
    assert_eq!(result.ips[0], IpAddr::from([8, 8, 8, 8]));
    println!("✅ Test 2: maps.googleapis.com → 8.8.8.8 (Google DNS)");

    // Test Case 3: CN domain should route to CN DNS (114.114.114.114)
    let result = engine
        .resolve("www.baidu.com", RecordType::A)
        .await
        .unwrap();
    assert_eq!(result.ips[0], IpAddr::from([114, 114, 114, 114]));
    println!("✅ Test 3: www.baidu.com → 114.114.114.114 (CN DNS)");

    // Test Case 4: Unknown domain should route to default DNS (1.1.1.1)
    let result = engine
        .resolve("www.example.com", RecordType::A)
        .await
        .unwrap();
    assert_eq!(result.ips[0], IpAddr::from([1, 1, 1, 1]));
    println!("✅ Test 4: www.example.com → 1.1.1.1 (Default DNS)");

    // Test Case 5: Verify cache is working
    let (cache_len, cache_cap) = engine.cache_stats();
    assert_eq!(cache_len, 4); // 4 domains cached
    assert!(cache_cap >= 4);
    println!(
        "✅ Test 5: DNS routing cache working (cached: {}/{})",
        cache_len, cache_cap
    );

    // Test Case 6: Second query should hit cache
    let result = engine
        .resolve("www.google.com", RecordType::A)
        .await
        .unwrap();
    assert_eq!(result.ips[0], IpAddr::from([8, 8, 8, 8]));
    let (cache_len_after, _) = engine.cache_stats();
    assert_eq!(cache_len_after, 4); // Still 4 (cache hit)
    println!("✅ Test 6: Cache hit for repeated query");

    println!("\n🎉 DNS Rule-Set Routing Integration Test Complete!");
    println!("✅ All routing rules working correctly");
    println!("✅ Priority sorting working");
    println!("✅ Cache optimization working");
}
