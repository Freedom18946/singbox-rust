#![cfg(feature = "router")]
use sb_config::ir::{DnsIR, DnsRuleIR};
use sb_core::dns::{DnsAnswer, DnsUpstream, RecordType, Resolver};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

// Mock Upstream
struct TestUpstream {
    tag: String,
}

#[async_trait::async_trait]
impl DnsUpstream for TestUpstream {
    async fn query(&self, _domain: &str, _record_type: RecordType) -> anyhow::Result<DnsAnswer> {
        Ok(DnsAnswer::new(
            vec![], 
            Duration::from_secs(60),
            sb_core::dns::cache::Source::System,
            sb_core::dns::cache::Rcode::NoError, 
        ))
    }
    fn name(&self) -> &str {
        &self.tag
    }
    async fn health_check(&self) -> bool {
        true
    }
}

#[tokio::test]
async fn test_dns_rule_query_type_matching() {
    // Config: Reject AAAA for example.com
    let mut ir = DnsIR::default();
    ir.servers.push(sb_config::ir::DnsServerIR {
        tag: "main".into(),
        address: "udp://1.1.1.1".into(),
        ..Default::default()
    });
    ir.rules.push(DnsRuleIR {
        domain: vec!["example.com".into()],
        query_type: vec!["AAAA".into()],
        action: Some("reject".into()),
        ..Default::default()
    });
    ir.default = Some("main".into());

    // We can't easily inject mock upstreams into config_builder::resolver_from_ir 
    // because it builds upstreams FROM config. 
    // However, we can use the `rule_engine` directly if we expose it or test via `resolver_from_ir` by mocking the upstream construction? 
    // `resolver_from_ir` calls `build_upstream_from_server`. We cannot intercept that easily without plumbing.
    
    // Instead, let's test `config_builder` parsing mapping correctly, 
    // AND test `rule_engine` logic by constructing it manually like `resolver_from_ir` does, but with mocks.
    
    // 1. Verify Config Builder Mapping
    let resolver = sb_core::dns::config_builder::resolver_from_ir(&ir);
    // If this errors, it means builder failed (e.g. valid checks).
    // Note: It will try to build udp://1.1.1.1, which is fine, it doesn't connect immediately usually?
    // UdpUpstream creation might bind socket? Ideally we don't bind ports in tests.
    // So let's rely on unit tests inside `rule_engine.rs` or `config_builder.rs` if possible?
    // But `rule_engine.rs` tests are private.
    
    // Let's modify `crates/sb-core/src/dns/rule_engine.rs` to make `MockUpstream` public or usable?
    // Or just define a test that constructs `DnsRuleEngine` with manual rules.
    
    // Verify DnsRuleEngine action logic manual construction
    
    use sb_core::dns::rule_engine::{DnsRuleEngine, DnsRoutingRule, DnsRuleAction};
    use sb_core::router::ruleset::{RuleSet, RuleSetSource, RuleSetFormat, Rule, DefaultRule};
    
    let ruleset = Arc::new(RuleSet {
        source: RuleSetSource::Local(std::path::PathBuf::from("test")),
        format: RuleSetFormat::Binary,
        version: 1,
        rules: vec![Rule::Default(DefaultRule {
             domain: vec![sb_core::router::ruleset::DomainRule::Exact("example.com".into())],
             query_type: vec!["AAAA".into()], // The field we added
             ..Default::default()
        })],
        #[cfg(feature = "suffix_trie")]
        domain_trie: Arc::new(Default::default()),
        #[cfg(not(feature = "suffix_trie"))]
        domain_suffixes: Arc::new(vec![]),
        ip_tree: Arc::new(Default::default()),
        last_updated: std::time::SystemTime::now(),
        etag: None,
    });
    
    let routing_rule = DnsRoutingRule {
        rule_set: ruleset,
        upstream_tag: None,
        action: DnsRuleAction::Reject,
        priority: 10,
        address_limit: None,
        rewrite_ip: None,
        rcode: None,
        answer: None,
        ns: None,
        extra: None,
    };
    
    let mut upstreams: HashMap<String, Arc<dyn DnsUpstream>> = HashMap::new();
    upstreams.insert("main".into(), Arc::new(TestUpstream { tag: "main".into() }));
    
    let engine = DnsRuleEngine::new(vec![routing_rule], upstreams, "main".into(), sb_core::dns::DnsStrategy::default(), Arc::new(sb_core::dns::transport::TransportRegistry::new()));
    
    // Test AAAA -> Reject
    let res: DnsAnswer = engine.resolve("example.com", RecordType::AAAA).await.unwrap();
    assert_eq!(res.rcode, sb_core::dns::cache::Rcode::Refused);
    
    // Test A -> Route (Default)
    let res: DnsAnswer = engine.resolve("example.com", RecordType::A).await.unwrap();
    assert_eq!(res.rcode, sb_core::dns::cache::Rcode::NoError);
}

#[tokio::test]
async fn test_dns_rule_action_hijack() {
     use sb_core::dns::rule_engine::{DnsRuleEngine, DnsRoutingRule, DnsRuleAction};
     use sb_core::router::ruleset::{RuleSet, RuleSetSource, RuleSetFormat, Rule, DefaultRule};
     
     let ruleset = Arc::new(RuleSet {
        source: RuleSetSource::Local(std::path::PathBuf::from("test")),
        format: RuleSetFormat::Binary,
        version: 1,
        rules: vec![Rule::Default(DefaultRule {
             domain_keyword: vec!["google".into()],
             ..Default::default()
        })],
        #[cfg(feature = "suffix_trie")]
        domain_trie: Arc::new(Default::default()),
        #[cfg(not(feature = "suffix_trie"))]
        domain_suffixes: Arc::new(vec![]),
        ip_tree: Arc::new(Default::default()),
        last_updated: std::time::SystemTime::now(),
        etag: None,
    });
    
    let routing_rule = DnsRoutingRule {
        rule_set: ruleset,
        upstream_tag: None,
        action: DnsRuleAction::HijackDns,
        priority: 10,
        address_limit: None,
        rewrite_ip: None,
        rcode: None,
        answer: None,
        ns: None,
        extra: None,
    };
    
    let mut upstreams: HashMap<String, Arc<dyn DnsUpstream>> = HashMap::new();
    upstreams.insert("main".into(), Arc::new(TestUpstream { tag: "main".into() }));
    
    let engine = DnsRuleEngine::new(vec![routing_rule], upstreams, "main".into(), sb_core::dns::DnsStrategy::default(), Arc::new(sb_core::dns::transport::TransportRegistry::new()));
    
    let res: DnsAnswer = engine.resolve("www.google.com", RecordType::A).await.unwrap();
    // HijackDns currently returns Refused in our implementation if no rewrite_ip
    assert_eq!(res.rcode, sb_core::dns::cache::Rcode::Refused);
}

#[tokio::test]
async fn test_dns_rule_action_hijack_with_rewrite() {
     use sb_core::dns::rule_engine::{DnsRuleEngine, DnsRoutingRule, DnsRuleAction};
     use sb_core::router::ruleset::{RuleSet, RuleSetSource, RuleSetFormat, Rule, DefaultRule};
     
     let ruleset = Arc::new(RuleSet {
        source: RuleSetSource::Local(std::path::PathBuf::from("test")),
        format: RuleSetFormat::Binary,
        version: 1,
        rules: vec![Rule::Default(DefaultRule {
             domain_keyword: vec!["hijack".into()],
             ..Default::default()
        })],
        #[cfg(feature = "suffix_trie")]
        domain_trie: Arc::new(Default::default()),
        #[cfg(not(feature = "suffix_trie"))]
        domain_suffixes: Arc::new(vec![]),
        ip_tree: Arc::new(Default::default()),
        last_updated: std::time::SystemTime::now(),
        etag: None,
    });
    
    let routing_rule = DnsRoutingRule {
        rule_set: ruleset,
        upstream_tag: None,
        action: DnsRuleAction::HijackDns,
        priority: 10,
        address_limit: None,
        rewrite_ip: Some(vec!["192.168.1.1".parse().unwrap()]),
        rcode: None,
        answer: None,
        ns: None,
        extra: None,
    };
    
    let mut upstreams: HashMap<String, Arc<dyn DnsUpstream>> = HashMap::new();
    upstreams.insert("main".into(), Arc::new(TestUpstream { tag: "main".into() }));
    
    let engine = DnsRuleEngine::new(vec![routing_rule], upstreams, "main".into(), sb_core::dns::DnsStrategy::default(), Arc::new(sb_core::dns::transport::TransportRegistry::new()));
    
    let res: DnsAnswer = engine.resolve("www.hijack.com", RecordType::A).await.unwrap();
    assert_eq!(res.rcode, sb_core::dns::cache::Rcode::NoError);
    assert_eq!(res.ips.len(), 1);
    assert_eq!(res.ips[0].to_string(), "192.168.1.1");
}

#[tokio::test]
async fn test_dns_rule_action_address_limit() {
     use sb_core::dns::rule_engine::{DnsRuleEngine, DnsRoutingRule, DnsRuleAction};
     use sb_core::router::ruleset::{RuleSet, RuleSetSource, RuleSetFormat, Rule, DefaultRule};
     
     // Mock upstream that returns 3 IPs
     struct MultiIpUpstream;
     #[async_trait::async_trait]
     impl DnsUpstream for MultiIpUpstream {
        async fn query(&self, _domain: &str, _record_type: RecordType) -> anyhow::Result<DnsAnswer> {
            Ok(DnsAnswer::new(
                vec![
                    "1.1.1.1".parse().unwrap(),
                    "1.0.0.1".parse().unwrap(),
                    "8.8.8.8".parse().unwrap()
                ],
                Duration::from_secs(60),
                sb_core::dns::cache::Source::System,
                sb_core::dns::cache::Rcode::NoError, 
            ))
        }
        fn name(&self) -> &str { "multi" }
        async fn health_check(&self) -> bool { true }
    }

     let ruleset = Arc::new(RuleSet {
        source: RuleSetSource::Local(std::path::PathBuf::from("test")),
        format: RuleSetFormat::Binary,
        version: 1,
        rules: vec![Rule::Default(DefaultRule {
             domain_keyword: vec!["limit".into()],
             ..Default::default()
        })],
        #[cfg(feature = "suffix_trie")]
        domain_trie: Arc::new(Default::default()),
        #[cfg(not(feature = "suffix_trie"))]
        domain_suffixes: Arc::new(vec![]),
        ip_tree: Arc::new(Default::default()),
        last_updated: std::time::SystemTime::now(),
        etag: None,
    });
    
    let routing_rule = DnsRoutingRule {
        rule_set: ruleset,
        upstream_tag: Some("multi".into()),
        action: DnsRuleAction::Route,
        priority: 10,
        address_limit: Some(1),
        rewrite_ip: None,
        rcode: None,
        answer: None,
        ns: None,
        extra: None,
    };
    
    let mut upstreams: HashMap<String, Arc<dyn DnsUpstream>> = HashMap::new();
    upstreams.insert("multi".into(), Arc::new(MultiIpUpstream));
    
    let engine = DnsRuleEngine::new(vec![routing_rule], upstreams, "multi".into(), sb_core::dns::DnsStrategy::default(), Arc::new(sb_core::dns::transport::TransportRegistry::new()));
    
    let res: DnsAnswer = engine.resolve("www.limit.com", RecordType::A).await.unwrap();
    assert_eq!(res.rcode, sb_core::dns::cache::Rcode::NoError);
    assert_eq!(res.ips.len(), 1);
}
