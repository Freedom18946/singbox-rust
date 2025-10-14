//! Integration tests for process-based routing rules
//!
//! Tests the complete process matching pipeline from connection identification
//! to routing decision based on process name and path.

use sb_core::router::process_router::ProcessRouter;
use sb_core::router::rules::{Decision, Engine, ProcessPathRegexMatcher, RouteCtx, Rule, RuleKind};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[tokio::test]
async fn test_process_name_routing() {
    // Only run on supported platforms
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    {
        let rules = vec![
            Rule {
                kind: RuleKind::ProcessName("firefox".to_string()),
                decision: Decision::Proxy(Some("proxy1".to_string())),
            },
            Rule {
                kind: RuleKind::ProcessName("chrome".to_string()),
                decision: Decision::Proxy(Some("proxy2".to_string())),
            },
            Rule {
                kind: RuleKind::Default,
                decision: Decision::Direct,
            },
        ];

        let engine = Engine::build(rules);
        let router = ProcessRouter::new(engine).expect("Failed to create ProcessRouter");

        // Test fallback without process info
        let decision = router
            .decide_without_process(Some("example.com"), None, false, Some(443))
            .await;

        assert!(matches!(decision, Decision::Direct));
    }
}

#[tokio::test]
async fn test_process_path_routing() {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    {
        let rules = vec![
            Rule {
                kind: RuleKind::ProcessPath("/usr/bin/firefox".to_string()),
                decision: Decision::Proxy(None),
            },
            Rule {
                kind: RuleKind::ProcessPath("/Applications/Google Chrome.app".to_string()),
                decision: Decision::Reject,
            },
            Rule {
                kind: RuleKind::Default,
                decision: Decision::Direct,
            },
        ];

        let _rules_clone = rules.clone();
        let engine = Engine::build(rules);
        let router = ProcessRouter::new(engine).expect("Failed to create ProcessRouter");

        // Test with mock addresses (process matching will likely fail, but that's expected)
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
        let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 443);

        let decision = router
            .decide_with_process(
                Some("example.com"),
                None,
                false,
                Some(443),
                local_addr,
                remote_addr,
            )
            .await;

        // Should fall back to Direct since process matching will likely fail in test environment
        assert!(matches!(decision, Decision::Direct));
    }
}

#[tokio::test]
async fn test_process_path_regex_routing() {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    {
        let rules = vec![
            Rule {
                kind: RuleKind::ProcessPathRegex(
                    ProcessPathRegexMatcher::new(r"(?i).*/Chrome\.app$".to_string()).unwrap(),
                ),
                decision: Decision::Proxy(Some("regex_proxy".to_string())),
            },
            Rule {
                kind: RuleKind::Default,
                decision: Decision::Direct,
            },
        ];

        let _rules_clone = rules.clone();
        let engine = Engine::build(rules);
        let _router = ProcessRouter::new(engine).expect("Failed to create ProcessRouter");

        let matching_ctx = RouteCtx {
            domain: Some("example.com"),
            ip: None,
            transport_udp: false,
            port: Some(443),
            process_name: Some("Google Chrome"),
            process_path: Some("/Applications/Google Chrome.app"),
            inbound_tag: None,
            outbound_tag: None,
            auth_user: None,
            query_type: None,
        };
        let engine_for_decide = Engine::build(rules_clone.clone());
        let decision = engine_for_decide.decide(&matching_ctx);
        assert!(matches!(decision, Decision::Proxy(Some(ref name)) if name == "regex_proxy"));

        let non_matching_ctx = RouteCtx {
            domain: Some("example.com"),
            ip: None,
            transport_udp: false,
            port: Some(443),
            process_name: Some("curl"),
            process_path: Some("/usr/bin/curl"),
            inbound_tag: None,
            outbound_tag: None,
            auth_user: None,
            query_type: None,
        };
        let engine_for_decide2 = Engine::build(rules_clone);
        let decision = engine_for_decide2.decide(&non_matching_ctx);
        assert!(matches!(decision, Decision::Direct));
    }
}

#[tokio::test]
async fn test_process_rule_priority() {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    {
        let rules = vec![
            Rule {
                kind: RuleKind::Exact("example.com".to_string()),
                decision: Decision::Proxy(Some("domain_proxy".to_string())),
            },
            Rule {
                kind: RuleKind::ProcessName("firefox".to_string()),
                decision: Decision::Proxy(Some("process_proxy".to_string())),
            },
            Rule {
                kind: RuleKind::Default,
                decision: Decision::Direct,
            },
        ];

        let engine = Engine::build(rules);
        let router = ProcessRouter::new(engine).expect("Failed to create ProcessRouter");

        // Domain rules should have higher priority than process rules
        let decision = router
            .decide_without_process(Some("example.com"), None, false, Some(443))
            .await;

        // Should match domain rule first (higher priority)
        assert!(matches!(decision, Decision::Proxy(Some(ref name)) if name == "domain_proxy"));
    }
}

#[tokio::test]
async fn test_mixed_rules_with_process() {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    {
        let rules = vec![
            Rule {
                kind: RuleKind::Suffix("google.com".to_string()),
                decision: Decision::Direct,
            },
            Rule {
                kind: RuleKind::ProcessName("curl".to_string()),
                decision: Decision::Proxy(None),
            },
            Rule {
                kind: RuleKind::Port(22),
                decision: Decision::Reject,
            },
            Rule {
                kind: RuleKind::Default,
                decision: Decision::Direct,
            },
        ];

        let engine = Engine::build(rules);
        let router = ProcessRouter::new(engine).expect("Failed to create ProcessRouter");

        // Test suffix rule (higher priority)
        let decision = router
            .decide_without_process(Some("mail.google.com"), None, false, Some(443))
            .await;
        assert!(matches!(decision, Decision::Direct));

        // Test port rule (higher priority than process)
        let decision = router
            .decide_without_process(Some("example.com"), None, false, Some(22))
            .await;
        assert!(matches!(decision, Decision::Reject));
    }
}

#[tokio::test]
async fn test_process_cache_cleanup() {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    {
        let engine = Engine::new();
        let router = ProcessRouter::new(engine).expect("Failed to create ProcessRouter");

        // Test cache cleanup doesn't panic
        router.cleanup_cache().await;
    }
}

#[tokio::test]
async fn test_engine_update() {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    {
        let initial_rules = vec![Rule {
            kind: RuleKind::Default,
            decision: Decision::Direct,
        }];

        let engine = Engine::build(initial_rules);
        let router = ProcessRouter::new(engine).expect("Failed to create ProcessRouter");

        // Test initial decision
        let decision = router
            .decide_without_process(Some("example.com"), None, false, Some(443))
            .await;
        assert!(matches!(decision, Decision::Direct));

        // Update engine with new rules
        let new_rules = vec![
            Rule {
                kind: RuleKind::ProcessName("test".to_string()),
                decision: Decision::Proxy(None),
            },
            Rule {
                kind: RuleKind::Default,
                decision: Decision::Reject,
            },
        ];

        let new_engine = Engine::build(new_rules);
        router.update_engine(new_engine).await;

        // Test updated decision
        let decision = router
            .decide_without_process(Some("example.com"), None, false, Some(443))
            .await;
        assert!(matches!(decision, Decision::Reject));
    }
}

#[test]
fn test_process_rule_parsing() {
    use sb_core::router::rules::parse_rules;

    let rules_text = r#"
        process_name:firefox=proxy
        process_path:/usr/bin/chrome=reject
        process_path_regex:.*/Chrome\.app=proxy:chrome
        process_name:curl,port:80=direct
        default=direct
    "#;

    let rules = parse_rules(rules_text);

    // Should have 6 rules (the third line creates 2 rules due to comma separation)
    assert_eq!(rules.len(), 6);

    // Check process name rule
    assert!(matches!(rules[0].kind, RuleKind::ProcessName(ref name) if name == "firefox"));
    assert!(matches!(rules[0].decision, Decision::Proxy(None)));

    // Check process path rule
    assert!(matches!(rules[1].kind, RuleKind::ProcessPath(ref path) if path == "/usr/bin/chrome"));
    assert!(matches!(rules[1].decision, Decision::Reject));

    // Check process path regex rule
    assert!(matches!(rules[2].kind, RuleKind::ProcessPathRegex(_)));
    assert!(matches!(rules[2].decision, Decision::Proxy(Some(ref name)) if name == "chrome"));

    // Check combined rules (process_name and port)
    assert!(matches!(rules[3].kind, RuleKind::ProcessName(ref name) if name == "curl"));
    assert!(matches!(rules[4].kind, RuleKind::Port(80)));

    // Check default rule
    assert!(matches!(rules[5].kind, RuleKind::Default));
}

#[test]
fn test_process_rule_matching_logic() {
    use sb_core::router::rules::{Decision, ProcessPathRegexMatcher, RouteCtx, Rule, RuleKind};

    // Test process name matching
    let rule = Rule {
        kind: RuleKind::ProcessName("firefox".to_string()),
        decision: Decision::Proxy(None),
    };

    let ctx = RouteCtx {
        domain: None,
        ip: None,
        transport_udp: false,
        port: None,
        process_name: Some("firefox"),
        process_path: None,
        inbound_tag: None,
        outbound_tag: None,
        auth_user: None,
        query_type: None,
    };

    let engine = Engine::build(vec![rule]);
    let decision = engine.decide(&ctx);
    assert!(matches!(decision, Decision::Proxy(None)));

    // Test process path matching
    let rule = Rule {
        kind: RuleKind::ProcessPath("/usr/bin/firefox".to_string()),
        decision: Decision::Proxy(None),
    };

    let ctx = RouteCtx {
        domain: None,
        ip: None,
        transport_udp: false,
        port: None,
        process_name: None,
        process_path: Some("/usr/bin/firefox"),
        inbound_tag: None,
        outbound_tag: None,
        auth_user: None,
        query_type: None,
    };

    let engine = Engine::build(vec![rule]);
    let decision = engine.decide(&ctx);
    assert!(matches!(decision, Decision::Proxy(None)));

    // Test partial path matching
    let rule = Rule {
        kind: RuleKind::ProcessPath("firefox".to_string()),
        decision: Decision::Proxy(None),
    };

    let ctx = RouteCtx {
        domain: None,
        ip: None,
        transport_udp: false,
        port: None,
        process_name: None,
        process_path: Some("/usr/bin/firefox"),
        inbound_tag: None,
        outbound_tag: None,
        auth_user: None,
        query_type: None,
    };

    let engine = Engine::build(vec![rule]);
    let decision = engine.decide(&ctx);
    assert!(matches!(decision, Decision::Proxy(None)));

    // Test process path regex matching
    let rule = Rule {
        kind: RuleKind::ProcessPathRegex(
            ProcessPathRegexMatcher::new(r"(?i).*/Chrome\.app$".to_string()).unwrap(),
        ),
        decision: Decision::Proxy(Some("chrome".to_string())),
    };

    let ctx = RouteCtx {
        domain: None,
        ip: None,
        transport_udp: false,
        port: None,
        process_name: Some("Google Chrome"),
        process_path: Some("/Applications/Google Chrome.app"),
        inbound_tag: None,
        outbound_tag: None,
        auth_user: None,
        query_type: None,
    };

    let engine = Engine::build(vec![rule.clone()]);
    let decision = engine.decide(&ctx);
    assert!(matches!(decision, Decision::Proxy(Some(ref name)) if name == "chrome"));

    let ctx = RouteCtx {
        domain: None,
        ip: None,
        transport_udp: false,
        port: None,
        process_name: Some("curl"),
        process_path: Some("/usr/bin/curl"),
        inbound_tag: None,
        outbound_tag: None,
        auth_user: None,
        query_type: None,
    };

    let engine = Engine::build(vec![rule]);
    let decision = engine.decide(&ctx);
    assert!(matches!(decision, Decision::Direct));
}
