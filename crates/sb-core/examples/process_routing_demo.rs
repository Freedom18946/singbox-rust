//! Process-based routing demonstration
//!
//! This example shows how to use process matching for routing decisions.
//! It demonstrates creating rules based on process names and paths,
//! and how the routing engine prioritizes different rule types.

use sb_core::router::process_router::ProcessRouter;
use sb_core::router::rules::{parse_rules, Decision, Engine, Rule, RuleKind};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Process-based Routing Demo");
    println!("=========================");

    // Example 1: Creating rules programmatically
    println!("\n1. Creating process rules programmatically:");

    let rules = vec![
        Rule {
            kind: RuleKind::ProcessName("firefox".to_string()),
            decision: Decision::Proxy(Some("browser_proxy".to_string())),
        },
        Rule {
            kind: RuleKind::ProcessName("chrome".to_string()),
            decision: Decision::Proxy(Some("browser_proxy".to_string())),
        },
        Rule {
            kind: RuleKind::ProcessPath("/usr/bin/curl".to_string()),
            decision: Decision::Direct,
        },
        Rule {
            kind: RuleKind::ProcessPath("/Applications/Telegram.app".to_string()),
            decision: Decision::Proxy(Some("messaging_proxy".to_string())),
        },
        Rule {
            kind: RuleKind::Exact("example.com".to_string()),
            decision: Decision::Reject,
        },
        Rule {
            kind: RuleKind::Default,
            decision: Decision::Direct,
        },
    ];

    let engine = Engine::build(rules);

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    {
        let router = ProcessRouter::new(engine)?;

        // Test routing without process information (fallback mode)
        println!("  Testing fallback routing (no process info):");

        let decision = router
            .decide_without_process(Some("google.com"), None, false, Some(443))
            .await;
        println!("    google.com:443 -> {:?}", decision);

        let decision = router
            .decide_without_process(Some("example.com"), None, false, Some(80))
            .await;
        println!("    example.com:80 -> {:?}", decision);

        // Test with mock connection info (process matching will likely fail in demo)
        println!("  Testing with connection info (process matching may fail in demo):");

        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
        let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 443);

        let decision = router
            .decide_with_process(
                Some("google.com"),
                None,
                false,
                Some(443),
                local_addr,
                remote_addr,
            )
            .await;
        println!("    google.com:443 with connection -> {:?}", decision);
    }

    // Example 2: Parsing rules from text
    println!("\n2. Parsing process rules from text:");

    let rules_text = r#"
        # Browser traffic through browser proxy
        process_name:firefox=proxy:browser_proxy
        process_name:chrome=proxy:browser_proxy
        process_name:safari=proxy:browser_proxy
        
        # Development tools go direct
        process_name:curl=direct
        process_name:wget=direct
        process_path:/usr/bin/git=direct
        
        # Messaging apps through messaging proxy
        process_path:/Applications/Telegram.app=proxy:messaging_proxy
        process_path:/Applications/Discord.app=proxy:messaging_proxy
        
        # Domain-based rules (higher priority than process rules)
        exact:blocked.example.com=reject
        suffix:.internal=direct
        
        # Port-based rules (higher priority than process rules)
        port:22=direct
        port:443,transport:tcp=proxy:https_proxy
        
        # Default fallback
        default=direct
    "#;

    let parsed_rules = parse_rules(rules_text);
    let parsed_engine = Engine::build(parsed_rules);

    let test_decision = parsed_engine.decide(&sb_core::router::rules::RouteCtx {
        domain: None,
        ip: None,
        transport_udp: false,
        port: None,
        process_name: None,
        process_path: None,
        inbound_tag: None,
        outbound_tag: None,
        auth_user: None,
        query_type: None,
        ..Default::default()
    });
    println!(
        "  Parsed rules successfully, default decision: {:?}",
        test_decision
    );

    // Example 3: Rule priority demonstration
    println!("\n3. Rule priority demonstration:");
    println!("   Priority order: exact > suffix > keyword > ip_cidr > transport > port > process > default");

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    {
        let router = ProcessRouter::new(parsed_engine)?;

        // Domain rule beats process rule
        let decision = router
            .decide_without_process(Some("blocked.example.com"), None, false, Some(80))
            .await;
        println!(
            "    blocked.example.com (domain rule wins) -> {:?}",
            decision
        );

        // Port rule beats process rule
        let decision = router
            .decide_without_process(Some("example.com"), None, false, Some(22))
            .await;
        println!("    example.com:22 (port rule wins) -> {:?}", decision);

        // Process rule applies when no higher priority rules match
        let decision = router
            .decide_without_process(Some("random.com"), None, false, Some(8080))
            .await;
        println!(
            "    random.com:8080 (would use process rule if matched) -> {:?}",
            decision
        );
    }

    // Example 4: Process matching accuracy note
    println!("\n4. Process matching accuracy:");
    println!("   Process matching requires appropriate system permissions and may not work");
    println!("   in all environments. The implementation aims for >95% accuracy when");
    println!("   system resources are accessible.");
    println!("   - Linux: Uses /proc filesystem");
    println!("   - macOS: Uses system calls and lsof fallback");
    println!("   - Windows: Uses netstat and tasklist/wmic");

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        println!("\nProcess matching is not supported on this platform.");
        println!("Supported platforms: Linux, macOS, Windows");
    }

    Ok(())
}
