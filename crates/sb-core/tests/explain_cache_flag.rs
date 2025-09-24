#[cfg(all(feature = "router_cache_explain", feature = "router_cache_lru_demo"))]
mod explain_cache_tests {
    use sb_core::router::engine::{decide_http_explain, DecisionExplain};

    #[test]
    fn test_decision_explain_structure() {
        let explain = decide_http_explain("example.com");

        // 验证基本字段存在
        assert!(!explain.decision.is_empty());
        assert!(!explain.reason.is_empty());
        assert!(!explain.reason_kind.is_empty());

        // 验证 cache_status 字段存在且初始为 None（因为这是直接查询，没有缓存）
        assert!(explain.cache_status.is_none());

        println!("Decision: {}", explain.decision);
        println!("Reason: {}", explain.reason);
        println!("Reason kind: {}", explain.reason_kind);
        println!("Cache status: {:?}", explain.cache_status);
    }

    #[test]
    fn test_decision_explain_with_ip() {
        let explain = decide_http_explain("1.1.1.1");

        // IP 解析应该有特定的 reason_kind
        assert!(explain.reason_kind == "ip" || explain.reason_kind == "default");
        assert!(explain.cache_status.is_none());

        println!("IP decision: {}", explain.decision);
        println!("IP reason: {}", explain.reason);
    }

    #[test]
    fn test_decision_explain_with_port() {
        let explain = decide_http_explain("example.com:8080");

        assert!(!explain.decision.is_empty());
        assert!(explain.cache_status.is_none());

        println!("Port decision: {}", explain.decision);
        println!("Port reason: {}", explain.reason);
    }

    #[tokio::test]
    async fn test_udp_explain() {
        use sb_core::router::engine::{decide_udp_async_explain, RouterHandle};

        let handle = RouterHandle::from_env();
        let explain = decide_udp_async_explain(&handle, "example.com").await;

        assert!(!explain.decision.is_empty());
        assert!(!explain.reason.is_empty());
        assert!(!explain.reason_kind.is_empty());
        assert!(explain.cache_status.is_none());

        println!("UDP decision: {}", explain.decision);
        println!("UDP reason: {}", explain.reason);
        println!("UDP reason kind: {}", explain.reason_kind);
    }
}

#[cfg(not(all(feature = "router_cache_explain", feature = "router_cache_lru_demo")))]
mod no_features {
    #[test]
    fn test_features_disabled() {
        println!("router_cache_explain or router_cache_lru_demo feature disabled");
    }
}
