#![cfg(feature = "router")]
use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

use sb_core::router::{DnsResolve, DnsResult, RouterHandle};

struct FakeResolverOk;
impl DnsResolve for FakeResolverOk {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        _timeout_ms: u64,
    ) -> Pin<Box<dyn std::future::Future<Output = DnsResult> + Send + 'a>> {
        Box::pin(async move {
            let _ = host; // unused
            DnsResult::Ok(vec![
                IpAddr::V4(Ipv4Addr::new(11, 1, 2, 3)),
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            ])
        })
    }
}

struct FakeResolverTimeout;
impl DnsResolve for FakeResolverTimeout {
    fn resolve<'a>(
        &'a self,
        _host: &'a str,
        _timeout_ms: u64,
    ) -> Pin<Box<dyn std::future::Future<Output = DnsResult> + Send + 'a>> {
        Box::pin(async move {
            // 模拟超时：超过调用方默认预算，这里直接 sleep 一会儿后返回 Timeout
            sleep(Duration::from_millis(50)).await;
            DnsResult::Timeout
        })
    }
}

#[tokio::test]
async fn resolver_route_hits_cidr_then_returns_decision() {
    // 规则：11.0.0.0/8 → proxy，默认 direct
    let rules = r#"
    cidr4:11.0.0.0/8=proxy
    default=direct
    "#;
    std::env::set_var("SB_ROUTER_RULES", rules);
    std::env::set_var("SB_ROUTER_DNS", "1");
    let h = RouterHandle::from_env().with_resolver(Arc::new(FakeResolverOk));
    let d = h.decide_udp_async("example.com").await;
    assert_eq!(d, "proxy");
}

#[tokio::test]
async fn resolver_timeout_or_error_falls_back_to_default() {
    let rules = r#"
    suffix:example.com=proxy
    default=direct
    "#;
    std::env::set_var("SB_ROUTER_RULES", rules);
    std::env::set_var("SB_ROUTER_DNS", "1");
    let h = RouterHandle::from_env().with_resolver(Arc::new(FakeResolverTimeout));
    // host 不匹配任何 suffix，解析又失败，应回退默认
    let d = h.decide_udp_async("nomatch.invalid").await;
    assert_eq!(d, "direct");
}
