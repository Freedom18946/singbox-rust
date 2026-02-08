//! Integration tests for selector functionality
//!
//! Tests multi-proxy scenarios, switching, health checking, and graceful degradation.

use sb_core::adapter::OutboundConnector;
use sb_core::outbound::selector_group::{ProxyHealth, ProxyMember, SelectMode, SelectorGroup};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;

#[derive(Debug)]
struct MockConnector {
    delay_ms: u64,
    fail_count: Arc<AtomicUsize>,
    max_fails: usize,
    permanent_fail: bool,
}

impl MockConnector {
    fn new(delay_ms: u64) -> Self {
        Self {
            delay_ms,
            fail_count: Arc::new(AtomicUsize::new(0)),
            max_fails: 0,
            permanent_fail: false,
        }
    }

    fn with_failures(delay_ms: u64, max_fails: usize) -> Self {
        Self {
            delay_ms,
            fail_count: Arc::new(AtomicUsize::new(0)),
            max_fails,
            permanent_fail: false,
        }
    }

    fn with_permanent_failure() -> Self {
        Self {
            delay_ms: 0,
            fail_count: Arc::new(AtomicUsize::new(0)),
            max_fails: 0,
            permanent_fail: true,
        }
    }
}

#[async_trait::async_trait]
impl OutboundConnector for MockConnector {
    async fn connect(&self, host: &str, port: u16) -> io::Result<TcpStream> {
        if self.permanent_fail {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "mock permanent failure",
            ));
        }

        sleep(Duration::from_millis(self.delay_ms)).await;

        let count = self.fail_count.fetch_add(1, Ordering::SeqCst);
        if self.max_fails > 0 && count < self.max_fails {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "mock transient failure",
            ));
        }

        TcpStream::connect((host, port)).await
    }
}

async fn start_health_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind health server");
    let addr = listener.local_addr().expect("health server addr");

    tokio::spawn(async move {
        loop {
            let (mut socket, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            tokio::spawn(async move {
                use tokio::io::AsyncReadExt;
                use tokio::io::AsyncWriteExt;

                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let _ = socket
                    .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                    .await;
            });
        }
    });

    sleep(Duration::from_millis(50)).await;
    addr
}

fn member(tag: &str, connector: MockConnector) -> ProxyMember {
    ProxyMember {
        tag: tag.to_string(),
        connector: Arc::new(connector),
        udp_factory: None,
        health: Arc::new(ProxyHealth::default()),
    }
}

#[tokio::test]
async fn test_manual_selector_multi_proxy_switching() {
    let members = vec![
        member("fast", MockConnector::new(5)),
        member("mid", MockConnector::new(15)),
        member("slow", MockConnector::new(25)),
    ];

    let selector = SelectorGroup::new_manual("manual".to_string(), members, Some("fast".to_string()), None, None);

    selector.select_by_name("slow").await.expect("select slow");
    assert_eq!(selector.get_selected().await, Some("slow".to_string()));

    let selected = selector.select_best().await.expect("select best");
    assert_eq!(selected.tag, "slow");
}

#[tokio::test]
async fn test_urltest_automatic_failover() {
    let addr = start_health_server().await;
    let url = format!("http://{}:{}/health", addr.ip(), addr.port());

    let members = vec![
        member("bad", MockConnector::with_permanent_failure()),
        member("good", MockConnector::new(5)),
    ];

    let selector = Arc::new(SelectorGroup::new_urltest(
        "urltest".to_string(),
        members,
        url,
        Duration::from_millis(50),
        Duration::from_secs(1),
        10,
        None,
        None,
    ));

    selector.clone().start_health_check();

    let mut selected = None;
    for _ in 0..20 {
        if let Some(member) = selector.select_best().await {
            selected = Some(member.tag.clone());
            if member.tag == "good" {
                break;
            }
        }
        sleep(Duration::from_millis(50)).await;
    }

    assert_eq!(selected.as_deref(), Some("good"));
}

#[tokio::test]
async fn test_load_balancer_distribution() {
    let members = vec![
        member("a", MockConnector::new(1)),
        member("b", MockConnector::new(1)),
        member("c", MockConnector::new(1)),
    ];
    let selector = SelectorGroup::new_load_balancer(
        "lb".to_string(),
        members,
        SelectMode::RoundRobin,
        None,
        None,
    );

    let mut counts = std::collections::HashMap::new();
    for _ in 0..60 {
        let member = selector.select_best().await.expect("select");
        *counts.entry(member.tag.clone()).or_insert(0usize) += 1;
    }

    assert_eq!(counts.len(), 3);
    for (tag, count) in counts {
        assert!(count >= 15, "member {} under-selected: {}", tag, count);
    }
}

#[tokio::test]
async fn test_selector_with_config_reload() {
    let members = vec![member("alpha", MockConnector::new(1))];
    let selector = SelectorGroup::new_manual("reload".to_string(), members, Some("alpha".to_string()), None, None);

    selector.select_by_name("alpha").await.expect("select alpha");
    assert_eq!(selector.get_selected().await, Some("alpha".to_string()));

    let new_members = vec![
        member("beta", MockConnector::new(1)),
        member("gamma", MockConnector::new(1)),
    ];
    let reloaded = SelectorGroup::new_manual(
        "reload".to_string(),
        new_members,
        Some("beta".to_string()),
        None,
        None,
    );

    assert!(reloaded.select_by_name("alpha").await.is_err());
    reloaded.select_by_name("gamma").await.expect("select gamma");
    assert_eq!(reloaded.get_selected().await, Some("gamma".to_string()));
}

#[tokio::test]
async fn test_concurrent_selector_access() {
    let members = vec![
        member("one", MockConnector::new(1)),
        member("two", MockConnector::new(1)),
    ];
    let selector = Arc::new(SelectorGroup::new_load_balancer(
        "concurrent".to_string(),
        members,
        SelectMode::Random,
        None,
        None,
    ));

    let mut tasks = Vec::new();
    for _ in 0..50 {
        let selector = selector.clone();
        tasks.push(tokio::spawn(async move {
            selector.select_best().await.map(|m| m.tag.clone())
        }));
    }

    for task in tasks {
        let selected = task.await.expect("join").expect("select");
        assert!(selected == "one" || selected == "two");
    }
}

#[tokio::test]
async fn test_health_check_recovery() {
    let addr = start_health_server().await;
    let url = format!("http://{}:{}/health", addr.ip(), addr.port());

    let members = vec![member("flaky", MockConnector::with_failures(5, 3))];
    let selector = Arc::new(SelectorGroup::new_urltest(
        "recovery".to_string(),
        members,
        url,
        Duration::from_millis(50),
        Duration::from_secs(1),
        10,
        None,
        None,
    ));

    selector.clone().start_health_check();

    let mut healthy = false;
    for _ in 0..30 {
        if let Some(member) = selector.select_best().await {
            if member.health.is_healthy() {
                healthy = true;
                break;
            }
        }
        sleep(Duration::from_millis(50)).await;
    }

    assert!(healthy, "proxy should recover after transient failures");
}
