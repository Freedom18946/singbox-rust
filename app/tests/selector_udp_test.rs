use sb_config::ir::{OutboundIR, OutboundType};
use sb_core::adapter::{
    Bridge, OutboundConnector, OutboundParam, UdpOutboundFactory, UdpOutboundSession,
};
use sb_core::context::{Context, ContextRegistry};
use sb_core::outbound::selector_group::ProxyMember;
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;

// Mock UDP Factory
#[derive(Debug, Clone)]
struct MockUdpFactoryImpl {
    tag: String,
}

impl UdpOutboundFactory for MockUdpFactoryImpl {
    fn open_session(
        &self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = std::io::Result<Arc<dyn UdpOutboundSession>>> + Send>,
    > {
        let tag = self.tag.clone();
        Box::pin(async move { Ok(Arc::new(MockUdpSession { tag }) as Arc<dyn UdpOutboundSession>) })
    }
}

#[derive(Debug)]
struct MockUdpSession {
    tag: String,
}

#[async_trait::async_trait]
impl UdpOutboundSession for MockUdpSession {
    async fn send_to(&self, _data: &[u8], _host: &str, _port: u16) -> std::io::Result<()> {
        Ok(())
    }
    async fn recv_from(&self) -> std::io::Result<(Vec<u8>, std::net::SocketAddr)> {
        Ok((self.tag.as_bytes().to_vec(), "127.0.0.1:0".parse().unwrap()))
    }
}

// Mock Connector
#[derive(Debug)]
struct MockConnector;
#[async_trait::async_trait]
impl OutboundConnector for MockConnector {
    async fn connect(&self, _host: &str, _port: u16) -> io::Result<TcpStream> {
        Err(io::Error::other("mock connector"))
    }
}

#[tokio::test]
async fn test_selector_udp_support() {
    // 1. Setup Bridge
    let mut bridge = Bridge::new(Context::new());

    // 2. Register mock members
    let member1_tag = "proxy1".to_string();
    let member2_tag = "proxy2".to_string();

    bridge.add_outbound(
        member1_tag.clone(),
        "mock".to_string(),
        Arc::new(MockConnector),
    );
    bridge.add_outbound_udp_factory(
        member1_tag.clone(),
        Arc::new(MockUdpFactoryImpl {
            tag: member1_tag.clone(),
        }),
    );

    bridge.add_outbound(
        member2_tag.clone(),
        "mock".to_string(),
        Arc::new(MockConnector),
    );
    bridge.add_outbound_udp_factory(
        member2_tag.clone(),
        Arc::new(MockUdpFactoryImpl {
            tag: member2_tag.clone(),
        }),
    );

    // 3. Build SelectorOutbound
    // We use the builder function from sb-adapters
    use sb_adapters::outbound::selector::build_selector_outbound;

    let selector_tag = "test-selector".to_string();
    let ir = OutboundIR {
        name: Some(selector_tag.clone()),
        ty: OutboundType::Selector,
        members: Some(vec![member1_tag.clone(), member2_tag.clone()]),
        default_member: Some(member1_tag.clone()),
        ..Default::default()
    };

    let param = OutboundParam {
        name: Some(selector_tag.clone()),
        ..Default::default()
    };

    let bridge_arc = Arc::new(bridge);
    let ctx = sb_core::adapter::registry::AdapterOutboundContext {
        bridge: bridge_arc.clone(),
        context: ContextRegistry::from(&bridge_arc.context),
    };

    let (_connector, udp_factory) =
        build_selector_outbound(&param, &ir, &ctx).expect("failed to build selector");

    assert!(udp_factory.is_some(), "Selector should support UDP");
    let udp_factory = udp_factory.unwrap();

    // 4. Test UDP session
    // By default, selector selects the default member (proxy1)
    let session = udp_factory
        .open_session()
        .await
        .expect("failed to open session");
    let (data, _) = session.recv_from().await.expect("failed to recv");
    assert_eq!(data, member1_tag.as_bytes(), "Should select proxy1");

    // 5. Change selection (we need access to SelectorGroup to change selection)
    // But we only have OutboundConnector and UdpOutboundFactory.
    // We can cast connector to SelectorOutbound if we knew the type, but it's dyn.
    // However, we can verify that if we select proxy2, it uses proxy2.
    // But we can't easily change selection from here without casting.

    // Ideally we should use SelectorGroup directly or expose selection method on the adapter?
    // The adapter wraps SelectorGroup.
    // SelectorGroup is exposed in sb-core.

    // Let's try to use SelectorGroup directly to verify selection logic with UDP factories
    // But we want to test the ADAPTER integration.

    // Since we can't easily change selection on the opaque adapter, we rely on the fact that it uses SelectorGroup.
    // We verified SelectorGroup logic in unit tests (though not UDP part specifically).
    // But wait, I removed UDP logic from SelectorGroup struct!
    // The UDP logic is in SelectorOutbound adapter.
    // And SelectorOutbound adapter uses SelectorGroup::select_best().

    // So if I want to test switching, I need to control what select_best() returns.
    // select_best() returns the manually selected proxy (if manual mode) or based on URLTest.
    // This is manual selector.
    // SelectorGroup exposes `select_by_name`.
    // But I don't have access to SelectorGroup instance here, it's inside the adapter.

    // I can construct SelectorOutbound manually?
    // Yes, SelectorOutbound is public in sb-adapters.
    use sb_adapters::outbound::selector::SelectorOutbound;
    use sb_core::outbound::selector_group::SelectorGroup;

    // Re-create members with UDP factories
    let members = vec![
        ProxyMember::new(
            member1_tag.clone(),
            Arc::new(MockConnector),
            Some(Arc::new(MockUdpFactoryImpl {
                tag: member1_tag.clone(),
            })),
        ),
        ProxyMember::new(
            member2_tag.clone(),
            Arc::new(MockConnector),
            Some(Arc::new(MockUdpFactoryImpl {
                tag: member2_tag.clone(),
            })),
        ),
    ];

    let group = SelectorGroup::new_manual(selector_tag.clone(), members, Some(member1_tag.clone()), None, None);
    let group = Arc::new(group);
    let outbound = SelectorOutbound::new(group.clone());

    // Test proxy1
    let session = outbound
        .open_session()
        .await
        .expect("failed to open session");
    let (data, _) = session.recv_from().await.expect("failed to recv");
    assert_eq!(data, member1_tag.as_bytes());

    // Switch to proxy2
    group
        .select_by_name(&member2_tag)
        .await
        .expect("failed to select proxy2");

    // Test proxy2
    let session = outbound
        .open_session()
        .await
        .expect("failed to open session");
    let (data, _) = session.recv_from().await.expect("failed to recv");
    assert_eq!(data, member2_tag.as_bytes());
}

#[tokio::test]
async fn test_urltest_udp_support() {
    // Similar setup for URLTest
    let member1_tag = "fast".to_string();
    let member2_tag = "slow".to_string();

    use sb_adapters::outbound::urltest::UrlTestOutbound;
    use sb_core::outbound::selector_group::SelectorGroup;

    let members = vec![
        ProxyMember::new(
            member1_tag.clone(),
            Arc::new(MockConnector),
            Some(Arc::new(MockUdpFactoryImpl {
                tag: member1_tag.clone(),
            })),
        ),
        ProxyMember::new(
            member2_tag.clone(),
            Arc::new(MockConnector),
            Some(Arc::new(MockUdpFactoryImpl {
                tag: member2_tag.clone(),
            })),
        ),
    ];

    // Set health for members
    members[0].health.record_success(10); // Fast
    members[1].health.record_success(100); // Slow

    let group = SelectorGroup::new_urltest(
        "test-urltest".to_string(),
        members,
        "http://test.com".to_string(),
        Duration::from_secs(60),
        Duration::from_secs(5),
        50,
        None,
        None,
    );
    let group = Arc::new(group);
    let outbound = UrlTestOutbound::new(group.clone());

    // Should select fast
    let session = outbound
        .open_session()
        .await
        .expect("failed to open session");
    let (data, _) = session.recv_from().await.expect("failed to recv");
    assert_eq!(data, member1_tag.as_bytes());
}
