use sb_adapters::outbound::selector_group::{ProxyMember, SelectorGroup, UrlTestOptions};
use sb_config::ir::{OutboundIR, OutboundType};
use sb_core::adapter::{Bridge, OutboundParam};
use sb_core::context::{Context, ContextRegistry};
use sb_types::Outbound;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug)]
struct MockConnector {
    tag: String,
}

impl MockConnector {
    fn new(tag: impl Into<String>) -> Self {
        Self { tag: tag.into() }
    }
}

impl Outbound for MockConnector {
    fn r#type(&self) -> &str {
        "mock"
    }

    fn tag(&self) -> sb_types::OutboundTag {
        sb_types::OutboundTag::new(self.tag.clone())
    }

    fn network(&self) -> &[sb_types::NetworkKind] {
        &[sb_types::NetworkKind::Udp]
    }

    fn dial<'a>(
        &'a self,
        _session: &'a sb_types::Session,
    ) -> sb_types::BoxFuture<'a, Result<sb_types::BoxedStream, sb_types::CoreError>> {
        Box::pin(async {
            Err(sb_types::CoreError::connect(
                sb_types::ConnectErrorKind::Unsupported,
                "mock only supports UDP",
            ))
        })
    }

    fn listen_packet<'a>(
        &'a self,
        _session: &'a sb_types::Session,
    ) -> sb_types::BoxFuture<'a, Result<sb_types::BoxedPacketConn, sb_types::CoreError>> {
        let tag = self.tag.clone();
        Box::pin(async move { Ok(Box::new(MockPacketConn { tag }) as sb_types::BoxedPacketConn) })
    }
}

#[derive(Debug)]
struct MockPacketConn {
    tag: String,
}

impl sb_types::PacketConn for MockPacketConn {
    fn send_to<'a>(
        &'a self,
        data: &'a [u8],
        _destination: &'a sb_types::TargetAddr,
    ) -> sb_types::BoxFuture<'a, Result<usize, sb_types::CoreError>> {
        Box::pin(async move { Ok(data.len()) })
    }

    fn recv_from<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> sb_types::BoxFuture<'a, Result<(usize, sb_types::TargetAddr), sb_types::CoreError>> {
        Box::pin(async move {
            let data = self.tag.as_bytes();
            let size = data.len().min(buffer.len());
            buffer[..size].copy_from_slice(&data[..size]);
            Ok((
                size,
                sb_types::TargetAddr::socket("127.0.0.1:0".parse().unwrap()),
            ))
        })
    }

    fn close(&self) -> sb_types::BoxFuture<'_, Result<(), sb_types::CoreError>> {
        Box::pin(async { Ok(()) })
    }

    fn local_addr(&self) -> Option<sb_types::TargetAddr> {
        None
    }

    fn set_deadline(
        &self,
        _deadline: Option<std::time::Instant>,
    ) -> Result<(), sb_types::CoreError> {
        Ok(())
    }

    fn set_read_deadline(
        &self,
        _deadline: Option<std::time::Instant>,
    ) -> Result<(), sb_types::CoreError> {
        Ok(())
    }

    fn set_write_deadline(
        &self,
        _deadline: Option<std::time::Instant>,
    ) -> Result<(), sb_types::CoreError> {
        Ok(())
    }
}

fn packet_session() -> sb_types::Session {
    sb_types::Session::new(
        0,
        sb_types::InboundTag::new("selector-test"),
        sb_types::TargetAddr::domain("example.test", 53),
    )
}

async fn assert_packet_tag(outbound: &dyn Outbound, expected: &str) {
    let packet = outbound
        .listen_packet(&packet_session())
        .await
        .expect("open canonical packet connection");
    let mut buffer = [0u8; 64];
    let (size, _) = packet.recv_from(&mut buffer).await.expect("recv tag");
    assert_eq!(&buffer[..size], expected.as_bytes());
}

#[tokio::test]
async fn selector_builder_routes_udp_through_selected_member() {
    let mut bridge = Bridge::new(Context::new());
    bridge.add_outbound(
        "proxy1".to_string(),
        "mock".to_string(),
        Arc::new(MockConnector::new("proxy1")),
    );
    bridge.add_outbound(
        "proxy2".to_string(),
        "mock".to_string(),
        Arc::new(MockConnector::new("proxy2")),
    );

    let ir = OutboundIR {
        name: Some("test-selector".to_string()),
        ty: OutboundType::Selector,
        members: Some(vec!["proxy1".to_string(), "proxy2".to_string()]),
        default_member: Some("proxy1".to_string()),
        ..Default::default()
    };
    let param = OutboundParam {
        name: Some("test-selector".to_string()),
        ..Default::default()
    };
    let bridge = Arc::new(bridge);
    let context = sb_core::adapter::registry::AdapterOutboundContext {
        context: ContextRegistry::from(&bridge.context),
        bridge,
    };
    let selector = sb_adapters::outbound::selector::build_selector_outbound(&param, &ir, &context)
        .expect("selector builder");

    assert!(selector.network().contains(&sb_types::NetworkKind::Udp));
    assert_packet_tag(selector.as_ref(), "proxy1").await;
}

#[tokio::test]
async fn selector_and_urltest_switch_canonical_udp_members() {
    let members = vec![
        ProxyMember::new("proxy1", Arc::new(MockConnector::new("proxy1"))),
        ProxyMember::new("proxy2", Arc::new(MockConnector::new("proxy2"))),
    ];
    let group = SelectorGroup::new_manual(
        "manual".to_string(),
        members,
        Some("proxy1".to_string()),
        None,
        None,
    );
    assert_packet_tag(&group, "proxy1").await;
    group.select_by_name("proxy2").await.expect("select proxy2");
    assert_packet_tag(&group, "proxy2").await;

    let members = vec![
        ProxyMember::new("fast", Arc::new(MockConnector::new("fast"))),
        ProxyMember::new("slow", Arc::new(MockConnector::new("slow"))),
    ];
    members[0].health.record_success(10);
    members[1].health.record_success(100);
    let group = SelectorGroup::new_urltest(
        "urltest".to_string(),
        members,
        UrlTestOptions {
            test_url: "http://test.invalid".to_string(),
            interval: Duration::from_secs(60),
            timeout: Duration::from_secs(5),
            tolerance_ms: 50,
            cache_file: None,
            urltest_history: None,
        },
    );
    assert_packet_tag(&group, "fast").await;
}
