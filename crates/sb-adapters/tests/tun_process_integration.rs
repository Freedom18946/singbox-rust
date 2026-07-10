#![cfg(all(target_os = "macos", feature = "tun_macos"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use sb_adapters::inbound::tun_process_aware::{ProcessAwareTunConfig, ProcessAwareTunInbound};

#[derive(Debug)]
struct DummyOutboundConnector;

impl sb_core::outbound::Outbound for DummyOutboundConnector {
    fn r#type(&self) -> &str {
        "dummy"
    }
    fn tag(&self) -> sb_types::OutboundTag {
        sb_types::OutboundTag::new("dummy")
    }
    fn network(&self) -> &[sb_types::NetworkKind] {
        &[sb_types::NetworkKind::Tcp]
    }
    fn dial<'a>(
        &'a self,
        _session: &'a sb_types::Session,
    ) -> sb_types::BoxFuture<'a, Result<sb_types::BoxedStream, sb_types::CoreError>> {
        Box::pin(async {
            Err(sb_types::CoreError::connect(
                sb_types::ConnectErrorKind::Unsupported,
                "dummy outbound connector",
            ))
        })
    }
    fn listen_packet<'a>(
        &'a self,
        _session: &'a sb_types::Session,
    ) -> sb_types::BoxFuture<'a, Result<sb_types::BoxedPacketConn, sb_types::CoreError>> {
        Box::pin(async {
            Err(sb_types::CoreError::connect(
                sb_types::ConnectErrorKind::Unsupported,
                "dummy outbound connector",
            ))
        })
    }
}

#[tokio::test]
async fn instantiate_and_shutdown_runtime() {
    let cfg = ProcessAwareTunConfig {
        name: "utun9".to_string(),
        ..Default::default()
    };
    let outbound = Arc::new(DummyOutboundConnector);
    let inbound = ProcessAwareTunInbound::new(cfg, outbound, None).unwrap();

    // Runtime requires elevated privileges; start may fail but should not panic.
    let result = inbound.start().await;
    if let Err(err) = result {
        eprintln!("start failed (likely due to missing privileges): {err}");
    }
    inbound.stop().await;
}
