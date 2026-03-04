#![cfg(all(target_os = "macos", feature = "tun_macos"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use sb_adapters::inbound::tun_process_aware::{ProcessAwareTunConfig, ProcessAwareTunInbound};

#[derive(Debug)]
struct DummyOutboundConnector;

#[async_trait::async_trait]
impl sb_core::outbound::OutboundConnector for DummyOutboundConnector {
    async fn connect_tcp(
        &self,
        _ctx: &sb_core::types::ConnCtx,
    ) -> sb_core::error::SbResult<tokio::net::TcpStream> {
        Err(sb_core::error::SbError::network(
            sb_core::error::ErrorClass::Connection,
            "dummy outbound connector",
        ))
    }

    async fn connect_udp(
        &self,
        _ctx: &sb_core::types::ConnCtx,
    ) -> sb_core::error::SbResult<Box<dyn sb_core::outbound::UdpTransport>> {
        Err(sb_core::error::SbError::network(
            sb_core::error::ErrorClass::Connection,
            "dummy outbound connector",
        ))
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
