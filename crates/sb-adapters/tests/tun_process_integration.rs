#![cfg(all(target_os = "macos", feature = "tun_macos"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use sb_adapters::inbound::tun_process_aware::{ProcessAwareTunConfig, ProcessAwareTunInbound};
use sb_core::outbound::DirectConnector;

#[tokio::test]
async fn instantiate_and_shutdown_runtime() {
    let cfg = ProcessAwareTunConfig {
        name: "utun9".to_string(),
        ..Default::default()
    };
    let outbound = Arc::new(DirectConnector::new());
    let inbound = ProcessAwareTunInbound::new(cfg, outbound, None).unwrap();

    // Runtime requires elevated privileges; start may fail but should not panic.
    let result = inbound.start().await;
    if let Err(err) = result {
        eprintln!("start failed (likely due to missing privileges): {err}");
    }
    inbound.stop().await;
}
