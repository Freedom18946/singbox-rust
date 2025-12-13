#![cfg(feature = "service_derp")]

use anyhow::Result;
use sb_config::validator::v2::to_ir_v1;
use sb_core::adapter::Bridge;
use sb_core::context::Context;
use sb_core::service::StartStage;
use serde_json::json;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::sleep;

fn find_free_port() -> std::io::Result<u16> {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|addr| addr.port())
}

#[tokio::test]
async fn derp_service_bridge_mock_relay_e2e() -> Result<()> {
    #[cfg(feature = "adapters")]
    sb_adapters::register_all();

    let port = match find_free_port() {
        Ok(port) => port,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping derp bridge test: {e}");
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };

    let config = json!({
        "services": [{
            "type": "derp",
            "tag": "derp-bridge",
            "listen": "127.0.0.1",
            "listen_port": port,
            "stun": { "enabled": false },
            "mesh_psk": "bridge-secret"
        }],
        "inbounds": [],
        "outbounds": [{
            "type": "direct",
            "tag": "direct-out"
        }]
    });

    let ir = to_ir_v1(&config);
    let bridge = Bridge::new_from_config(&ir, Context::new())?;
    assert_eq!(bridge.services.len(), 1);
    let service = bridge.services[0].clone();

    service
        .start(StartStage::Initialize)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    service
        .start(StartStage::Start)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    sleep(Duration::from_millis(50)).await;

    let addr = ("127.0.0.1", port);
    let mut a = TcpStream::connect(addr).await?;
    let mut b = TcpStream::connect(addr).await?;

    a.write_all(b"DERP session bridge token=bridge-secret\n")
        .await?;
    b.write_all(b"DERP session bridge token=bridge-secret\n")
        .await?;

    sleep(Duration::from_millis(20)).await;

    a.write_all(b"ping").await?;
    let mut buf = [0u8; 4];
    b.read_exact(&mut buf).await?;
    assert_eq!(&buf, b"ping");

    service
        .close()
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    Ok(())
}
