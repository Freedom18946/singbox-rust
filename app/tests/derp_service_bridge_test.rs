#![cfg(feature = "service_derp")]

use anyhow::Result;
use sb_config::validator::v2::to_ir_v1;
use sb_core::adapter::Bridge;
use sb_core::context::Context;
use sb_core::service::StartStage;
use serde_json::json;
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;
use tempfile::{NamedTempFile, TempDir};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::sleep;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

fn find_free_port() -> std::io::Result<u16> {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|addr| addr.port())
}

#[tokio::test]
async fn derp_service_bridge_mock_relay_e2e() -> Result<()> {
    #[cfg(feature = "adapters")]
    sb_adapters::register_all();

    let _ = rustls::crypto::ring::default_provider().install_default();

    let port = match find_free_port() {
        Ok(port) => port,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping derp bridge test: {e}");
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };

    let psk = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_pem = cert.serialize_pem()?;
    let key_pem = cert.serialize_private_key_pem();
    let mut cert_file = NamedTempFile::new()?;
    cert_file.write_all(cert_pem.as_bytes())?;
    let mut key_file = NamedTempFile::new()?;
    key_file.write_all(key_pem.as_bytes())?;
    let config_dir = TempDir::new()?;
    let config_path = config_dir
        .path()
        .join("derp.key")
        .to_string_lossy()
        .to_string();

    let config = json!({
        "services": [{
            "type": "derp",
            "tag": "derp-bridge",
            "listen": "127.0.0.1",
            "listen_port": port,
            "config_path": config_path,
            "tls": {
                "enabled": true,
                "certificate_path": cert_file.path().to_string_lossy(),
                "key_path": key_file.path().to_string_lossy()
            },
            "stun": { "enabled": false },
            "mesh_psk": psk
        }],
        "inbounds": [],
        "outbounds": [{
            "type": "direct",
            "name": "direct-out"
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
    let connector = build_tls_connector(&cert_pem)?;
    let mut a = connect_tls(addr, &connector).await?;
    let mut b = connect_tls(addr, &connector).await?;

    let handshake = format!("DERP session bridge token={psk}\n");
    a.write_all(handshake.as_bytes()).await?;
    b.write_all(handshake.as_bytes()).await?;

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

fn build_tls_connector(cert_pem: &str) -> Result<TlsConnector> {
    let mut roots = RootCertStore::empty();
    let mut reader = std::io::Cursor::new(cert_pem.as_bytes());
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    for cert in certs {
        roots
            .add(cert)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    }
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

async fn connect_tls(
    addr: (&str, u16),
    connector: &TlsConnector,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let stream = TcpStream::connect(addr).await?;
    let server_name =
        ServerName::try_from("localhost").map_err(|e| anyhow::anyhow!(e.to_string()))?;
    Ok(connector.connect(server_name, stream).await?)
}
