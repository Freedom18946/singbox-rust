use sb_adapters::outbound::vless::{FlowControl, VlessConfig, VlessConnector};
use sb_adapters::traits::{from_transport_stream, DialOpts, OutboundConnector, Target};
use sb_adapters::transport_config::TransportConfig;
use sb_tls::{ensure_crypto_provider, RealityClientConfig, RealityConnector, TlsConnector};
use serde::Serialize;
use std::collections::HashMap;
use std::env;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use uuid::Uuid;

#[derive(Serialize)]
struct PhaseResult {
    ok: bool,
    elapsed_micros: u64,
    error: Option<String>,
}

#[derive(Serialize)]
struct ProbeOutput {
    server: String,
    port: u16,
    server_name: String,
    transport_type: String,
    uses_transport_dialer: bool,
    target: String,
    direct_reality: PhaseResult,
    transport_reality: PhaseResult,
    vless_dial: PhaseResult,
    vless_probe_io: PhaseResult,
}

fn env_or(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_string())
}

fn env_port(name: &str, default: u16) -> Result<u16, Box<dyn std::error::Error>> {
    Ok(env::var(name)
        .ok()
        .map(|value| value.parse::<u16>())
        .transpose()?
        .unwrap_or(default))
}

fn env_uuid(name: &str, default: &str) -> Result<Uuid, Box<dyn std::error::Error>> {
    Ok(Uuid::parse_str(&env_or(name, default))?)
}

async fn probe_direct_reality(
    server: &str,
    port: u16,
    reality: &RealityClientConfig,
) -> PhaseResult {
    let started_at = Instant::now();
    let result = async {
        let stream = TcpStream::connect((server, port)).await?;
        let connector = RealityConnector::new(reality.clone())?;
        let _tls = connector.connect(stream, &reality.server_name).await?;
        Result::<(), Box<dyn std::error::Error + Send + Sync>>::Ok(())
    }
    .await;

    match result {
        Ok(()) => PhaseResult {
            ok: true,
            elapsed_micros: started_at.elapsed().as_micros() as u64,
            error: None,
        },
        Err(error) => PhaseResult {
            ok: false,
            elapsed_micros: started_at.elapsed().as_micros() as u64,
            error: Some(error.to_string()),
        },
    }
}

async fn probe_transport_reality(
    config: &VlessConfig,
    reality: &RealityClientConfig,
) -> PhaseResult {
    let started_at = Instant::now();
    let result = async {
        let dialer = config.transport_layer.create_dialer_with_layers(None, None);
        let stream = dialer.connect(&config.server, config.port).await?;
        let stream = from_transport_stream(stream);
        let connector = RealityConnector::new(reality.clone())?;
        let _tls = connector.connect(stream, &reality.server_name).await?;
        Result::<(), Box<dyn std::error::Error + Send + Sync>>::Ok(())
    }
    .await;

    match result {
        Ok(()) => PhaseResult {
            ok: true,
            elapsed_micros: started_at.elapsed().as_micros() as u64,
            error: None,
        },
        Err(error) => PhaseResult {
            ok: false,
            elapsed_micros: started_at.elapsed().as_micros() as u64,
            error: Some(error.to_string()),
        },
    }
}

async fn probe_vless_dial(connector: &VlessConnector, target: &Target) -> PhaseResult {
    let started_at = Instant::now();
    match connector.dial(target.clone(), DialOpts::new()).await {
        Ok(_stream) => PhaseResult {
            ok: true,
            elapsed_micros: started_at.elapsed().as_micros() as u64,
            error: None,
        },
        Err(error) => PhaseResult {
            ok: false,
            elapsed_micros: started_at.elapsed().as_micros() as u64,
            error: Some(error.to_string()),
        },
    }
}

async fn probe_vless_probe_io(
    connector: &VlessConnector,
    target: &Target,
    timeout_ms: u64,
) -> PhaseResult {
    let started_at = Instant::now();
    let result = async {
        let mut stream = connector.dial(target.clone(), DialOpts::new()).await?;
        stream
            .write_all(b"HEAD / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
            .await
            .map_err(sb_adapters::error::AdapterError::Io)?;
        stream
            .flush()
            .await
            .map_err(sb_adapters::error::AdapterError::Io)?;

        let mut first_byte = [0u8; 1];
        tokio::time::timeout(
            std::time::Duration::from_millis(timeout_ms),
            stream.read_exact(&mut first_byte),
        )
        .await
        .map_err(|_| {
            sb_adapters::error::AdapterError::Other(format!(
                "timed out waiting for first upstream byte after {}ms",
                timeout_ms
            ))
        })?
        .map_err(sb_adapters::error::AdapterError::Io)?;

        Result::<(), sb_adapters::error::AdapterError>::Ok(())
    }
    .await;

    match result {
        Ok(()) => PhaseResult {
            ok: true,
            elapsed_micros: started_at.elapsed().as_micros() as u64,
            error: None,
        },
        Err(error) => PhaseResult {
            ok: false,
            elapsed_micros: started_at.elapsed().as_micros() as u64,
            error: Some(error.to_string()),
        },
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ensure_crypto_provider();

    let server = env_or("SB_VLESS_SERVER", "127.0.0.1");
    let port = env_port("SB_VLESS_PORT", 443)?;
    let server_name = env_or("SB_VLESS_SERVER_NAME", "www.apple.com");
    let public_key = env_or(
        "SB_VLESS_REALITY_PUBLIC_KEY",
        "ERERERERERERERERERERERERERERERERERERERERERE",
    );
    let short_id = env_or("SB_VLESS_REALITY_SHORT_ID", "01ab");
    let fingerprint = env_or("SB_VLESS_FINGERPRINT", "chrome");
    let uuid = env_uuid("SB_VLESS_UUID", "550e8400-e29b-41d4-a716-446655440000")?;
    let target_host = env_or("SB_VLESS_TARGET_HOST", "example.com");
    let target_port = env_port("SB_VLESS_TARGET_PORT", 80)?;
    let probe_io_timeout_ms = env::var("SB_VLESS_PROBE_IO_TIMEOUT_MS")
        .ok()
        .map(|value| value.parse::<u64>())
        .transpose()?
        .unwrap_or(20_000);

    let reality = RealityClientConfig {
        target: server_name.clone(),
        server_name: server_name.clone(),
        public_key,
        short_id: Some(short_id),
        fingerprint,
        alpn: Vec::new(),
    };

    let config = VlessConfig {
        server: server.clone(),
        port,
        uuid,
        flow: FlowControl::XtlsRprxVision,
        encryption: sb_adapters::outbound::vless::Encryption::None,
        headers: HashMap::new(),
        timeout: Some(60),
        tcp_fast_open: false,
        transport_layer: TransportConfig::Tcp,
        #[cfg(feature = "transport_mux")]
        multiplex: None,
        #[cfg(feature = "tls_reality")]
        reality: Some(reality.clone()),
        #[cfg(feature = "transport_ech")]
        ech: None,
    };
    let connector = VlessConnector::new(config.clone());
    let target = Target::tcp(&target_host, target_port);

    let output = ProbeOutput {
        server,
        port,
        server_name,
        transport_type: format!("{:?}", connector.transport_type()),
        uses_transport_dialer: connector.uses_transport_dialer(),
        target: format!("{}:{}", target.host, target.port),
        direct_reality: probe_direct_reality(&config.server, config.port, &reality).await,
        transport_reality: probe_transport_reality(&config, &reality).await,
        vless_dial: probe_vless_dial(&connector, &target).await,
        vless_probe_io: probe_vless_probe_io(&connector, &target, probe_io_timeout_ms).await,
    };

    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}
