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
    class: Option<String>,
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
    phase_timeout_ms: u64,
    probe_io_timeout_ms: u64,
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

impl PhaseResult {
    fn ok(elapsed_micros: u64) -> Self {
        Self {
            ok: true,
            elapsed_micros,
            class: None,
            error: None,
        }
    }

    fn error(elapsed_micros: u64, error: impl ToString) -> Self {
        let raw_error = error.to_string();
        let class = classify_probe_error_text(&raw_error).to_string();
        let error = sanitize_probe_detail(&raw_error);
        Self {
            ok: false,
            elapsed_micros,
            class: Some(class),
            error: Some(error),
        }
    }

    fn timeout(elapsed_micros: u64, timeout_ms: u64) -> Self {
        Self {
            ok: false,
            elapsed_micros,
            class: Some("timeout".to_string()),
            error: Some(format!("timeout after {}ms", timeout_ms)),
        }
    }
}

fn classify_probe_error_text(error: &str) -> &'static str {
    let lower = error.to_ascii_lowercase();
    if lower.contains("http2 framing") || lower.contains("http/2 framing") {
        "http2_framing"
    } else if lower.contains("tls handshake eof") || lower.contains("handshake eof") {
        "reality_dial_eof"
    } else if lower.contains("early eof") || lower.contains("unexpected eof") || lower == "eof" {
        "post_dial_eof"
    } else if lower.contains("timed out") || lower.contains("timeout") {
        "timeout"
    } else if lower.contains("can't complete socks5") || lower.contains("socks5") {
        "socks_connect"
    } else if lower.contains("connection reset") {
        "connection_reset"
    } else if lower.contains("broken pipe") {
        "broken_pipe"
    } else if lower.contains("connection refused") {
        "connection_refused"
    } else {
        "other"
    }
}

fn sanitize_probe_detail(detail: &str) -> String {
    let collapsed = detail.split_whitespace().collect::<Vec<_>>().join(" ");
    const MAX_DETAIL_LEN: usize = 240;
    if collapsed.len() <= MAX_DETAIL_LEN {
        collapsed
    } else {
        format!(
            "{}...",
            collapsed.chars().take(MAX_DETAIL_LEN).collect::<String>()
        )
    }
}

async fn probe_direct_reality(
    server: &str,
    port: u16,
    reality: &RealityClientConfig,
    timeout_ms: u64,
) -> PhaseResult {
    let started_at = Instant::now();
    let result = tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), async {
        let stream = TcpStream::connect((server, port)).await?;
        let connector = RealityConnector::new(reality.clone())?;
        let _tls = connector.connect(stream, &reality.server_name).await?;
        Result::<(), Box<dyn std::error::Error + Send + Sync>>::Ok(())
    })
    .await;

    match result {
        Ok(Ok(())) => PhaseResult::ok(started_at.elapsed().as_micros() as u64),
        Ok(Err(error)) => PhaseResult::error(started_at.elapsed().as_micros() as u64, error),
        Err(_) => PhaseResult::timeout(started_at.elapsed().as_micros() as u64, timeout_ms),
    }
}

async fn probe_transport_reality(
    config: &VlessConfig,
    reality: &RealityClientConfig,
    timeout_ms: u64,
) -> PhaseResult {
    let started_at = Instant::now();
    let result = tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), async {
        let dialer = config.transport_layer.create_dialer_with_layers(None, None);
        let stream = dialer.connect(&config.server, config.port).await?;
        let stream = from_transport_stream(stream);
        let connector = RealityConnector::new(reality.clone())?;
        let _tls = connector.connect(stream, &reality.server_name).await?;
        Result::<(), Box<dyn std::error::Error + Send + Sync>>::Ok(())
    })
    .await;

    match result {
        Ok(Ok(())) => PhaseResult::ok(started_at.elapsed().as_micros() as u64),
        Ok(Err(error)) => PhaseResult::error(started_at.elapsed().as_micros() as u64, error),
        Err(_) => PhaseResult::timeout(started_at.elapsed().as_micros() as u64, timeout_ms),
    }
}

async fn probe_vless_dial(
    connector: &VlessConnector,
    target: &Target,
    timeout_ms: u64,
) -> PhaseResult {
    let started_at = Instant::now();
    match tokio::time::timeout(
        std::time::Duration::from_millis(timeout_ms),
        connector.dial(target.clone(), DialOpts::new()),
    )
    .await
    {
        Ok(Ok(_stream)) => PhaseResult::ok(started_at.elapsed().as_micros() as u64),
        Ok(Err(error)) => PhaseResult::error(started_at.elapsed().as_micros() as u64, error),
        Err(_) => PhaseResult::timeout(started_at.elapsed().as_micros() as u64, timeout_ms),
    }
}

async fn probe_vless_probe_io(
    connector: &VlessConnector,
    target: &Target,
    timeout_ms: u64,
) -> PhaseResult {
    let started_at = Instant::now();
    let result = tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), async {
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
    })
    .await;

    match result {
        Ok(Ok(())) => PhaseResult::ok(started_at.elapsed().as_micros() as u64),
        Ok(Err(error)) => PhaseResult::error(started_at.elapsed().as_micros() as u64, error),
        Err(_) => PhaseResult::timeout(started_at.elapsed().as_micros() as u64, timeout_ms),
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
    let phase_timeout_ms = env::var("SB_VLESS_PHASE_TIMEOUT_MS")
        .ok()
        .map(|value| value.parse::<u64>())
        .transpose()?
        .unwrap_or(probe_io_timeout_ms);

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
        phase_timeout_ms,
        probe_io_timeout_ms,
        direct_reality: probe_direct_reality(
            &config.server,
            config.port,
            &reality,
            phase_timeout_ms,
        )
        .await,
        transport_reality: probe_transport_reality(&config, &reality, phase_timeout_ms).await,
        vless_dial: probe_vless_dial(&connector, &target, phase_timeout_ms).await,
        vless_probe_io: probe_vless_probe_io(&connector, &target, probe_io_timeout_ms).await,
    };

    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_probe_error_text_covers_reality_live_failures() {
        assert_eq!(
            classify_probe_error_text("REALITY handshake failed: tls handshake eof"),
            "reality_dial_eof"
        );
        assert_eq!(
            classify_probe_error_text("curl: (16) Error in the HTTP2 framing layer"),
            "http2_framing"
        );
        assert_eq!(classify_probe_error_text("early eof"), "post_dial_eof");
        assert_eq!(classify_probe_error_text("unexpected eof"), "post_dial_eof");
        assert_eq!(
            classify_probe_error_text("timed out waiting for first upstream byte"),
            "timeout"
        );
        assert_eq!(
            classify_probe_error_text("Can't complete SOCKS5 connection"),
            "socks_connect"
        );
        assert_eq!(
            classify_probe_error_text("connection reset by peer"),
            "connection_reset"
        );
        assert_eq!(classify_probe_error_text("broken pipe"), "broken_pipe");
    }

    #[test]
    fn phase_result_error_classifies_and_sanitizes_details() {
        let result = PhaseResult::error(7, "REALITY\n handshake failed: tls handshake eof");
        assert!(!result.ok);
        assert_eq!(result.elapsed_micros, 7);
        assert_eq!(result.class.as_deref(), Some("reality_dial_eof"));
        assert_eq!(
            result.error.as_deref(),
            Some("REALITY handshake failed: tls handshake eof")
        );
    }

    #[test]
    fn sanitize_probe_detail_truncates_long_errors() {
        let long = "x".repeat(300);
        let sanitized = sanitize_probe_detail(&long);
        assert_eq!(sanitized.len(), 243);
        assert!(sanitized.ends_with("..."));
    }

    #[test]
    fn phase_result_classifies_before_truncating_details() {
        let result = PhaseResult::error(9, format!("{} tls handshake eof", "x".repeat(260)));
        assert_eq!(result.class.as_deref(), Some("reality_dial_eof"));
        assert_eq!(result.error.as_ref().unwrap().len(), 243);
    }
}
