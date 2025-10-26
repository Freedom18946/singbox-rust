//! Shadowsocks 2022 minimal connection harness for testing.
//!
//! Provides [`connect_env`] for basic connectivity testing without full protocol implementation.
//! Optionally supports TLS-first connections via feature gate.

use sb_transport::{Dialer, TcpDialer};
use std::time::Instant;
use thiserror::Error;

#[cfg(feature = "proto_ss2022_tls_first")]
use sb_transport::tls::{smoke_empty_roots_config, TlsDialer};

/// Errors that can occur during SS2022 harness operations.
#[derive(Debug, Error)]
pub enum HarnessError {
    /// Connection timeout.
    #[error("connection timeout")]
    Timeout,
    /// Transport-level error.
    #[error("transport error: {0}")]
    Transport(String),
    /// Feature not enabled.
    #[error("feature not enabled: {0}")]
    FeatureDisabled(&'static str),
}

/// Report of a connection attempt.
#[derive(Debug, Clone)]
pub struct ConnectReport {
    /// Whether the connection succeeded.
    pub ok: bool,
    /// Connection path taken ("tcp" or "tls").
    pub path: &'static str,
    /// Time elapsed in milliseconds.
    pub elapsed_ms: u64,
}

/// Attempts a minimal connection to test SS2022 connectivity.
///
/// # Parameters
/// - `host`: Target hostname or IP
/// - `port`: Target port
/// - `timeout_ms`: Connection timeout in milliseconds (clamped to 10-60000)
/// - `tls`: Whether to use TLS (requires `proto_ss2022_tls_first` feature)
///
/// # Errors
/// Returns `HarnessError` on timeout, transport failure, or feature unavailability.
pub async fn connect_env(
    host: &str,
    port: u16,
    timeout_ms: u64,
    tls: bool,
) -> Result<ConnectReport, HarnessError> {
    let start = Instant::now();
    let timeout_duration = std::time::Duration::from_millis(timeout_ms.clamp(10, 60_000));

    if tls {
        #[cfg(feature = "proto_ss2022_tls_first")]
        {
            let config = smoke_empty_roots_config();
            let tls_dialer = TlsDialer::from_env(TcpDialer, config);
            tokio::time::timeout(timeout_duration, tls_dialer.connect(host, port))
                .await
                .map_err(|_| HarnessError::Timeout)?
                .map_err(|e| HarnessError::Transport(e.to_string()))?;

            Ok(ConnectReport {
                ok: true,
                path: "tls",
                elapsed_ms: start.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
            })
        }
        #[cfg(not(feature = "proto_ss2022_tls_first"))]
        {
            Err(HarnessError::FeatureDisabled("proto_ss2022_tls_first"))
        }
    } else {
        let dialer = TcpDialer;
        tokio::time::timeout(timeout_duration, dialer.connect(host, port))
            .await
            .map_err(|_| HarnessError::Timeout)?
            .map_err(|e| HarnessError::Transport(e.to_string()))?;

        Ok(ConnectReport {
            ok: true,
            path: "tcp",
            elapsed_ms: start.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
        })
    }
}

/// Builds a TLS ClientHello first packet (placeholder for testing).
///
/// # Security Warning
/// This is a MOCK implementation for testing byte shapes only. Does NOT perform real TLS handshake.
#[cfg(feature = "proto_ss2022_tls_first")]
#[must_use]
pub fn build_tls_first_packet(payload: &[u8], sni: Option<&str>) -> Vec<u8> {
    let mut packet = Vec::new();

    // TLS Record Header
    packet.push(0x16); // Content Type: Handshake
    packet.extend_from_slice(&[0x03, 0x03]); // Version: TLS 1.2

    let length_pos = packet.len();
    packet.extend_from_slice(&[0x00, 0x00]); // Length placeholder

    let hello_start = packet.len();

    // Client Hello
    packet.push(0x01); // Handshake Type

    let hello_length_pos = packet.len();
    packet.extend_from_slice(&[0x00, 0x00, 0x00]);

    let hello_content_start = packet.len();

    // Version
    packet.extend_from_slice(&[0x03, 0x03]); // TLS 1.2

    // Random (32 bytes) - hash payload for pseudo-random
    let mut hasher = blake3::Hasher::new();
    hasher.update(payload);
    let hash = hasher.finalize();
    packet.extend_from_slice(&hash.as_bytes()[..32]);

    // Session ID
    packet.push(0x00);

    // Cipher Suites
    packet.extend_from_slice(&[0x00, 0x04]);
    packet.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
    packet.extend_from_slice(&[0x13, 0x02]); // TLS_AES_256_GCM_SHA384

    // Compression
    packet.push(0x01);
    packet.push(0x00);

    // Extensions
    let ext_length_pos = packet.len();
    packet.extend_from_slice(&[0x00, 0x00]);
    let ext_start = packet.len();

    if let Some(sni_name) = sni {
        packet.extend_from_slice(&[0x00, 0x00]); // SNI extension type

        let sni_ext_length_pos = packet.len();
        packet.extend_from_slice(&[0x00, 0x00]);
        let sni_ext_start = packet.len();

        let sni_list_length_pos = packet.len();
        packet.extend_from_slice(&[0x00, 0x00]);
        let sni_list_start = packet.len();

        packet.push(0x00); // host_name type

        let name_bytes = sni_name.as_bytes();
        packet.extend_from_slice(&[0x00, name_bytes.len() as u8]);
        packet.extend_from_slice(name_bytes);

        let sni_list_length = packet.len() - sni_list_start;
        packet[sni_list_length_pos..sni_list_length_pos + 2]
            .copy_from_slice(&(sni_list_length as u16).to_be_bytes());

        let sni_ext_length = packet.len() - sni_ext_start;
        packet[sni_ext_length_pos..sni_ext_length_pos + 2]
            .copy_from_slice(&(sni_ext_length as u16).to_be_bytes());
    }

    let ext_total_length = packet.len() - ext_start;
    packet[ext_length_pos..ext_length_pos + 2]
        .copy_from_slice(&(ext_total_length as u16).to_be_bytes());

    let hello_content_length = packet.len() - hello_content_start;
    let hello_bytes = (hello_content_length as u32).to_be_bytes();
    packet[hello_length_pos..hello_length_pos + 3].copy_from_slice(&hello_bytes[1..]);

    let record_length = packet.len() - hello_start;
    packet[length_pos..length_pos + 2].copy_from_slice(&(record_length as u16).to_be_bytes());

    packet
}

/// Generates a hex dump preview of a TLS first packet for debugging.
#[cfg(feature = "proto_ss2022_tls_first")]
#[must_use]
pub fn preview_tls_first_packet(payload: &[u8]) -> String {
    use std::fmt::Write;
    let packet = build_tls_first_packet(payload, Some("example.com"));
    let mut hex_output = String::new();

    for (i, byte) in packet.iter().enumerate() {
        if i % 16 == 0 {
            if i > 0 {
                let _ = writeln!(&mut hex_output);
            }
            let _ = write!(&mut hex_output, "{:04x}: ", i);
        }
        let _ = write!(&mut hex_output, "{:02x} ", byte);
    }
    if !packet.is_empty() {
        let _ = writeln!(&mut hex_output);
    }
    hex_output
}
