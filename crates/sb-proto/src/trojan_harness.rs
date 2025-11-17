//! Trojan end-to-end testing harness with minimal connectivity checks.
//!
//! Provides [`connect_env`] for testing Trojan connections over TCP or TLS.
//! Primarily intended for validation and admin tools, not production data channels.
//!
//! # Security Note
//! Network access is gated by `SB_ADMIN_ALLOW_NET` environment variable in admin contexts.

use crate::trojan_min::TrojanHello;
use sb_transport::dialer::{Dialer, TcpDialer};
#[cfg(feature = "transport_tls")]
use sb_transport::tls::{webpki_roots_config, TlsDialer};
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::time::{timeout, Duration, Instant};

/// Errors that can occur during harness operations.
#[derive(Debug, Error)]
pub enum HarnessError {
    /// Connection or write timeout.
    #[error("operation timeout")]
    Timeout,
    /// Transport-level error.
    #[error("transport error: {0}")]
    Transport(String),
}

/// Connection options for harness testing.
#[derive(Debug, Clone)]
pub struct ConnectOpts {
    /// Whether to use TLS transport.
    pub tls: bool,
    /// Timeout in milliseconds (clamped to 10-10000).
    pub timeout_ms: u64,
}

impl Default for ConnectOpts {
    fn default() -> Self {
        Self {
            tls: false,
            timeout_ms: 100,
        }
    }
}

/// Report of a connection attempt.
#[derive(Debug, Clone)]
pub struct ConnectReport {
    /// Connection path taken ("tcp" or "tls").
    pub path: &'static str,
    /// Time elapsed in milliseconds.
    pub elapsed_ms: u64,
}

/// Performs TCP-only connection and writes Trojan hello packet.
async fn tcp_hello(
    host: &str,
    port: u16,
    password: &str,
    duration: Duration,
) -> Result<(), HarnessError> {
    let dialer = TcpDialer;
    let mut stream = timeout(duration, dialer.connect(host, port))
        .await
        .map_err(|_| HarnessError::Timeout)?
        .map_err(|e| HarnessError::Transport(e.to_string()))?;

    let hello = TrojanHello {
        password: password.to_string(),
        host: host.to_string(),
        port,
    };
    let buf = hello.to_bytes();

    timeout(duration, stream.write_all(&buf))
        .await
        .map_err(|_| HarnessError::Timeout)?
        .map_err(|e| HarnessError::Transport(e.to_string()))?;

    Ok(())
}

/// Performs minimal Trojan connection test with optional TLS.
///
/// Falls back to TCP if TLS is requested but `transport_tls` feature is not enabled.
///
/// # Errors
/// Returns `HarnessError` on timeout or transport failure.
pub async fn connect_env(
    host: &str,
    port: u16,
    password: &str,
    opts: ConnectOpts,
) -> Result<ConnectReport, HarnessError> {
    let duration = Duration::from_millis(opts.timeout_ms.clamp(10, 10_000));
    let start = Instant::now();

    if opts.tls {
        #[cfg(feature = "transport_tls")]
        {
            let dialer = TlsDialer::from_env(TcpDialer, webpki_roots_config());
            let mut stream = timeout(duration, dialer.connect(host, port))
                .await
                .map_err(|_| HarnessError::Timeout)?
                .map_err(|e| HarnessError::Transport(e.to_string()))?;

            let hello = TrojanHello {
                password: password.to_string(),
                host: host.to_string(),
                port,
            };
            let buf = hello.to_bytes();

            timeout(duration, stream.write_all(&buf))
                .await
                .map_err(|_| HarnessError::Timeout)?
                .map_err(|e| HarnessError::Transport(e.to_string()))?;

            return Ok(ConnectReport {
                path: "tls",
                elapsed_ms: start.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
            });
        }
        #[cfg(not(feature = "transport_tls"))]
        {
            // Fallback to TCP when TLS not available
        }
    }

    tcp_hello(host, port, password, duration).await?;
    Ok(ConnectReport {
        path: "tcp",
        elapsed_ms: start.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
    })
}
