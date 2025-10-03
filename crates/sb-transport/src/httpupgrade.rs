//! HTTPUpgrade Transport Layer
//!
//! Minimal client-side HTTP/1.1 Upgrade handshake to establish a raw byte stream
//! over an HTTP connection. Useful for environments where WebSocket is not desired
//! but an upgrade-based tunnel is acceptable.
//!
//! This implementation performs a simple GET with `Upgrade` and `Connection: Upgrade`
//! headers, validates a `101 Switching Protocols` response, and then returns the
//! underlying stream for further use.

use crate::dialer::{DialError, Dialer, IoStream};
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::debug;

#[derive(Debug, Clone)]
pub struct HttpUpgradeConfig {
    pub path: String,
    pub headers: Vec<(String, String)>,
}

impl Default for HttpUpgradeConfig {
    fn default() -> Self {
        Self { path: "/".to_string(), headers: Vec::new() }
    }
}

pub struct HttpUpgradeDialer {
    config: HttpUpgradeConfig,
    inner: Box<dyn Dialer>,
}

impl HttpUpgradeDialer {
    pub fn new(config: HttpUpgradeConfig, inner: Box<dyn Dialer>) -> Self { Self { config, inner } }
    pub fn with_default_config(inner: Box<dyn Dialer>) -> Self { Self::new(HttpUpgradeConfig::default(), inner) }
}

#[async_trait]
impl Dialer for HttpUpgradeDialer {
    async fn connect(&self, host: &str, port: u16) -> Result<IoStream, DialError> {
        debug!("Dialing HTTPUpgrade: {}:{}{}", host, port, self.config.path);
        let mut stream = self.inner.connect(host, port).await?;

        // Compose request
        let mut req = format!(
            "GET {} HTTP/1.1\r\nHost: {}:{}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n",
            self.config.path, host, port
        );
        for (k, v) in &self.config.headers {
            req.push_str(&format!("{}: {}\r\n", k, v));
        }
        req.push_str("\r\n");

        // Send request
        stream
            .write_all(req.as_bytes())
            .await
            .map_err(|e| DialError::Other(format!("HTTPUpgrade write failed: {}", e)))?;

        // Read response headers until CRLFCRLF
        let mut buf = Vec::with_capacity(1024);
        let mut tmp = [0u8; 256];
        loop {
            let n = stream
                .read(&mut tmp)
                .await
                .map_err(|e| DialError::Other(format!("HTTPUpgrade read failed: {}", e)))?;
            if n == 0 { return Err(DialError::Other("HTTPUpgrade: EOF before headers".into())); }
            buf.extend_from_slice(&tmp[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") { break; }
            if buf.len() > 8192 { return Err(DialError::Other("HTTPUpgrade: header too large".into())); }
        }

        // Validate status line contains 101
        let header_str = String::from_utf8_lossy(&buf);
        let ok = header_str
            .lines()
            .next()
            .map(|line| line.contains(" 101 ") || line.starts_with("HTTP/1.1 101") || line.starts_with("HTTP/1.0 101"))
            .unwrap_or(false);
        if !ok {
            return Err(DialError::Other(format!("HTTPUpgrade: bad status line: {}", header_str.lines().next().unwrap_or(""))));
        }

        Ok(stream)
    }
}

