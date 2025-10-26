//! Minimal Trojan outbound connector with injectable dialer.
//!
//! This module provides a [`TrojanConnector`] that establishes connections and writes
//! the Trojan hello packet. It's primarily designed for testing with injectable dialers.
//!
//! # Behavior
//! - Dials the target using the injected `Dialer`
//! - Writes the [`TrojanHello`] first packet
//! - Does not implement full proxy logic (minimal implementation)

use crate::connector::{IoStream, OutboundConnector, ProtoError, Target};
use crate::trojan_min::TrojanHello;
use async_trait::async_trait;
use sb_transport::dialer::Dialer;

/// Trojan connector with injectable dialer for testing.
///
/// This connector writes the Trojan handshake packet but doesn't implement
/// full bidirectional proxying.
#[derive(Debug, Clone)]
pub struct TrojanConnector<D: Dialer + Send + Sync + 'static> {
    /// Injected dialer for establishing connections.
    pub dialer: D,
    /// Password for Trojan authentication.
    pub password: String,
}

impl<D: Dialer + Send + Sync + 'static> TrojanConnector<D> {
    /// Creates a new Trojan connector with the specified dialer and password.
    #[must_use]
    pub fn new(dialer: D, password: impl Into<String>) -> Self {
        Self {
            dialer,
            password: password.into(),
        }
    }
}

#[async_trait]
impl<D: Dialer + Send + Sync + 'static> OutboundConnector for TrojanConnector<D> {
    async fn connect(
        &self,
        target: &Target,
    ) -> Result<Box<dyn IoStream>, ProtoError> {
        let mut stream = self
            .dialer
            .connect(target.host(), target.port())
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        let hello = TrojanHello {
            password: self.password.clone(),
            host: target.host().to_string(),
            port: target.port(),
        };
        let buf = hello.to_bytes();

        // Write hello packet
        tokio::io::AsyncWriteExt::write_all(&mut stream, &buf).await?;
        tokio::io::AsyncWriteExt::flush(&mut stream).await?;

        Ok(Box::new(stream))
    }
}
