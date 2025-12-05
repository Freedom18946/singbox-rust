use crate::outbound::OutboundConnector;
use crate::error::Result;
use arti_client::config::CfgPath;
use arti_client::{TorClient, TorClientConfig};
use async_trait::async_trait;
use sb_config::ir::OutboundIR;
use sb_core::context::Context;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::OnceCell;
use tor_rtcompat::PreferredRuntime;
use tracing::{debug, warn};

/// Tor outbound adapter using the Arti (Rust-native Tor) client.
///
/// # Architectural Differences from Go
///
/// The Go sing-box implementation uses `bine` to wrap the external `tor` executable,
/// which allows it to:
/// - Configure an upstream SOCKS5 proxy via `Socks5Proxy` option
/// - Expose a local SOCKS listener for external applications
///
/// This Rust implementation uses Arti (embedded Tor), which:
/// - Does not support upstream proxy configuration in its public API (as of v0.23)
/// - Connects directly to the Tor network
/// - Is more portable but less configurable
///
/// # Supported Configuration
///
/// - `tor_data_directory`: Persistent state/cache directory
/// - `tor_options`: Limited mapping to Arti config (see below)
///
/// # Mapped tor_options Keys
///
/// | Key | Arti Equivalent | Notes |
/// |-----|-----------------|-------|
/// | `circuit_idle_timeout` | `circuit_timing.max_idle` | Seconds |
/// | `stream_timeout` | `stream_timeouts.connect_timeout` | Seconds |
///
/// # Unsupported Options
///
/// - `Socks5Proxy`: Arti does not expose upstream proxy configuration
/// - `ControlPort`, `SocksPort`: Not applicable for embedded client
#[derive(Clone)]
pub struct TorOutbound {
    client: Arc<OnceCell<TorClient<PreferredRuntime>>>,
    config: TorClientConfig,
}

impl std::fmt::Debug for TorOutbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TorOutbound").finish()
    }
}

impl TorOutbound {
    /// Create a new Tor outbound adapter.
    ///
    /// # Configuration Mapping
    ///
    /// - `ir.tor_data_directory`: Sets both state and cache directories
    /// - `ir.tor_proxy_addr`: **Not supported** - Arti does not expose proxy config
    /// - `ir.tor_options`: Partial mapping to Arti settings (see struct docs)
    pub fn new(ir: &OutboundIR, _ctx: &Context) -> Result<Self> {
        let mut config_builder = TorClientConfig::builder();

        // 1) Data directory (persistent state)
        if let Some(dir) = &ir.tor_data_directory {
            debug!(dir = %dir, "Setting Tor data directory");
            config_builder.storage().state_dir(CfgPath::new(dir.clone()));
            config_builder.storage().cache_dir(CfgPath::new(dir.clone()));
        }

        // 2) SOCKS5 upstream proxy
        // NOTE: Arti (as of v0.23) does not expose upstream proxy configuration
        // through its TorClientConfigBuilder. This is an architectural limitation.
        // The Go implementation uses `bine` which wraps the Tor executable and can
        // pass `Socks5Proxy` options to torrc.
        if let Some(proxy_addr) = &ir.tor_proxy_addr {
            warn!(
                proxy_addr = %proxy_addr,
                "tor_proxy_addr is configured but Arti does not support upstream proxies. \
                 This option will be ignored. Consider using a different outbound chain \
                 (e.g., socks5 -> tor) to achieve similar functionality."
            );
        }

        // 3) Map tor_options to Arti config
        if let Some(options) = &ir.tor_options {
            for (key, value) in options {
                match key.as_str() {
                    "circuit_idle_timeout" => {
                        if let Ok(secs) = value.parse::<u64>() {
                            debug!(key = %key, value = %value, "Mapping circuit_idle_timeout");
                            // Note: Arti's circuit_timing().max_dirtiness() is similar but not exact
                            // The idle timeout controls how long unused circuits are kept
                            let _ = config_builder.circuit_timing().max_dirtiness(Duration::from_secs(secs));
                        } else {
                            warn!(key = %key, value = %value, "Invalid value for circuit_idle_timeout, expected integer seconds");
                        }
                    }
                    "stream_timeout" => {
                        if let Ok(secs) = value.parse::<u64>() {
                            debug!(key = %key, value = %value, "Mapping stream_timeout");
                            config_builder.stream_timeouts().connect_timeout(Duration::from_secs(secs));
                        } else {
                            warn!(key = %key, value = %value, "Invalid value for stream_timeout, expected integer seconds");
                        }
                    }
                    _ => {
                        debug!(key = %key, value = %value, "Unknown tor_option, ignoring");
                    }
                }
            }
        }

        let config = config_builder.build().map_err(|e| crate::error::AdapterError::Other(format!("Invalid Tor config: {}", e)))?;

        Ok(Self {
            client: Arc::new(OnceCell::new()),
            config,
        })
    }

    async fn get_client(&self) -> Result<&TorClient<PreferredRuntime>> {
        self.client.get_or_try_init(|| async {
            TorClient::create_bootstrapped(self.config.clone()).await
                .map_err(|e| crate::error::AdapterError::Other(format!("Failed to bootstrap Tor client: {}", e)))
        }).await
    }
}

#[async_trait]
impl OutboundConnector for TorOutbound {
    async fn start(&self) -> Result<()> {
        let _ = self.get_client().await?;
        Ok(())
    }

    async fn dial(&self, target: crate::traits::Target, _opts: crate::traits::DialOpts) -> Result<crate::traits::BoxedStream> {
        let client = self.get_client().await?;
        let stream = client
            .connect((target.host.as_str(), target.port))
            .await
            .map_err(|e| crate::error::AdapterError::Other(e.to_string()))?;
        Ok(Box::new(stream))
    }
}
