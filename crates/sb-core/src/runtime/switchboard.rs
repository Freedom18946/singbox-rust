//! Outbound switchboard: registry and selection of outbound connectors
//!
//! This module provides the central registry for outbound adapters/connectors,
//! mapping routing decisions to actual connector implementations.

use crate::error::SbResult;

use anyhow::Context;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

/// Adapter error types
#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    #[error("Connection timeout after {0:?}")]
    Timeout(Duration),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Unsupported protocol: {0}")]
    UnsupportedProtocol(String),
    #[error("Not implemented: {0}")]
    NotImplemented(String),
    #[error("Invalid config: {0}")]
    InvalidConfig(&'static str),
    #[error("Other error: {0}")]
    Other(#[from] anyhow::Error),
}

pub type AdapterResult<T> = Result<T, AdapterError>;

/// Outbound switchboard for managing and selecting connectors
#[derive(Debug)]
pub struct OutboundSwitchboard {
    /// Registry mapping outbound names to connector instances
    registry: HashMap<String, Arc<dyn sb_types::Outbound>>,
    /// Default connector when no routing match is found
    default_connector: Option<Arc<dyn sb_types::Outbound>>,
}

impl OutboundSwitchboard {
    /// Create a new empty switchboard
    pub fn new() -> Self {
        Self {
            registry: HashMap::new(),
            default_connector: None,
        }
    }

    /// Register an outbound connector with a given name
    pub fn register<C>(&mut self, name: String, connector: C) -> SbResult<()>
    where
        C: sb_types::Outbound + 'static,
    {
        let connector = Arc::new(connector);

        self.registry.insert(name.clone(), connector);
        info!("Registered outbound connector: '{}'", name);
        Ok(())
    }

    /// Set the default connector to use when no routing match is found
    pub fn set_default<C>(&mut self, connector: C) -> SbResult<()>
    where
        C: sb_types::Outbound + 'static,
    {
        let connector = Arc::new(connector);

        self.default_connector = Some(connector);
        info!("Set default outbound connector");
        Ok(())
    }

    /// Get a connector by name.
    ///
    /// No implicit fallback is performed for unknown names.
    pub fn get_connector(&self, name: &str) -> Option<Arc<dyn sb_types::Outbound>> {
        if let Some(connector) = self.registry.get(name) {
            return Some(connector.clone());
        }

        if name == "default" {
            return self.default_connector.clone();
        }

        let mut available = self.list_connectors();
        if self.default_connector.is_some() {
            available.push("default".to_string());
            available.sort();
        }
        warn!(
            requested = %name,
            available = ?available,
            "Outbound connector not found; no fallback connector is applied"
        );
        None
    }

    /// List all registered connector names
    pub fn list_connectors(&self) -> Vec<String> {
        let mut names: Vec<_> = self.registry.keys().cloned().collect();
        names.sort();
        names
    }

    /// Get the number of registered connectors
    pub fn len(&self) -> usize {
        self.registry.len()
    }

    /// Check if the switchboard is empty
    pub fn is_empty(&self) -> bool {
        self.registry.is_empty() && self.default_connector.is_none()
    }
}

impl Default for OutboundSwitchboard {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for constructing outbound switchboard from configuration
pub struct SwitchboardBuilder {
    switchboard: OutboundSwitchboard,
}

impl SwitchboardBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            switchboard: OutboundSwitchboard::new(),
        }
    }

    /// Build outbound connectors from configuration IR
    pub fn from_config_ir(ir: &sb_config::ir::ConfigIR) -> SbResult<OutboundSwitchboard> {
        let mut builder = Self::new();

        // Register outbound connectors from IR
        for outbound_ir in &ir.outbounds {
            let name = outbound_ir.name.as_deref().unwrap_or("unnamed");
            let result = builder.try_register_from_ir(outbound_ir);
            match result {
                Ok(()) => {
                    info!("Successfully registered outbound: {}", name);
                }
                Err(e) => {
                    warn!(
                        "Failed to register outbound '{}': {}. Using 501 degraded mode.",
                        name, e
                    );

                    // Register a 501 degraded connector for this outbound
                    let degraded = DegradedConnector::new(name, e.to_string());
                    builder
                        .switchboard
                        .register(name.to_string(), degraded)
                        .context("Failed to register degraded connector")?;
                }
            }
        }

        Ok(builder.switchboard)
    }

    /// Try to register a connector from outbound IR
    #[allow(unreachable_code)]
    fn try_register_from_ir(&mut self, ir: &sb_config::ir::OutboundIR) -> AdapterResult<()> {
        use sb_config::ir::OutboundType;

        #[allow(unused_variables)]
        let name = ir.name.as_deref().unwrap_or("unnamed");

        match ir.ty {
            OutboundType::Direct => {
                self.switchboard
                    .register(
                        name.to_string(),
                        crate::adapter::canonical_bridge::DirectOutbound::new(name),
                    )
                    .map_err(|e| AdapterError::Other(e.into()))?;
            }

            OutboundType::Block => {
                self.switchboard
                    .register(
                        name.to_string(),
                        crate::adapter::canonical_bridge::BlockOutbound::new(name),
                    )
                    .map_err(|e| AdapterError::Other(e.into()))?;
            }

            OutboundType::Http => {
                return Err(AdapterError::UnsupportedProtocol(
                    "HTTP outbound in switchboard is disabled; use adapter bridge/supervisor path"
                        .to_string(),
                ));
            }

            OutboundType::Socks => {
                return Err(AdapterError::UnsupportedProtocol(
                    "SOCKS outbound in switchboard is disabled; use adapter bridge/supervisor path"
                        .to_string(),
                ));
            }

            OutboundType::Hysteria2 => {
                return Err(AdapterError::UnsupportedProtocol(
                    "Hysteria2 outbound in switchboard is disabled; use adapter bridge/supervisor path"
                        .to_string(),
                ));
            }

            OutboundType::Selector | OutboundType::UrlTest => {
                return Err(AdapterError::UnsupportedProtocol(
                    "Selector/urltest outbounds are handled via bridge/registry".to_string(),
                ));
            }

            _ => {
                return Err(AdapterError::UnsupportedProtocol(format!(
                    "Outbound type {:?} not supported or feature not enabled",
                    ir.ty
                )));
            }
        }

        Ok(())
    }

    /// Consume the builder and return the switchboard
    pub fn build(self) -> OutboundSwitchboard {
        self.switchboard
    }
}

impl Default for SwitchboardBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// -----------------------------------------------------------------------------
// IR -> Config mapping helpers (for reuse and contract tests)
// -----------------------------------------------------------------------------

#[cfg(all(feature = "out_hysteria2", test))]
fn hysteria2_from_ir(
    ir: &sb_config::ir::OutboundIR,
) -> AdapterResult<Option<crate::outbound::hysteria2::Hysteria2Config>> {
    use crate::outbound::hysteria2::{BrutalConfig, Hysteria2Config};
    let server = match &ir.server {
        Some(s) if !s.is_empty() => s.clone(),
        _ => return Ok(None),
    };
    let port = ir
        .port
        .ok_or(AdapterError::InvalidConfig("hysteria2.port is required"))?;
    let password = ir.password.clone().ok_or(AdapterError::InvalidConfig(
        "hysteria2.password is required",
    ))?;
    let brutal = match (ir.brutal_up_mbps, ir.brutal_down_mbps) {
        (Some(up), Some(down)) => Some(BrutalConfig {
            up_mbps: up,
            down_mbps: down,
        }),
        _ => None,
    };
    let alpn_list = ir.tls_alpn.clone();
    Ok(Some(Hysteria2Config {
        server,
        port,
        password,
        congestion_control: ir.congestion_control.clone(),
        up_mbps: ir.up_mbps,
        down_mbps: ir.down_mbps,
        obfs: ir.obfs.clone(),
        skip_cert_verify: ir.skip_cert_verify.unwrap_or(false),
        sni: ir.tls_sni.clone(),
        alpn: alpn_list,
        salamander: ir.salamander.clone(),
        brutal,
        tls_ca_paths: ir.tls_ca_paths.clone(),
        tls_ca_pem: ir.tls_ca_pem.clone(),
        zero_rtt_handshake: ir.zero_rtt_handshake.unwrap_or(false),
    }))
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[cfg(feature = "scaffold")]
    #[test]
    fn registers_http_and_socks_connectors() {
        let ir = sb_config::ir::ConfigIR {
            outbounds: vec![
                sb_config::ir::OutboundIR {
                    ty: sb_config::ir::OutboundType::Http,
                    name: Some("h1".into()),
                    server: Some("127.0.0.1".into()),
                    port: Some(8080),
                    ..Default::default()
                },
                sb_config::ir::OutboundIR {
                    ty: sb_config::ir::OutboundType::Socks,
                    name: Some("s1".into()),
                    server: Some("127.0.0.1".into()),
                    port: Some(1080),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let sw = SwitchboardBuilder::from_config_ir(&ir).expect("switchboard");
        let names = sw.list_connectors();
        assert!(names.iter().any(|n| n == "h1"));
        assert!(names.iter().any(|n| n == "s1"));
    }

    #[cfg(feature = "out_hysteria2")]
    #[test]
    fn hysteria2_mapping_defaults_and_alpn_split() {
        let ob = sb_config::ir::OutboundIR {
            ty: sb_config::ir::OutboundType::Hysteria2,
            name: Some("hy1".into()),
            server: Some("hy.example".into()),
            port: Some(8443),
            password: Some("pw".into()),
            tls_alpn: Some(vec!["h3".to_string(), "hysteria2".to_string()]),
            ..Default::default()
        };

        let cfg = hysteria2_from_ir(&ob).expect("ok").expect("some");
        assert_eq!(cfg.server, "hy.example");
        assert_eq!(cfg.port, 8443);
        assert!(!cfg.skip_cert_verify);
        assert!(!cfg.zero_rtt_handshake);
        let alpn = cfg.alpn.unwrap();
        assert_eq!(alpn, vec!["h3".to_string(), "hysteria2".to_string()]);
    }
}

/// A degraded connector that returns 501 Not Implemented for failed construction
#[derive(Debug)]
struct DegradedConnector {
    name: String,
    error_reason: String,
}

impl DegradedConnector {
    fn new(name: &str, error_reason: String) -> Self {
        Self {
            name: name.to_string(),
            error_reason,
        }
    }
}

impl sb_types::Outbound for DegradedConnector {
    fn r#type(&self) -> &str {
        "degraded"
    }
    fn tag(&self) -> sb_types::OutboundTag {
        sb_types::OutboundTag::new(self.name.clone())
    }
    fn network(&self) -> &[sb_types::NetworkKind] {
        &[sb_types::NetworkKind::Tcp]
    }
    fn dial<'a>(
        &'a self,
        _session: &'a sb_types::Session,
    ) -> sb_types::BoxFuture<'a, Result<sb_types::BoxedStream, sb_types::CoreError>> {
        Box::pin(async move {
            Err(sb_types::CoreError::connect(
                sb_types::ConnectErrorKind::Unsupported,
                format!(
                    "Outbound '{}' is in degraded mode: {}",
                    self.name, self.error_reason
                ),
            ))
        })
    }
    fn listen_packet<'a>(
        &'a self,
        _session: &'a sb_types::Session,
    ) -> sb_types::BoxFuture<'a, Result<sb_types::BoxedPacketConn, sb_types::CoreError>> {
        Box::pin(async {
            Err(sb_types::CoreError::connect(
                sb_types::ConnectErrorKind::Unsupported,
                "degraded outbound",
            ))
        })
    }
}
