//! Minimal outbound protocol registry (feature: `outbound_registry`).
//!
//! Provides a simple registry for managing Trojan and Shadowsocks 2022 outbound configurations,
//! primarily intended for testing and admin interfaces.
//!
//! # Features
//!
//! - Protocol registration (Trojan, SS2022)
//! - Dry-run connection testing with first-packet write
//! - TCP and TLS transport support (via feature gates)

#[cfg(feature = "proto_ss2022_min")]
use crate::ss2022_min::Ss2022Hello;
use crate::trojan_min::TrojanHello;
use sb_transport::dialer::{Dialer, TcpDialer};
#[cfg(feature = "transport_tls")]
use sb_transport::tls::{webpki_roots_config, TlsDialer};
use std::collections::BTreeMap;
use thiserror::Error;

/// Errors that can occur in registry operations.
#[derive(Debug, Error)]
pub enum RegistryError {
    /// Outbound not found in registry.
    #[error("outbound not found: {0}")]
    NotFound(String),

    /// Protocol kind not supported for the requested operation.
    #[error("protocol kind not supported: {0:?}")]
    UnsupportedKind(OutboundKind),

    /// Required field missing (e.g., password).
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// Transport error during connection.
    #[error("transport error: {0}")]
    Transport(String),

    /// Feature not enabled at compile time.
    #[error("feature not enabled: {0}")]
    FeatureDisabled(&'static str),
}

/// Type of outbound protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundKind {
    /// Trojan protocol.
    Trojan,
    /// Shadowsocks 2022 protocol.
    Ss2022,
}

/// Specification for an outbound connection.
#[derive(Debug, Clone)]
pub struct OutboundSpec {
    /// Unique name identifier.
    pub name: String,
    /// Protocol type.
    pub kind: OutboundKind,
    /// Password/key for authentication.
    pub password: Option<String>,
    /// Cipher method (SS2022 only).
    pub method: Option<String>,
}

/// Registry for managing outbound protocol specifications.
#[derive(Default)]
pub struct Registry {
    specs: BTreeMap<String, OutboundSpec>,
}

impl Registry {
    /// Creates a new empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts an outbound specification into the registry.
    ///
    /// Overwrites existing entry with the same name.
    pub fn insert(&mut self, spec: OutboundSpec) {
        self.specs.insert(spec.name.clone(), spec);
    }

    /// Returns all registered outbound names.
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        self.specs.keys().cloned().collect()
    }

    /// Retrieves an outbound specification by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&OutboundSpec> {
        self.specs.get(name)
    }
}

/// Helper to write Trojan hello packet to a stream.
async fn write_trojan_hello<D: Dialer>(
    dialer: D,
    password: &str,
    host: &str,
    port: u16,
) -> Result<(), RegistryError> {
    let mut stream = dialer
        .connect(host, port)
        .await
        .map_err(|e| RegistryError::Transport(e.to_string()))?;

    let hello = TrojanHello {
        password: password.to_string(),
        host: host.to_string(),
        port,
    };
    let buf = hello.to_bytes();

    tokio::io::AsyncWriteExt::write_all(&mut stream, &buf)
        .await
        .map_err(|e| RegistryError::Transport(e.to_string()))?;
    tokio::io::AsyncWriteExt::flush(&mut stream)
        .await
        .map_err(|e| RegistryError::Transport(e.to_string()))?;

    Ok(())
}

/// Performs a dry-run Trojan connection over TCP.
///
/// Connects to the target and writes the Trojan hello packet.
///
/// # Errors
/// Returns `RegistryError` if the outbound is not found, not Trojan, or connection fails.
pub async fn trojan_dryrun_tcp(
    name: &str,
    reg: &Registry,
    host: &str,
    port: u16,
) -> Result<(), RegistryError> {
    let spec = reg
        .get(name)
        .ok_or_else(|| RegistryError::NotFound(name.to_string()))?;

    match spec.kind {
        OutboundKind::Trojan => {
            let password = spec
                .password
                .as_deref()
                .ok_or(RegistryError::MissingField("password"))?;
            write_trojan_hello(TcpDialer, password, host, port).await
        }
        kind => Err(RegistryError::UnsupportedKind(kind)),
    }
}

/// Performs a dry-run Trojan connection over TLS (if enabled) or falls back to TCP.
///
/// # Errors
/// Returns `RegistryError` if the outbound is not found, not Trojan, or connection fails.
pub async fn trojan_dryrun_tls_env(
    name: &str,
    reg: &Registry,
    host: &str,
    port: u16,
) -> Result<(), RegistryError> {
    let spec = reg
        .get(name)
        .ok_or_else(|| RegistryError::NotFound(name.to_string()))?;

    match spec.kind {
        OutboundKind::Trojan => {
            let password = spec
                .password
                .as_deref()
                .ok_or(RegistryError::MissingField("password"))?;

            #[cfg(feature = "transport_tls")]
            {
                let dialer = TlsDialer::from_env(TcpDialer, webpki_roots_config());
                write_trojan_hello(dialer, password, host, port).await
            }
            #[cfg(not(feature = "transport_tls"))]
            {
                // Fallback to TCP
                write_trojan_hello(TcpDialer, password, host, port).await
            }
        }
        kind => Err(RegistryError::UnsupportedKind(kind)),
    }
}

/// Generates Shadowsocks 2022 hello packet bytes.
///
/// # Errors
/// Returns `RegistryError` if the outbound is not found, not SS2022, or feature disabled.
pub fn ss2022_hello_bytes(
    name: &str,
    reg: &Registry,
    host: &str,
    port: u16,
) -> Result<Vec<u8>, RegistryError> {
    let spec = reg
        .get(name)
        .ok_or_else(|| RegistryError::NotFound(name.to_string()))?;

    match spec.kind {
        OutboundKind::Ss2022 => {
            #[cfg(feature = "proto_ss2022_min")]
            {
                let method = spec
                    .method
                    .clone()
                    .unwrap_or_else(|| "2022-blake3-aes-256-gcm".to_string());
                let password = spec
                    .password
                    .clone()
                    .ok_or(RegistryError::MissingField("password"))?;

                Ok(Ss2022Hello {
                    method,
                    password,
                    host: host.to_string(),
                    port,
                }
                .to_bytes())
            }
            #[cfg(not(feature = "proto_ss2022_min"))]
            {
                Err(RegistryError::FeatureDisabled("proto_ss2022_min"))
            }
        }
        kind => Err(RegistryError::UnsupportedKind(kind)),
    }
}
