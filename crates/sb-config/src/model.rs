use serde::{Deserialize, Serialize};

use crate::defaults;

/// Socket listen address (host/IP + port)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListenAddr {
    pub addr: String,
    pub port: u16,
}

impl ListenAddr {
    pub fn as_socket_addr(&self) -> String {
        format!("{}:{}", self.addr, self.port)
    }
}

/// SOCKS username/password pair
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct User {
    pub username: String,
    pub password: String,
}

/// SOCKS authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum SocksAuth {
    /// No authentication (method 0x00)
    #[default]
    #[serde(alias = "none")]
    None,
    /// RFC1929 username/password users
    Users(Vec<User>),
}

/// Inbound wrapper with optional tag, flattening the concrete kind
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inbound {
    /// Optional tag (compatible with sing-box conventions)
    #[serde(default)]
    pub tag: Option<String>,
    /// Concrete inbound kind
    #[serde(flatten)]
    pub kind: InboundDef,
}

/// Supported inbound kinds (adjacently tagged)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum InboundDef {
    /// Minimal HTTP inbound
    Http {
        /// Listen address; accepts either "ip:port" string or {"addr"/"address"/"host", "port"}
        #[serde(
            default = "defaults::default_http_listen",
            with = "crate::de::listen_addr"
        )]
        listen: ListenAddr,
    },
    /// Minimal SOCKS5 inbound
    Socks {
        /// Listen address; accepts either "ip:port" string or {"addr"/"address"/"host", "port"}
        #[serde(
            default = "defaults::default_socks_listen",
            with = "crate::de::listen_addr"
        )]
        listen: ListenAddr,
        /// Authentication (none or users list)
        #[serde(default)]
        auth: SocksAuth,
    },
    /// Placeholder for TUN inbound (kept simple at this stage)
    Tun {
        #[serde(default)]
        name: Option<String>,
    },
}

/// Outbound wrapper with required tag (router refers to this tag)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Outbound {
    /// Unique outbound tag
    pub tag: String,
    /// Concrete outbound kind
    #[serde(flatten)]
    pub kind: OutboundDef,
}

/// Supported outbound kinds (adjacently tagged)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum OutboundDef {
    /// Direct connect to the destination
    Direct,
    /// Block the request
    Block,
}

/// Routing rule set (kept minimal for first iteration)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Rule {
    /// Match by domain suffix; route to the outbound identified by `outbound` tag
    DomainSuffix { suffix: String, outbound: String },
}

/// Top-level configuration
///
/// **DEPRECATED**: This Config type is legacy and rarely used.
/// Use `ir::ConfigIR` for all internal processing.
/// Kept for backward compatibility only.
#[deprecated(
    since = "0.1.0",
    note = "Use ir::ConfigIR instead. This type will be removed in a future version."
)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub inbounds: Vec<Inbound>,
    #[serde(default)]
    pub outbounds: Vec<Outbound>,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

impl Config {
    /// Normalize config to a fully-usable shape:
    // - Ensure default outbounds exist ("direct", "block") if not provided
    // - Leave inbounds as-is (defaults handled by serde)
    #[allow(deprecated)]
    pub fn normalize(mut self) -> Self {
        let has_direct = self.outbounds.iter().any(|o| o.tag == "direct");
        let has_block = self.outbounds.iter().any(|o| o.tag == "block");
        if !has_direct {
            self.outbounds.push(Outbound {
                tag: "direct".into(),
                kind: OutboundDef::Direct,
            });
        }
        if !has_block {
            self.outbounds.push(Outbound {
                tag: "block".into(),
                kind: OutboundDef::Block,
            });
        }
        self
    }
}
