//! Outbound adapters module.
//! sb-adapters 的"出站适配器"模块。
//!
//! Contains outbound connector implementations for various protocols, including:
//! 包含各种协议的出站连接器实现，包括：
//! - Direct and Block (直连和阻断)
//! - HTTP Proxy Connector (HTTP 代理连接器)
//! - SOCKS5 Proxy Connector (SOCKS5 代理连接器)
//! - Shadowsocks Connector (Shadowsocks 连接器)
//! - VMess Protocol Connector (VMess 协议连接器)
//! - VLESS Protocol Connector (VLESS 协议连接器)
//! - TUIC Protocol Connector (TUIC 协议连接器)

pub mod prelude {
    //! Common imports for all adapter implementations
    //! 所有适配器实现的通用导入
    pub use crate::error::{AdapterError, Result};
    pub use crate::traits::BoxedStream;
    pub use async_trait::async_trait;
    pub use sb_types::{ConnectOptions, Outbound, ResolveMode, RetryPolicy, Session, TargetAddr};
    pub use std::fmt::Debug;
    pub use std::time::Duration;
}

pub(crate) const TCP: &[sb_types::NetworkKind] = &[sb_types::NetworkKind::Tcp];

/// Block outbound adapter - rejects all connection attempts
/// 阻断出站适配器 - 拒绝所有连接尝试
pub mod block;
pub mod detour;
/// Direct outbound adapter - connects directly to target
/// 直连出站适配器 - 直接连接到目标
pub mod direct;

// Helper functions for tracing
// 用于追踪的辅助函数
#[allow(dead_code)]
pub(crate) fn span_dial(adapter: &'static str, target: &impl std::fmt::Debug) -> tracing::Span {
    tracing::info_span!("dial",
        adapter = adapter,
        dest = ?target,
        kind = "tcp"
    )
}

/// Convert an adapter error at the canonical outbound boundary.
pub(crate) fn core_error(
    error: crate::error::AdapterError,
    session: &sb_types::Session,
) -> sb_types::CoreError {
    use crate::error::AdapterError;
    use sb_types::{ConnectErrorKind, CoreError};
    use std::io::ErrorKind;

    match error {
        AdapterError::Io(error) => match error.kind() {
            ErrorKind::TimedOut => {
                CoreError::timeout("outbound-dial", session.connect.connect_timeout)
            }
            ErrorKind::ConnectionRefused => {
                CoreError::connect(ConnectErrorKind::Refused, error.to_string())
            }
            ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted => {
                CoreError::connect(ConnectErrorKind::Reset, error.to_string())
            }
            ErrorKind::NotConnected
            | ErrorKind::AddrNotAvailable
            | ErrorKind::NetworkUnreachable => {
                CoreError::connect(ConnectErrorKind::Unreachable, error.to_string())
            }
            _ => CoreError::io(error.to_string()),
        },
        AdapterError::Timeout(duration) => CoreError::timeout("outbound-dial", duration),
        AdapterError::UnsupportedProtocol(message) => {
            CoreError::connect(ConnectErrorKind::Unsupported, message)
        }
        AdapterError::NotImplemented { what } => {
            CoreError::connect(ConnectErrorKind::Unsupported, what)
        }
        AdapterError::InvalidConfig(message) => {
            CoreError::connect(ConnectErrorKind::InvalidConfig, message)
        }
        AdapterError::AuthenticationFailed => CoreError::auth("adapter authentication failed"),
        AdapterError::Protocol(message) => CoreError::protocol(message),
        AdapterError::Network(message) => CoreError::dns(message),
        AdapterError::Other(message) => CoreError::io(message),
    }
}

/// Shared state for canonical packet associations implemented by adapters.
#[cfg(any(
    feature = "adapter-shadowsocks",
    feature = "adapter-trojan",
    feature = "adapter-vless"
))]
#[derive(Debug)]
pub(crate) struct PacketState {
    target: parking_lot::RwLock<sb_types::TargetAddr>,
    idle_timeout: std::time::Duration,
    deadlines: parking_lot::Mutex<(Option<std::time::Instant>, Option<std::time::Instant>)>,
    closed: std::sync::atomic::AtomicBool,
}

#[cfg(any(
    feature = "adapter-shadowsocks",
    feature = "adapter-trojan",
    feature = "adapter-vless"
))]
impl PacketState {
    pub(crate) fn new(target: sb_types::TargetAddr, idle_timeout: std::time::Duration) -> Self {
        Self {
            target: parking_lot::RwLock::new(target),
            idle_timeout,
            deadlines: parking_lot::Mutex::new((None, None)),
            closed: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub(crate) fn ensure_open(&self) -> Result<(), sb_types::CoreError> {
        if self.closed.load(std::sync::atomic::Ordering::Acquire) {
            Err(sb_types::CoreError::io("packet connection closed"))
        } else {
            Ok(())
        }
    }

    pub(crate) fn target(&self) -> sb_types::TargetAddr {
        self.target.read().clone()
    }

    pub(crate) fn set_target(&self, target: &sb_types::TargetAddr) {
        *self.target.write() = target.clone();
    }

    pub(crate) fn close(&self) {
        self.closed
            .store(true, std::sync::atomic::Ordering::Release);
    }

    pub(crate) fn set_deadline(&self, deadline: Option<std::time::Instant>) {
        *self.deadlines.lock() = (deadline, deadline);
    }

    pub(crate) fn set_read_deadline(&self, deadline: Option<std::time::Instant>) {
        self.deadlines.lock().0 = deadline;
    }

    pub(crate) fn set_write_deadline(&self, deadline: Option<std::time::Instant>) {
        self.deadlines.lock().1 = deadline;
    }

    pub(crate) fn read_deadline(&self) -> Option<std::time::Instant> {
        Some(
            self.deadlines
                .lock()
                .0
                .unwrap_or_else(|| std::time::Instant::now() + self.idle_timeout),
        )
    }

    pub(crate) fn write_deadline(&self) -> Option<std::time::Instant> {
        Some(
            self.deadlines
                .lock()
                .1
                .unwrap_or_else(|| std::time::Instant::now() + self.idle_timeout),
        )
    }
}

#[cfg(any(
    feature = "adapter-shadowsocks",
    feature = "adapter-trojan",
    feature = "adapter-vless",
    feature = "socks-udp"
))]
pub(crate) async fn with_packet_deadline<T>(
    deadline: Option<std::time::Instant>,
    operation: impl std::future::Future<Output = Result<T, std::io::Error>>,
) -> Result<T, sb_types::CoreError> {
    match deadline {
        Some(deadline) => {
            let timeout_duration = deadline.saturating_duration_since(std::time::Instant::now());
            tokio::time::timeout(timeout_duration, operation)
                .await
                .map_err(|_| sb_types::CoreError::timeout("packet-io", timeout_duration))?
                .map_err(|error| sb_types::CoreError::io(error.to_string()))
        }
        None => operation
            .await
            .map_err(|error| sb_types::CoreError::io(error.to_string())),
    }
}

#[cfg(all(
    test,
    any(
        feature = "adapter-shadowsocks",
        feature = "adapter-trojan",
        feature = "adapter-vless"
    )
))]
mod packet_state_tests {
    use super::*;

    #[tokio::test]
    async fn idle_timeout_applies_without_explicit_deadline() {
        let idle_timeout = std::time::Duration::from_millis(10);
        let state = PacketState::new(
            sb_types::TargetAddr::domain("example.com", 53),
            idle_timeout,
        );

        let error = with_packet_deadline(
            state.read_deadline(),
            std::future::pending::<Result<(), std::io::Error>>(),
        )
        .await
        .expect_err("pending packet operation must time out");

        match error {
            sb_types::CoreError::Timeout { duration, .. } => {
                assert!(duration <= idle_timeout);
                assert!(!duration.is_zero());
            }
            other => panic!("expected packet timeout, got {other}"),
        }
    }

    #[tokio::test]
    async fn explicit_deadline_overrides_idle_timeout() {
        let idle_timeout = std::time::Duration::from_secs(1);
        let explicit_timeout = std::time::Duration::from_millis(10);
        let state = PacketState::new(
            sb_types::TargetAddr::domain("example.com", 53),
            idle_timeout,
        );
        state.set_write_deadline(Some(std::time::Instant::now() + explicit_timeout));

        let error = with_packet_deadline(
            state.write_deadline(),
            std::future::pending::<Result<(), std::io::Error>>(),
        )
        .await
        .expect_err("pending packet operation must use explicit deadline");

        match error {
            sb_types::CoreError::Timeout { duration, .. } => {
                assert!(duration <= explicit_timeout);
                assert!(duration < idle_timeout);
                assert!(!duration.is_zero());
            }
            other => panic!("expected packet timeout, got {other}"),
        }
    }
}

/// Implement canonical stream outbound for session-native protocol code.
#[macro_export]
macro_rules! impl_canonical_outbound {
    ($type:ty, $protocol:literal, $tag:expr, $networks:expr) => {
        impl sb_types::Outbound for $type {
            fn r#type(&self) -> &str {
                $protocol
            }

            fn tag(&self) -> sb_types::OutboundTag {
                let tag = $tag;
                sb_types::OutboundTag::new(tag(self))
            }

            fn network(&self) -> &[sb_types::NetworkKind] {
                $networks
            }

            fn dial<'a>(
                &'a self,
                session: &'a sb_types::Session,
            ) -> sb_types::BoxFuture<'a, Result<sb_types::BoxedStream, sb_types::CoreError>> {
                Box::pin(async move {
                    use tokio_util::compat::TokioAsyncReadCompatExt;

                    let stream = <$type>::dial(self, session)
                        .await
                        .map_err(|error| $crate::outbound::core_error(error, session))?;
                    Ok(Box::new(stream.compat()) as sb_types::BoxedStream)
                })
            }

            fn listen_packet<'a>(
                &'a self,
                _session: &'a sb_types::Session,
            ) -> sb_types::BoxFuture<'a, Result<sb_types::BoxedPacketConn, sb_types::CoreError>>
            {
                Box::pin(async {
                    Err(sb_types::CoreError::connect(
                        sb_types::ConnectErrorKind::Unsupported,
                        concat!($protocol, " does not support packet associations"),
                    ))
                })
            }
        }
    };
}

// Feature-gated adapter modules
// 特性门控的适配器模块
#[cfg(feature = "adapter-anytls")]
pub mod anytls;
#[cfg(feature = "adapter-dns")]
pub mod dns;
#[cfg(feature = "adapter-http")]
pub mod http;
#[cfg(feature = "adapter-hysteria")]
pub mod hysteria;
#[cfg(feature = "adapter-hysteria2")]
pub mod hysteria2;
#[cfg(feature = "adapter-naive")]
pub mod naive_h2;
#[cfg(feature = "adapter-shadowsocks")]
pub mod shadowsocks;
#[cfg(feature = "legacy_shadowsocksr")]
pub mod shadowsocksr;
#[cfg(feature = "adapter-shadowtls")]
pub mod shadowtls;
#[cfg(feature = "adapter-socks")]
pub mod socks4;
#[cfg(feature = "adapter-socks")]
pub mod socks5;
#[cfg(feature = "socks-udp")]
pub mod socks5_udp;
#[cfg(feature = "adapter-ssh")]
pub mod ssh;
#[cfg(feature = "legacy_tailscale_outbound")]
pub mod tailscale;
#[cfg(feature = "adapter-tor")]
pub mod tor;
#[cfg(feature = "adapter-trojan")]
pub mod trojan;
// Shared QUIC utilities for TUIC and Hysteria protocols
#[cfg(any(
    feature = "adapter-tuic",
    feature = "adapter-hysteria",
    feature = "adapter-hysteria2"
))]
pub(crate) mod quic_util;
#[cfg(feature = "tuic")]
pub mod tuic;
#[cfg(feature = "adapter-vless")]
pub mod vless;
#[cfg(feature = "adapter-vmess")]
pub mod vmess;
#[cfg(feature = "adapter-wireguard-outbound")]
pub mod wireguard;
// Selector group adapters (always available since they're core functionality)
// 选择器组适配器（始终可用，因为它们是核心功能）
pub mod selector;
pub mod urltest;

// Re-export traits for easy access
// 重导出 trait 以便轻松访问
pub use crate::traits::*;

#[allow(dead_code)]
fn unsupported_ir_conversion(what: &'static str) -> crate::error::AdapterError {
    crate::error::AdapterError::NotImplemented { what }
}

// IR to adapter construction bridges
// IR 到适配器构造的桥接
#[cfg(feature = "adapter-http")]
impl TryFrom<&sb_config::ir::OutboundIR> for http::HttpProxyConnector {
    type Error = crate::error::AdapterError;

    fn try_from(ir: &sb_config::ir::OutboundIR) -> Result<Self, Self::Error> {
        use sb_config::ir::OutboundType;

        if ir.ty != OutboundType::Http {
            return Err(crate::error::AdapterError::InvalidConfig(
                "Expected HTTP outbound type",
            ));
        }

        let server = ir
            .server
            .as_ref()
            .ok_or(crate::error::AdapterError::InvalidConfig(
                "HTTP proxy server address required",
            ))?;
        let port = ir.port.unwrap_or(8080);

        let server_addr = if server.contains(':') {
            server.clone()
        } else {
            format!("{}:{}", server, port)
        };

        let config = sb_config::outbound::HttpProxyConfig {
            server: server_addr,
            tag: ir.name.clone(),
            username: ir.credentials.as_ref().and_then(|c| c.username.clone()),
            password: ir.credentials.as_ref().and_then(|c| c.password.clone()),
            connect_timeout_sec: Some(30),
            tls: None,
        };

        Ok(Self::new(config))
    }
}

#[cfg(feature = "adapter-socks")]
impl TryFrom<&sb_config::ir::OutboundIR> for socks5::Socks5Connector {
    type Error = crate::error::AdapterError;

    fn try_from(ir: &sb_config::ir::OutboundIR) -> Result<Self, Self::Error> {
        use sb_config::ir::OutboundType;

        if ir.ty != OutboundType::Socks {
            return Err(crate::error::AdapterError::InvalidConfig(
                "Expected SOCKS outbound type",
            ));
        }

        let server = ir
            .server
            .as_ref()
            .ok_or(crate::error::AdapterError::InvalidConfig(
                "SOCKS5 proxy server address required",
            ))?;
        let port = ir.port.unwrap_or(1080);

        let server_addr = if server.contains(':') {
            server.clone()
        } else {
            format!("{}:{}", server, port)
        };

        let config = sb_config::outbound::Socks5Config {
            server: server_addr,
            tag: ir.name.clone(),
            username: ir.credentials.as_ref().and_then(|c| c.username.clone()),
            password: ir.credentials.as_ref().and_then(|c| c.password.clone()),
            connect_timeout_sec: Some(30),
            tls: None,
        };

        Ok(Self::new(config))
    }
}

#[cfg(feature = "adapter-socks")]
impl TryFrom<&sb_config::ir::OutboundIR> for socks4::Socks4Connector {
    type Error = crate::error::AdapterError;

    fn try_from(ir: &sb_config::ir::OutboundIR) -> Result<Self, Self::Error> {
        use sb_config::ir::OutboundType;

        if ir.ty != OutboundType::Socks {
            return Err(crate::error::AdapterError::InvalidConfig(
                "Expected SOCKS4 outbound type",
            ));
        }

        let server = ir
            .server
            .as_ref()
            .ok_or(crate::error::AdapterError::InvalidConfig(
                "SOCKS4 proxy server address required",
            ))?;
        let port = ir.port.unwrap_or(1080);

        let server_addr = if server.contains(':') {
            server.clone()
        } else {
            format!("{}:{}", server, port)
        };

        let config = sb_config::outbound::Socks4Config {
            server: server_addr,
            tag: ir.name.clone(),
            user_id: ir.credentials.as_ref().and_then(|c| c.username.clone()),
            connect_timeout_sec: Some(30),
        };

        Ok(Self::new(config))
    }
}

#[cfg(feature = "adapter-shadowsocks")]
impl TryFrom<&sb_config::ir::OutboundIR> for shadowsocks::ShadowsocksConnector {
    type Error = crate::error::AdapterError;

    fn try_from(ir: &sb_config::ir::OutboundIR) -> Result<Self, Self::Error> {
        use sb_config::ir::OutboundType;

        if ir.ty != OutboundType::Shadowsocks {
            return Err(crate::error::AdapterError::InvalidConfig(
                "Expected Shadowsocks outbound type",
            ));
        }

        Err(unsupported_ir_conversion(
            "TryFrom<OutboundIR> for ShadowsocksConnector",
        ))
    }
}

#[cfg(feature = "legacy_shadowsocksr")]
impl TryFrom<&sb_config::ir::OutboundIR> for shadowsocksr::ShadowsocksROutbound {
    type Error = crate::error::AdapterError;

    fn try_from(ir: &sb_config::ir::OutboundIR) -> Result<Self, Self::Error> {
        use sb_config::ir::OutboundType;

        if ir.ty != OutboundType::ShadowsocksR {
            return Err(crate::error::AdapterError::InvalidConfig(
                "Expected ShadowsocksR outbound type",
            ));
        }

        let server = ir
            .server
            .as_ref()
            .ok_or(crate::error::AdapterError::InvalidConfig(
                "ShadowsocksR requires server address",
            ))?
            .clone();
        let port = ir.port.unwrap_or(0);
        let method = ir.method.clone().unwrap_or_default();
        let password = ir.password.clone().unwrap_or_default();
        let obfs = ir.obfs.clone().unwrap_or_default();
        let protocol = ir.protocol.clone().unwrap_or_default();

        let config = shadowsocksr::ShadowsocksROutboundConfig {
            tag: ir.name.clone(),
            server,
            port,
            method,
            password,
            obfs,
            obfs_param: ir.obfs_param.clone(),
            protocol,
            protocol_param: ir.protocol_param.clone(),
        };

        Self::new(config).map_err(|e| crate::error::AdapterError::Other(e.to_string()))
    }
}

#[cfg(feature = "adapter-trojan")]
impl TryFrom<&sb_config::ir::OutboundIR> for trojan::TrojanConnector {
    type Error = crate::error::AdapterError;

    fn try_from(ir: &sb_config::ir::OutboundIR) -> Result<Self, Self::Error> {
        use sb_config::ir::OutboundType;

        if ir.ty != OutboundType::Trojan {
            return Err(crate::error::AdapterError::InvalidConfig(
                "Expected Trojan outbound type",
            ));
        }

        Err(unsupported_ir_conversion(
            "TryFrom<OutboundIR> for TrojanConnector",
        ))
    }
}

#[cfg(feature = "adapter-vmess")]
impl TryFrom<&sb_config::ir::OutboundIR> for vmess::VmessConnector {
    type Error = crate::error::AdapterError;

    fn try_from(ir: &sb_config::ir::OutboundIR) -> Result<Self, Self::Error> {
        use sb_config::ir::OutboundType;

        if ir.ty != OutboundType::Vmess {
            return Err(crate::error::AdapterError::InvalidConfig(
                "Expected VMess outbound type",
            ));
        }

        Err(unsupported_ir_conversion(
            "TryFrom<OutboundIR> for VmessConnector",
        ))
    }
}

#[cfg(feature = "adapter-vless")]
impl TryFrom<&sb_config::ir::OutboundIR> for vless::VlessConnector {
    type Error = crate::error::AdapterError;

    fn try_from(ir: &sb_config::ir::OutboundIR) -> Result<Self, Self::Error> {
        use sb_config::ir::OutboundType;

        if ir.ty != OutboundType::Vless {
            return Err(crate::error::AdapterError::InvalidConfig(
                "Expected VLESS outbound type",
            ));
        }

        Err(unsupported_ir_conversion(
            "TryFrom<OutboundIR> for VlessConnector",
        ))
    }
}

#[cfg(feature = "adapter-hysteria2")]
impl TryFrom<&sb_config::ir::OutboundIR> for hysteria2::Hysteria2Connector {
    type Error = crate::error::AdapterError;

    fn try_from(ir: &sb_config::ir::OutboundIR) -> Result<Self, Self::Error> {
        use sb_config::ir::OutboundType;

        if ir.ty != OutboundType::Hysteria2 {
            return Err(crate::error::AdapterError::InvalidConfig(
                "Expected hysteria2 outbound type",
            ));
        }

        let server = ir
            .server
            .as_ref()
            .ok_or(crate::error::AdapterError::InvalidConfig(
                "hysteria2 requires server address",
            ))?
            .clone();
        let port = ir.port.unwrap_or(443);
        let password = ir
            .password
            .as_ref()
            .ok_or(crate::error::AdapterError::InvalidConfig(
                "hysteria2 requires password",
            ))?
            .clone();

        let cfg = crate::outbound::hysteria2::Hysteria2AdapterConfig {
            tag: ir.name.clone(),
            server,
            port,
            password,
            skip_cert_verify: false,
            sni: ir.tls_sni.clone(),
            alpn: ir.tls_alpn.clone(),
            congestion_control: None,
            up_mbps: None,
            down_mbps: None,
            obfs: None,
            salamander: None,
            brutal: None,
            tls_ca_paths: ir.tls_ca_paths.clone(),
            tls_ca_pem: ir.tls_ca_pem.clone(),
            zero_rtt_handshake: ir.zero_rtt_handshake.unwrap_or(false),
        };

        Ok(Self::new(cfg))
    }
}

// ShadowTLS outbound: IR mapping is not available yet because OutboundType
// does not include `shadowtls` in sb-config IR. Adapter can still be used
// programmatically.

#[cfg(feature = "adapter-dns")]
impl TryFrom<&sb_config::ir::OutboundIR> for dns::DnsConnector {
    type Error = crate::error::AdapterError;

    fn try_from(ir: &sb_config::ir::OutboundIR) -> Result<Self, Self::Error> {
        use sb_config::ir::OutboundType;

        if ir.ty != OutboundType::Dns {
            return Err(crate::error::AdapterError::InvalidConfig(
                "Expected DNS outbound type",
            ));
        }

        Err(unsupported_ir_conversion(
            "TryFrom<OutboundIR> for DnsConnector",
        ))
    }
}

#[cfg(feature = "tuic")]
impl TryFrom<&sb_config::ir::OutboundIR> for tuic::TuicConnector {
    type Error = crate::error::AdapterError;

    fn try_from(ir: &sb_config::ir::OutboundIR) -> Result<Self, Self::Error> {
        use sb_config::ir::OutboundType;

        if ir.ty != OutboundType::Tuic {
            return Err(crate::error::AdapterError::InvalidConfig(
                "Expected TUIC outbound type",
            ));
        }

        Err(unsupported_ir_conversion(
            "TryFrom<OutboundIR> for TuicConnector",
        ))
    }
}

#[cfg(feature = "adapter-shadowtls")]
impl TryFrom<&sb_config::ir::OutboundIR> for shadowtls::ShadowTlsConnector {
    type Error = crate::error::AdapterError;

    fn try_from(ir: &sb_config::ir::OutboundIR) -> Result<Self, Self::Error> {
        use sb_config::ir::OutboundType;

        if ir.ty != OutboundType::Shadowtls {
            return Err(crate::error::AdapterError::InvalidConfig(
                "Expected shadowtls outbound type",
            ));
        }

        let server = ir
            .server
            .as_ref()
            .ok_or(crate::error::AdapterError::InvalidConfig(
                "shadowtls requires server address",
            ))?
            .clone();
        let port = ir.port.unwrap_or(443);
        let password = ir
            .password
            .clone()
            .ok_or(crate::error::AdapterError::InvalidConfig(
                "shadowtls requires password",
            ))?;
        let cfg = crate::outbound::shadowtls::ShadowTlsAdapterConfig {
            server,
            port,
            tag: ir.name.clone(),
            version: ir.version.unwrap_or(1),
            password,
            sni: ir
                .tls_sni
                .clone()
                .unwrap_or_else(|| "example.com".to_string()),
            alpn: ir.tls_alpn.as_ref().map(|v| v.join(",")),
            skip_cert_verify: false,
            utls_fingerprint: ir.utls_fingerprint.clone(),
        };
        Ok(Self::new(cfg))
    }
}

#[cfg(feature = "adapter-ssh")]
impl TryFrom<&sb_config::ir::OutboundIR> for ssh::SshConnector {
    type Error = crate::error::AdapterError;

    fn try_from(ir: &sb_config::ir::OutboundIR) -> Result<Self, Self::Error> {
        use sb_config::ir::OutboundType;

        if ir.ty != OutboundType::Ssh {
            return Err(crate::error::AdapterError::InvalidConfig(
                "Expected ssh outbound type",
            ));
        }

        let server = ir
            .server
            .as_ref()
            .ok_or(crate::error::AdapterError::InvalidConfig(
                "SSH requires server address",
            ))?
            .clone();
        let port = ir.port.unwrap_or(22);
        let username = ir
            .credentials
            .as_ref()
            .and_then(|c| c.username.clone())
            .ok_or(crate::error::AdapterError::InvalidConfig(
                "SSH requires username",
            ))?;

        let cfg = crate::outbound::ssh::SshAdapterConfig {
            tag: ir.name.clone(),
            server,
            port,
            username,
            password: ir.credentials.as_ref().and_then(|c| c.password.clone()),
            private_key: ir.ssh_private_key.clone(),
            private_key_passphrase: ir.ssh_private_key_passphrase.clone(),
            host_key_verification: ir.ssh_host_key_verification.unwrap_or(true),
            known_hosts_path: ir.ssh_known_hosts_path.clone(),
            connection_pool_size: ir.ssh_connection_pool_size,
            compression: ir.ssh_compression.unwrap_or(false),
            keepalive_interval: ir.ssh_keepalive_interval,
            connect_timeout: ir.connect_timeout_sec.map(|s| s as u64),
        };

        Ok(Self::new(cfg))
    }
}

#[cfg(test)]
mod canonical_capability_tests {
    #[cfg(any(feature = "adapter-dns", feature = "adapter-vmess"))]
    use sb_types::{NetworkKind, Outbound};

    #[cfg(feature = "adapter-vmess")]
    #[test]
    fn vmess_stream_only_contract_does_not_advertise_packet_associations() {
        let outbound = super::vmess::VmessConnector::default();
        assert_eq!(Outbound::network(&outbound), &[NetworkKind::Tcp]);
    }

    #[cfg(feature = "adapter-dns")]
    #[test]
    fn dns_stream_wrapper_does_not_advertise_packet_associations() {
        let outbound = super::dns::DnsConnector::default();
        assert_eq!(Outbound::network(&outbound), &[NetworkKind::Tcp]);
    }
}
