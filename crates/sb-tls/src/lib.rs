//! # sb-tls: TLS Abstraction & Anti-Censorship Layer
//! # sb-tls: TLS 抽象与抗审查层
//!
//! This crate provides TLS abstractions and anti-censorship protocols for singbox-rust:
//! 本 crate 为 singbox-rust 提供 TLS 抽象和抗审查协议：
//! - `TlsConnector` trait for extensible TLS implementations
//! - `TlsConnector` trait 用于可扩展的 TLS 实现
//! - REALITY protocol for anti-censorship (certificate stealing)
//! - REALITY 协议用于抗审查（证书窃取）
//! - ECH (Encrypted Client Hello) support
//! - ECH (加密客户端 Hello) 支持
//!
//! ## Features
//! ## 特性
//! - `reality`: REALITY anti-censorship protocol (default)
//! - `reality`: REALITY 抗审查协议（默认）
//! - `ech`: Encrypted Client Hello
//! - `ech`: 加密客户端 Hello
//!
//! ## Design Philosophy
//! ## 设计理念
//! - **Extensible TLS**: Pluggable TLS implementations
//! - **可扩展 TLS**: 可插拔的 TLS 实现
//! - **Anti-Censorship**: Protocols to bypass DPI and SNI filtering
//! - **抗审查**: 绕过 DPI 和 SNI 过滤的协议
//! - **Security First**: Proper key management and authentication
//! - **安全优先**: 正确的密钥管理和认证

use async_trait::async_trait;
use std::io;
use std::sync::OnceLock;
use tokio::io::{AsyncRead, AsyncWrite};

static RUSTLS_CRYPTO_PROVIDER_INSTALLED: OnceLock<()> = OnceLock::new();

/// Ensure the rustls crypto provider is installed process-wide.
///
/// This function is safe to call multiple times; only the first call has effect.
/// It selects the `ring` provider for consistency when multiple providers are available.
pub fn ensure_crypto_provider() {
    RUSTLS_CRYPTO_PROVIDER_INSTALLED.get_or_init(|| {
        // Prefer ring for consistency when multiple providers are enabled.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Combined `AsyncRead` + `AsyncWrite` trait
/// 组合的 `AsyncRead` + `AsyncWrite` trait
///
/// This trait is automatically implemented for any type that implements
/// `AsyncRead` + `AsyncWrite` + `Unpin` + `Send`.
/// 此 trait 会自动为任何实现了 `AsyncRead` + `AsyncWrite` + `Unpin` + `Send` 的类型实现。
pub trait TlsStream: AsyncRead + AsyncWrite + Unpin + Send {}

/// Blanket implementation for `TlsStream`
/// `TlsStream` 的全覆盖实现
impl<T> TlsStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

/// TLS stream type alias
/// TLS 流类型别名
pub type TlsIoStream = Box<dyn TlsStream>;

/// TLS connector trait
/// TLS 连接器 trait
///
/// This trait provides an abstraction for different TLS implementations:
/// 此 trait 为不同的 TLS 实现提供抽象：
/// - Standard TLS 1.3 (rustls)
/// - 标准 TLS 1.3 (rustls)
/// - REALITY (anti-censorship)
/// - REALITY (抗审查)
/// - REALITY (anti-censorship)
/// - REALITY (抗审查)
/// - ECH (encrypted client hello)
/// - ECH (加密客户端 Hello)
#[async_trait]
pub trait TlsConnector: Send + Sync {
    /// Connect to a TLS server
    /// 连接到 TLS 服务器
    ///
    /// # Arguments
    /// # 参数
    /// - `stream`: The underlying TCP stream
    /// - `stream`: 底层 TCP 流
    /// - `server_name`: The server name for SNI
    /// - `server_name`: 用于 SNI 的服务器名称
    async fn connect<S>(&self, stream: S, server_name: &str) -> io::Result<TlsIoStream>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static;
}

/// Standard TLS connector (rustls)
/// 标准 TLS 连接器 (rustls)
pub mod standard;

/// Dangerous TLS certificate verifiers (NoVerify, PinVerify)
pub mod danger;

/// Global TLS configuration (root stores, certificate overrides)
pub mod global;

/// REALITY anti-censorship protocol
/// REALITY 抗审查协议
#[cfg(feature = "reality")]
pub mod reality;

/// Encrypted Client Hello
/// 加密客户端 Hello
#[cfg(feature = "ech")]
pub mod ech;

/// ACME (Automated Certificate Management Environment)
/// ACME (自动证书管理环境)
#[cfg(feature = "acme")]
pub mod acme;

/// uTLS Client Fingerprinting
/// uTLS 客户端指纹模拟
///
/// Provides TLS client fingerprinting to mimic browsers like Chrome, Firefox, Safari.
/// 提供 TLS 客户端指纹模拟，模仿 Chrome、Firefox、Safari 等浏览器。
#[cfg(feature = "utls")]
pub mod utls;

// Re-exports
pub use standard::StandardTlsConnector;

#[cfg(feature = "reality")]
pub use reality::{RealityAcceptor, RealityClientConfig, RealityConnector, RealityServerConfig};

#[cfg(feature = "ech")]
pub use ech::{EchClientConfig, EchConnector, EchKeypair, EchServerConfig};

#[cfg(feature = "utls")]
pub use utls::{CustomFingerprint, UtlsConfig, UtlsFingerprint, available_fingerprints};

/// TLS error types
/// TLS 错误类型
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("TLS handshake error: {0}")]
    Handshake(String),

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Certificate error: {0}")]
    Certificate(String),
}

pub type TlsResult<T> = Result<T, TlsError>;
