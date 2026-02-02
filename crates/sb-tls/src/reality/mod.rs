//! # REALITY Anti-Censorship Protocol
//! # REALITY 抗审查协议
//!
//! REALITY is an anti-censorship protocol that bypasses SNI whitelisting by:
//! REALITY 是一种抗审查协议，通过以下方式绕过 SNI 白名单：
//! - Stealing TLS certificates from real target websites
//! - 窃取真实目标网站的 TLS 证书
//! - Using SNI forgery to appear as legitimate traffic
//! - 使用 SNI 伪造来伪装成合法流量
//! - Authenticating with shared keys
//! - 使用共享密钥进行认证
//! - Falling back to real target on auth failure
//! - 认证失败时回退到真实目标
//!
//! ## How it Works
//! ## 工作原理
//!
//! **Client Side:**
//! **客户端:**
//! 1. Connects with forged SNI (e.g., "www.apple.com")
//! 1. 使用伪造的 SNI 连接（例如 "www.apple.com"）
//! 2. Embeds authentication data in TLS handshake
//! 2. 在 TLS 握手中嵌入认证数据
//! 3. Receives either:
//! 3. 接收以下之一：
//!    - Temporary trusted certificate (proxy connection)
//!    - 临时受信任证书（代理连接）
//!    - Real target certificate (fallback mode)
//!    - 真实目标证书（回退模式）
//!
//! **Server Side:**
//! **服务端:**
//! 1. Receives TLS ClientHello
//! 1. 接收 TLS ClientHello
//! 2. Validates authentication data
//! 2. 验证认证数据
//! 3. If valid: issues temporary certificate and proxies traffic
//! 3. 如果有效：颁发临时证书并代理流量
//! 4. If invalid: proxies to real target website (disguise)
//! 4. 如果无效：代理到真实目标网站（伪装）
//!
//! ## Security Model
//! ## 安全模型
//!
//! - Uses X25519 key exchange for authentication
//! - 使用 X25519 密钥交换进行认证
//! - Short ID identifies different clients
//! - Short ID 标识不同的客户端
//! - Target domain certificate is "stolen" (proxied)
//! - 目标域名证书被"窃取"（代理）
//! - Falls back to real website on failure (anti-detection)
//! - 失败时回退到真实网站（反检测）

pub mod auth;
pub mod client;
pub mod config;
pub mod server;
pub mod tls_record;

pub use auth::{RealityAuth, generate_keypair};
pub use client::RealityConnector;
pub use config::{RealityClientConfig, RealityServerConfig};
pub use server::RealityAcceptor;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum RealityError {
    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Target connection failed: {0}")]
    TargetFailed(String),

    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type RealityResult<T> = Result<T, RealityError>;
pub mod cloning;
