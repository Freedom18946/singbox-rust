//! Minimal outbound protocol registry (feature: `outbound_registry`).
//! 最小化出站协议注册表（特性：`outbound_registry`）。
//!
//! Provides a simple registry for managing Trojan and Shadowsocks 2022 outbound configurations,
//! primarily intended for testing and admin interfaces.
//! 提供一个简单的注册表，用于管理 Trojan 和 Shadowsocks 2022 出站配置，
//! 主要用于测试和管理接口。
//!
//! # Features / 特性
//!
//! - Protocol registration (Trojan, SS2022)
//!   - 协议注册 (Trojan, SS2022)
//! - Dry-run connection testing with first-packet write
//!   - 带首包写入的空跑连接测试
//! - TCP and TLS transport support (via feature gates)
//!   - TCP 和 TLS 传输支持（通过特性开关）
//!
//! # Strategic Value / 战略价值
//!
//! This registry enables dynamic configuration and dispatch of protocols at runtime,
//! which is essential for systems that need to manage multiple proxy targets dynamically.
//! 此注册表支持运行时协议的动态配置和分发，
//! 这对于需要动态管理多个代理目标的系统至关重要。

use crate::ss2022::Ss2022Hello;
use std::collections::BTreeMap;
use thiserror::Error;

/// Errors that can occur in registry operations.
/// 注册表操作中可能发生的错误。
#[derive(Debug, Error)]
pub enum RegistryError {
    /// Outbound not found in registry.
    /// 注册表中未找到出站配置。
    #[error("outbound not found: {0}")]
    NotFound(String),

    /// Protocol kind not supported for the requested operation.
    /// 请求的操作不支持该协议类型。
    #[error("protocol kind not supported: {0:?}")]
    UnsupportedKind(OutboundKind),

    /// Required field missing (e.g., password).
    /// 缺少必填字段（例如密码）。
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// Transport error during connection.
    /// 连接期间的传输错误。
    #[error("transport error: {0}")]
    Transport(String),

    /// Feature not enabled at compile time.
    /// 编译时未启用特性。
    #[error("feature not enabled: {0}")]
    FeatureDisabled(&'static str),
}

/// Type of outbound protocol.
/// 出站协议的类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundKind {
    /// Trojan protocol.
    /// Trojan 协议。
    Trojan,
    /// Shadowsocks 2022 protocol.
    /// Shadowsocks 2022 协议。
    Ss2022,
}

/// Specification for an outbound connection.
/// 出站连接的规范。
#[derive(Debug, Clone)]
pub struct OutboundSpec {
    /// Unique name identifier.
    /// 唯一名称标识符。
    pub name: String,
    /// Protocol type.
    /// 协议类型。
    pub kind: OutboundKind,
    /// Password/key for authentication.
    /// 用于认证的密码/密钥。
    pub password: Option<String>,
    /// Cipher method (SS2022 only).
    /// 加密方法（仅限 SS2022）。
    pub method: Option<String>,
}

/// Registry for managing outbound protocol specifications.
/// 用于管理出站协议规范的注册表。
#[derive(Default)]
pub struct Registry {
    specs: BTreeMap<String, OutboundSpec>,
}

impl Registry {
    /// Creates a new empty registry.
    /// 创建一个新的空注册表。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts an outbound specification into the registry.
    /// 将出站规范插入注册表。
    ///
    /// Overwrites existing entry with the same name.
    /// 覆盖具有相同名称的现有条目。
    pub fn insert(&mut self, spec: OutboundSpec) {
        self.specs.insert(spec.name.clone(), spec);
    }

    /// Returns all registered outbound names.
    /// 返回所有已注册的出站名称。
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        self.specs.keys().cloned().collect()
    }

    /// Retrieves an outbound specification by name.
    /// 按名称检索出站规范。
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&OutboundSpec> {
        self.specs.get(name)
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
        kind => Err(RegistryError::UnsupportedKind(kind)),
    }
}
