//! Simplified inbound definitions for app and test usage.
//! 用于应用和测试的简化入站定义。
//!
//! This module provides a minimal [`InboundDef`] enum that uses [`serde_json::Value`]
//! for flexibility. Future iterations will introduce strongly-typed schemas.
//! 本模块提供了一个最小化的 [`InboundDef`] 枚举，使用 [`serde_json::Value`] 以获得灵活性。
//! 未来的迭代将引入强类型模式。

use serde::Deserialize;
use serde_json::Value;

/// Simplified inbound definition using raw JSON values.
/// 使用原始 JSON 值的简化入站定义。
///
/// Used by app layer and tests as a temporary representation until
/// strongly-typed schemas are fully defined.
/// 被应用层和测试用作临时表示，直到完全定义强类型模式。
///
/// # Variants
/// - `Http`: HTTP proxy inbound / HTTP 代理入站
/// - `Socks`: SOCKS5 proxy inbound / SOCKS5 代理入站
/// - `Tun`: TUN device inbound (platform-dependent) / TUN 设备入站（平台相关）
///
/// # Future Work
/// Replace `Value` with concrete types (e.g., `HttpInboundConfig`).
/// 用具体类型（例如 `HttpInboundConfig`）替换 `Value`。
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[non_exhaustive]
pub enum InboundDef {
    /// HTTP proxy inbound configuration.
    /// HTTP 代理入站配置。
    Http(Value),
    /// SOCKS5 proxy inbound configuration.
    /// SOCKS5 代理入站配置。
    Socks(Value),
    /// TUN device inbound configuration.
    /// TUN 设备入站配置。
    Tun(Value),
}
