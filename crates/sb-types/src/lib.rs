//! sb-types: cross-crate stable contracts (error codes, shared enums/structs).
//! sb-types: 跨 crate 的稳定契约（错误代码，共享枚举/结构体）。
//!
//! # Global Strategic Logic / 全局战略逻辑
//! This crate defines the **Contract Layer** of the workspace. It serves as the immutable interface
//! between dynamic components.
//! 本 crate 定义了工作区的 **契约层**。它充当动态组件之间的不可变接口。
//!
//! ## Strategic Design / 战略设计
//! 1. **Decoupling / 解耦**:
//!    - By defining types here, `sb-core` (logic) and `sb-config` (validation) can communicate without
//!      direct dependencies.
//!    - 通过在此处定义类型，`sb-core`（逻辑）和 `sb-config`（验证）可以在没有直接依赖的情况下进行通信。
//!
//! 2. **Stability / 稳定性**:
//!    - Types defined here are meant to be stable across versions. They are the "lingua franca".
//!    - 此处定义的类型旨在跨版本保持稳定。它们是“通用语言”。
//!
//! 3. **Observability / 可观测性**:
//!    - `IssueCode` provides machine-readable error categorization for metrics and logs.
//!    - `IssueCode` 为指标和日志提供机器可读的错误分类。
//!
//! 4. **Zero Dependencies / 零依赖**:
//!    - Keeps the dependency tree minimal to allow fast compilation and easy inclusion in any part of the system (e.g. WASM, embedded).
//!    - 保持依赖树最小化，以允许快速编译并轻松包含在系统的任何部分（例如 WASM，嵌入式）。

// ============================================================================
// Module declarations (V2 architecture)
// ============================================================================

/// Session and data plane types.
pub mod session;

/// Typed error types for cross-crate error handling.
pub mod errors;

/// Ports (trait contracts) for cross-crate abstractions.
pub mod ports;

// Re-export commonly used types at crate root.
pub use errors::{CoreError, DnsError, ErrorClass, TransportError};
pub use ports::{
    AdminPort, AsyncStream, BoxedStream, ConnSnapshot, Datagram, DnsCacheStats, DnsPort,
    HttpClient, HttpMethod, HttpRequest, HttpResponse, InboundAcceptor, InboundHandler, Lifecycle,
    LogLevel, MetricsPort, NoOpMetrics, OutboundConnector, Service, StartStage, Startable,
    StatsPort, TrafficSnapshot,
};
pub use session::{InboundTag, OutboundTag, Session, SessionId, SessionMeta, TargetAddr, UserId};

// ============================================================================
// Legacy issue codes (kept for backward compatibility)
// ============================================================================

use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

/// Stable issue codes used by config validation / CLI / network diagnostics.
/// 用于配置验证 / CLI / 网络诊断的稳定问题代码。
///
/// # Strategic Usage / 战略用法
/// - **Config Validation**: Used by `sb-config` to report schema violations.
/// - **Runtime Diagnostics**: Used by `sb-core` to report connectivity issues.
/// - **UI Integration**: Frontends can use these codes to show localized error messages.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum IssueCode {
    // ========================================================================
    // CLI / General Interaction
    // CLI / 通用交互
    // ========================================================================
    /// Invalid command line argument provided.
    /// 提供了无效的命令行参数。
    CliInvalidArg,

    /// IO failure during CLI operation (e.g., config file not readable).
    /// CLI 操作期间的 IO 失败（例如，配置文件不可读）。
    CliIoFail,

    // ========================================================================
    // Validation / Schema (Config Layer)
    // 验证 / 模式（配置层）
    // ========================================================================
    // Strategic Note: These codes allow the UI to highlight specific config lines.
    // 战略说明：这些代码允许 UI 高亮显示特定的配置行。
    /// Field is not recognized by the schema.
    /// 模式无法识别该字段。
    UnknownField,

    /// A required field is missing.
    /// 缺少必填字段。
    MissingRequired,

    /// Field value has an incorrect type (e.g., string instead of int).
    /// 字段值类型不正确（例如，应为 int 却为 string）。
    TypeMismatch,

    /// Numerical value is out of allowed range.
    /// 数值超出允许范围。
    RangeExceeded,

    /// Value is not one of the allowed enum variants.
    /// 值不是允许的枚举变体之一。
    InvalidEnum,

    /// Logical conflict between two fields (e.g., A requires B to be unset).
    /// 两个字段之间的逻辑冲突（例如，A 要求 B 未设置）。
    Conflict,

    // ----- Legacy compatibility / 遗留兼容性 -----
    // Kept for backward compatibility with older config parsers.
    // 保留以向后兼容旧的配置解析器。
    InvalidType,
    OutOfRange,
    DuplicateTag,
    SchemaInvalid,
    SchemaMissingField,
    SchemaTypeMismatch,
    SchemaRangeInvalid,

    // ========================================================================
    // CLI Tools Specific
    // CLI 工具特定
    // ========================================================================
    /// Minimization skipped because the field uses negation logic.
    /// 由于字段使用否定逻辑，跳过了最小化。
    MinimizeSkippedByNegation,

    // ========================================================================
    // TLS / Security Layer
    // TLS / 安全层
    // ========================================================================
    /// TLS handshake timed out.
    /// TLS 握手超时。
    TlsHandshakeTimeout,

    /// TLS protocol error (e.g., version mismatch).
    /// TLS 协议错误（例如，版本不匹配）。
    TlsHandshakeProtocol,

    /// Certificate validation failed.
    /// 证书验证失败。
    TlsCertInvalid,

    // ========================================================================
    // Network / Transport Layer
    // 网络 / 传输层
    // ========================================================================
    /// General network timeout.
    /// 通用网络超时。
    NetTimeout,

    /// Connection refused by peer.
    /// 连接被对端拒绝。
    NetRefused,

    /// Protocol level error (e.g., HTTP/2 framing error).
    /// 协议层错误（例如，HTTP/2 帧错误）。
    NetProto,

    /// Network certificate issue (generic).
    /// 网络证书问题（通用）。
    NetCert,

    /// Uncategorized network error.
    /// 未分类的网络错误。
    NetOther,

    // ========================================================================
    // Upstream / Proxy Layer
    // 上游 / 代理层
    // ========================================================================
    /// Upstream proxy timed out.
    /// 上游代理超时。
    UpstreamTimeout,

    /// Upstream returned ICMP error.
    /// 上游返回 ICMP 错误。
    UpstreamIcmp,

    /// Upstream refused connection.
    /// 上游拒绝连接。
    UpstreamRefused,

    /// Uncategorized upstream error.
    /// 未分类的上游错误。
    UpstreamOther,
}

impl IssueCode {
    /// Returns the canonical string representation of the issue code.
    /// 返回问题代码的规范字符串表示形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        use IssueCode::*;
        match self {
            CliInvalidArg => "CliInvalidArg",
            CliIoFail => "CliIoFail",
            UnknownField => "UnknownField",
            MissingRequired => "MissingRequired",
            TypeMismatch => "TypeMismatch",
            RangeExceeded => "RangeExceeded",
            InvalidEnum => "InvalidEnum",
            Conflict => "Conflict",
            InvalidType => "InvalidType",
            OutOfRange => "OutOfRange",
            DuplicateTag => "DuplicateTag",
            SchemaInvalid => "SchemaInvalid",
            SchemaMissingField => "SchemaMissingField",
            SchemaTypeMismatch => "SchemaTypeMismatch",
            SchemaRangeInvalid => "SchemaRangeInvalid",
            MinimizeSkippedByNegation => "MinimizeSkippedByNegation",
            TlsHandshakeTimeout => "TlsHandshakeTimeout",
            TlsHandshakeProtocol => "TlsHandshakeProtocol",
            TlsCertInvalid => "TlsCertInvalid",
            NetTimeout => "NetTimeout",
            NetRefused => "NetRefused",
            NetProto => "NetProto",
            NetCert => "NetCert",
            NetOther => "NetOther",
            UpstreamTimeout => "UpstreamTimeout",
            UpstreamIcmp => "UpstreamIcmp",
            UpstreamRefused => "UpstreamRefused",
            UpstreamOther => "UpstreamOther",
        }
    }
}

impl Display for IssueCode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl AsRef<str> for IssueCode {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Common error payload shape used across crates.
/// 跨 crate 使用的通用错误负载形状。
///
/// # Strategic Purpose / 战略目的
/// - **Standardization**: Enforces a consistent error format across the entire system.
/// - **Correlation**: The `fingerprint` field allows correlating client errors with server logs.
/// - **Actionability**: The `hint` field guides users to fix the problem themselves.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct IssuePayload {
    /// Error kind/category (e.g., "schema", "cli", "network").
    /// 错误种类/类别（例如 "schema", "cli", "network"）。
    pub kind: String,

    /// Stable machine-readable code.
    /// 稳定的机器可读代码。
    pub code: IssueCode,

    /// Optional RFC6901 JSON Pointer pointing to the offending location.
    /// 可选的 RFC6901 JSON 指针，指向出错位置。
    ///
    /// Used primarily in config validation to tell the UI exactly which line is wrong.
    /// 主要用于配置验证，以告诉 UI 确切是哪一行错误。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ptr: Option<String>,

    /// Human-readable message.
    /// 人类可读的消息。
    pub msg: String,

    /// Optional remediation hint.
    /// 可选的补救提示。
    ///
    /// Example: "Try increasing the timeout value."
    /// 示例："尝试增加超时值。"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,

    /// Optional build/runtime fingerprint for correlation.
    /// 可选的构建/运行时指纹，用于关联。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

impl IssuePayload {
    /// Construct a new payload with the required fields.
    /// 使用必填字段构造新的负载。
    #[inline]
    pub fn new(kind: impl Into<String>, code: IssueCode, msg: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            code,
            ptr: None,
            msg: msg.into(),
            hint: None,
            fingerprint: None,
        }
    }

    /// Attach a JSON pointer.
    /// 附加 JSON 指针。
    #[inline]
    pub fn with_ptr(mut self, ptr: impl Into<String>) -> Self {
        self.ptr = Some(ptr.into());
        self
    }

    /// Attach a hint message.
    /// 附加提示消息。
    #[inline]
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    /// Attach a fingerprint string.
    /// 附加指纹字符串。
    #[inline]
    pub fn with_fingerprint(mut self, fp: impl Into<String>) -> Self {
        self.fingerprint = Some(fp.into());
        self
    }
}

impl Display for IssuePayload {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // Compact single-line format for logs.
        match (&self.ptr, &self.hint) {
            (Some(ptr), Some(hint)) => write!(
                f,
                "[{kind}] {code}: {msg} (at {ptr}; hint: {hint})",
                kind = self.kind,
                code = self.code,
                msg = self.msg
            ),
            (Some(ptr), None) => write!(
                f,
                "[{kind}] {code}: {msg} (at {ptr})",
                kind = self.kind,
                code = self.code,
                msg = self.msg
            ),
            (None, Some(hint)) => write!(
                f,
                "[{kind}] {code}: {msg} (hint: {hint})",
                kind = self.kind,
                code = self.code,
                msg = self.msg
            ),
            (None, None) => write!(
                f,
                "[{kind}] {code}: {msg}",
                kind = self.kind,
                code = self.code,
                msg = self.msg
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn issuecode_serialization() {
        let res = serde_json::to_string(&IssueCode::SchemaInvalid);
        match res {
            Ok(j) => assert_eq!(j, "\"SchemaInvalid\""),
            Err(e) => panic!("serialization failed: {e}"),
        }
    }
}
