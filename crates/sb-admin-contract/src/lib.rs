//! # Admin Contract / 管理接口契约
//!
//! Minimal shared contract for admin/CLI JSON envelopes.
//! 最小化的 Admin/CLI JSON 信封共享契约。
//!
//! This crate defines a standardized JSON response format used across
//! singbox-rust admin APIs and CLI tools, ensuring consistent error
//! handling and data serialization.
//! 此 crate 定义了 singbox-rust 管理 API 和 CLI 工具使用的标准化 JSON 响应格式，
//! 确保了一致的错误处理和数据序列化。
//!
//! ## Strategic Logic Association / 战略逻辑关联
//!
//! - **Role**: Defines the contract for data exchange between the Core/Manager and external clients (CLI, Dashboard).
//!   **角色**: 定义核心/管理器与外部客户端（CLI、仪表板）之间数据交换的契约。
//! - **Benefit**: Ensures consistent error handling and response structure across the system.
//!   **收益**: 确保整个系统具有一致的错误处理和响应结构。
//!
//! # Examples / 示例
//!
//! ```
//! use sb_admin_contract::{ResponseEnvelope, ErrorKind};
//!
//! // Success response
//! let ok_resp = ResponseEnvelope::ok("data".to_string())
//!     .with_request_id("req-123");
//! assert!(ok_resp.ok);
//!
//! // Error response
//! let err_resp: ResponseEnvelope<()> = ResponseEnvelope::err(
//!     ErrorKind::NotFound,
//!     "Resource not found"
//! );
//! assert!(!err_resp.ok);
//! ```
//!
//! MSRV = 1.90

#![deny(warnings)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![warn(clippy::pedantic, clippy::nursery)]

use serde::{ser::Serializer, Deserialize, Serialize};

/// Recursively removes all `null` values from a JSON value.
/// 递归地从 JSON 值中移除所有 `null` 值。
///
/// This function traverses objects and arrays, filtering out:
/// 此函数遍历对象和数组，过滤掉：
/// - Object keys with `null` values
///   值为 `null` 的对象键
/// - Recursively processing nested structures
///   递归处理嵌套结构
///
/// # Performance / 性能
/// Uses single-pass iteration with in-place mutation for efficiency.
/// 使用单遍迭代和原地修改以提高效率。
fn strip_nulls(mut v: serde_json::Value) -> serde_json::Value {
    match &mut v {
        serde_json::Value::Object(map) => {
            // Remove null entries in-place
            map.retain(|_, val| !val.is_null());
            // Recursively process remaining values
            for val in map.values_mut() {
                *val = strip_nulls(std::mem::take(val));
            }
            serde_json::Value::Object(std::mem::take(map))
        }
        serde_json::Value::Array(arr) => {
            let new = std::mem::take(arr).into_iter().map(strip_nulls).collect();
            serde_json::Value::Array(new)
        }
        _ => v,
    }
}

/// Custom serializer that skips `null` values in nested JSON structures.
/// 自定义序列化器，跳过嵌套 JSON 结构中的 `null` 值。
///
/// Used by `ResponseEnvelope` to ensure clean JSON output without
/// unnecessary `null` fields in the `data` payload.
/// 由 `ResponseEnvelope` 使用，以确保输出干净的 JSON，
/// 在 `data` 负载中没有不必要的 `null` 字段。
///
/// Note: Takes `&Option<T>` instead of `Option<&T>` to match serde's
/// generated code expectations (cannot be changed without manual Serialize impl).
#[allow(clippy::ref_option)]
fn serialize_data_skip_none<T, S>(data: &Option<T>, serializer: S) -> Result<S::Ok, S::Error>
where
    T: Serialize,
    S: Serializer,
{
    match data {
        None => serializer.serialize_none(),
        Some(value) => {
            let json = serde_json::to_value(value).map_err(serde::ser::Error::custom)?;
            let filtered = strip_nulls(json);
            serializer.serialize_some(&filtered)
        }
    }
}

/// Standard JSON response envelope for admin APIs and CLI output.
/// 用于管理 API 和 CLI 输出的标准 JSON 响应信封。
///
/// Provides a consistent structure for success/failure responses with
/// optional metadata (request ID, error details).
/// 为成功/失败响应提供一致的结构，并包含可选的元数据（请求 ID、错误详情）。
///
/// # Fields / 字段
/// - `ok`: `true` for success, `false` for errors
///   `ok`: `true` 表示成功，`false` 表示错误
/// - `data`: Optional payload (only present when `ok == true`)
///   `data`: 可选负载（仅当 `ok == true` 时存在）
/// - `error`: Optional error details (only present when `ok == false`)
///   `error`: 可选错误详情（仅当 `ok == false` 时存在）
/// - `request_id`: Optional request tracking ID
///   `request_id`: 可选的请求跟踪 ID
///
/// # Examples / 示例
/// ```
/// use sb_admin_contract::ResponseEnvelope;
///
/// let resp = ResponseEnvelope::ok(vec![1, 2, 3])
///     .with_request_id("abc-123");
/// assert_eq!(resp.request_id, Some("abc-123".to_string()));
/// ```
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[serde(bound(
    serialize = "T: serde::Serialize",
    deserialize = "T: serde::de::DeserializeOwned"
))]
pub struct ResponseEnvelope<T> {
    /// Indicates success (`true`) or failure (`false`).
    /// 指示成功 (`true`) 或失败 (`false`)。
    pub ok: bool,
    /// Response data (only present on success).
    /// 响应数据（仅在成功时存在）。
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "serialize_data_skip_none")]
    pub data: Option<T>,
    /// Error details (only present on failure).
    /// 错误详情（仅在失败时存在）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorBody>,
    /// Optional request tracking identifier.
    /// 可选的请求跟踪标识符。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

impl<T> ResponseEnvelope<T> {
    /// Creates a successful response with the given data.
    /// 创建包含给定数据的成功响应。
    ///
    /// # Examples
    /// ```
    /// use sb_admin_contract::ResponseEnvelope;
    ///
    /// let resp = ResponseEnvelope::ok("success");
    /// assert!(resp.ok);
    /// assert_eq!(resp.data, Some("success"));
    /// ```
    #[must_use]
    pub const fn ok(data: T) -> Self {
        Self {
            ok: true,
            data: Some(data),
            error: None,
            request_id: None,
        }
    }

    /// Creates an error response with the specified kind and message.
    /// 创建包含指定类型和消息的错误响应。
    ///
    /// # Examples
    /// ```
    /// use sb_admin_contract::{ResponseEnvelope, ErrorKind};
    ///
    /// let resp: ResponseEnvelope<()> = ResponseEnvelope::err(
    ///     ErrorKind::NotFound,
    ///     "User not found"
    /// );
    /// assert!(!resp.ok);
    /// assert!(resp.error.is_some());
    /// ```
    #[must_use]
    pub fn err(kind: ErrorKind, msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            data: None,
            error: Some(ErrorBody {
                kind,
                msg: msg.into(),
                ptr: None,
                hint: None,
            }),
            request_id: None,
        }
    }

    /// Attaches a request ID to this response.
    /// 将请求 ID 附加到此响应。
    ///
    /// # Examples
    /// ```
    /// use sb_admin_contract::ResponseEnvelope;
    ///
    /// let resp = ResponseEnvelope::ok(42)
    ///     .with_request_id("req-999");
    /// assert_eq!(resp.request_id, Some("req-999".to_string()));
    /// ```
    #[must_use]
    pub fn with_request_id(mut self, id: impl Into<String>) -> Self {
        self.request_id = Some(id.into());
        self
    }

    /// Returns this envelope as a `Result`, moving the payload on success
    /// or the error body on failure. This is useful for chaining with `?`.
    /// 将此信封作为 `Result` 返回，成功时移动负载，失败时移动错误体。
    /// 这对于使用 `?` 进行链式调用非常有用。
    ///
    /// # Examples
    /// ```
    /// use sb_admin_contract::{ResponseEnvelope, ErrorKind};
    ///
    /// let ok = ResponseEnvelope::ok(1).as_result();
    /// assert_eq!(ok, Ok(1));
    ///
    /// let err: ResponseEnvelope<()> = ResponseEnvelope::err(ErrorKind::Internal, "boom");
    /// assert!(err.as_result().is_err());
    /// ```
    /// # Errors
    /// Returns `Err(ErrorBody)` when `ok == false` or when `ok == true` but
    /// the envelope unexpectedly lacks `data` (defensive fallback).
    /// 当 `ok == false` 或 `ok == true` 但信封意外缺少 `data`（防御性回退）时返回 `Err(ErrorBody)`。
    pub fn as_result(self) -> Result<T, ErrorBody> {
        if self.ok {
            // `ok` envelopes must not carry `error`.
            // Move the payload out, defaulting to a unit error if malformed (defensive).
            self.data.ok_or_else(|| ErrorBody {
                kind: ErrorKind::Internal,
                msg: "missing data in ok response".to_string(),
                ptr: None,
                hint: Some("this is a bug; please report".to_string()),
            })
        } else {
            // Error envelopes must carry `error`; provide a fallback if absent.
            Err(self.error.unwrap_or_else(|| ErrorBody {
                kind: ErrorKind::Internal,
                msg: "missing error in error response".to_string(),
                ptr: None,
                hint: Some("this is a bug; please report".to_string()),
            }))
        }
    }

    /// Attach a JSON pointer (RFC6901) to the error, if present.
    /// No-op for successful envelopes.
    /// 如果存在错误，则附加 JSON 指针 (RFC6901)。
    /// 对于成功的信封，此操作无效。
    #[must_use]
    pub fn with_error_ptr(mut self, ptr: impl Into<String>) -> Self {
        if let Some(err) = &mut self.error {
            err.ptr = Some(ptr.into());
        }
        self
    }

    /// Attach a human-readable hint to the error, if present.
    /// No-op for successful envelopes.
    /// 如果存在错误，则附加人类可读的提示。
    /// 对于成功的信封，此操作无效。
    #[must_use]
    pub fn with_error_hint(mut self, hint: impl Into<String>) -> Self {
        if let Some(err) = &mut self.error {
            err.hint = Some(hint.into());
        }
        self
    }
}

/// Detailed error information for failed responses.
/// 失败响应的详细错误信息。
///
/// # Fields / 字段
/// - `kind`: Categorizes the error type
///   `kind`: 错误类型分类
/// - `msg`: Human-readable error message
///   `msg`: 人类可读的错误消息
/// - `ptr`: Optional JSON pointer to the problematic field (RFC 6901)
///   `ptr`: 指向问题字段的可选 JSON 指针 (RFC 6901)
/// - `hint`: Optional suggestion for resolving the error
///   `hint`: 解决错误的可选建议
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ErrorBody {
    /// The category of error.
    /// 错误类别。
    pub kind: ErrorKind,
    /// A human-readable error message.
    /// 人类可读的错误消息。
    pub msg: String,
    /// Optional JSON pointer (RFC 6901) to the problematic field.
    /// 指向问题字段的可选 JSON 指针 (RFC 6901)。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ptr: Option<String>,
    /// Optional hint for resolution.
    /// 解决问题的可选提示。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

/// Categorizes different types of errors.
/// 对不同类型的错误进行分类。
///
/// Marked `#[non_exhaustive]` to allow adding new variants without
/// breaking compatibility.
/// 标记为 `#[non_exhaustive]` 以允许在不破坏兼容性的情况下添加新变体。
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "value", rename_all = "camelCase")]
#[non_exhaustive]
pub enum ErrorKind {
    /// Resource not found.
    /// 资源未找到。
    NotFound,
    /// Resource conflict (e.g., duplicate).
    /// 资源冲突（例如，重复）。
    Conflict,
    /// Invalid state transition.
    /// 无效的状态转换。
    State,
    /// Authentication/authorization failure.
    /// 认证/授权失败。
    Auth,
    /// Rate limit exceeded.
    /// 超出速率限制。
    RateLimit,
    /// I/O error.
    /// I/O 错误。
    Io,
    /// Decoding/parsing error.
    /// 解码/解析错误。
    Decode,
    /// Operation timeout.
    /// 操作超时。
    Timeout,
    /// Internal server error.
    /// 内部服务器错误。
    Internal,
    /// Custom error type.
    /// 自定义错误类型。
    Other(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_ok() -> Result<(), Box<dyn std::error::Error>> {
        let env =
            ResponseEnvelope::ok(serde_json::json!({"hello": "world"})).with_request_id("r-1");
        let s = serde_json::to_string(&env)?;
        let de: ResponseEnvelope<serde_json::Value> = serde_json::from_str(&s)?;
        assert!(de.ok);
        assert_eq!(de.request_id.as_deref(), Some("r-1"));
        Ok(())
    }

    #[test]
    fn roundtrip_err() -> Result<(), Box<dyn std::error::Error>> {
        let env: ResponseEnvelope<()> =
            ResponseEnvelope::err(ErrorKind::NotFound, "Resource missing");
        let s = serde_json::to_string(&env)?;
        let de: ResponseEnvelope<()> = serde_json::from_str(&s)?;
        assert!(!de.ok);
        assert!(de.data.is_none());
        assert_eq!(
            de.error.as_ref().map(|e| e.msg.as_str()),
            Some("Resource missing")
        );
        Ok(())
    }

    #[test]
    fn strip_nulls_removes_null_values() {
        let input = serde_json::json!({
            "a": 1,
            "b": null,
            "c": {
                "d": null,
                "e": "value"
            },
            "f": [1, null, 3]
        });
        let output = strip_nulls(input);
        assert_eq!(
            output,
            serde_json::json!({
                "a": 1,
                "c": {
                    "e": "value"
                },
                "f": [1, null, 3]  // Array nulls are preserved
            })
        );
    }

    #[test]
    fn serialize_skips_nested_nulls() -> Result<(), Box<dyn std::error::Error>> {
        #[derive(Serialize, Deserialize)]
        struct Data {
            field1: Option<String>,
            field2: String,
        }
        let data = Data {
            field1: None,
            field2: "value".to_string(),
        };
        let env = ResponseEnvelope::ok(data);
        let s = serde_json::to_string(&env)?;
        // Verify nested nulls are stripped
        assert!(!s.contains("field1"));
        assert!(s.contains("field2"));
        Ok(())
    }

    #[test]
    fn error_kinds_serialize_correctly() -> Result<(), Box<dyn std::error::Error>> {
        let kinds = vec![
            ErrorKind::NotFound,
            ErrorKind::Conflict,
            ErrorKind::Auth,
            ErrorKind::Other("custom".to_string()),
        ];
        for kind in kinds {
            let env: ResponseEnvelope<()> = ResponseEnvelope::err(kind, "test");
            let s = serde_json::to_string(&env)?;
            let _: ResponseEnvelope<()> = serde_json::from_str(&s)?;
        }
        Ok(())
    }
}
