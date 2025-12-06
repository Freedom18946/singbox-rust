//! HTTP Response Utilities (Zero-Dependency)
//!
//! # Global Strategic Logic / 全局战略逻辑
//! This module provides **Lightweight HTTP Helpers** for constructing raw responses.
//! It is designed to work without heavy dependencies (like `hyper` or `axum`) in minimal builds,
//! or to provide low-level control for specific protocols.
//!
//! 本模块提供了用于构建原始响应的 **轻量级 HTTP 辅助工具**。
//! 它的设计目标是在最小化构建中无需重型依赖（如 `hyper` 或 `axum`）即可工作，
//! 或为特定协议提供底层控制。
//!
//! ## Strategic Features / 战略特性
//!
//!   - **Raw TCP Writing / 原始 TCP 写入**: Writes HTTP/1.1 responses directly to `TcpStream` for maximum performance and minimal overhead.
//!     直接向 `TcpStream` 写入 HTTP/1.1 响应，以获得最大性能和最小开销。
//!   - **Hyper Integration / Hyper 集成**: Provides helpers for `hyper::Response` when the full HTTP stack is available.
//!     当完整的 HTTP 栈可用时，提供 `hyper::Response` 的辅助工具。
//!
//! HTTP utility functions for building responses
//!
//! All `Response::builder().expect()` calls in this module are safe because
//! they only fail with invalid headers, which we never provide.
#![allow(clippy::expect_used, clippy::needless_pass_by_value)]

use hyper::{Body, Response, StatusCode};
use std::io::Write;

#[allow(dead_code)]
pub fn write_200_json(s: &mut std::net::TcpStream, body: &serde_json::Value) -> std::io::Result<()> {
    let b = serde_json::to_vec(body).unwrap_or_default();
    write!(
        s,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        b.len()
    )?;
    s.write_all(&b)
}

#[allow(dead_code)]
pub fn write_503_json(s: &mut std::net::TcpStream, body: &serde_json::Value) -> std::io::Result<()> {
    let b = serde_json::to_vec(body).unwrap_or_default();
    write!(s, "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", b.len())?;
    s.write_all(&b)
}

#[allow(dead_code)]
pub fn write_200_octet(s: &mut std::net::TcpStream, mime: &str, buf: &[u8]) -> std::io::Result<()> {
    write!(
        s,
        "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\n\r\n",
        mime,
        buf.len()
    )?;
    s.write_all(buf)
}

#[allow(dead_code)]
pub fn write_400(s: &mut std::net::TcpStream, msg: &str) -> std::io::Result<()> {
    // Convert to JSON error response
    let json_body = serde_json::json!({
        "error": msg,
        "hint": "use JSON error; legacy plain removed",
        "code": 400,
        "trace_id": "legacy_plain"
    });
    let body_str =
        serde_json::to_string(&json_body).unwrap_or_else(|_| r#"{"error":"unknown"}"#.to_string());
    write!(
        s,
        "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body_str.len(),
        body_str
    )
}

#[allow(dead_code)]
pub fn write_404(s: &mut std::net::TcpStream) -> std::io::Result<()> {
    write!(s, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
}

// Hyper response helpers for sb-explaind
/// Creates a 400 Bad Request response with JSON error body
///
/// # Panics
/// Panics if response builder fails (only happens with invalid headers)
#[must_use]
pub fn bad_request(msg: &str) -> Response<Body> {
    // Convert to JSON error response
    let json_body = serde_json::json!({
        "error": msg,
        "hint": "use JSON error; legacy plain removed",
        "code": 400,
        "trace_id": "legacy_plain"
    });
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&json_body)
                .unwrap_or_else(|_| r#"{"error":"unknown"}"#.to_string()),
        ))
        .expect("response builder failed")
}

/// Creates a response with custom status code and JSON error body
///
/// # Panics
/// Panics if response builder fails (only happens with invalid headers)
#[must_use]
pub fn text(status: StatusCode, msg: &str) -> Response<Body> {
    // Convert to JSON error response
    let json_body = serde_json::json!({
        "error": msg,
        "hint": "use JSON error; legacy plain removed",
        "code": status.as_u16(),
        "trace_id": "legacy_plain"
    });
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&json_body)
                .unwrap_or_else(|_| r#"{"error":"unknown"}"#.to_string()),
        ))
        .expect("response builder failed")
}

/// Creates a 200 OK response with JSON body
///
/// # Panics
/// Panics if response builder fails (only happens with invalid headers)
#[must_use]
pub fn ok_json(body: serde_json::Value) -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap_or_default()))
        .expect("response builder failed")
}

/// Creates a 200 OK response with binary body
///
/// # Panics
/// Panics if response builder fails (only happens with invalid headers)
#[must_use]
pub fn ok_octet(mime: &str, buf: Vec<u8>) -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", mime)
        .body(Body::from(buf))
        .expect("response builder failed")
}

/// Creates a 404 Not Found response
///
/// # Panics
/// Panics if response builder fails (only happens with invalid headers)
#[must_use]
pub fn not_found() -> Response<Body> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::empty())
        .expect("response builder failed")
}

/// Creates a 503 Service Unavailable response with JSON body
///
/// # Panics
/// Panics if response builder fails (only happens with invalid headers)
#[must_use]
pub fn service_unavailable_json(body: serde_json::Value) -> Response<Body> {
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap_or_default()))
        .expect("response builder failed")
}
