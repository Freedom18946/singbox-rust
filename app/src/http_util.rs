//! HTTP utility functions for building responses
//!
//! All `Response::builder().expect()` calls in this module are safe because
//! they only fail with invalid headers, which we never provide.
#![allow(clippy::expect_used, clippy::needless_pass_by_value)]

use hyper::{Body, Response, StatusCode};
use std::io::Write;

pub fn write_200_json(s: &mut std::net::TcpStream, body: &serde_json::Value) {
    let b = serde_json::to_vec(body).unwrap_or_default();
    let _ = write!(
        s,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        b.len()
    );
    let _ = s.write_all(&b);
}

pub fn write_503_json(s: &mut std::net::TcpStream, body: &serde_json::Value) {
    let b = serde_json::to_vec(body).unwrap_or_default();
    let _ = write!(s, "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", b.len());
    let _ = s.write_all(&b);
}

pub fn write_200_octet(s: &mut std::net::TcpStream, mime: &str, buf: &[u8]) {
    let _ = write!(
        s,
        "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\n\r\n",
        mime,
        buf.len()
    );
    let _ = s.write_all(buf);
}

pub fn write_400(s: &mut std::net::TcpStream, msg: &str) {
    // Convert to JSON error response
    let json_body = serde_json::json!({
        "error": msg,
        "hint": "use JSON error; legacy plain removed",
        "code": 400,
        "trace_id": "legacy_plain"
    });
    let body_str =
        serde_json::to_string(&json_body).unwrap_or_else(|_| r#"{"error":"unknown"}"#.to_string());
    let _ = write!(
        s,
        "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body_str.len(),
        body_str
    );
}

pub fn write_404(s: &mut std::net::TcpStream) {
    let _ = write!(s, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
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
