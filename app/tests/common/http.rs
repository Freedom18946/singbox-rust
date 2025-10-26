#![allow(dead_code)]
//! HTTP client helpers for testing

use std::io::{Read, Write};
use std::net::TcpStream;

/// Send a simple HTTP GET request and return the response as a string.
///
/// This is a minimal HTTP client for testing purposes only.
/// Does not handle redirects, chunked encoding, or complex headers.
///
/// # Example
///
/// ```no_run
/// let resp = get("127.0.0.1:8080", "/health");
/// assert!(resp.contains("200 OK"));
/// ```
pub fn get(host: &str, path: &str) -> String {
    let mut stream = TcpStream::connect(host).expect("Failed to connect");
    let request = format!("GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", path, host);
    stream
        .write_all(request.as_bytes())
        .expect("Failed to write request");

    let mut buffer = Vec::new();
    stream
        .read_to_end(&mut buffer)
        .expect("Failed to read response");

    String::from_utf8_lossy(&buffer).to_string()
}

/// Send a simple HTTP POST request with JSON body and return the response.
///
/// This is a minimal HTTP client for testing purposes only.
/// Does not handle redirects, chunked encoding, or complex headers.
///
/// # Example
///
/// ```no_run
/// let body = r#"{"key": "value"}"#;
/// let resp = post_json("127.0.0.1:8080", "/api/endpoint", body);
/// assert!(resp.contains("200 OK"));
/// ```
pub fn post_json(host: &str, path: &str, body: &str) -> String {
    let mut stream = TcpStream::connect(host).expect("Failed to connect");
    let request = format!(
        "POST {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        path,
        host,
        body.len(),
        body
    );

    stream
        .write_all(request.as_bytes())
        .expect("Failed to write request");

    let mut buffer = Vec::new();
    stream
        .read_to_end(&mut buffer)
        .expect("Failed to read response");

    String::from_utf8_lossy(&buffer).to_string()
}

/// Send a simple HTTP PUT request with JSON body and return the response.
///
/// # Example
///
/// ```no_run
/// let body = r#"{"updated": true}"#;
/// let resp = put_json("127.0.0.1:8080", "/api/resource", body);
/// assert!(resp.contains("200 OK"));
/// ```
pub fn put_json(host: &str, path: &str, body: &str) -> String {
    let mut stream = TcpStream::connect(host).expect("Failed to connect");
    let request = format!(
        "PUT {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        path,
        host,
        body.len(),
        body
    );

    stream
        .write_all(request.as_bytes())
        .expect("Failed to write request");

    let mut buffer = Vec::new();
    stream
        .read_to_end(&mut buffer)
        .expect("Failed to read response");

    String::from_utf8_lossy(&buffer).to_string()
}

/// Extract the status code from an HTTP response string.
///
/// # Example
///
/// ```
/// # use app::tests::common::http::extract_status;
/// let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
/// assert_eq!(extract_status(&response), Some(200));
/// ```
pub fn extract_status(response: &str) -> Option<u16> {
    let status_line = response.lines().next()?;
    let parts: Vec<&str> = status_line.split_whitespace().collect();
    if parts.len() >= 2 {
        parts[1].parse().ok()
    } else {
        None
    }
}
