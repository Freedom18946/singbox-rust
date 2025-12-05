//! Lightweight gRPC Transport Implementation
//!
//! Provides a minimal gRPC-like transport layer without full protobuf/tonic
//! dependencies. This is useful for environments where binary size matters.
//!
//! ## Protocol
//!
//! Uses HTTP/2 with a simplified gRPC frame format:
//! ```text
//! +------------------+
//! | Compressed (1B)  |
//! +------------------+
//! | Length (4B BE)   |
//! +------------------+
//! | Message          |
//! +------------------+
//! ```
//!
//! ## Features
//! - Minimal dependencies (only h2 for HTTP/2)
//! - Compatible with standard gRPC servers
//! - Streaming support

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// gRPC frame header size (1 byte compressed flag + 4 bytes length)
pub const GRPC_HEADER_SIZE: usize = 5;

/// Maximum gRPC message size (4MB default)
pub const MAX_MESSAGE_SIZE: usize = 4 * 1024 * 1024;

/// gRPC-lite configuration
#[derive(Debug, Clone)]
pub struct GrpcLiteConfig {
    /// Service name (e.g., "TunService")
    pub service_name: String,
    /// Method name (e.g., "Tun")  
    pub method_name: String,
    /// Host header
    pub host: String,
    /// Custom path (overrides service/method)
    pub path: Option<String>,
    /// User-Agent header
    pub user_agent: Option<String>,
}

impl GrpcLiteConfig {
    /// Create a new gRPC-lite configuration
    pub fn new(service: impl Into<String>, method: impl Into<String>) -> Self {
        Self {
            service_name: service.into(),
            method_name: method.into(),
            host: String::new(),
            path: None,
            user_agent: None,
        }
    }

    /// Set host header
    pub fn with_host(mut self, host: impl Into<String>) -> Self {
        self.host = host.into();
        self
    }

    /// Set custom path
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// Set user agent
    pub fn with_user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(ua.into());
        self
    }

    /// Get the gRPC path
    pub fn grpc_path(&self) -> String {
        self.path.clone().unwrap_or_else(|| {
            format!("/{}/{}", self.service_name, self.method_name)
        })
    }
}

/// gRPC message frame
#[derive(Debug, Clone)]
pub struct GrpcFrame {
    /// Whether the message is compressed
    pub compressed: bool,
    /// Message data
    pub data: Bytes,
}

impl GrpcFrame {
    /// Create a new uncompressed frame
    pub fn new(data: impl Into<Bytes>) -> Self {
        Self {
            compressed: false,
            data: data.into(),
        }
    }

    /// Create a compressed frame
    pub fn compressed(data: impl Into<Bytes>) -> Self {
        Self {
            compressed: true,
            data: data.into(),
        }
    }

    /// Encode frame to bytes
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(GRPC_HEADER_SIZE + self.data.len());
        buf.put_u8(if self.compressed { 1 } else { 0 });
        buf.put_u32(self.data.len() as u32);
        buf.put_slice(&self.data);
        buf.freeze()
    }

    /// Decode frame from buffer
    pub fn decode(buf: &mut BytesMut) -> io::Result<Option<Self>> {
        if buf.len() < GRPC_HEADER_SIZE {
            return Ok(None);
        }

        let compressed = buf[0] != 0;
        let length = ((buf[1] as usize) << 24)
            | ((buf[2] as usize) << 16)
            | ((buf[3] as usize) << 8)
            | (buf[4] as usize);

        if length > MAX_MESSAGE_SIZE {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!("gRPC message too large: {} bytes", length),
            ));
        }

        if buf.len() < GRPC_HEADER_SIZE + length {
            return Ok(None);
        }

        buf.advance(GRPC_HEADER_SIZE);
        let data = buf.split_to(length).freeze();

        Ok(Some(Self { compressed, data }))
    }
}

/// gRPC-lite stream wrapper
pub struct GrpcLiteStream<S> {
    inner: S,
    config: GrpcLiteConfig,
    read_buffer: BytesMut,
    write_buffer: BytesMut,
    headers_sent: bool,
}

impl<S> GrpcLiteStream<S> {
    /// Create a new gRPC-lite stream
    pub fn new(inner: S, config: GrpcLiteConfig) -> Self {
        Self {
            inner,
            config,
            read_buffer: BytesMut::with_capacity(MAX_MESSAGE_SIZE),
            write_buffer: BytesMut::with_capacity(4096),
            headers_sent: false,
        }
    }

    /// Get reference to inner stream
    pub fn inner(&self) -> &S {
        &self.inner
    }

    /// Get mutable reference to inner stream
    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Get the configuration
    pub fn config(&self) -> &GrpcLiteConfig {
        &self.config
    }
}

/// Simple HTTP/2-like frame for gRPC transport
/// This is a simplified version that works over raw TCP with TLS
pub struct GrpcRawFrame {
    /// Frame type
    pub frame_type: GrpcFrameType,
    /// Frame data
    pub data: Bytes,
}

/// gRPC frame types (simplified)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrpcFrameType {
    /// Data frame
    Data = 0x00,
    /// Headers frame
    Headers = 0x01,
    /// Trailer frame (for status)
    Trailers = 0x02,
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for GrpcLiteStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Read more data
        let mut tmp = [0u8; 4096];
        let mut read_buf = ReadBuf::new(&mut tmp);
        
        match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                let n = read_buf.filled().len();
                if n == 0 && this.read_buffer.is_empty() {
                    return Poll::Ready(Ok(()));
                }
                this.read_buffer.extend_from_slice(read_buf.filled());
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending if this.read_buffer.is_empty() => return Poll::Pending,
            Poll::Pending => {}
        }

        // Try to decode a gRPC frame
        match GrpcFrame::decode(&mut this.read_buffer)? {
            Some(frame) => {
                let len = std::cmp::min(buf.remaining(), frame.data.len());
                buf.put_slice(&frame.data[..len]);
                Poll::Ready(Ok(()))
            }
            None => Poll::Pending,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for GrpcLiteStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let frame = GrpcFrame::new(Bytes::copy_from_slice(buf));
        let encoded = frame.encode();
        
        match Pin::new(&mut self.inner).poll_write(cx, &encoded) {
            Poll::Ready(Ok(n)) if n >= encoded.len() => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Ok(_)) => Poll::Ready(Err(io::Error::new(
                ErrorKind::WriteZero,
                "failed to write complete gRPC frame",
            ))),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// gRPC status codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GrpcStatus {
    /// OK
    Ok = 0,
    /// Cancelled
    Cancelled = 1,
    /// Unknown error
    Unknown = 2,
    /// Invalid argument
    InvalidArgument = 3,
    /// Deadline exceeded
    DeadlineExceeded = 4,
    /// Not found
    NotFound = 5,
    /// Already exists
    AlreadyExists = 6,
    /// Permission denied
    PermissionDenied = 7,
    /// Resource exhausted
    ResourceExhausted = 8,
    /// Failed precondition
    FailedPrecondition = 9,
    /// Aborted
    Aborted = 10,
    /// Out of range
    OutOfRange = 11,
    /// Unimplemented
    Unimplemented = 12,
    /// Internal error
    Internal = 13,
    /// Unavailable
    Unavailable = 14,
    /// Data loss
    DataLoss = 15,
    /// Unauthenticated
    Unauthenticated = 16,
}

impl GrpcStatus {
    /// Convert to HTTP status code
    pub fn to_http_status(&self) -> u16 {
        match self {
            Self::Ok => 200,
            Self::Cancelled => 499,
            Self::Unknown => 500,
            Self::InvalidArgument => 400,
            Self::DeadlineExceeded => 504,
            Self::NotFound => 404,
            Self::AlreadyExists => 409,
            Self::PermissionDenied => 403,
            Self::ResourceExhausted => 429,
            Self::FailedPrecondition => 400,
            Self::Aborted => 409,
            Self::OutOfRange => 400,
            Self::Unimplemented => 501,
            Self::Internal => 500,
            Self::Unavailable => 503,
            Self::DataLoss => 500,
            Self::Unauthenticated => 401,
        }
    }
}

/// Build gRPC request headers
pub fn build_grpc_headers(config: &GrpcLiteConfig) -> Vec<(String, String)> {
    let mut headers = vec![
        (":method".to_string(), "POST".to_string()),
        (":path".to_string(), config.grpc_path()),
        (":scheme".to_string(), "https".to_string()),
        ("content-type".to_string(), "application/grpc".to_string()),
        ("te".to_string(), "trailers".to_string()),
    ];

    if !config.host.is_empty() {
        headers.push((":authority".to_string(), config.host.clone()));
    }

    if let Some(ref ua) = config.user_agent {
        headers.push(("user-agent".to_string(), ua.clone()));
    } else {
        headers.push(("user-agent".to_string(), "grpc-rust/1.0".to_string()));
    }

    headers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grpc_path() {
        let config = GrpcLiteConfig::new("TunService", "Tun");
        assert_eq!(config.grpc_path(), "/TunService/Tun");

        let config = GrpcLiteConfig::new("service", "method")
            .with_path("/custom/path");
        assert_eq!(config.grpc_path(), "/custom/path");
    }

    #[test]
    fn test_frame_encode_decode() {
        let frame = GrpcFrame::new(Bytes::from("hello gRPC"));
        let encoded = frame.encode();
        
        assert_eq!(encoded.len(), GRPC_HEADER_SIZE + 10);
        assert_eq!(encoded[0], 0); // not compressed
        
        let mut buf = BytesMut::from(&encoded[..]);
        let decoded = GrpcFrame::decode(&mut buf).unwrap().unwrap();
        
        assert!(!decoded.compressed);
        assert_eq!(decoded.data, Bytes::from("hello gRPC"));
    }

    #[test]
    fn test_compressed_frame() {
        let frame = GrpcFrame::compressed(Bytes::from("compressed data"));
        let encoded = frame.encode();
        
        assert_eq!(encoded[0], 1); // compressed
        
        let mut buf = BytesMut::from(&encoded[..]);
        let decoded = GrpcFrame::decode(&mut buf).unwrap().unwrap();
        
        assert!(decoded.compressed);
    }

    #[test]
    fn test_headers_build() {
        let config = GrpcLiteConfig::new("TestService", "TestMethod")
            .with_host("example.com")
            .with_user_agent("test-client/1.0");
        
        let headers = build_grpc_headers(&config);
        
        assert!(headers.iter().any(|(k, v)| k == ":path" && v == "/TestService/TestMethod"));
        assert!(headers.iter().any(|(k, v)| k == ":authority" && v == "example.com"));
        assert!(headers.iter().any(|(k, v)| k == "content-type" && v == "application/grpc"));
    }

    #[test]
    fn test_status_to_http() {
        assert_eq!(GrpcStatus::Ok.to_http_status(), 200);
        assert_eq!(GrpcStatus::NotFound.to_http_status(), 404);
        assert_eq!(GrpcStatus::Internal.to_http_status(), 500);
    }
}
