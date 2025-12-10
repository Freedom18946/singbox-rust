//! Simple obfuscation plugin transport (simple-obfs)
//!
//! Provides HTTP and TLS obfuscation wrapping for traffic. Compatible with
//! the `simple-obfs` plugin protocol used in Shadowsocks.
//!
//! ## Obfuscation Modes
//! - `http` - HTTP request/response obfuscation
//! - `tls` - TLS ClientHello obfuscation
//!
//! ## References
//! - https://github.com/shadowsocks/simple-obfs

use bytes::{BufMut, Bytes, BytesMut};
use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Obfuscation type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObfsType {
    /// HTTP obfuscation (GET request wrapper)
    Http,
    /// TLS obfuscation (fake TLS ClientHello)
    Tls,
}

impl Default for ObfsType {
    fn default() -> Self {
        Self::Http
    }
}

impl std::str::FromStr for ObfsType {
    type Err = io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "http" => Ok(Self::Http),
            "tls" => Ok(Self::Tls),
            _ => Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("unknown obfs type: {}", s),
            )),
        }
    }
}

/// Simple obfs configuration
#[derive(Debug, Clone)]
pub struct SimpleObfsConfig {
    /// Obfuscation type (http or tls)
    pub obfs_type: ObfsType,
    /// Host header for HTTP obfs, SNI for TLS obfs
    pub host: String,
    /// Custom URI path for HTTP obfs (default: "/")
    pub path: Option<String>,
}

impl Default for SimpleObfsConfig {
    fn default() -> Self {
        Self {
            obfs_type: ObfsType::Http,
            host: "www.bing.com".to_string(),
            path: None,
        }
    }
}

/// State machine for obfuscation handshake
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObfsState {
    /// Initial state, need to send obfuscation header
    Init,
    /// For HTTP: waiting for response header
    WaitingResponse,
    /// Handshake complete, pass-through mode
    Established,
}

/// Simple obfuscation stream wrapper
pub struct SimpleObfsStream<S> {
    inner: S,
    config: SimpleObfsConfig,
    state: ObfsState,
    read_buffer: BytesMut,
    write_buffer: BytesMut,
    #[allow(dead_code)]
    pending_data: Option<Bytes>,
}

impl<S> SimpleObfsStream<S> {
    /// Create a new obfuscated stream
    pub fn new(inner: S, config: SimpleObfsConfig) -> Self {
        Self {
            inner,
            config,
            state: ObfsState::Init,
            read_buffer: BytesMut::with_capacity(4096),
            write_buffer: BytesMut::with_capacity(4096),
            pending_data: None,
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

    /// Consume wrapper and return inner stream
    pub fn into_inner(self) -> S {
        self.inner
    }

    /// Build HTTP request header for obfuscation
    fn build_http_request(&self, payload: &[u8]) -> Bytes {
        let path = self.config.path.as_deref().unwrap_or("/");
        let content_len = payload.len();

        let header = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: curl/7.64.1\r\n\
             Accept: */*\r\n\
             Content-Length: {}\r\n\
             Content-Type: application/octet-stream\r\n\
             Connection: keep-alive\r\n\r\n",
            path, self.config.host, content_len
        );

        let mut buf = BytesMut::with_capacity(header.len() + payload.len());
        buf.put_slice(header.as_bytes());
        buf.put_slice(payload);
        buf.freeze()
    }

    /// Build TLS ClientHello for obfuscation
    fn build_tls_client_hello(&self, payload: &[u8]) -> Bytes {
        let host_bytes = self.config.host.as_bytes();
        let host_len = host_bytes.len();

        // Simplified TLS 1.2 ClientHello structure
        let mut buf = BytesMut::with_capacity(256 + payload.len());

        // TLS record header
        buf.put_u8(0x16); // Handshake
        buf.put_u8(0x03);
        buf.put_u8(0x01); // TLS 1.0 for ClientHello

        // Length placeholder (filled later)
        let len_pos = buf.len();
        buf.put_u16(0);

        // Handshake header
        buf.put_u8(0x01); // ClientHello

        // Handshake length placeholder
        let hs_len_pos = buf.len();
        buf.put_u8(0);
        buf.put_u16(0);

        // Client version (TLS 1.2)
        buf.put_u8(0x03);
        buf.put_u8(0x03);

        // Random (32 bytes)
        let random: [u8; 32] = rand::random();
        buf.put_slice(&random);

        // Session ID (empty)
        buf.put_u8(0);

        // Cipher suites
        buf.put_u16(4); // length
        buf.put_u16(0xc02f); // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        buf.put_u16(0xc030); // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384

        // Compression methods
        buf.put_u8(1);
        buf.put_u8(0); // null

        // Extensions
        let ext_start = buf.len();
        buf.put_u16(0); // extension length placeholder

        // SNI extension
        buf.put_u16(0x0000); // type: server_name
        buf.put_u16((host_len + 5) as u16); // extension data length
        buf.put_u16((host_len + 3) as u16); // server name list length
        buf.put_u8(0x00); // host name type
        buf.put_u16(host_len as u16);
        buf.put_slice(host_bytes);

        // Application layer protocol (encrypted data goes here)
        if !payload.is_empty() {
            buf.put_u16(0x0010); // ALPN
            buf.put_u16((payload.len() + 2) as u16);
            buf.put_u16(payload.len() as u16);
            buf.put_slice(payload);
        }

        // Fix extension length
        let ext_len = buf.len() - ext_start - 2;
        buf[ext_start] = ((ext_len >> 8) & 0xff) as u8;
        buf[ext_start + 1] = (ext_len & 0xff) as u8;

        // Fix handshake length (3 bytes, big-endian)
        let hs_len = buf.len() - hs_len_pos - 3;
        buf[hs_len_pos] = ((hs_len >> 16) & 0xff) as u8;
        buf[hs_len_pos + 1] = ((hs_len >> 8) & 0xff) as u8;
        buf[hs_len_pos + 2] = (hs_len & 0xff) as u8;

        // Fix record length
        let record_len = buf.len() - len_pos - 2;
        buf[len_pos] = ((record_len >> 8) & 0xff) as u8;
        buf[len_pos + 1] = (record_len & 0xff) as u8;

        buf.freeze()
    }

    /// Parse HTTP response header
    fn parse_http_response(&mut self) -> io::Result<bool> {
        if let Some(pos) = self.read_buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            // Found header end, skip response headers
            let _ = self.read_buffer.split_to(pos + 4);
            self.state = ObfsState::Established;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Parse TLS ServerHello
    fn parse_tls_response(&mut self) -> io::Result<bool> {
        if self.read_buffer.len() < 5 {
            return Ok(false);
        }

        // Check for TLS record header
        if self.read_buffer[0] == 0x16 {
            let record_len = ((self.read_buffer[3] as usize) << 8) | (self.read_buffer[4] as usize);
            if self.read_buffer.len() >= 5 + record_len {
                // Skip the TLS record
                let _ = self.read_buffer.split_to(5 + record_len);
                self.state = ObfsState::Established;
                return Ok(true);
            }
        } else {
            // Not a TLS response, treat as established
            self.state = ObfsState::Established;
            return Ok(true);
        }

        Ok(false)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for SimpleObfsStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // If we have buffered data after parsing headers, return it first
        if !self.read_buffer.is_empty() && self.state == ObfsState::Established {
            let len = std::cmp::min(buf.remaining(), self.read_buffer.len());
            buf.put_slice(&self.read_buffer.split_to(len));
            return Poll::Ready(Ok(()));
        }

        // Read from inner stream
        let this = self.get_mut();
        let mut inner_buf = [0u8; 4096];
        let mut read_buf = ReadBuf::new(&mut inner_buf);

        match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                let n = read_buf.filled().len();
                if n == 0 {
                    return Poll::Ready(Ok(()));
                }

                this.read_buffer.extend_from_slice(read_buf.filled());

                // Handle state machine
                match this.state {
                    ObfsState::Init | ObfsState::WaitingResponse => {
                        let parsed = match this.config.obfs_type {
                            ObfsType::Http => this.parse_http_response()?,
                            ObfsType::Tls => this.parse_tls_response()?,
                        };

                        if parsed && !this.read_buffer.is_empty() {
                            let len = std::cmp::min(buf.remaining(), this.read_buffer.len());
                            buf.put_slice(&this.read_buffer.split_to(len));
                        }

                        Poll::Ready(Ok(()))
                    }
                    ObfsState::Established => {
                        let len = std::cmp::min(buf.remaining(), this.read_buffer.len());
                        buf.put_slice(&this.read_buffer.split_to(len));
                        Poll::Ready(Ok(()))
                    }
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for SimpleObfsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        match this.state {
            ObfsState::Init => {
                // Build obfuscation header with first write data
                let obfs_data = match this.config.obfs_type {
                    ObfsType::Http => this.build_http_request(buf),
                    ObfsType::Tls => this.build_tls_client_hello(buf),
                };

                this.write_buffer.extend_from_slice(&obfs_data);
                this.state = ObfsState::WaitingResponse;

                // Write the obfuscated data
                match Pin::new(&mut this.inner).poll_write(cx, &this.write_buffer) {
                    Poll::Ready(Ok(n)) => {
                        let _ = this.write_buffer.split_to(n);
                        Poll::Ready(Ok(buf.len()))
                    }
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    Poll::Pending => Poll::Pending,
                }
            }
            ObfsState::WaitingResponse | ObfsState::Established => {
                // Pass through after initial handshake
                Pin::new(&mut this.inner).poll_write(cx, buf)
            }
        }
    }

    #[allow(unused_mut)]
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_obfs_type_parse() {
        assert_eq!("http".parse::<ObfsType>().unwrap(), ObfsType::Http);
        assert_eq!("HTTP".parse::<ObfsType>().unwrap(), ObfsType::Http);
        assert_eq!("tls".parse::<ObfsType>().unwrap(), ObfsType::Tls);
        assert_eq!("TLS".parse::<ObfsType>().unwrap(), ObfsType::Tls);
        assert!("invalid".parse::<ObfsType>().is_err());
    }

    #[test]
    fn test_http_request_builder() {
        let config = SimpleObfsConfig {
            obfs_type: ObfsType::Http,
            host: "example.com".to_string(),
            path: Some("/api".to_string()),
        };

        let stream = SimpleObfsStream::new(std::io::Cursor::<Vec<u8>>::new(vec![]), config);
        let data = stream.build_http_request(b"test payload");
        let request = String::from_utf8_lossy(&data);

        assert!(request.contains("GET /api HTTP/1.1"));
        assert!(request.contains("Host: example.com"));
        assert!(request.contains("test payload"));
    }

    #[test]
    fn test_tls_client_hello_builder() {
        let config = SimpleObfsConfig {
            obfs_type: ObfsType::Tls,
            host: "example.com".to_string(),
            path: None,
        };

        let stream = SimpleObfsStream::new(std::io::Cursor::<Vec<u8>>::new(vec![]), config);
        let data = stream.build_tls_client_hello(b"test");

        // Check TLS record header
        assert_eq!(data[0], 0x16); // Handshake
        assert_eq!(data[1], 0x03); // TLS 1.x
        assert_eq!(data[5], 0x01); // ClientHello
    }
}
