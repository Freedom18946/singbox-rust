//! Async HTTP CONNECT upstream connector (scaffold). Optional Basic auth.
//! Warning: this is a minimal implementation intended for CI paths.
//! Production should come from sb-adapter.
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncReadCompatExt;

#[derive(Debug)]
pub struct HttpUp {
    server: String,
    port: u16,
    user: Option<String>,
    pass: Option<String>,
}

impl HttpUp {
    pub fn new(server: String, port: u16, user: Option<String>, pass: Option<String>) -> Self {
        Self {
            server,
            port,
            user,
            pass,
        }
    }
}

impl HttpUp {
    async fn connect(&self, host: &str, port: u16) -> std::io::Result<TcpStream> {
        let addr = format!("{}:{}", self.server, self.port);
        let mut stream = TcpStream::connect(&addr).await?;

        // Build CONNECT request
        let mut req = format!(
            "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n",
            host, port, host, port
        );
        if let (Some(u), Some(p)) = (self.user.as_ref(), self.pass.as_ref()) {
            use base64::Engine as _;
            let token = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", u, p));
            req.push_str(&format!("Proxy-Authorization: Basic {}\r\n", token));
        }
        req.push_str("\r\n");

        // Send CONNECT request
        stream.write_all(req.as_bytes()).await?;

        // Read response status line
        {
            let mut reader = BufReader::new(&mut stream);
            let mut status_line = String::new();
            reader.read_line(&mut status_line).await?;

            let ok =
                status_line.starts_with("HTTP/1.1 200") || status_line.starts_with("HTTP/1.0 200");

            // Discard remaining headers
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).await?;
                if line.trim().is_empty() {
                    break;
                }
            }

            if !ok {
                return Err(std::io::Error::other(format!(
                    "http upstream not 200: {}",
                    status_line.trim()
                )));
            }
            // BufReader drops here, releasing the borrow
        }

        // Return the stream
        Ok(stream)
    }
}

impl sb_types::Outbound for HttpUp {
    fn r#type(&self) -> &str {
        "http"
    }
    fn tag(&self) -> sb_types::OutboundTag {
        sb_types::OutboundTag::new(format!("{}:{}", self.server, self.port))
    }
    fn network(&self) -> &[sb_types::NetworkKind] {
        &[sb_types::NetworkKind::Tcp]
    }
    fn dial<'a>(
        &'a self,
        session: &'a sb_types::Session,
    ) -> sb_types::BoxFuture<'a, Result<sb_types::BoxedStream, sb_types::CoreError>> {
        Box::pin(async move {
            let (host, port) = match &session.target {
                sb_types::TargetAddr::Socket(address) => (address.ip().to_string(), address.port()),
                sb_types::TargetAddr::Domain(host, port) => (host.clone(), *port),
            };
            let stream = self
                .connect(&host, port)
                .await
                .map_err(|error| sb_types::CoreError::io(error.to_string()))?;
            Ok(Box::new(stream.compat()) as sb_types::BoxedStream)
        })
    }
    fn listen_packet<'a>(
        &'a self,
        _session: &'a sb_types::Session,
    ) -> sb_types::BoxFuture<'a, Result<sb_types::BoxedPacketConn, sb_types::CoreError>> {
        Box::pin(async {
            Err(sb_types::CoreError::connect(
                sb_types::ConnectErrorKind::Unsupported,
                "HTTP CONNECT scaffold has no packet support",
            ))
        })
    }
}
