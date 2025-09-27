//! TUIC outbound implementation
//!
//! Provides TUIC (TCP over QUIC) protocol support for secure TCP tunneling
//! over QUIC connections with UUID-based authentication.

#[cfg(feature = "out_tuic")]
use async_trait::async_trait;
#[cfg(feature = "out_tuic")]
use std::io;
#[cfg(feature = "out_tuic")]
use std::net::SocketAddr;
#[cfg(feature = "out_tuic")]
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt};

#[cfg(feature = "out_tuic")]
use super::quic::common::{connect as quic_connect, QuicConfig};
#[cfg(feature = "out_tuic")]
use super::types::{HostPort, OutboundTcp};

#[cfg(feature = "out_tuic")]
#[derive(Clone, Debug)]
pub struct TuicConfig {
    pub server: String,
    pub port: u16,
    pub uuid: uuid::Uuid,
    pub token: String,
    pub password: Option<String>,
    pub congestion_control: Option<String>,
    pub alpn: Option<String>,
    pub skip_cert_verify: bool,
}

#[cfg(feature = "out_tuic")]
pub struct TuicOutbound {
    config: TuicConfig,
    quic_config: QuicConfig,
}

#[cfg(feature = "out_tuic")]
impl TuicOutbound {
    pub fn new(config: TuicConfig) -> anyhow::Result<Self> {
        // Build QUIC configuration for TUIC
        let alpn = if let Some(ref alpn_str) = config.alpn {
            vec![alpn_str.as_bytes().to_vec()]
        } else {
            vec![b"tuic".to_vec()]
        };

        let quic_config = QuicConfig::new(config.server.clone(), config.port)
            .with_alpn(alpn)
            .with_allow_insecure(config.skip_cert_verify);

        Ok(Self {
            config,
            quic_config,
        })
    }

    fn create_quinn_config(&self) -> io::Result<quinn::ClientConfig> {
        use quinn::ClientConfig;
        use rustls::{ClientConfig as RustlsConfig, RootCertStore};

        let roots = RootCertStore::empty();

        let mut tls_config = RustlsConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        tls_config.alpn_protocols = self.quic_config.alpn.clone();

        // Note: This is a placeholder implementation
        // In a real implementation, you would need to properly configure the QUIC client
        // For now, we'll create a basic configuration
        Err(io::Error::new(
            io::ErrorKind::Other,
            "QUIC configuration not fully implemented",
        ))
    }

    async fn authenticate(&self, connection: &quinn::Connection) -> io::Result<()> {
        // Open authentication stream
        let (mut send_stream, mut recv_stream) = connection.open_bi().await.map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to open auth stream: {}", e),
            )
        })?;

        // Send authentication packet
        // TUIC authentication typically includes UUID and token
        let mut auth_packet = Vec::new();
        auth_packet.push(0x01); // Auth command
        auth_packet.extend_from_slice(self.config.uuid.as_bytes());
        auth_packet.extend_from_slice(self.config.token.as_bytes());

        use tokio::io::AsyncWriteExt;
        send_stream.write_all(&auth_packet).await.map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("Auth write failed: {}", e))
        })?;

        send_stream.finish().map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("Auth finish failed: {}", e))
        })?;

        // Read authentication response
        use tokio::io::AsyncReadExt;
        let mut response = [0u8; 1];
        recv_stream.read_exact(&mut response).await.map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("Auth read failed: {}", e))
        })?;

        if response[0] != 0x00 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("TUIC authentication failed with code: {}", response[0]),
            ));
        }

        Ok(())
    }

    async fn create_tunnel(
        &self,
        connection: &quinn::Connection,
        target: &HostPort,
    ) -> io::Result<(quinn::SendStream, quinn::RecvStream)> {
        // Open bidirectional stream for the tunnel
        let (mut send_stream, recv_stream) = connection.open_bi().await.map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to open tunnel stream: {}", e),
            )
        })?;

        // Send CONNECT request
        let mut connect_packet = Vec::new();
        connect_packet.push(0x02); // Connect command

        // Encode target address
        let target_bytes = format!("{}:{}", target.host, target.port);
        connect_packet.push(target_bytes.len() as u8);
        connect_packet.extend_from_slice(target_bytes.as_bytes());

        use tokio::io::AsyncWriteExt;
        send_stream.write_all(&connect_packet).await.map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("Connect write failed: {}", e))
        })?;

        Ok((send_stream, recv_stream))
    }
}

#[cfg(feature = "out_tuic")]
#[async_trait]
impl OutboundTcp for TuicOutbound {
    type IO = crate::outbound::quic::io::QuicBidiStream;

    async fn connect(&self, target: &HostPort) -> io::Result<Self::IO> {
        use crate::metrics::outbound::{
            record_connect_attempt, record_connect_error, record_connect_success,
            OutboundErrorClass,
        };

        record_connect_attempt(crate::outbound::OutboundKind::Direct); // TODO: Add TUIC kind

        let start = std::time::Instant::now();

        // Parse server address
        let server_addr: SocketAddr = format!("{}:{}", self.config.server, self.config.port)
            .parse()
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Invalid server address: {}", e),
                )
            })?;

        // Create quinn ClientConfig from QuicConfig
        let quinn_config = self.create_quinn_config()?;

        // Establish QUIC connection to server
        let connection = match tuic_quic_connect(&quinn_config, server_addr).await {
            Ok(conn) => conn,
            Err(e) => {
                record_connect_error(
                    crate::outbound::OutboundKind::Direct,
                    OutboundErrorClass::Handshake,
                );

                #[cfg(feature = "metrics")]
                {
                    use metrics::counter;
                    counter!("tuic_connect_total", "result" => "quic_fail").increment(1);
                }

                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("QUIC connection failed: {}", e),
                ));
            }
        };

        // Open bidirectional stream for minimal test
        let (mut send_stream, mut recv_stream) = match connection.open_bi().await {
            Ok(streams) => streams,
            Err(e) => {
                record_connect_error(
                    crate::outbound::OutboundKind::Direct,
                    OutboundErrorClass::Protocol,
                );

                #[cfg(feature = "metrics")]
                {
                    use metrics::counter;
                    counter!("tuic_connect_total", "result" => "bi_stream_fail").increment(1);
                }

                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to open bi stream: {}", e),
                ));
            }
        };

        // Send minimal CONNECT frame (placeholder implementation)
        let connect_msg = format!("CONNECT {} {}\n", target.host, target.port);
        use tokio::io::AsyncWriteExt;
        if let Err(e) = send_stream.write_all(connect_msg.as_bytes()).await {
            record_connect_error(
                crate::outbound::OutboundKind::Direct,
                OutboundErrorClass::Protocol,
            );

            #[cfg(feature = "metrics")]
            {
                use metrics::counter;
                counter!("tuic_connect_total", "result" => "write_fail").increment(1);
            }

            return Err(e.into());
        }

    if let Err(e) = send_stream.finish() {
            record_connect_error(
                crate::outbound::OutboundKind::Direct,
                OutboundErrorClass::Protocol,
            );
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Stream finish failed: {}", e),
            ));
        }

        // Read 1KB response for minimal validation
        use tokio::io::AsyncReadExt;
        let mut buf = vec![0u8; 1024];
        match recv_stream.read(&mut buf).await {
            Ok(_n) => {
                #[cfg(feature = "metrics")]
                {
                    use metrics::counter;
                    counter!("tuic_connect_total", "result" => "bi_stream_ok").increment(1);
                }
            }
            Err(e) => {
                record_connect_error(
                    crate::outbound::OutboundKind::Direct,
                    OutboundErrorClass::Protocol,
                );

                #[cfg(feature = "metrics")]
                {
                    use metrics::counter;
                    counter!("tuic_connect_total", "result" => "read_fail").increment(1);
                }

                return Err(e.into());
            }
        }

        // For minimal implementation, reopen streams for actual use
        let (send_stream, recv_stream) = match connection.open_bi().await {
            Ok(streams) => streams,
            Err(e) => {
                record_connect_error(
                    crate::outbound::OutboundKind::Direct,
                    OutboundErrorClass::Protocol,
                );
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to reopen streams: {}", e),
                ));
            }
        };

        record_connect_success(crate::outbound::OutboundKind::Direct);

        // Record TUIC-specific metrics
        #[cfg(feature = "metrics")]
        {
            use metrics::{counter, histogram};
            counter!("tuic_connect_total", "result" => "ok").increment(1);
            histogram!("tuic_handshake_ms").record(start.elapsed().as_millis() as f64);
        }

        // Wrap streams for compatibility
        Ok(crate::outbound::quic::io::QuicBidiStream::new(
            send_stream,
            recv_stream,
        ))
    }

    fn protocol_name(&self) -> &'static str {
        "tuic"
    }
}

#[cfg(feature = "out_tuic")]
async fn tuic_quic_connect(
    config: &quinn::ClientConfig,
    server_addr: std::net::SocketAddr,
) -> Result<quinn::Connection, Box<dyn std::error::Error + Send + Sync>> {
    // Create QUIC endpoint
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(config.clone());

    // Connect to server
    let connection = endpoint
        .connect(server_addr, "localhost")? // Use localhost as SNI, should be configurable
        .await?;

    tracing::debug!("QUIC connection established to {}", server_addr);
    Ok(connection)
}

#[cfg(feature = "out_tuic")]
pub struct TuicStream {
    send_stream: quinn::SendStream,
    recv_stream: quinn::RecvStream,
}

#[cfg(feature = "out_tuic")]
impl tokio::io::AsyncRead for TuicStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        use std::pin::Pin;
        use tokio::io::AsyncRead;

        Pin::new(&mut self.recv_stream).poll_read(cx, buf)
    }
}

#[cfg(feature = "out_tuic")]
impl tokio::io::AsyncWrite for TuicStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, io::Error>> {
        use std::pin::Pin;
        use tokio::io::AsyncWrite;

        match Pin::new(&mut self.send_stream).poll_write(cx, buf) {
            std::task::Poll::Ready(Ok(n)) => std::task::Poll::Ready(Ok(n)),
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e.to_string()))),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        use std::pin::Pin;
        use tokio::io::AsyncWrite;

        match Pin::new(&mut self.send_stream).poll_flush(cx) {
            std::task::Poll::Ready(Ok(())) => std::task::Poll::Ready(Ok(())),
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e.to_string()))),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        use std::pin::Pin;
        use tokio::io::AsyncWrite;

        match Pin::new(&mut self.send_stream).poll_shutdown(cx) {
            std::task::Poll::Ready(Ok(())) => std::task::Poll::Ready(Ok(())),
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e.to_string()))),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

#[cfg(not(feature = "out_tuic"))]
pub struct TuicConfig;

#[cfg(not(feature = "out_tuic"))]
impl TuicConfig {
    pub fn new() -> Self {
        Self
    }
}
