//! VLESS TCP outbound implementation
//!
//! Provides minimal VLESS protocol support for TCP connections
//! with UUID-based authentication and optional flow control.

#[cfg(feature = "out_vless")]
use async_trait::async_trait;
#[cfg(feature = "out_vless")]
use std::io;
#[cfg(feature = "out_vless")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(feature = "out_vless")]
use tokio::net::TcpStream;

#[cfg(feature = "out_vless")]
use super::types::{encode_ss_addr, Addr};
#[cfg(feature = "out_vless")]
use super::types::{HostPort, OutboundTcp};

#[cfg(feature = "out_vless")]
#[derive(Clone, Debug)]
pub struct VlessConfig {
    pub server: String,
    pub port: u16,
    pub uuid: uuid::Uuid,
    pub flow: Option<String>,
    pub encryption: Option<String>, // "none" for minimal implementation
    // Transport layering from IR (optional)
    pub transport: Option<Vec<String>>, // e.g., ["tls","ws"], ["tls","h2"]
    pub ws_path: Option<String>,
    pub ws_host: Option<String>,
    pub h2_path: Option<String>,
    pub h2_host: Option<String>,
    pub tls_sni: Option<String>,
    pub tls_alpn: Option<Vec<String>>,
    pub grpc_service: Option<String>,
    pub grpc_method: Option<String>,
    pub grpc_authority: Option<String>,
    pub grpc_metadata: Vec<(String, String)>,
    pub http_upgrade_path: Option<String>,
    pub http_upgrade_headers: Vec<(String, String)>,
    pub multiplex: Option<sb_config::ir::MultiplexOptionsIR>,
}

impl Default for VlessConfig {
    fn default() -> Self {
        Self {
            server: String::new(),
            port: 0,
            uuid: uuid::Uuid::nil(),
            flow: None,
            encryption: Some("none".to_string()),
            transport: None,
            ws_path: None,
            ws_host: None,
            h2_path: None,
            h2_host: None,
            tls_sni: None,
            tls_alpn: None,
            grpc_service: None,
            grpc_method: None,
            grpc_authority: None,
            grpc_metadata: Vec::new(),
            http_upgrade_path: None,
            http_upgrade_headers: Vec::new(),
            multiplex: None,
        }
    }
}

#[cfg(feature = "out_vless")]
#[derive(Debug)]
pub struct VlessOutbound {
    config: VlessConfig,
}

#[cfg(feature = "out_vless")]
impl VlessOutbound {
    pub fn new(config: VlessConfig) -> anyhow::Result<Self> {
        // Validate encryption setting
        if let Some(ref enc) = config.encryption {
            if enc != "none" {
                return Err(anyhow::anyhow!(
                    "VLESS minimal implementation only supports encryption=none, got: {}",
                    enc
                ));
            }
        }

        Ok(Self { config })
    }

    #[cfg(feature = "out_vless")]
    pub(crate) async fn do_handshake_on<
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + ?Sized,
    >(
        &self,
        target: &HostPort,
        stream: &mut S,
    ) -> io::Result<()> {
        #[cfg(feature = "metrics")]
        let t0 = std::time::Instant::now();
        // Send VLESS request header
        let request = self.encode_vless_request(target);
        stream.write_all(&request).await?;

        // Read response header - validation with timeout
        let mut response_header = [0u8; 2];
        let handshake_timeout = std::time::Duration::from_millis(
            std::env::var("SB_VLESS_HANDSHAKE_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(800),
        );
        tokio::time::timeout(handshake_timeout, stream.read_exact(&mut response_header))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "VLESS handshake timeout"))??;

        // Validate response version and additional length
        if response_header[0] != 0x01 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid VLESS response version: {}", response_header[0]),
            ));
        }

        // Skip additional data if present
        let additional_len = response_header[1];
        if additional_len > 0 {
            let mut additional_data = vec![0u8; additional_len as usize];
            stream.read_exact(&mut additional_data).await?;
        }

        #[cfg(feature = "metrics")]
        {
            use metrics::{counter, histogram};
            counter!("vless_handshake_total", "result"=>"ok").increment(1);
            histogram!("vless_handshake_ms").record(t0.elapsed().as_millis() as f64);
        }

        Ok(())
    }

    fn encode_vless_request(&self, target: &HostPort) -> Vec<u8> {
        let mut request = Vec::new();

        // Version (1 byte) - VLESS v1
        request.push(0x01);

        // UUID (16 bytes)
        request.extend_from_slice(self.config.uuid.as_bytes());

        // Additional TLVs
        let mut additional = Vec::new();
        if let Some(flow) = &self.config.flow {
            if !flow.is_empty() {
                additional.push(0x01); // flow TLV id
                let fb = flow.as_bytes();
                additional.push(fb.len() as u8);
                additional.extend_from_slice(fb);
            }
        }
        if let Some(enc) = &self.config.encryption {
            if enc != "none" {
                additional.push(0x02); // encryption TLV id
                let eb = enc.as_bytes();
                additional.push(eb.len() as u8);
                additional.extend_from_slice(eb);
            }
        }
        // Additional length (1 byte) followed by TLV content
        request.push(additional.len() as u8);
        if !additional.is_empty() {
            request.extend_from_slice(&additional);
        }

        // Command (1 byte) - TCP connect
        request.push(0x01);

        // Target address encoding
        let addr = if let Ok(ip) = target.host.parse::<std::net::IpAddr>() {
            match ip {
                std::net::IpAddr::V4(v4) => Addr::V4(v4),
                std::net::IpAddr::V6(v6) => Addr::V6(v6),
            }
        } else {
            Addr::Domain(target.host.clone())
        };

        encode_ss_addr(&addr, target.port, &mut request);

        request
    }
}

// V2Ray transport integration (feature-gated)
#[cfg(all(feature = "out_vless", feature = "v2ray_transport"))]
#[async_trait::async_trait]
impl crate::outbound::traits::OutboundConnectorIo for VlessOutbound {
    async fn connect_tcp_io(
        &self,
        ctx: &crate::types::ConnCtx,
    ) -> crate::error::SbResult<sb_transport::IoStream> {
        use sb_transport::Dialer as _;
        use sb_transport::TransportBuilder;

        let target = HostPort {
            host: match &ctx.dst.host {
                crate::types::Host::Name(d) => d.to_string(),
                crate::types::Host::Ip(ip) => ip.to_string(),
            },
            port: ctx.dst.port,
        };

        // Use unified IR→Builder mapping (no env overrides)
        let alpn_csv = self.config.tls_alpn.as_ref().map(|v| v.join(","));

        let chain_opt = self.config.transport.as_deref();
        let builder = crate::runtime::transport::map::apply_layers(
            TransportBuilder::tcp(),
            chain_opt,
            self.config.tls_sni.as_deref(),
            alpn_csv.as_deref(),
            self.config.ws_path.as_deref(),
            self.config.ws_host.as_deref(),
            self.config.h2_path.as_deref(),
            self.config.h2_host.as_deref(),
            self.config.http_upgrade_path.as_deref(),
            &self.config.http_upgrade_headers,
            self.config.grpc_service.as_deref(),
            self.config.grpc_method.as_deref(),
            self.config.grpc_authority.as_deref(),
            &self.config.grpc_metadata,
            None,
            self.config.multiplex.as_ref(),
        );

        let mut stream = builder
            .build()
            .connect(self.config.server.as_str(), self.config.port)
            .await
            .map_err(|e| crate::error::SbError::other(format!("transport dial failed: {}", e)))?;

        // Perform VLESS handshake over the established stream
        self.do_handshake_on(&target, &mut *stream)
            .await
            .map_err(crate::error::SbError::from)?;

        Ok(stream)
    }
}

#[cfg(feature = "out_vless")]
#[async_trait]
impl OutboundTcp for VlessOutbound {
    type IO = TcpStream;

    async fn connect(&self, target: &HostPort) -> io::Result<Self::IO> {
        use crate::metrics::outbound::{record_connect_attempt, record_connect_success};
        use crate::metrics::record_outbound_error;
        use crate::metrics::{record_connect_error, OutboundErrorClass};

        record_connect_attempt(crate::outbound::OutboundKind::Vless);

        #[cfg(feature = "metrics")]
        let start = std::time::Instant::now();

        // Connect to VLESS server
        let mut stream =
            match TcpStream::connect((self.config.server.as_str(), self.config.port)).await {
                Ok(stream) => stream,
                Err(e) => {
                    record_outbound_error(crate::outbound::OutboundKind::Direct, &e);

                    #[cfg(feature = "metrics")]
                    {
                        use metrics::counter;
                        counter!("vless_connect_total", "result" => "connect_fail").increment(1);
                    }

                    return Err(e);
                }
            };

        // Send VLESS request header
        let request = self.encode_vless_request(target);
        if let Err(e) = stream.write_all(&request).await {
            record_outbound_error(crate::outbound::OutboundKind::Direct, &e);

            #[cfg(feature = "metrics")]
            {
                use metrics::counter;
                counter!("vless_connect_total", "result" => "handshake_fail").increment(1);
            }

            return Err(e);
        }

        // Read response header - minimal validation
        let mut response_header = [0u8; 2];
        if let Err(e) = stream.read_exact(&mut response_header).await {
            record_outbound_error(crate::outbound::OutboundKind::Direct, &e);

            #[cfg(feature = "metrics")]
            {
                use metrics::counter;
                counter!("vless_connect_total", "result" => "response_fail").increment(1);
            }

            return Err(e);
        }

        // Validate response version and additional length
        if response_header[0] != 0x01 {
            record_outbound_error(
                crate::outbound::OutboundKind::Direct,
                &io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Invalid VLESS response version: {}", response_header[0]),
                ),
            );

            #[cfg(feature = "metrics")]
            {
                use metrics::counter;
                counter!("vless_connect_total", "result" => "version_mismatch").increment(1);
            }

            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid VLESS response version: {}", response_header[0]),
            ));
        }

        // Skip additional data if present
        let additional_len = response_header[1];
        if additional_len > 0 {
            let mut additional_data = vec![0u8; additional_len as usize];
            if let Err(e) = stream.read_exact(&mut additional_data).await {
                record_connect_error(
                    crate::outbound::OutboundKind::Direct,
                    OutboundErrorClass::Protocol,
                );
                return Err(e);
            }
        }

        record_connect_success(crate::outbound::OutboundKind::Direct);

        // Record VLESS-specific metrics and risk indicators
        #[cfg(feature = "metrics")]
        {
            use crate::metrics::labels::{
                record_connect_total, record_handshake_duration, Proto, ResultTag,
            };
            use metrics::counter;

            record_connect_total(Proto::Vless, ResultTag::Ok);
            record_handshake_duration(Proto::Vless, start.elapsed().as_millis() as f64);

            // Risk metrics for encryption=none
            if self.config.encryption.as_deref() == Some("none") || self.config.encryption.is_none()
            {
                let flow_reason: &'static str = if let Some(ref flow) = self.config.flow {
                    if !flow.is_empty() {
                        "flow_with_none_encryption"
                    } else {
                        "none_encryption_no_flow"
                    }
                } else {
                    "none_encryption_no_flow"
                };

                let flow_value: &'static str = if let Some(ref flow) = self.config.flow {
                    if flow.is_empty() {
                        "empty"
                    } else {
                        "configured"
                    }
                } else {
                    "none"
                };

                counter!("vless_risky_total",
                    "flow" => flow_value,
                    "reason" => flow_reason
                )
                .increment(1);
            }
        }

        Ok(stream)
    }

    fn protocol_name(&self) -> &'static str {
        "vless"
    }
}

#[cfg(feature = "out_vless")]
#[async_trait::async_trait]
impl crate::adapter::OutboundConnector for VlessOutbound {
    async fn connect(&self, host: &str, port: u16) -> std::io::Result<tokio::net::TcpStream> {
        // Create target host:port
        let target = HostPort {
            host: host.to_string(),
            port,
        };

        // Use async connect implementation
        OutboundTcp::connect(self, &target).await
    }
}

#[cfg(test)]
#[cfg(feature = "out_vless")]
mod tests {
    use super::*;

    #[test]
    fn test_vless_encode_basic() {
        let cfg = VlessConfig {
            server: "s".into(),
            port: 443,
            uuid: uuid::Uuid::new_v4(),
            flow: None,
            encryption: Some("none".into()),
            ..Default::default()
        };
        let outbound = VlessOutbound::new(cfg).unwrap();
        let hp = HostPort {
            host: "example.com".into(),
            port: 80,
        };
        let req = outbound.encode_vless_request(&hp);
        assert_eq!(req[0], 0x01); // version
                                  // additional length is 0 when no TLV
        assert_eq!(req[17], 0x00);
    }

    #[test]
    fn test_vless_encode_with_flow_tlv() {
        let cfg = VlessConfig {
            server: "s".into(),
            port: 443,
            uuid: uuid::Uuid::new_v4(),
            flow: Some("xtls-rprx-vision".into()),
            encryption: Some("none".into()),
            ..Default::default()
        };
        let outbound = VlessOutbound::new(cfg).unwrap();
        let hp = HostPort {
            host: "example.com".into(),
            port: 80,
        };
        let req = outbound.encode_vless_request(&hp);
        assert_eq!(req[0], 0x01);
        assert!(req[17] > 0); // additional has content
    }
}

#[cfg(not(feature = "out_vless"))]
pub struct VlessConfig;

#[cfg(not(feature = "out_vless"))]
impl VlessConfig {
    pub fn new() -> Self {
        Self
    }
}
