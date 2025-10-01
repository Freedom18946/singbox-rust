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

    fn encode_vless_request(&self, target: &HostPort) -> Vec<u8> {
        let mut request = Vec::new();

        // Version (1 byte) - VLESS v1
        request.push(0x01);

        // UUID (16 bytes)
        request.extend_from_slice(self.config.uuid.as_bytes());

        // Additional length (1 byte) - currently 0 for minimal implementation
        request.push(0x00);

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

#[cfg(feature = "out_vless")]
#[async_trait]
impl OutboundTcp for VlessOutbound {
    type IO = TcpStream;

    async fn connect(&self, target: &HostPort) -> io::Result<Self::IO> {
        use crate::metrics::outbound::{
            record_connect_attempt, record_connect_error, record_connect_success,
            OutboundErrorClass,
        };

        record_connect_attempt(crate::outbound::OutboundKind::Vless);

        let start = std::time::Instant::now();

        // Connect to VLESS server
        let mut stream =
            match TcpStream::connect((self.config.server.as_str(), self.config.port)).await {
                Ok(stream) => stream,
                Err(e) => {
                    record_connect_error(
                        crate::outbound::OutboundKind::Direct,
                        OutboundErrorClass::Io,
                    );

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
            record_connect_error(
                crate::outbound::OutboundKind::Direct,
                OutboundErrorClass::Protocol,
            );

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
            record_connect_error(
                crate::outbound::OutboundKind::Direct,
                OutboundErrorClass::Protocol,
            );

            #[cfg(feature = "metrics")]
            {
                use metrics::counter;
                counter!("vless_connect_total", "result" => "response_fail").increment(1);
            }

            return Err(e);
        }

        // Validate response version and additional length
        if response_header[0] != 0x01 {
            record_connect_error(
                crate::outbound::OutboundKind::Direct,
                OutboundErrorClass::Protocol,
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

#[cfg(not(feature = "out_vless"))]
pub struct VlessConfig;

#[cfg(not(feature = "out_vless"))]
impl VlessConfig {
    pub fn new() -> Self {
        Self
    }
}
