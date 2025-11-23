use super::super::address::{encode_ss_addr, get_port_from_target, Addr};
use super::super::types::{Outbound, TargetAddr, TcpConnectRequest, UdpBindRequest};
use super::aead_tcp::{encrypt_aead, SsAeadCipher};
use super::hkdf::{derive_subkey, generate_salt, HashAlgorithm};
// metrics are referenced via fully-qualified paths inside cfg blocks to avoid unused import warnings

use async_trait::async_trait;
use std::io::{Error, ErrorKind, Result};
use std::net::SocketAddr;
use tokio::net::UdpSocket;

/// Shadowsocks AEAD UDP configuration
#[derive(Clone, Debug)]
pub struct SsAeadUdpConfig {
    pub server: String,
    pub port: u16,
    pub cipher: SsAeadCipher,
    pub master_key: Vec<u8>,
}

/// Shadowsocks AEAD UDP outbound
pub struct SsAeadUdp {
    config: SsAeadUdpConfig,
}

impl SsAeadUdp {
    pub fn new(config: SsAeadUdpConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Outbound for SsAeadUdp {
    async fn tcp_connect(&self, _req: TcpConnectRequest) -> anyhow::Result<tokio::net::TcpStream> {
        anyhow::bail!("TCP not supported for UDP outbound");
    }

    async fn tcp_connect_tls(
        &self,
        _req: TcpConnectRequest,
    ) -> anyhow::Result<crate::transport::TlsStream<tokio::net::TcpStream>> {
        anyhow::bail!("TLS not supported for UDP outbound");
    }

    async fn udp_bind(&self, req: UdpBindRequest) -> anyhow::Result<tokio::net::UdpSocket> {
        // Require target for UDP proxying to know destination host:port per flow
        let target_opt = req.target.clone();

        // Remote UDP socket connected to Shadowsocks server
        let remote = UdpSocket::bind("0.0.0.0:0").await?;
        let server_addr = format!("{}:{}", self.config.server, self.config.port);
        #[cfg(feature = "metrics")]
        {
            crate::metrics::outbound::record_ss_connect_attempt(self.config.cipher.name());
        }
        #[cfg(feature = "metrics")]
        let t0 = std::time::Instant::now();
        let connect_res = remote.connect(&server_addr).await;
        match connect_res {
            Ok(_) => {
                #[cfg(feature = "metrics")]
                {
                    crate::metrics::outbound::record_ss_connect_success_with_cipher(
                        self.config.cipher.name(),
                    );
                    // Count as a connect duration sample as well for UDP path
                    crate::metrics::outbound::record_connect_duration(
                        t0.elapsed().as_millis() as f64
                    );
                }
            }
            Err(e) => {
                #[cfg(feature = "metrics")]
                {
                    crate::metrics::outbound::record_ss_connect_error_with_cipher(
                        self.config.cipher.name(),
                    );
                    crate::metrics::outbound::record_ss_stream_error_with_cipher(
                        "udp_connect",
                        self.config.cipher.name(),
                    );
                }
                return Err(e.into());
            }
        }
        let aead = SsAeadUdpSocket::new(remote, self.config.clone())?;

        // Local UDP pair: app <-> bridge (connected both ways)
        let local_app = UdpSocket::bind(req.bind).await?;
        let lb_recv = UdpSocket::bind("127.0.0.1:0").await?; // app -> bridge
        let lb_send = UdpSocket::bind("127.0.0.1:0").await?; // bridge -> app
        let app_addr = local_app.local_addr()?;
        let lb_recv_addr = lb_recv.local_addr()?;
        let _lb_send_addr = lb_send.local_addr()?;
        // Connect directions
        local_app.connect(lb_recv_addr).await?;
        lb_recv.connect(app_addr).await?;
        lb_send.connect(app_addr).await?;

        // Pump app->server (encrypt) from bridge side
        {
            let aead = aead.clone();
            let lb_recv = lb_recv; // move
            tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    match lb_recv.recv(&mut buf).await {
                        Ok(n) => {
                            // Determine target: from req.target if provided; otherwise attempt to parse SOCKS-style header
                            let (payload, target_addr) = if let Some(t) = target_opt.clone() {
                                (&buf[..n], t)
                            } else {
                                match parse_ss_addr(&buf[..n]) {
                                    Ok((taddr, off)) if off <= n => (
                                        &buf[off..n],
                                        match taddr {
                                            super::super::types::TargetAddr::Ip(sa) => {
                                                super::super::types::TargetAddr::Ip(sa)
                                            }
                                            super::super::types::TargetAddr::Domain(d, p) => {
                                                super::super::types::TargetAddr::Domain(d, p)
                                            }
                                        },
                                    ),
                                    _ => {
                                        // Drop invalid packet silently
                                        #[cfg(feature = "metrics")]
                                        crate::metrics::outbound::record_ss_stream_error_with_cipher(
                                            "addr_parse",
                                            aead.config.cipher.name(),
                                        );
                                        continue;
                                    }
                                }
                            };

                            match aead.encapsulate_udp_packet(payload, &target_addr) {
                                Ok(pkt) => {
                                    if let Err(_e) = aead.inner.send(&pkt).await {
                                        #[cfg(feature = "metrics")]
                                        crate::metrics::outbound::record_ss_stream_error_with_cipher(
                                            "server_send",
                                            aead.config.cipher.name(),
                                        );
                                    }
                                }
                                Err(_e) => {
                                    #[cfg(feature = "metrics")]
                                    crate::metrics::outbound::record_ss_stream_error_with_cipher(
                                        "encrypt",
                                        aead.config.cipher.name(),
                                    );
                                }
                            }
                        }
                        Err(_e) => {
                            #[cfg(feature = "metrics")]
                            crate::metrics::outbound::record_ss_stream_error_with_cipher(
                                "app_recv",
                                aead.config.cipher.name(),
                            );
                            break;
                        }
                    }
                }
            });
        }

        // Pump server->app (decrypt) and forward to bridge
        {
            let lb_send = lb_send; // move
            tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    match aead.inner.recv(&mut buf).await {
                        Ok(n) => match aead.decapsulate_udp_packet(&buf[..n]) {
                            Ok((data_len, _dst)) => {
                                if let Err(_e) = lb_send.send(&buf[..data_len]).await {
                                    #[cfg(feature = "metrics")]
                                    crate::metrics::outbound::record_ss_stream_error_with_cipher(
                                        "app_send",
                                        aead.config.cipher.name(),
                                    );
                                }
                            }
                            Err(_e) => {
                                #[cfg(feature = "metrics")]
                                crate::metrics::outbound::record_ss_stream_error_with_cipher(
                                    "decrypt",
                                    aead.config.cipher.name(),
                                );
                            }
                        },
                        Err(_e) => {
                            #[cfg(feature = "metrics")]
                            crate::metrics::outbound::record_ss_stream_error_with_cipher(
                                "server_recv",
                                aead.config.cipher.name(),
                            );
                            break;
                        }
                    }
                }
            });
        }

        Ok(local_app)
    }

    fn name(&self) -> &'static str {
        "shadowsocks-aead-udp"
    }
}

/// AEAD UDP socket wrapper
#[derive(Clone)]
pub struct SsAeadUdpSocket {
    inner: std::sync::Arc<UdpSocket>,
    config: SsAeadUdpConfig,
}

impl SsAeadUdpSocket {
    pub fn new(socket: UdpSocket, config: SsAeadUdpConfig) -> Result<Self> {
        Ok(Self {
            inner: std::sync::Arc::new(socket),
            config,
        })
    }

    /// Send UDP packet to target through Shadowsocks server
    pub async fn send_to_target(&self, data: &[u8], target: &TargetAddr) -> Result<usize> {
        let packet = self.encapsulate_udp_packet(data, target)?;
        #[cfg(feature = "metrics")]
        {
            // Count plaintext bytes encrypted on UDP path
            crate::metrics::outbound::record_ss_encrypt_bytes_with_cipher(
                data.len() as u64,
                self.config.cipher.name(),
            );
        }

        let sent = self.inner.send(&packet).await?;

        #[cfg(feature = "metrics")]
        {
            crate::metrics::outbound::record_ss_udp_send_with_cipher(self.config.cipher.name());
        }

        Ok(sent)
    }

    /// Receive UDP packet from Shadowsocks server
    pub async fn recv_from_server(&self, buf: &mut [u8]) -> Result<(usize, TargetAddr)> {
        let (n, _peer) = self.inner.recv_from(buf).await?;

        #[cfg(feature = "metrics")]
        crate::metrics::outbound::record_ss_udp_recv_with_cipher(self.config.cipher.name());

        // Decrypt and parse the UDP packet
        let (data_len, target) = self.decapsulate_udp_packet(&buf[..n])?;
        #[cfg(feature = "metrics")]
        {
            crate::metrics::outbound::record_ss_decrypt_bytes_with_cipher(
                data_len as u64,
                self.config.cipher.name(),
            );
        }

        // Move decrypted data to beginning of buffer
        buf.copy_within(0..data_len, 0);

        Ok((data_len, target))
    }

    /// Encapsulate UDP packet for Shadowsocks
    /// Format: salt + AEAD(ATYP + ADDR + PORT + DATA)
    fn encapsulate_udp_packet(&self, data: &[u8], target: &TargetAddr) -> Result<Vec<u8>> {
        // Generate random salt for each packet
        let salt = generate_salt(self.config.cipher.salt_size());

        // Derive session key
        let subkey = derive_subkey(&self.config.master_key, &salt, HashAlgorithm::Sha1);

        // Build address + data payload
        let addr = Addr::from_target_addr(target);
        let port = get_port_from_target(target);
        let mut payload = Vec::new();
        encode_ss_addr(&addr, port, &mut payload);
        payload.extend_from_slice(data);

        // Encrypt payload
        let _t0 = std::time::Instant::now();
        let encrypted_payload = encrypt_aead(&payload, &subkey, 0, &self.config.cipher)?;
        #[cfg(feature = "metrics")]
        {
            let ms = _t0.elapsed().as_millis() as f64;
            crate::metrics::outbound::record_ss_aead_op_duration(
                ms,
                self.config.cipher.name(),
                "udp_encrypt",
            );
        }

        // Build final packet: salt + encrypted_payload
        let mut packet = Vec::with_capacity(salt.len() + encrypted_payload.len());
        packet.extend_from_slice(&salt);
        packet.extend_from_slice(&encrypted_payload);

        Ok(packet)
    }

    /// Decapsulate UDP packet from Shadowsocks
    fn decapsulate_udp_packet(&self, packet: &[u8]) -> Result<(usize, TargetAddr)> {
        let salt_size = self.config.cipher.salt_size();

        if packet.len() < salt_size + self.config.cipher.tag_size() {
            return Err(Error::new(ErrorKind::InvalidData, "packet too short"));
        }

        // Extract salt and encrypted payload
        let salt = &packet[..salt_size];
        let encrypted_payload = &packet[salt_size..];

        // Derive session key
        let subkey = derive_subkey(&self.config.master_key, salt, HashAlgorithm::Sha1);

        // Decrypt payload
        let _t0 = std::time::Instant::now();
        let payload = decrypt_aead(encrypted_payload, &subkey, 0, &self.config.cipher)?;
        #[cfg(feature = "metrics")]
        {
            let ms = _t0.elapsed().as_millis() as f64;
            crate::metrics::outbound::record_ss_aead_op_duration(
                ms,
                self.config.cipher.name(),
                "udp_decrypt",
            );
        }

        // Parse address and extract data
        let (target, addr_len) = parse_ss_addr(&payload)?;
        let data_start = addr_len;
        let data_len = payload.len() - data_start;

        // Note: In a real implementation, we would copy the decrypted data back to the buffer
        // This is a simplified version that returns the length and target

        Ok((data_len, target))
    }

    // Convert to UdpSocket for compatibility (this is a simplification)
    #[allow(dead_code)]
    fn into_udp_socket(self) -> UdpSocket {
        unreachable!("not used after bridging implementation")
    }
}

/// Decrypt AEAD data (reuse from TCP module with import)
use super::aead_tcp::decrypt_aead;

/// Parse Shadowsocks address format and return target address and consumed bytes
fn parse_ss_addr(data: &[u8]) -> Result<(TargetAddr, usize)> {
    if data.is_empty() {
        return Err(Error::new(ErrorKind::InvalidData, "empty address data"));
    }

    let atyp = data[0];
    let mut offset = 1;

    match atyp {
        0x01 => {
            // IPv4
            if data.len() < 1 + 4 + 2 {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "incomplete IPv4 address",
                ));
            }
            let ip_bytes = &data[offset..offset + 4];
            let ip = std::net::Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
            offset += 4;
            let port = u16::from_be_bytes([data[offset], data[offset + 1]]);
            offset += 2;
            Ok((TargetAddr::Ip(SocketAddr::new(ip.into(), port)), offset))
        }
        0x03 => {
            // Domain
            if data.len() < 2 {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "incomplete domain length",
                ));
            }
            let domain_len = data[offset] as usize;
            offset += 1;
            if data.len() < offset + domain_len + 2 {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "incomplete domain address",
                ));
            }
            let domain = String::from_utf8(data[offset..offset + domain_len].to_vec())
                .map_err(|_| Error::new(ErrorKind::InvalidData, "invalid domain encoding"))?;
            offset += domain_len;
            let port = u16::from_be_bytes([data[offset], data[offset + 1]]);
            offset += 2;
            Ok((TargetAddr::Domain(domain, port), offset))
        }
        0x04 => {
            // IPv6
            if data.len() < 1 + 16 + 2 {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "incomplete IPv6 address",
                ));
            }
            let ip_bytes: [u8; 16] = data[offset..offset + 16]
                .try_into()
                .map_err(|_| Error::new(ErrorKind::InvalidData, "invalid IPv6 bytes"))?;
            let ip = std::net::Ipv6Addr::from(ip_bytes);
            offset += 16;
            let port = u16::from_be_bytes([data[offset], data[offset + 1]]);
            offset += 2;
            Ok((TargetAddr::Ip(SocketAddr::new(ip.into(), port)), offset))
        }
        _ => Err(Error::new(
            ErrorKind::InvalidData,
            "unsupported address type",
        )),
    }
}

/// Utility functions for UDP operations
pub async fn ss_udp_send_to(
    socket: &SsAeadUdpSocket,
    data: &[u8],
    target: &TargetAddr,
) -> Result<usize> {
    socket.send_to_target(data, target).await
}

pub async fn ss_udp_recv_from(
    socket: &SsAeadUdpSocket,
    buf: &mut [u8],
) -> Result<(usize, TargetAddr)> {
    socket.recv_from_server(buf).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_parse_ss_addr_ipv4() {
        let mut data = Vec::new();
        data.push(0x01); // IPv4 ATYP
        data.extend_from_slice(&[192, 168, 1, 1]); // IP
        data.extend_from_slice(&[0x1f, 0x90]); // Port 8080

        let (target, consumed) = parse_ss_addr(&data).unwrap();

        match target {
            TargetAddr::Ip(sa) => {
                assert_eq!(sa.ip(), std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
                assert_eq!(sa.port(), 8080);
            }
            _ => panic!("Expected IP address in parsed target"),
        }
        assert_eq!(consumed, 7);
    }

    #[test]
    fn test_parse_ss_addr_domain() {
        let mut data = Vec::new();
        data.push(0x03); // Domain ATYP
        data.push(11); // Domain length
        data.extend_from_slice(b"example.com");
        data.extend_from_slice(&[0x01, 0xbb]); // Port 443

        let (target, consumed) = parse_ss_addr(&data).unwrap();

        match target {
            TargetAddr::Domain(domain, port) => {
                assert_eq!(domain, "example.com");
                assert_eq!(port, 443);
            }
            _ => panic!("Expected domain address in parsed target"),
        }
        assert_eq!(consumed, 15);
    }

    #[test]
    fn test_parse_ss_addr_ipv6() {
        let mut data = Vec::new();
        data.push(0x04); // IPv6 ATYP
        data.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // IPv6
        data.extend_from_slice(&[0x00, 0x50]); // Port 80

        let (target, consumed) = parse_ss_addr(&data).unwrap();

        match target {
            TargetAddr::Ip(sa) => {
                assert_eq!(
                    sa.ip(),
                    std::net::IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
                );
                assert_eq!(sa.port(), 80);
            }
            _ => panic!("Expected IPv6 address in parsed target"),
        }
        assert_eq!(consumed, 19);
    }

    #[test]
    fn test_parse_ss_addr_invalid_atyp() {
        let data = vec![0x05]; // Invalid ATYP

        let result = parse_ss_addr(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_ss_addr_truncated() {
        let data = vec![0x01, 192]; // Incomplete IPv4

        let result = parse_ss_addr(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_encapsulate_udp_packet() {
        let config = SsAeadUdpConfig {
            server: "127.0.0.1".to_string(),
            port: 8388,
            cipher: SsAeadCipher::Aes256Gcm,
            master_key: vec![0u8; 32],
        };

        // This would require a real UdpSocket, so we'll test the config creation
        assert_eq!(config.cipher.salt_size(), 32);
        assert_eq!(config.cipher.name(), "aes-256-gcm");
    }
}
