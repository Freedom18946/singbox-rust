//! Adapter-owned SOCKS5 UDP association used by inbound proxy routing.
//!
//! Owns SOCKS5 UDP session handling in the adapter layer while reusing
//! canonical [`sb_types::PacketConn`] from [`super::socks5::Socks5Connector`].

use super::socks5::Socks5Connector;
use anyhow::{anyhow, Context, Result};
use sb_core::outbound::endpoint::{ProxyEndpoint, ProxyKind};
use sb_types::{Outbound, PacketConn, Session, TargetAddr};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tokio::time::timeout;

type UdpReceiver = Arc<Mutex<mpsc::Receiver<(SocketAddr, Vec<u8>)>>>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpSocksSessionConfig {
    pub background_receive: bool,
    pub receive_channel_capacity: usize,
    pub observe_io: bool,
}

impl Default for UpSocksSessionConfig {
    fn default() -> Self {
        Self {
            background_receive: false,
            receive_channel_capacity: 256,
            observe_io: false,
        }
    }
}

pub struct UpSocksSession {
    packet: Arc<dyn PacketConn>,
    rx: Option<UdpReceiver>,
    recv_task: Option<JoinHandle<()>>,
    obs_enabled: bool,
    obs_index: Option<usize>,
    obs_pool: Option<String>,
}

impl std::fmt::Debug for UpSocksSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UpSocksSession")
            .field("background_receive", &self.rx.is_some())
            .field("obs_enabled", &self.obs_enabled)
            .field("obs_index", &self.obs_index)
            .field("obs_pool", &self.obs_pool)
            .finish()
    }
}

impl UpSocksSession {
    pub async fn create(
        endpoint: ProxyEndpoint,
        timeout_ms: u64,
        config: &UpSocksSessionConfig,
    ) -> Result<Self> {
        anyhow::ensure!(
            matches!(endpoint.kind, ProxyKind::Socks5),
            "not a socks5 endpoint"
        );

        let connector = Socks5Connector::no_auth(endpoint.addr.to_string());
        let mut session = Session::outbound(TargetAddr::Socket(endpoint.addr));
        session.connect.connect_timeout = Duration::from_millis(timeout_ms.max(1));
        let packet = connector
            .listen_packet(&session)
            .await
            .context("create adapter SOCKS5 UDP association")?;
        let packet: Arc<dyn PacketConn> = Arc::from(packet);

        #[cfg(feature = "metrics")]
        metrics::counter!("udp_upstream_assoc_total", "result" => "ok").increment(1);

        if config.background_receive {
            let capacity = config.receive_channel_capacity.clamp(1, 16_384);
            let (tx, rx) = mpsc::channel::<(SocketAddr, Vec<u8>)>(capacity);
            let packet_clone = packet.clone();
            let recv_task = tokio::spawn(async move {
                let mut buffer = vec![0u8; 64 * 1024];
                loop {
                    match packet_clone.recv_from(&mut buffer).await {
                        Ok((size, source)) if size > 0 => {
                            let source = target_to_socket_addr(source);
                            #[cfg(feature = "metrics")]
                            {
                                metrics::counter!("udp_upstream_pkts_in_total").increment(1);
                                metrics::counter!("udp_upstream_bytes_in_total")
                                    .increment(size as u64);
                            }
                            if tx.try_send((source, buffer[..size].to_vec())).is_err() {
                                #[cfg(feature = "metrics")]
                                metrics::counter!(
                                    "udp_upstream_error_total",
                                    "class" => "receive_queue_full"
                                )
                                .increment(1);
                            }
                        }
                        Ok(_) => continue,
                        Err(error) => {
                            #[cfg(feature = "metrics")]
                            metrics::counter!(
                                "udp_upstream_error_total",
                                "class" => "recv"
                            )
                            .increment(1);
                            tracing::debug!(%error, "adapter SOCKS5 UDP receive task stopped");
                            break;
                        }
                    }
                }
            });
            Ok(Self {
                packet,
                rx: Some(Arc::new(Mutex::new(rx))),
                recv_task: Some(recv_task),
                obs_enabled: config.observe_io,
                obs_index: None,
                obs_pool: None,
            })
        } else {
            Ok(Self {
                packet,
                rx: None,
                recv_task: None,
                obs_enabled: config.observe_io,
                obs_index: None,
                obs_pool: None,
            })
        }
    }

    pub async fn send_to(&self, destination: SocketAddr, payload: &[u8]) -> Result<usize> {
        let payload_size = self
            .packet
            .send_to(payload, &TargetAddr::Socket(destination))
            .await
            .context("send adapter SOCKS5 UDP datagram")?;
        let sent = payload_size
            + match destination {
                SocketAddr::V4(_) => 10,
                SocketAddr::V6(_) => 22,
            };

        if self.obs_enabled {
            if let (Some(pool), Some(index)) = (&self.obs_pool, self.obs_index) {
                tracing::trace!(%pool, index, %destination, bytes = sent, "SOCKS5 UDP observation");
            }
        }

        #[cfg(feature = "metrics")]
        {
            metrics::counter!("udp_upstream_pkts_out_total").increment(1);
            metrics::counter!("udp_upstream_bytes_out_total").increment(sent as u64);
        }
        Ok(sent)
    }

    pub async fn recv_once(&self, timeout_ms: u64) -> Result<Option<(SocketAddr, Vec<u8>)>> {
        let deadline = Duration::from_millis(timeout_ms.max(1));
        if let Some(rx) = &self.rx {
            return match timeout(deadline, rx.lock().await.recv()).await {
                Ok(packet) => Ok(packet),
                Err(_) => Ok(None),
            };
        }

        let mut buffer = vec![0u8; 64 * 1024];
        match timeout(deadline, self.packet.recv_from(&mut buffer)).await {
            Ok(Ok((size, source))) => {
                #[cfg(feature = "metrics")]
                {
                    metrics::counter!("udp_upstream_pkts_in_total").increment(1);
                    metrics::counter!("udp_upstream_bytes_in_total").increment(size as u64);
                }
                Ok(Some((
                    target_to_socket_addr(source),
                    buffer[..size].to_vec(),
                )))
            }
            Ok(Err(error)) => {
                #[cfg(feature = "metrics")]
                metrics::counter!("udp_upstream_error_total", "class" => "recv").increment(1);
                Err(anyhow!(error))
            }
            Err(_) => Ok(None),
        }
    }

    pub fn bind_observation(&mut self, pool: String, index: usize) {
        self.obs_pool = Some(pool);
        self.obs_index = Some(index);
    }
}

impl Drop for UpSocksSession {
    fn drop(&mut self) {
        if let Some(task) = self.recv_task.take() {
            task.abort();
        }
    }
}

fn target_to_socket_addr(target: TargetAddr) -> SocketAddr {
    match target {
        TargetAddr::Socket(address) => address,
        TargetAddr::Domain(_, port) => SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
    }
}

pub fn strip_udp_reply(packet: &[u8]) -> Result<(SocketAddr, &[u8])> {
    if packet.len() < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
        return Err(anyhow!("invalid SOCKS5 UDP reply header"));
    }
    let mut offset = 4;
    let address = match packet[3] {
        0x01 => {
            if offset + 6 > packet.len() {
                return Err(anyhow!("truncated SOCKS5 UDP IPv4 reply"));
            }
            let ip = Ipv4Addr::new(
                packet[offset],
                packet[offset + 1],
                packet[offset + 2],
                packet[offset + 3],
            );
            offset += 4;
            let port = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
            offset += 2;
            SocketAddr::new(IpAddr::V4(ip), port)
        }
        0x04 => {
            if offset + 18 > packet.len() {
                return Err(anyhow!("truncated SOCKS5 UDP IPv6 reply"));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&packet[offset..offset + 16]);
            offset += 16;
            let port = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
            offset += 2;
            SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port)
        }
        0x03 => {
            if offset >= packet.len() {
                return Err(anyhow!("truncated SOCKS5 UDP domain reply"));
            }
            let length = packet[offset] as usize;
            offset += 1;
            if offset + length + 2 > packet.len() {
                return Err(anyhow!("truncated SOCKS5 UDP domain reply"));
            }
            offset += length;
            let port = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
            offset += 2;
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
        }
        address_type => return Err(anyhow!("invalid SOCKS5 UDP address type {address_type}")),
    };
    Ok((address, &packet[offset..]))
}
