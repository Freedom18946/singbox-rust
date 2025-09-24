use crate::inbound::socks5::{encode_udp_request, greet_noauth, udp_associate};
use crate::outbound::endpoint::{ProxyEndpoint, ProxyKind};
use crate::socks5::decode_udp_reply;
use anyhow::{anyhow, Context, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tokio::time::{timeout, Duration};

/// SOCKS5 UDP associate session that keeps the control TCP stream alive and relays datagrams.
pub struct UpSocksSession {
    _ctrl: TcpStream,
    relay: SocketAddr,
    udp: Arc<UdpSocket>,
    // Optional receive queue populated by background task (disabled by default).
    rx: Option<Arc<Mutex<mpsc::Receiver<(SocketAddr, Vec<u8>)>>>>,
    recv_task: Option<JoinHandle<()>>,
    // Optional lightweight IO observation (behind env: SB_OBS_UDP_IO)
    obs_enabled: bool,
    obs_index: Option<usize>,
    obs_pool: Option<String>,
}

impl UpSocksSession {
    /// Establish a SOCKS5 UDP associate session against the given proxy endpoint.
    pub async fn create(ep: ProxyEndpoint, timeout_ms: u64) -> Result<Self> {
        anyhow::ensure!(
            matches!(ep.kind, ProxyKind::Socks5),
            "not a socks5 endpoint"
        );
        let connect_deadline = Duration::from_millis(timeout_ms.max(1));
        let mut ctrl = timeout(connect_deadline, TcpStream::connect(ep.addr))
            .await
            .map_err(|_| anyhow!("socks5 udp: tcp connect timeout"))??;
        greet_noauth(&mut ctrl).await?;
        let bind_hint: SocketAddr = match ep.addr {
            SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        };
        let relay = udp_associate(&mut ctrl, Some(bind_hint)).await?;
        let bind_addr = match relay {
            SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        };
        let udp = UdpSocket::bind(bind_addr).await?;
        udp.connect(relay).await?;
        #[cfg(feature = "metrics")]
        {
            metrics::counter!("udp_upstream_assoc_total", "result" => "ok").increment(1);
        }
        // behind env: SB_SOCKS_UDP_UP_RECV_TASK=1 enables background receives.
        let enable_recv_task = std::env::var("SB_SOCKS_UDP_UP_RECV_TASK")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let udp = Arc::new(udp);
        if enable_recv_task {
            let cap = std::env::var("SB_SOCKS_UDP_UP_RECV_CH")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(256)
                .clamp(1, 16_384);
            let (tx, rx) = mpsc::channel::<(SocketAddr, Vec<u8>)>(cap);
            let udp_clone = udp.clone();
            let recv_task = tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    match udp_clone.recv(&mut buf).await {
                        Ok(n) if n > 0 => match decode_udp_reply(&buf[..n]) {
                            Ok((addr, payload)) => {
                                #[cfg(feature = "metrics")]
                                {
                                    metrics::counter!("udp_upstream_pkts_in_total").increment(1);
                                    metrics::counter!("udp_upstream_bytes_in_total")
                                        .increment(payload.len() as u64);
                                }
                                let _ = tx.try_send((addr, payload.to_vec()));
                            }
                            Err(_e) => {
                                #[cfg(feature = "metrics")]
                                {
                                    metrics::counter!("udp_upstream_error_total", "class" => "decode")
                                        .increment(1);
                                }
                            }
                        },
                        Ok(_) => continue,
                        Err(_) => break,
                    }
                }
            });
            Ok(Self {
                _ctrl: ctrl,
                relay,
                udp,
                rx: Some(Arc::new(Mutex::new(rx))),
                recv_task: Some(recv_task),
                obs_enabled: std::env::var("SB_OBS_UDP_IO")
                    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false),
                obs_index: None,
                obs_pool: None,
            })
        } else {
            Ok(Self {
                _ctrl: ctrl,
                relay,
                udp,
                rx: None,
                recv_task: None,
                obs_enabled: std::env::var("SB_OBS_UDP_IO")
                    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false),
                obs_index: None,
                obs_pool: None,
            })
        }
    }

    /// Return the relay address learnt during UDP associate.
    pub fn relay_addr(&self) -> SocketAddr {
        self.relay
    }

    /// Send one UDP datagram to the relay targeting `dst`.
    pub async fn send_to(&self, dst: SocketAddr, payload: &[u8]) -> Result<usize> {
        let pkt = encode_udp_request(&dst, payload);
        let n = self.udp.send(&pkt).await?;
        #[cfg(feature = "metrics")]
        {
            metrics::counter!("udp_upstream_pkts_out_total").increment(1);
            metrics::counter!("udp_upstream_bytes_out_total").increment(n as u64);
        }
        Ok(n)
    }

    /// Convenience wrapper for IP + port inputs.
    pub async fn send_to_ip(&self, ip: IpAddr, port: u16, payload: &[u8]) -> Result<usize> {
        let dst = SocketAddr::new(ip, port);
        self.send_to(dst, payload).await
    }

    /// Try receiving one datagram from the relay within `timeout_ms`.
    pub async fn recv_once(&self, timeout_ms: u64) -> Result<Option<(SocketAddr, Vec<u8>)>> {
        if let Some(rx) = &self.rx {
            match timeout(
                Duration::from_millis(timeout_ms.max(1)),
                rx.lock().await.recv(),
            )
            .await
            {
                Ok(Some((addr, payload))) => return Ok(Some((addr, payload))),
                Ok(None) => return Ok(None),
                Err(_) => return Ok(None),
            }
        }
        let mut buf = vec![0u8; 2048];
        let fut = self.udp.recv(&mut buf);
        match timeout(Duration::from_millis(timeout_ms.max(1)), fut).await {
            Ok(Ok(n)) => {
                let (addr, payload) = decode_udp_reply(&buf[..n])?;
                #[cfg(feature = "metrics")]
                {
                    metrics::counter!("udp_upstream_pkts_in_total").increment(1);
                    metrics::counter!("udp_upstream_bytes_in_total")
                        .increment(payload.len() as u64);
                }
                // Optional: success IO observation hook (disabled by default).
                // The real selection feedback is already handled at session creation time
                // via with_observation(). This hook exists only to allow faster EMA convergence
                // when enabled, but intentionally does nothing here to keep behavior unchanged.
                Ok(Some((addr, payload.to_vec())))
            }
            Ok(Err(e)) => {
                #[cfg(feature = "metrics")]
                {
                    metrics::counter!("udp_upstream_error_total", "class" => "recv").increment(1);
                }
                Err(e.into())
            }
            Err(_) => Ok(None),
        }
    }

    /// Access the underlying UDP socket for advanced scenarios.
    pub fn udp_socket(&self) -> Arc<UdpSocket> {
        Arc::clone(&self.udp)
    }

    /// Optionally bind observation context for lightweight IO observation.
    /// This is a no-op by default and only records metadata for potential hooks.
    pub fn bind_observation(&mut self, pool: String, index: usize) {
        self.obs_pool = Some(pool);
        self.obs_index = Some(index);
    }
}

impl Drop for UpSocksSession {
    fn drop(&mut self) {
        // Best-effort shutdown of the background receive task when the session ends.
        if let Some(handle) = self.recv_task.take() {
            handle.abort();
        }
    }
}

/// Parse a SOCKS5 UDP reply packet and return the stripped payload.
pub fn strip_udp_reply<'a>(pkt: &'a [u8]) -> Result<(SocketAddr, &'a [u8])> {
    decode_udp_reply(pkt).context("decode socks5 udp reply")
}
