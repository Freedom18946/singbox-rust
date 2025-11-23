use sb_config::ir::EndpointIR;
use sb_core::endpoint::{Endpoint, EndpointContext, StartStage};
use std::sync::Arc;
use tokio::sync::Mutex;

#[cfg(feature = "adapter-wireguard-endpoint")]
use {
    base64::{engine::general_purpose::STANDARD as BASE64, Engine as _},
    boringtun::noise::{Tunn, TunnResult},
    boringtun::x25519::{PublicKey, StaticSecret},
    std::net::SocketAddr,
    std::time::Duration,
    tokio::io::{AsyncReadExt, AsyncWriteExt},
    tokio::net::UdpSocket,
};

#[derive(Clone)]
pub struct WireGuardEndpoint {
    inner: Arc<Inner>,
}

struct Inner {
    tag: String,
    ir: EndpointIR,
    handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl WireGuardEndpoint {
    pub fn new(ir: EndpointIR) -> Self {
        Self {
            inner: Arc::new(Inner {
                tag: ir.tag.clone().unwrap_or_else(|| "wireguard".to_string()),
                ir,
                handle: Mutex::new(None),
            }),
        }
    }

    #[cfg(not(feature = "adapter-wireguard-endpoint"))]
    async fn run(&self) {
        tracing::warn!(
            "WireGuard endpoint started but adapter-wireguard-endpoint feature is disabled"
        );
        std::future::pending::<()>().await;
    }

    #[cfg(feature = "adapter-wireguard-endpoint")]
    async fn run(&self) {
        let tag = &self.inner.tag;
        tracing::info!("Starting WireGuard userspace endpoint: {}", tag);

        if let Err(e) = self.run_internal().await {
            tracing::error!("WireGuard endpoint {} error: {}", tag, e);
        }
    }

    #[cfg(feature = "adapter-wireguard-endpoint")]
    async fn run_internal(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let ir = &self.inner.ir;

        // 1. Parse Private Key
        let private_key_str = ir
            .wireguard_private_key
            .as_ref()
            .ok_or("Missing private key")?;
        let private_key_bytes = BASE64
            .decode(private_key_str)
            .map_err(|_| "Invalid private key base64")?;
        let private_key_arr: [u8; 32] = private_key_bytes
            .try_into()
            .map_err(|_| "Invalid private key length")?;
        let private_key = StaticSecret::from(private_key_arr);

        // 2. Initialize TUN device
        let mut config = tun::Configuration::default();

        if let Some(name) = &ir.wireguard_name {
            config.name(name);
        }

        if let Some(addrs) = &ir.wireguard_address {
            for addr in addrs {
                if let Ok(cidr) = addr.parse::<ipnet::IpNet>() {
                    config.address(cidr.addr());
                    config.netmask(cidr.netmask());
                    break;
                }
            }
        }

        if let Some(mtu) = ir.wireguard_mtu {
            config.mtu(mtu.try_into().unwrap_or(1420));
        }

        config.up();

        #[cfg(target_os = "linux")]
        config.platform(|config| {
            config.packet_information(true);
        });

        let mut tun_device = tun::create_as_async(&config)?;
        let tun_name = "tun"; // We don't strictly need the name for Tunn
        tracing::info!("Created TUN device");

        // 3. Initialize UDP socket
        let listen_port = ir.wireguard_listen_port.unwrap_or(0);
        let udp_socket = UdpSocket::bind(format!("0.0.0.0:{}", listen_port)).await?;
        tracing::info!("WireGuard listening on {}", udp_socket.local_addr()?);

        // 4. Parse Peer (Single Peer MVP)
        let peers = ir.wireguard_peers.as_ref().ok_or("No peers configured")?;
        if peers.is_empty() {
            return Err("No peers configured".into());
        }
        if peers.len() > 1 {
            tracing::warn!("Multiple peers configured, but userspace WireGuard MVP only supports the first peer.");
        }
        let peer = &peers[0];

        let peer_pk_str = peer.public_key.as_ref().ok_or("Missing peer public key")?;
        let peer_pk_bytes = BASE64
            .decode(peer_pk_str)
            .map_err(|_| "Invalid peer public key base64")?;
        let peer_pk_arr: [u8; 32] = peer_pk_bytes
            .try_into()
            .map_err(|_| "Invalid peer public key length")?;
        let peer_pk = PublicKey::from(peer_pk_arr);

        let peer_endpoint: SocketAddr = if let (Some(addr), Some(port)) = (&peer.address, peer.port)
        {
            format!("{}:{}", addr, port).parse()?
        } else {
            return Err("Peer missing address/port".into());
        };

        let psk = if let Some(psk_str) = &peer.pre_shared_key {
            if let Ok(bytes) = BASE64.decode(psk_str) {
                bytes.try_into().ok()
            } else {
                None
            }
        } else {
            None
        };

        // 5. Initialize boringtun Tunn
        // Tunn::new(static_private, peer_static_public, preshared_key, persistent_keepalive, index, rate_limiter)
        let mut tunn = Tunn::new(
            private_key,
            peer_pk,
            psk,
            peer.persistent_keepalive_interval,
            0,
            None,
        );

        // 6. Event Loop
        let mut buf_tun = [0u8; 65535];
        let mut buf_udp = [0u8; 65535];
        let mut buf_out = [0u8; 65535];

        loop {
            tokio::select! {
                // Read from TUN -> Encapsulate -> Send to Peer
                res = tun_device.read(&mut buf_tun) => {
                    let n = res?;
                    let packet = &buf_tun[..n];
                    match tunn.encapsulate(packet, &mut buf_out) {
                        TunnResult::WriteToNetwork(packet) => {
                            udp_socket.send_to(packet, peer_endpoint).await?;
                        }
                        _ => {}
                    }
                }
                // Read from UDP -> Decapsulate -> Write to TUN
                res = udp_socket.recv_from(&mut buf_udp) => {
                    let (n, src) = res?;
                    // In MVP, we only accept from our peer?
                    // Or we accept from anyone and let Tunn decrypt?
                    // Tunn::decapsulate takes src_addr? No, it takes src_addr to update endpoint?
                    // Wait, Tunn::decapsulate signature:
                    // pub fn decapsulate<'a>(&mut self, src_addr: Option<IpAddr>, packet: &[u8], dst_buf: &'a mut [u8]) -> TunnResult<'a>
                    // It takes Option<IpAddr>.

                    if src != peer_endpoint {
                        // Optional: strict checking
                        // But for roaming, we might want to allow it?
                        // Tunn will handle decryption.
                    }

                    let packet = &buf_udp[..n];
                    match tunn.decapsulate(Some(src.ip()), packet, &mut buf_out) {
                        TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                            tun_device.write_all(packet).await?;
                        }
                        TunnResult::WriteToNetwork(packet) => {
                             udp_socket.send_to(packet, src).await?;
                        }
                        _ => {}
                    }
                }
                // Timer
                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                     match tunn.update_timers(&mut buf_out) {
                        TunnResult::WriteToNetwork(packet) => {
                            udp_socket.send_to(packet, peer_endpoint).await?;
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

impl Endpoint for WireGuardEndpoint {
    fn endpoint_type(&self) -> &str {
        "wireguard"
    }

    fn tag(&self) -> &str {
        &self.inner.tag
    }

    fn start(&self, stage: StartStage) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if stage == StartStage::Start {
            let this = self.clone();
            let handle = tokio::spawn(async move {
                this.run().await;
            });

            if let Ok(mut guard) = self.inner.handle.try_lock() {
                *guard = Some(handle);
            } else {
                tracing::warn!(
                    "Failed to acquire lock to store task handle for {}",
                    self.inner.tag
                );
            }
        }
        Ok(())
    }

    fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Ok(mut guard) = self.inner.handle.try_lock() {
            if let Some(handle) = guard.take() {
                handle.abort();
            }
        }
        Ok(())
    }
}

pub fn build_wireguard_endpoint(
    ir: &EndpointIR,
    _ctx: &EndpointContext,
) -> Option<Arc<dyn Endpoint>> {
    Some(Arc::new(WireGuardEndpoint::new(ir.clone())))
}
