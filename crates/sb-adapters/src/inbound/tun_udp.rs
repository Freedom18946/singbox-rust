//! Lightweight UDP NAT for the Enhanced TUN datapath.
//!
//! Scope: forward UDP datagrams read off the TUN device to the routed outbound and
//! relay the replies back to the kernel as bare IP/UDP packets. Only outbounds whose
//! [`OutboundRegistryHandle::connect_udp`] succeeds (today: `direct`) are usable;
//! anything else surfaces a loud error and the datagram is dropped instead of being
//! silently black-holed.
//!
//! Boundary note: a general/shared UDP NAT + session-management layer is owned by
//! P1313-09. If that lands, the Enhanced datapath should migrate onto it and this
//! module can be removed. `OutboundRegistryHandle::connect_udp` is a public outbound
//! capability and is intended to be reused by that work.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::Mutex;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tracing::debug;

use sb_core::outbound::{Endpoint, OutboundRegistryHandle, RouteTarget, UdpTransport};
use sb_core::types::{Endpoint as TypesEndpoint, Host};

use crate::inbound::tun_session::{build_udp_response_packet, FourTuple, TunWriter};

/// Upper bound on concurrent UDP NAT entries to avoid unbounded growth.
const MAX_NAT_ENTRIES: usize = 4096;

struct UdpNatEntry {
    transport: Arc<dyn UdpTransport>,
    last_active: Mutex<Instant>,
    relay_task: JoinHandle<()>,
}

impl Drop for UdpNatEntry {
    fn drop(&mut self) {
        self.relay_task.abort();
    }
}

/// Per-inbound UDP NAT for the Enhanced TUN backend.
pub(crate) struct EnhancedUdpNat {
    sessions: DashMap<FourTuple, UdpNatEntry>,
    ttl: Duration,
    mtu: usize,
}

impl std::fmt::Debug for EnhancedUdpNat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnhancedUdpNat")
            .field("ttl", &self.ttl)
            .field("mtu", &self.mtu)
            .field("sessions", &self.sessions.len())
            .finish()
    }
}

impl EnhancedUdpNat {
    pub(crate) fn new(udp_timeout_ms: u64, mtu: usize) -> Self {
        let ttl = if udp_timeout_ms == 0 {
            Duration::from_secs(60)
        } else {
            Duration::from_millis(udp_timeout_ms)
        };
        Self {
            sessions: DashMap::new(),
            ttl,
            mtu: mtu.max(1280),
        }
    }

    /// How often the eviction sweep should run: at most every 30s, at least every 1s.
    pub(crate) fn eviction_period(&self) -> Duration {
        self.ttl
            .min(Duration::from_secs(30))
            .max(Duration::from_secs(1))
    }

    /// Forward one UDP datagram to the routed outbound, establishing the NAT entry
    /// and reverse relay on first sight of a flow.
    pub(crate) async fn forward(
        &self,
        tuple: FourTuple,
        payload: &[u8],
        target: &RouteTarget,
        outbounds: &OutboundRegistryHandle,
        writer: Arc<dyn TunWriter + Send + Sync>,
    ) -> io::Result<()> {
        let dst_endpoint = TypesEndpoint::new(Host::ip(tuple.dst_ip), tuple.dst_port);

        // Fast path: existing flow. Clone the transport out and drop the DashMap guard
        // *before* awaiting so the shard lock is never held across `.await`.
        let existing = self.sessions.get(&tuple).map(|entry| {
            *entry.last_active.lock() = Instant::now();
            Arc::clone(&entry.transport)
        });
        if let Some(transport) = existing {
            transport
                .send_to(payload, &dst_endpoint)
                .await
                .map_err(|e| io::Error::other(format!("udp send failed: {e}")))?;
            return Ok(());
        }

        if self.sessions.len() >= MAX_NAT_ENTRIES {
            debug!(tuple = %tuple, "tun enhanced udp: NAT table full, dropping datagram");
            return Ok(());
        }

        // Slow path: establish a new outbound UDP association.
        let routing_endpoint = Endpoint::Ip(SocketAddr::new(tuple.dst_ip, tuple.dst_port));
        let transport: Arc<dyn UdpTransport> =
            Arc::from(outbounds.connect_udp(target, routing_endpoint).await?);

        transport
            .send_to(payload, &dst_endpoint)
            .await
            .map_err(|e| io::Error::other(format!("udp send failed: {e}")))?;

        let relay_task = spawn_udp_reverse_relay(
            tuple,
            Arc::clone(&transport),
            writer,
            self.ttl,
            self.mtu,
        );

        self.sessions.insert(
            tuple,
            UdpNatEntry {
                transport,
                last_active: Mutex::new(Instant::now()),
                relay_task,
            },
        );
        Ok(())
    }

    /// Drop NAT entries that are past their idle TTL or whose relay task has ended.
    pub(crate) fn evict_expired(&self) {
        let now = Instant::now();
        let ttl = self.ttl;
        self.sessions.retain(|_, entry| {
            now.duration_since(*entry.last_active.lock()) < ttl && !entry.relay_task.is_finished()
        });
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.sessions.len()
    }
}

/// Spawn the reverse relay: read datagrams from the outbound transport and write
/// them back to the TUN as bare IP/UDP packets (no platform AF prefix — the
/// platform `write` adds that). Ends on idle timeout, transport error, or writer close.
fn spawn_udp_reverse_relay(
    tuple: FourTuple,
    transport: Arc<dyn UdpTransport>,
    writer: Arc<dyn TunWriter + Send + Sync>,
    ttl: Duration,
    mtu: usize,
) -> JoinHandle<()> {
    // Replies are addressed back to the client: src = original dst, dst = original src.
    let reply_tuple = tuple.reverse();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match timeout(ttl, transport.recv_from(&mut buf)).await {
                Ok(Ok((n, _src))) if n > 0 => {
                    let packet = match build_udp_response_packet(reply_tuple, &buf[..n]) {
                        Ok(p) => p,
                        Err(err) => {
                            debug!(error = %err, tuple = %tuple, "tun enhanced udp: build reply failed");
                            continue;
                        }
                    };
                    if packet.len() > mtu {
                        debug!(
                            len = packet.len(),
                            mtu, "tun enhanced udp: reply exceeds MTU, dropping"
                        );
                        continue;
                    }
                    if writer.write_packet(&packet).await.is_err() {
                        break;
                    }
                }
                // timeout (idle), transport error, or 0-length read ends the relay.
                _ => break,
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_uses_default_ttl_on_zero_timeout() {
        let nat = EnhancedUdpNat::new(0, 1500);
        assert_eq!(nat.ttl, Duration::from_secs(60));
        assert_eq!(nat.eviction_period(), Duration::from_secs(30));
    }

    #[test]
    fn eviction_period_is_clamped() {
        let fast = EnhancedUdpNat::new(500, 1500); // 500ms ttl
        assert_eq!(fast.eviction_period(), Duration::from_secs(1));
        let slow = EnhancedUdpNat::new(120_000, 1500); // 120s ttl
        assert_eq!(slow.eviction_period(), Duration::from_secs(30));
    }

    #[test]
    fn evict_expired_on_empty_is_noop() {
        let nat = EnhancedUdpNat::new(1000, 1500);
        nat.evict_expired();
        assert_eq!(nat.len(), 0);
    }

    #[test]
    fn mtu_floor_is_enforced() {
        let nat = EnhancedUdpNat::new(1000, 100);
        assert_eq!(nat.mtu, 1280);
    }
}
