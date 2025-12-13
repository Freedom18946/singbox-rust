use crate::dns::{
    global,
    message::{parse_question_key, QuestionKey},
    DnsAnswer,
};
use crate::service::{Service, StartStage};
use sb_config::ir::ServiceIR;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Notify;

/// Architectural Divergence:
/// The Go reference implementation of `resolved` service acts as a D-Bus server (org.freedesktop.resolve1.Manager).
/// The Rust implementation currently acts as a simple UDP DNS forwarder for local applications (e.g. 127.0.0.53:53).
/// This service is renamed to `DnsForwarderService` to reflect its actual behavior, though it corresponds to `resolved` config type.
pub struct DnsForwarderService {
    tag: String,
    listen_addr: SocketAddr,
    running: Arc<Notify>,
}

impl DnsForwarderService {
    pub fn new(ir: &ServiceIR) -> Self {
        let host = ir
            .listen
            .as_deref()
            .unwrap_or("127.0.0.53")
            .to_string();
        let port = ir.listen_port.unwrap_or(53);
        let addr_str = format!("{}:{}", host, port);
        let listen_addr = addr_str.parse().unwrap_or_else(|_| {
            tracing::warn!(
                "Invalid resolved listen address: {}, using 127.0.0.53:53",
                addr_str
            );
            "127.0.0.53:53".parse().unwrap()
        });

        Self {
            tag: ir.tag.clone().unwrap_or_else(|| "resolved".to_string()),
            listen_addr,
            running: Arc::new(Notify::new()),
        }
    }

    async fn run_server(addr: SocketAddr, running: Arc<Notify>) {
        let socket = match UdpSocket::bind(addr).await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                tracing::error!("Failed to bind resolved service at {}: {}", addr, e);
                return;
            }
        };

        tracing::info!("Resolved service listening on {}", addr);

        let mut buf = [0u8; 4096];

        loop {
            tokio::select! {
                _ = running.notified() => {
                    tracing::info!("Resolved service shutting down");
                    break;
                }
                res = socket.recv_from(&mut buf) => {
                    match res {
                        Ok((len, src)) => {
                            let data = buf[..len].to_vec();
                            let socket = socket.clone();
                            tokio::spawn(async move {
                                Self::handle_query(socket, data, src).await;
                            });
                        }
                        Err(e) => {
                            tracing::error!("Resolved service recv error: {}", e);
                        }
                    }
                }
            }
        }
    }

    async fn handle_query(socket: Arc<UdpSocket>, pkt: Vec<u8>, src: SocketAddr) {
        // 1. Parse header to get ID and QR
        if pkt.len() < 12 {
            return;
        }
        // let id = [pkt[0], pkt[1]];
        let qr = (pkt[2] & 0x80) != 0;
        if qr {
            return;
        } // Ignore responses

        // 2. Parse question
        let q_key = match parse_question_key(&pkt) {
            Some(k) => k,
            None => return, // Invalid or unsupported
        };

        tracing::debug!(
            "Resolved service received query for {} type {}",
            q_key.name,
            q_key.qtype
        );

        // 3. Resolve
        let resolver = global::get();
        let answer = if let Some(r) = resolver {
            r.resolve(&q_key.name).await
        } else {
            Err(anyhow::anyhow!("No resolver"))
        };

        // 4. Build response
        let resp = Self::build_response(&pkt, &q_key, answer);

        // 5. Send
        if let Err(e) = socket.send_to(&resp, src).await {
            tracing::debug!("Failed to send DNS response to {}: {}", src, e);
        }
    }

    fn build_response(req: &[u8], q: &QuestionKey, result: anyhow::Result<DnsAnswer>) -> Vec<u8> {
        // Copy ID
        let mut resp = Vec::with_capacity(512);
        resp.extend_from_slice(&req[0..2]);

        // Flags: QR=1, Opcode=0, AA=0, TC=0, RD=req.RD, RA=1, Z=0, RCODE
        let req_flags = u16::from_be_bytes([req[2], req[3]]);
        let rd = (req_flags & 0x0100) != 0;
        let mut flags = 0x8000u16; // QR=1
        if rd {
            flags |= 0x0100;
        } // Copy RD
        flags |= 0x0080; // RA=1 (Recursion Available)

        let (rcode, ips, ttl) = match result {
            Ok(ans) => (0, ans.ips, ans.ttl.as_secs() as u32),
            Err(_) => (2, vec![], 0), // 2=SERVFAIL
        };

        flags |= rcode;
        resp.extend_from_slice(&flags.to_be_bytes());

        // Counts
        resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1

        // Filter IPs by qtype
        let mut answers = Vec::new();
        if rcode == 0 {
            for ip in ips {
                match (q.qtype, ip) {
                    (1, IpAddr::V4(v4)) => answers.push(IpAddr::V4(v4)),
                    (28, IpAddr::V6(v6)) => answers.push(IpAddr::V6(v6)),
                    _ => {}
                }
            }
        }

        resp.extend_from_slice(&(answers.len() as u16).to_be_bytes()); // ANCOUNT
        resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

        // Question Section
        for label in q.name.split('.') {
            if label.is_empty() {
                continue;
            }
            resp.push(label.len() as u8);
            resp.extend_from_slice(label.as_bytes());
        }
        resp.push(0);
        resp.extend_from_slice(&q.qtype.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes()); // QCLASS=IN

        // Answer Section
        for ip in answers {
            // Name ptr to offset 12 (0xC00C)
            resp.extend_from_slice(&0xC00Cu16.to_be_bytes());
            match ip {
                IpAddr::V4(v4) => {
                    resp.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
                    resp.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
                    resp.extend_from_slice(&ttl.to_be_bytes());
                    resp.extend_from_slice(&4u16.to_be_bytes()); // RDLEN
                    resp.extend_from_slice(&v4.octets());
                }
                IpAddr::V6(v6) => {
                    resp.extend_from_slice(&28u16.to_be_bytes()); // TYPE AAAA
                    resp.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
                    resp.extend_from_slice(&ttl.to_be_bytes());
                    resp.extend_from_slice(&16u16.to_be_bytes()); // RDLEN
                    resp.extend_from_slice(&v6.octets());
                }
            }
        }

        resp
    }
}

impl Service for DnsForwarderService {
    fn service_type(&self) -> &str {
        "resolved"
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    fn start(&self, stage: StartStage) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if stage == StartStage::Start {
            let addr = self.listen_addr;
            let running = self.running.clone();
            tokio::spawn(async move {
                Self::run_server(addr, running).await;
            });
        }
        Ok(())
    }

    fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.running.notify_waiters();
        Ok(())
    }
}

pub fn build_dns_forwarder_service(
    ir: &ServiceIR,
    _ctx: &crate::service::ServiceContext,
) -> Option<Arc<dyn Service>> {
    Some(Arc::new(DnsForwarderService::new(ir)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Resolver;
    use async_trait::async_trait;
    use std::time::Duration;

    struct MockResolver;

    #[async_trait]
    impl Resolver for MockResolver {
        async fn resolve(&self, domain: &str) -> anyhow::Result<DnsAnswer> {
            if domain == "example.com" {
                Ok(DnsAnswer::new(
                    vec!["1.2.3.4".parse().unwrap()],
                    Duration::from_secs(60),
                    crate::dns::cache::Source::System,
                    crate::dns::cache::Rcode::NoError,
                ))
            } else {
                Err(anyhow::anyhow!("NXDOMAIN"))
            }
        }
        fn name(&self) -> &str {
            "mock"
        }
    }

    #[tokio::test]
    async fn test_dns_forwarder_service() {
        // Setup global resolver
        crate::dns::global::set(Arc::new(MockResolver));

        // Start service
        let port = 53535;
        let ir_json = serde_json::json!({
            "type": "resolved",
            "tag": "resolved-test",
            "listen": "127.0.0.1",
            "listen_port": port
        });
        let ir: ServiceIR = serde_json::from_value(ir_json).unwrap();
        let service = Arc::new(DnsForwarderService::new(&ir));
        let service_clone = service.clone();

        tokio::spawn(async move {
            service_clone.start(StartStage::Start).unwrap();
        });

        // Wait for start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Send query
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut query = Vec::new();
        // Build simple query for example.com
        // Header
        query.extend_from_slice(&[0x12, 0x34]); // ID
        query.extend_from_slice(&[0x01, 0x00]); // Flags (RD=1)
        query.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
        query.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
        query.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
        query.extend_from_slice(&[0x00, 0x00]); // ARCOUNT
                                                // QNAME example.com
        query.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        // QTYPE A (1)
        query.extend_from_slice(&[0x00, 0x01]);
        // QCLASS IN (1)
        query.extend_from_slice(&[0x00, 0x01]);

        socket
            .send_to(&query, format!("127.0.0.1:{}", port))
            .await
            .unwrap();

        let mut buf = [0u8; 1024];
        let (len, _) = socket.recv_from(&mut buf).await.unwrap();
        let resp = &buf[..len];

        // Verify response
        assert_eq!(resp[0], 0x12);
        assert_eq!(resp[1], 0x34);
        assert_eq!(resp[2] & 0x80, 0x80); // QR=1
        assert_eq!(resp[3] & 0x0F, 0); // RCODE=0

        // Check answer count
        let ancount = u16::from_be_bytes([resp[6], resp[7]]);
        assert_eq!(ancount, 1);

        service.close().unwrap();
    }
}
