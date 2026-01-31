#![cfg(feature = "router")]

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tracing::{debug, trace, warn};

use crate::adapter::{UdpOutboundFactory, UdpOutboundSession};
use crate::endpoint::{CloseHandler, ConnectionHandler, EndpointStream, InboundContext};
use crate::net::metered::TrafficRecorder;
use crate::outbound::{Endpoint as OutEndpoint, OutboundKind, OutboundRegistryHandle, RouteTarget};
use crate::router::{RouteCtx, RouterHandle, Transport};
use crate::services::v2ray_api::StatsManager;

const UDP_BUF_SIZE: usize = 64 * 1024;

#[derive(Clone)]
pub struct EndpointConnectionHandler {
    router: Arc<RouterHandle>,
    outbounds: Arc<OutboundRegistryHandle>,
    udp_factories: Arc<HashMap<String, Arc<dyn UdpOutboundFactory>>>,
    stats: Option<Arc<StatsManager>>,
}

impl EndpointConnectionHandler {
    pub fn new(
        router: Arc<RouterHandle>,
        outbounds: Arc<OutboundRegistryHandle>,
        udp_factories: Arc<HashMap<String, Arc<dyn UdpOutboundFactory>>>,
        stats: Option<Arc<StatsManager>>,
    ) -> Self {
        Self {
            router,
            outbounds,
            udp_factories,
            stats,
        }
    }

    fn build_route_ctx<'a>(
        &'a self,
        metadata: &'a InboundContext,
        dest_host: &'a str,
        dest_ip: Option<IpAddr>,
        dest_port: u16,
        transport: Transport,
    ) -> RouteCtx<'a> {
        let network = match transport {
            Transport::Tcp => "tcp",
            Transport::Udp => "udp",
        };
        let (source_ip, source_port) = metadata
            .source
            .as_ref()
            .and_then(|s| s.to_socket_addr())
            .map(|sa| (Some(sa.ip()), Some(sa.port())))
            .unwrap_or((None, None));

        RouteCtx {
            host: Some(dest_host),
            ip: dest_ip,
            port: Some(dest_port),
            transport,
            network,
            source_ip,
            source_port,
            inbound_tag: Some(metadata.inbound.as_str()),
            ..Default::default()
        }
    }

    fn decision_to_target(
        &self,
        decision: crate::router::rules::Decision,
    ) -> (RouteTarget, String, bool) {
        use crate::router::rules::Decision;
        match decision {
            Decision::Direct => (
                RouteTarget::Kind(OutboundKind::Direct),
                "direct".to_string(),
                true,
            ),
            Decision::Reject | Decision::RejectDrop => (
                RouteTarget::Kind(OutboundKind::Block),
                "block".to_string(),
                false,
            ),
            Decision::Proxy(Some(tag)) => (RouteTarget::Named(tag.clone()), tag, true),
            Decision::Proxy(None) => (
                RouteTarget::Kind(OutboundKind::Direct),
                "direct".to_string(),
                true,
            ),
            Decision::Hijack { .. } | Decision::Sniff | Decision::Resolve => (
                RouteTarget::Kind(OutboundKind::Direct),
                "direct".to_string(),
                true,
            ),
        }
    }

    fn traffic_recorder(
        &self,
        inbound_tag: Option<&str>,
        outbound_tag: Option<&str>,
    ) -> Option<Arc<dyn TrafficRecorder>> {
        self.stats
            .as_ref()
            .and_then(|stats| stats.traffic_recorder(inbound_tag, outbound_tag, None))
    }

    fn extract_destination(
        metadata: &InboundContext,
    ) -> Option<(OutEndpoint, String, Option<IpAddr>, u16)> {
        let dest = metadata
            .destination
            .as_ref()
            .or(metadata.origin_destination.as_ref())?;

        match &dest.host {
            crate::endpoint::SocksaddrHost::Ip(ip) => {
                let ep = OutEndpoint::Ip(SocketAddr::new(*ip, dest.port));
                let host = ip.to_string();
                Some((ep, host, Some(*ip), dest.port))
            }
            crate::endpoint::SocksaddrHost::Fqdn(host) => {
                let ep = OutEndpoint::Domain(host.clone(), dest.port);
                Some((ep, host.clone(), None, dest.port))
            }
        }
    }

    fn extract_source_addr(metadata: &InboundContext) -> Option<SocketAddr> {
        metadata.source.as_ref().and_then(|s| s.to_socket_addr())
    }
}

#[async_trait::async_trait]
impl ConnectionHandler for EndpointConnectionHandler {
    async fn route_connection(
        &self,
        mut conn: EndpointStream,
        metadata: InboundContext,
        on_close: Option<CloseHandler>,
    ) {
        let (endpoint, host, ip, port) = match Self::extract_destination(&metadata) {
            Some(v) => v,
            None => {
                warn!(
                    inbound = %metadata.inbound,
                    "endpoint connection missing destination; dropping"
                );
                if let Some(close) = on_close {
                    close();
                }
                return;
            }
        };

        let transport = Transport::Tcp;
        let route_ctx = self.build_route_ctx(&metadata, &host, ip, port, transport);
        let decision = self.router.decide(&route_ctx);
        let (target, outbound_tag, allowed) = self.decision_to_target(decision);
        if !allowed {
            if let Some(close) = on_close {
                close();
            }
            return;
        }

        let traffic = self.traffic_recorder(Some(metadata.inbound.as_str()), Some(&outbound_tag));

        let mut outbound = match self.outbounds.connect_preferred(&target, endpoint).await {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    inbound = %metadata.inbound,
                    outbound = %outbound_tag,
                    error = %e,
                    "endpoint tcp connect failed"
                );
                if let Some(close) = on_close {
                    close();
                }
                return;
            }
        };

        let result = crate::net::metered::copy_bidirectional_streaming_ctl(
            &mut conn,
            &mut outbound,
            "endpoint",
            Duration::from_secs(1),
            None,
            None,
            None,
            traffic,
        )
        .await;

        if let Err(err) = result {
            warn!(error = %err, "endpoint tcp copy failed");
        }
        if let Some(close) = on_close {
            close();
        }
    }

    async fn route_packet_connection(
        &self,
        socket: Arc<UdpSocket>,
        metadata: InboundContext,
        on_close: Option<CloseHandler>,
    ) {
        let (_endpoint, host, ip, port) = match Self::extract_destination(&metadata) {
            Some(v) => v,
            None => {
                warn!(
                    inbound = %metadata.inbound,
                    "endpoint packet connection missing destination; dropping"
                );
                if let Some(close) = on_close {
                    close();
                }
                return;
            }
        };

        let transport = Transport::Udp;
        let route_ctx = self.build_route_ctx(&metadata, &host, ip, port, transport);
        let decision = self.router.decide(&route_ctx);
        let (_target, outbound_tag, allowed) = self.decision_to_target(decision);
        if !allowed {
            if let Some(close) = on_close {
                close();
            }
            return;
        }

        let traffic = self.traffic_recorder(Some(metadata.inbound.as_str()), Some(&outbound_tag));
        let client_addr = Self::extract_source_addr(&metadata);

        if let Some(factory) = self.udp_factories.get(&outbound_tag) {
            let session = match factory.open_session().await {
                Ok(s) => s,
                Err(e) => {
                    warn!(
                        inbound = %metadata.inbound,
                        outbound = %outbound_tag,
                        error = %e,
                        "endpoint udp session open failed"
                    );
                    if let Some(close) = on_close {
                        close();
                    }
                    return;
                }
            };

            self.run_udp_session(socket, session, host, port, client_addr, traffic, on_close)
                .await;
            return;
        }

        debug!(
            inbound = %metadata.inbound,
            outbound = %outbound_tag,
            "endpoint udp uses direct socket (no factory)"
        );

        if let Err(e) = self
            .run_udp_direct(socket, host, port, client_addr, traffic, on_close)
            .await
        {
            warn!(error = %e, "endpoint udp direct failed");
        }
    }
}

impl EndpointConnectionHandler {
    async fn run_udp_session(
        &self,
        socket: Arc<UdpSocket>,
        session: Arc<dyn UdpOutboundSession>,
        host: String,
        port: u16,
        client_addr: Option<SocketAddr>,
        traffic: Option<Arc<dyn TrafficRecorder>>,
        on_close: Option<CloseHandler>,
    ) {
        let last_client = Arc::new(tokio::sync::Mutex::new(client_addr));
        let socket_up = socket.clone();
        let session_up = session.clone();
        let host_up = host.clone();
        let traffic_up = traffic.clone();
        let last_client_up = last_client.clone();

        let upload = tokio::spawn(async move {
            let mut buf = [0u8; UDP_BUF_SIZE];
            loop {
                match socket_up.recv_from(&mut buf).await {
                    Ok((n, addr)) if n > 0 => {
                        *last_client_up.lock().await = Some(addr);
                        if let Err(e) = session_up.send_to(&buf[..n], &host_up, port).await {
                            trace!(error = %e, "endpoint udp send_to failed");
                            break;
                        }
                        if let Some(ref recorder) = traffic_up {
                            recorder.record_up(n as u64);
                            recorder.record_up_packet(1);
                        }
                    }
                    Ok(_) => break,
                    Err(e) => {
                        trace!(error = %e, "endpoint udp recv_from failed");
                        break;
                    }
                }
            }
        });

        let socket_down = socket.clone();
        let session_down = session.clone();
        let traffic_down = traffic.clone();
        let last_client_down = last_client.clone();

        let download = tokio::spawn(async move {
            loop {
                match session_down.recv_from().await {
                    Ok((data, _addr)) if !data.is_empty() => {
                        let client = { *last_client_down.lock().await };
                        if let Some(client) = client {
                            if socket_down.send_to(&data, client).await.is_err() {
                                break;
                            }
                            if let Some(ref recorder) = traffic_down {
                                recorder.record_down(data.len() as u64);
                                recorder.record_down_packet(1);
                            }
                        }
                    }
                    Ok(_) => break,
                    Err(e) => {
                        trace!(error = %e, "endpoint udp session recv failed");
                        break;
                    }
                }
            }
        });

        let _ = tokio::join!(upload, download);
        if let Some(close) = on_close {
            close();
        }
    }

    async fn run_udp_direct(
        &self,
        socket: Arc<UdpSocket>,
        host: String,
        port: u16,
        client_addr: Option<SocketAddr>,
        traffic: Option<Arc<dyn TrafficRecorder>>,
        on_close: Option<CloseHandler>,
    ) -> std::io::Result<()> {
        let remote = UdpSocket::bind("0.0.0.0:0").await?;
        let remote = Arc::new(remote);
        let last_client = Arc::new(tokio::sync::Mutex::new(client_addr));

        let remote_up = remote.clone();
        let socket_up = socket.clone();
        let host_up = host.clone();
        let traffic_up = traffic.clone();
        let last_client_up = last_client.clone();

        let upload = tokio::spawn(async move {
            let mut buf = [0u8; UDP_BUF_SIZE];
            loop {
                match socket_up.recv_from(&mut buf).await {
                    Ok((n, addr)) if n > 0 => {
                        *last_client_up.lock().await = Some(addr);
                        let addr = format!("{}:{}", host_up, port);
                        if let Err(e) = remote_up.send_to(&buf[..n], &addr).await {
                            trace!(error = %e, "endpoint udp direct send failed");
                            break;
                        }
                        if let Some(ref recorder) = traffic_up {
                            recorder.record_up(n as u64);
                            recorder.record_up_packet(1);
                        }
                    }
                    Ok(_) => break,
                    Err(e) => {
                        trace!(error = %e, "endpoint udp direct recv failed");
                        break;
                    }
                }
            }
        });

        let remote_down = remote.clone();
        let socket_down = socket.clone();
        let traffic_down = traffic.clone();
        let last_client_down = last_client.clone();

        let download = tokio::spawn(async move {
            let mut buf = [0u8; UDP_BUF_SIZE];
            loop {
                match remote_down.recv_from(&mut buf).await {
                    Ok((n, _addr)) if n > 0 => {
                        let client = { *last_client_down.lock().await };
                        if let Some(client) = client {
                            if socket_down.send_to(&buf[..n], client).await.is_err() {
                                break;
                            }
                            if let Some(ref recorder) = traffic_down {
                                recorder.record_down(n as u64);
                                recorder.record_down_packet(1);
                            }
                        }
                    }
                    Ok(_) => break,
                    Err(e) => {
                        trace!(error = %e, "endpoint udp direct recv failed");
                        break;
                    }
                }
            }
        });

        let _ = tokio::join!(upload, download);
        if let Some(close) = on_close {
            close();
        }
        Ok(())
    }
}
