
use anyhow::{anyhow, bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
// tracing: 保留按需引入
use async_trait::async_trait;

use crate::transport::{Dialer, SystemDialer, TlsStream};
// TlsClient/TlsClientParams 此文件未直接使用，移除未用导入
use super::{Outbound, OutboundContext, TargetAddr, TcpConnectRequest, UdpBindRequest};
use crate::telemetry::{dial as dialm, error_class};
use base64::Engine;

#[derive(Clone, Debug)]
pub struct HttpProxyOptions {
    pub server: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Clone)]
pub struct HttpProxyOutbound<D = SystemDialer> {
    pub ctx: OutboundContext<D>,
    pub opts: HttpProxyOptions,
    pub auth: Option<(String, String)>,
}

impl<D> HttpProxyOutbound<D>
where
    D: Dialer + Clone + Send + Sync + 'static,
{
    pub fn with_ctx(ctx: OutboundContext<D>, opts: HttpProxyOptions) -> Self {
        Self {
            ctx,
            opts,
            auth: None,
        }
    }
}

#[async_trait]
impl<D> Outbound for HttpProxyOutbound<D>
where
    D: Dialer + Clone + Send + Sync + 'static,
{
    fn name(&self) -> &'static str {
        "http-proxy"
    }
    async fn tcp_connect(&self, req: TcpConnectRequest) -> Result<TcpStream> {
        let target_addr = match &req.target {
            TargetAddr::Ip(sa) => sa.to_string(),
            TargetAddr::Domain(host, port) => format!("{host}:{port}"),
        };

        // Parse proxy server address
        let (proxy_host, proxy_port) = self
            .opts
            .server
            .rsplit_once(':')
            .ok_or_else(|| anyhow!("invalid proxy server format"))?;
        let proxy_port: u16 = proxy_port.parse()
            .map_err(|_| anyhow!("invalid proxy port"))?;

        // Phase 1: TCP connect to proxy server
        let t0 = dialm::start();
        let mut stream = match self.ctx.dialer.tcp_connect_host(proxy_host, proxy_port, &req.opts).await {
            Ok(s) => {
                dialm::record_ok("http", dialm::Phase::TcpConnect, t0);
                s
            }
            Err(e) => {
                let class = error_class::classify_proto(&e);
                dialm::record_err("http", dialm::Phase::TcpConnect, t0, class);
                return Err(e);
            }
        };

        // Phase 2: HTTP CONNECT handshake
        let t1 = dialm::start();

        // Send CONNECT request
        let connect_req = if let Some((u, p)) = &self.auth {
            let token = base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"));
            format!("CONNECT {target_addr} HTTP/1.1\r\nHost: {target_addr}\r\nProxy-Authorization: Basic {token}\r\n\r\n")
        } else {
            format!("CONNECT {target_addr} HTTP/1.1\r\nHost: {target_addr}\r\n\r\n")
        };

        if let Err(e) = stream.write_all(connect_req.as_bytes()).await {
            let class = error_class::classify_io(&e);
            dialm::record_err("http", dialm::Phase::ProxyHandshake, t1, class);
            return Err(e.into());
        }

        // Read response
        let mut buf = [0u8; 512];
        match stream.read(&mut buf).await {
            Ok(n) => {
                match std::str::from_utf8(&buf[..n]) {
                    Ok(response) => {
                        if response.starts_with("HTTP/1.1 200") || response.starts_with("HTTP/1.0 200") {
                            dialm::record_ok("http", dialm::Phase::ProxyHandshake, t1);
                            Ok(stream)
                        } else {
                            dialm::record_err("http", dialm::Phase::ProxyHandshake, t1, "bad_status");
                            bail!("HTTP proxy connect failed: {}", response.lines().next().unwrap_or(""))
                        }
                    }
                    Err(e) => {
                        dialm::record_err("http", dialm::Phase::ProxyHandshake, t1, "invalid_response");
                        Err(e.into())
                    }
                }
            }
            Err(e) => {
                let class = error_class::classify_io(&e);
                dialm::record_err("http", dialm::Phase::ProxyHandshake, t1, class);
                Err(e.into())
            }
        }
    }

    async fn tcp_connect_tls(&self, req: TcpConnectRequest) -> Result<TlsStream<TcpStream>> {
        // 克隆参数以避免借用冲突
        let server_name = match &req.tls {
            Some(p) => p.server_name.clone(),
            None => return Err(anyhow!("tls params required")),
        };
        let client = match &req.tls {
            Some(p) => p.client.clone(),
            None => return Err(anyhow!("tls params required")),
        };
        // 连接下游代理再升级 TLS：attempt/latency 记在 tcp_connect 内
        let tcp = self
            .tcp_connect(TcpConnectRequest {
                target: req.target.clone(),
                tls: req.tls.clone(),
                opts: req.opts.clone(),
            })
            .await?;
        let tls = client.connect(&server_name, tcp).await?;
        Ok(tls)
    }

    async fn udp_bind(&self, _req: UdpBindRequest) -> Result<tokio::net::UdpSocket> {
        bail!("http proxy outbound does not support udp");
    }
}