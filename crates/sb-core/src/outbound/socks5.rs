use anyhow::{anyhow, bail, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
// 移除未使用导入
use async_trait::async_trait;

use crate::transport::{Dialer, SystemDialer, TlsStream};

use super::{Outbound, OutboundContext, TargetAddr, TcpConnectRequest, UdpBindRequest};
use crate::telemetry::{dial as dialm, error_class};

use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct Socks5Opts {
    pub server: String, // host:port
    pub username: Option<String>,
    pub password: Option<String>,
    pub connect_timeout_sec: Option<u64>,
}

#[derive(Clone)]
pub struct Socks5Outbound<D = SystemDialer> {
    ctx: OutboundContext<D>,
    opts: Arc<Socks5Opts>,
}

impl<D> Socks5Outbound<D> {
    pub fn new(ctx: OutboundContext<D>, opts: Socks5Opts) -> Self {
        Self { ctx, opts: Arc::new(opts) }
    }
}

#[async_trait]
impl<D> Outbound for Socks5Outbound<D>
where
    D: Dialer + Clone + Send + Sync + 'static,
{
    async fn tcp_connect(&self, req: TcpConnectRequest) -> Result<TcpStream> {
        // Parse upstream proxy server
        let upstream = {
            let mut parts = self.opts.server.split(':');
            let h = parts.next().unwrap_or("127.0.0.1");
            let p = parts.next().unwrap_or("1080").parse::<u16>().unwrap_or(1080);
            (h.to_string(), p)
        };
        let mut opts = req.opts.clone();
        if let Some(sec) = self.opts.connect_timeout_sec {
            opts.timeout = Some(std::time::Duration::from_secs(sec));
        }

        // Phase 1: TCP connect to SOCKS5 proxy
        let t0 = dialm::start();
        let mut s = match self.ctx.dialer.tcp_connect_host(&upstream.0, upstream.1, &opts).await {
            Ok(s) => {
                dialm::record_ok("socks5", dialm::Phase::TcpConnect, t0);
                s
            }
            Err(e) => {
                let class = error_class::classify_proto(&e);
                dialm::record_err("socks5", dialm::Phase::TcpConnect, t0, class);
                return Err(e);
            }
        };

        // Phase 2: SOCKS5 handshake
        let t1 = dialm::start();

        // Method negotiation
        let method_req = if self.opts.username.is_some() {
            &[0x05, 0x01, 0x02] // VER=5, NMETHODS=1, METHODS=USERPASS
        } else {
            &[0x05, 0x01, 0x00] // NOAUTH
        };

        if let Err(e) = s.write_all(method_req).await {
            dialm::record_err("socks5", dialm::Phase::ProxyHandshake, t1, error_class::classify_io(&e));
            return Err(e.into());
        }

        let mut rsp = [0u8; 2];
        if let Err(e) = s.read_exact(&mut rsp).await {
            dialm::record_err("socks5", dialm::Phase::ProxyHandshake, t1, error_class::classify_io(&e));
            return Err(e.into());
        }

        if rsp[0] != 0x05 {
            dialm::record_err("socks5", dialm::Phase::ProxyHandshake, t1, "bad_version");
            bail!("socks5: bad version");
        }

        if rsp[1] == 0x02 {
            // User/password authentication
            let u = self.opts.username.clone().unwrap_or_default();
            let p = self.opts.password.clone().unwrap_or_default();
            if u.len() > 255 || p.len() > 255 {
                dialm::record_err("socks5", dialm::Phase::ProxyHandshake, t1, "creds_too_long");
                bail!("socks5: user/pass too long");
            }
            let mut buf = Vec::with_capacity(3 + u.len() + p.len());
            buf.extend_from_slice(&[0x01, u.len() as u8]);
            buf.extend_from_slice(u.as_bytes());
            buf.push(p.len() as u8);
            buf.extend_from_slice(p.as_bytes());

            if let Err(e) = s.write_all(&buf).await {
                dialm::record_err("socks5", dialm::Phase::ProxyHandshake, t1, error_class::classify_io(&e));
                return Err(e.into());
            }

            let mut vr = [0u8; 2];
            if let Err(e) = s.read_exact(&mut vr).await {
                dialm::record_err("socks5", dialm::Phase::ProxyHandshake, t1, error_class::classify_io(&e));
                return Err(e.into());
            }

            if vr[1] != 0x00 {
                dialm::record_err("socks5", dialm::Phase::ProxyHandshake, t1, "auth_failed");
                bail!("socks5: auth failed");
            }
        } else if rsp[1] != 0x00 {
            dialm::record_err("socks5", dialm::Phase::ProxyHandshake, t1, "no_acceptable_methods");
            bail!("socks5: no acceptable methods");
        }

        // Send CONNECT request
        let (host, port) = match &req.target {
            TargetAddr::Ip(sa) => (None, *sa),
            TargetAddr::Domain(h, p) => (Some((h.clone(), *p)), std::net::SocketAddr::from(([0, 0, 0, 0], 0))),
        };
        let mut msg = Vec::with_capacity(22);
        msg.extend_from_slice(&[0x05, 0x01, 0x00]); // VER=5, CMD=CONNECT, RSV
        if let Some((h, p)) = host {
            msg.push(0x03);
            msg.push(h.len() as u8);
            msg.extend_from_slice(h.as_bytes());
            msg.extend_from_slice(&p.to_be_bytes());
        } else {
            msg.push(0x01);
            let oct = match port.ip() {
                std::net::IpAddr::V4(v) => v.octets(),
                std::net::IpAddr::V6(_) => {
                    dialm::record_err("socks5", dialm::Phase::ProxyHandshake, t1, "ipv6_not_supported");
                    return Err(anyhow!("socks5: ipv6 not implemented"));
                }
            };
            msg.extend_from_slice(&oct);
            msg.extend_from_slice(&port.port().to_be_bytes());
        }

        if let Err(e) = s.write_all(&msg).await {
            dialm::record_err("socks5", dialm::Phase::ProxyHandshake, t1, error_class::classify_io(&e));
            return Err(e.into());
        }

        // Read CONNECT response
        let mut head = [0u8; 4];
        if let Err(e) = s.read_exact(&mut head).await {
            dialm::record_err("socks5", dialm::Phase::ProxyHandshake, t1, error_class::classify_io(&e));
            return Err(e.into());
        }

        if head[1] != 0x00 {
            dialm::record_err("socks5", dialm::Phase::ProxyHandshake, t1, "connect_failed");
            bail!("socks5: connect failed, rep={:02x}", head[1]);
        }

        // Read BND.ADDR (consume the rest of the response)
        let atyp = head[3];
        let addr_read_result = match atyp {
            0x01 => {
                let mut b = [0u8; 4 + 2];
                s.read_exact(&mut b).await
            }
            0x03 => {
                let mut l = [0u8; 1];
                match s.read_exact(&mut l).await {
                    Ok(()) => {
                        let mut dom = vec![0u8; l[0] as usize + 2];
                        s.read_exact(&mut dom).await
                    }
                    Err(e) => Err(e),
                }
            }
            0x04 => {
                let mut b = [0u8; 16 + 2];
                s.read_exact(&mut b).await
            }
            _ => {
                dialm::record_err("socks5", dialm::Phase::ProxyHandshake, t1, "bad_atyp");
                return Err(anyhow!("socks5: bad atyp"));
            }
        };

        if let Err(e) = addr_read_result {
            dialm::record_err("socks5", dialm::Phase::ProxyHandshake, t1, error_class::classify_io(&e));
            return Err(e.into());
        }

        dialm::record_ok("socks5", dialm::Phase::ProxyHandshake, t1);
        Ok(s)
    }

    async fn tcp_connect_tls(&self, req: TcpConnectRequest) -> Result<TlsStream<TcpStream>> {
        let params = req.tls.clone().ok_or_else(|| anyhow!("tls params required"))?;
        let target = req.target.clone();
        let opts = req.opts.clone();
        let tcp = self
            .tcp_connect(TcpConnectRequest {
                target,
                tls: None,
                opts,
            })
            .await?;
        let tls = params.client.connect(&params.server_name, tcp).await?;
        Ok(tls)
    }

    async fn udp_bind(&self, _req: UdpBindRequest) -> Result<UdpSocket> {
        bail!("socks5 outbound does not support udp");
    }

    fn name(&self) -> &'static str {
        "socks5"
    }
}
