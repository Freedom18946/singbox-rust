//! Shadowsocks AEAD inbound (TCP) minimal server
//! Shadowsocks AEAD 入站（TCP）最小化服务端
//! Supports AES-256-GCM and CHACHA20-POLY1305
//! 支持 AES-256-GCM 和 CHACHA20-POLY1305

use anyhow::{anyhow, Result};
use hkdf::Hkdf;
use sha1::Sha1;
type HkdfSha1 = Hkdf<Sha1>;

use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce as AesNonce,
};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaNonce};

use sb_core::outbound::registry;
use sb_core::outbound::selector::PoolSelector;
use sb_core::outbound::{
    direct_connect_hostport, http_proxy_connect_through_proxy, socks5_connect_through_socks5,
    ConnectOpts,
};
use sb_core::router;
use sb_core::router::rules as rules_global;
use sb_core::router::rules::{Decision as RDecision, RouteCtx};
use sb_core::router::runtime::{default_proxy, ProxyChoice};
use sb_core::net::tcp_rate_limit::{TcpRateLimiter, TcpRateLimitConfig};
use sb_core::net::rate_limit_metrics;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::select;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::{info, warn};

#[derive(Clone, Debug)]
pub enum AeadCipherKind {
    Aes256Gcm,
    Chacha20Poly1305,
}

impl AeadCipherKind {
    fn from_method(m: &str) -> Option<Self> {
        match m.to_ascii_lowercase().as_str() {
            "aes-256-gcm" => Some(Self::Aes256Gcm),
            "chacha20-ietf-poly1305" | "chacha20-poly1305" => Some(Self::Chacha20Poly1305),
            _ => None,
        }
    }
    fn key_len(&self) -> usize {
        32
    }
    fn salt_len(&self) -> usize {
        32
    }
    fn tag_len(&self) -> usize {
        16
    }
}

#[derive(Clone, Debug)]
pub struct ShadowsocksInboundConfig {
    pub listen: SocketAddr,
    pub method: String,   // e.g., aes-256-gcm, chacha20-ietf-poly1305
    pub password: String, // master key (derived to 32 bytes via KDF below)
    pub router: Arc<router::RouterHandle>,
    pub multiplex: Option<sb_transport::multiplex::MultiplexServerConfig>,
    /// V2Ray transport layer configuration (WebSocket, gRPC, HTTPUpgrade)
    /// V2Ray 传输层配置（WebSocket, gRPC, HTTPUpgrade）
    /// If None, defaults to TCP
    /// 如果为 None，默认为 TCP
    pub transport_layer: Option<crate::transport_config::TransportConfig>,
}

fn evp_bytes_to_key(password: &str, key_len: usize) -> Vec<u8> {
    // Minimal EVP_BytesToKey-like derivation using SHA1 (not identical but deterministic)
    // 使用 SHA1 的最小化 EVP_BytesToKey 派生（不完全相同但确定性）
    // For production, prefer scrypt/argon2 or standard SS KDF; here we ensure 32 bytes key.
    // 生产环境中应首选 scrypt/argon2 或标准 SS KDF；此处确保生成 32 字节密钥。
    use sha1::Digest;
    let mut hasher = sha1::Sha1::new();
    hasher.update(password.as_bytes());
    let mut out = hasher.finalize().to_vec();
    while out.len() < key_len {
        let mut h = sha1::Sha1::new();
        h.update(&out);
        out.extend_from_slice(&h.finalize());
    }
    out.truncate(key_len);
    out
}

fn hkdf_subkey(master: &[u8], salt: &[u8]) -> Result<[u8; 32]> {
    let hk = HkdfSha1::new(Some(salt), master);
    let mut okm = [0u8; 32];
    hk.expand(b"ss-subkey", &mut okm)
        .map_err(|_| anyhow!("hkdf expand failed"))?;
    Ok(okm)
}

async fn read_exact_n(r: &mut (impl tokio::io::AsyncRead + Unpin), n: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

fn aead_decrypt(
    cipher: &AeadCipherKind,
    key: &[u8],
    nonce_ctr: u64,
    data: &[u8],
) -> Result<Vec<u8>> {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&nonce_ctr.to_le_bytes());
    match cipher {
        AeadCipherKind::Aes256Gcm => {
            let aead = Aes256Gcm::new_from_slice(key).map_err(|_| anyhow!("bad aes key"))?;
            Ok(aead
                .decrypt(
                    AesNonce::from_slice(&nonce),
                    Payload {
                        msg: data,
                        aad: &[],
                    },
                )
                .map_err(|_| anyhow!("decrypt"))?)
        }
        AeadCipherKind::Chacha20Poly1305 => {
            let aead =
                ChaCha20Poly1305::new_from_slice(key).map_err(|_| anyhow!("bad chacha key"))?;
            Ok(aead
                .decrypt(
                    ChaNonce::from_slice(&nonce),
                    Payload {
                        msg: data,
                        aad: &[],
                    },
                )
                .map_err(|_| anyhow!("decrypt"))?)
        }
    }
}

fn aead_encrypt(
    cipher: &AeadCipherKind,
    key: &[u8],
    nonce_ctr: u64,
    data: &[u8],
) -> Result<Vec<u8>> {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&nonce_ctr.to_le_bytes());
    match cipher {
        AeadCipherKind::Aes256Gcm => {
            let aead = Aes256Gcm::new_from_slice(key).map_err(|_| anyhow!("bad aes key"))?;
            Ok(aead
                .encrypt(
                    AesNonce::from_slice(&nonce),
                    Payload {
                        msg: data,
                        aad: &[],
                    },
                )
                .map_err(|_| anyhow!("encrypt"))?)
        }
        AeadCipherKind::Chacha20Poly1305 => {
            let aead =
                ChaCha20Poly1305::new_from_slice(key).map_err(|_| anyhow!("bad chacha key"))?;
            Ok(aead
                .encrypt(
                    ChaNonce::from_slice(&nonce),
                    Payload {
                        msg: data,
                        aad: &[],
                    },
                )
                .map_err(|_| anyhow!("encrypt"))?)
        }
    }
}

async fn read_aead_chunk(
    cipher: &AeadCipherKind,
    key: &[u8],
    nonce_ctr: &mut u64,
    r: &mut (impl tokio::io::AsyncRead + Unpin),
) -> Result<Vec<u8>> {
    let tag = cipher.tag_len();
    // read encrypted length (2 bytes + tag)
    // 读取加密长度（2 字节 + tag）
    let enc_len = read_exact_n(r, 2 + tag).await?;
    let len_plain = aead_decrypt(cipher, key, *nonce_ctr, &enc_len)?;
    *nonce_ctr += 1;
    if len_plain.len() != 2 {
        return Err(anyhow!("bad len"));
    }
    let mut lbytes = [0u8; 2];
    lbytes.copy_from_slice(&len_plain);
    let plen = u16::from_be_bytes(lbytes) as usize;
    // read encrypted payload
    // 读取加密负载
    let enc_payload = read_exact_n(r, plen + tag).await?;
    let payload = aead_decrypt(cipher, key, *nonce_ctr, &enc_payload)?;
    *nonce_ctr += 1;
    Ok(payload)
}

async fn write_aead_chunk(
    cipher: &AeadCipherKind,
    key: &[u8],
    nonce_ctr: &mut u64,
    w: &mut (impl tokio::io::AsyncWrite + Unpin),
    data: &[u8],
) -> Result<()> {
    let len_be = (data.len() as u16).to_be_bytes();
    let enc_len = aead_encrypt(cipher, key, *nonce_ctr, &len_be)?;
    *nonce_ctr += 1;
    let enc_payload = aead_encrypt(cipher, key, *nonce_ctr, data)?;
    *nonce_ctr += 1;
    w.write_all(&enc_len).await?;
    w.write_all(&enc_payload).await?;
    Ok(())
}

fn parse_ss_addr(buf: &[u8]) -> Result<(String, u16, usize)> {
    if buf.is_empty() {
        return Err(anyhow!("empty addr"));
    }
    let atyp = buf[0];
    match atyp {
        1 => {
            // IPv4
            if buf.len() < 1 + 4 + 2 {
                return Err(anyhow!("trunc ipv4"));
            }
            let ip = IpAddr::V4(Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]));
            let port = u16::from_be_bytes([buf[5], buf[6]]);
            Ok((ip.to_string(), port, 1 + 4 + 2))
        }
        3 => {
            // domain
            if buf.len() < 2 {
                return Err(anyhow!("trunc domain len"));
            }
            let dlen = buf[1] as usize;
            if buf.len() < 2 + dlen + 2 {
                return Err(anyhow!("trunc domain"));
            }
            let domain = String::from_utf8_lossy(&buf[2..2 + dlen]).to_string();
            let port = u16::from_be_bytes([buf[2 + dlen], buf[2 + dlen + 1]]);
            Ok((domain, port, 2 + dlen + 2))
        }
        4 => {
            // IPv6
            if buf.len() < 1 + 16 + 2 {
                return Err(anyhow!("trunc ipv6"));
            }
            let mut ipb = [0u8; 16];
            ipb.copy_from_slice(&buf[1..17]);
            let ip = IpAddr::V6(Ipv6Addr::from(ipb));
            let port = u16::from_be_bytes([buf[17], buf[18]]);
            Ok((ip.to_string(), port, 1 + 16 + 2))
        }
        _ => Err(anyhow!("bad atyp")),
    }
}

pub async fn serve(cfg: ShadowsocksInboundConfig, mut stop_rx: mpsc::Receiver<()>) -> Result<()> {
    let method =
        AeadCipherKind::from_method(&cfg.method).ok_or_else(|| anyhow!("unsupported method"))?;
    let master = evp_bytes_to_key(&cfg.password, method.key_len());

    // Create listener based on transport configuration (defaults to TCP if not specified)
    // 基于传输配置创建监听器（如果未指定，默认为 TCP）
    let transport = cfg.transport_layer.clone().unwrap_or_default();
    let listener = transport.create_inbound_listener(cfg.listen).await?;
    let actual = listener.local_addr().unwrap_or(cfg.listen);

    // Initialize rate limiter
    // 初始化速率限制器
    let rate_limiter = TcpRateLimiter::new(TcpRateLimitConfig::from_env());

    info!(
        addr=?cfg.listen,
        actual=?actual,
        transport=?transport.transport_type(),
        multiplex=?cfg.multiplex.is_some(),
        "shadowsocks: inbound bound"
    );

    // If multiplex is enabled, wrap the listener
    // 如果启用了多路复用，包装监听器
    if let Some(_mux_config) = cfg.multiplex.clone() {
        info!("shadowsocks: multiplex enabled");

        // Note: Multiplex wrapping over non-TCP transports needs special handling
        // 注意：非 TCP 传输上的多路复用包装需要特殊处理
        // For now, we accept connections from the InboundListener directly
        // 目前，我们直接接受来自 InboundListener 的连接
        let mut hb = interval(Duration::from_secs(5));
        loop {
            select! {
                _ = stop_rx.recv() => break,
                _ = hb.tick() => { tracing::debug!("shadowsocks: multiplex accept-loop heartbeat"); }
                r = listener.accept() => {
                    let (mut stream, peer) = match r {
                        Ok(v) => v,
                        Err(e) => {
                            warn!(error=%e, "ss: multiplex accept error");
                            sb_core::metrics::http::record_error_display(&e);
                            sb_core::metrics::record_inbound_error_display("shadowsocks", &e);
                            continue;
                        }
                    };

                    // Check rate limit
                    // 检查速率限制
                    if !rate_limiter.allow_connection(peer.ip()) {
                        warn!(%peer, "ss: connection rate limited");
                        continue;
                    }
                    if rate_limiter.is_banned(peer.ip()) {
                        warn!(%peer, "ss: IP banned due to excessive auth failures");
                        continue;
                    }

                    let cfg_clone = cfg.clone();
                    let method_clone = method.clone();
                    let master_clone = master.clone();
                    let rate_limiter_clone = rate_limiter.clone();
                    
                    rate_limit_metrics::inc_active_connections("shadowsocks");
                    
                    tokio::spawn(async move {
                        let _guard = scopeguard::guard((), |_| {
                            rate_limit_metrics::dec_active_connections("shadowsocks");
                        });
                        // For multiplexed streams or non-TCP transports, we don't have a peer address
                        // 对于多路复用流或非 TCP 传输，我们没有对端地址
                        // But we have it from accept() now if it's TCP
                        // 但如果是 TCP，我们现在从 accept() 中获取了它
                        if let Err(e) = handle_conn_stream(&cfg_clone, method_clone, &master_clone, &mut stream, peer, &rate_limiter_clone).await {
                            sb_core::metrics::http::record_error_display(&e);
                            sb_core::metrics::record_inbound_error_display("shadowsocks", &e);
                            warn!(%peer, error=%e, "ss: multiplex session error");
                        }
                    });
                }
            }
        }
    } else {
        // Standard listener without multiplex
        // 无多路复用的标准监听器
        let mut hb = interval(Duration::from_secs(5));
        loop {
            select! {
                _ = stop_rx.recv() => break,
                _ = hb.tick() => { tracing::debug!("shadowsocks: accept-loop heartbeat"); }
                r = listener.accept() => {
                    let (mut stream, peer) = match r {
                        Ok(v) => v,
                        Err(e) => {
                            warn!(error=%e, "ss: accept error");
                            sb_core::metrics::http::record_error_display(&e);
                            sb_core::metrics::record_inbound_error_display("shadowsocks", &e);
                            continue;
                        }
                    };

                    // Check rate limit
                    if !rate_limiter.allow_connection(peer.ip()) {
                        warn!(%peer, "ss: connection rate limited");
                        rate_limit_metrics::record_rate_limited("shadowsocks", "connection_limit");
                        continue;
                    }
                    if rate_limiter.is_banned(peer.ip()) {
                        warn!(%peer, "ss: IP banned due to excessive auth failures");
                        rate_limit_metrics::record_rate_limited("shadowsocks", "auth_failure_ban");
                        continue;
                    }

                    let cfg_clone = cfg.clone();
                    let method_clone = method.clone();
                    let master_clone = master.clone();
                    let rate_limiter_clone = rate_limiter.clone();
                    
                    rate_limit_metrics::inc_active_connections("shadowsocks");
                    
                    tokio::spawn(async move {
                        let _guard = scopeguard::guard((), |_| {
                            rate_limit_metrics::dec_active_connections("shadowsocks");
                        });
                        if let Err(e) = handle_conn_stream(&cfg_clone, method_clone, &master_clone, &mut stream, peer, &rate_limiter_clone).await {
                            sb_core::metrics::http::record_error_display(&e);
                            sb_core::metrics::record_inbound_error_display("shadowsocks", &e);
                            warn!(%peer, error=%e, "ss: session error");
                        }
                    });
                }
            }
        }
    }
    Ok(())
}

// Helper function to handle connections from generic streams (for multiplex support)
// 处理来自通用流的连接的辅助函数（用于多路复用支持）
async fn handle_conn_stream(
    _cfg: &ShadowsocksInboundConfig,
    cipher: AeadCipherKind,
    master_key: &[u8],
    cli: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send),
    peer: SocketAddr,
    rate_limiter: &TcpRateLimiter,
) -> Result<()> {
    handle_conn_impl(_cfg, cipher, master_key, cli, peer, rate_limiter).await
}

async fn handle_conn_impl(
    _cfg: &ShadowsocksInboundConfig,
    cipher: AeadCipherKind,
    master_key: &[u8],
    cli: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
    peer: SocketAddr,
    rate_limiter: &TcpRateLimiter,
) -> Result<()> {
    // Step 1: read client salt
    // 步骤 1：读取客户端 salt
    let csalt = read_exact_n(cli, cipher.salt_len()).await?;
    let c_subkey = hkdf_subkey(master_key, &csalt)?;
    let mut c_read_nonce: u64 = 0;

    // Step 2: read first AEAD chunk -> target address
    // 步骤 2：读取第一个 AEAD 块 -> 目标地址
    let first = match read_aead_chunk(&cipher, &c_subkey, &mut c_read_nonce, cli).await {
        Ok(v) => v,
        Err(e) => {
            // If decryption fails, it's likely a bad password/auth failure
            // 如果解密失败，很可能是密码错误/认证失败
            if e.to_string().contains("decrypt") {
                rate_limiter.record_auth_failure(peer.ip());
                rate_limit_metrics::record_auth_failure("shadowsocks");
            }
            return Err(e);
        }
    };
    let (host, port, _consumed) = parse_ss_addr(&first)?;

    // Step 3: router decision
    // 步骤 3：路由决策
    let mut decision = RDecision::Direct;
    if let Some(eng) = rules_global::global() {
        let ctx = RouteCtx {
            domain: Some(&host),
            ip: None,
            transport_udp: false,
            port: Some(port),
            process_name: None,
            process_path: None,
            inbound_tag: Some("shadowsocks"),
            outbound_tag: None,
            auth_user: None,
            query_type: None,
        };
        let d = eng.decide(&ctx);
        if matches!(d, RDecision::Reject) {
            return Err(anyhow!("ss: rejected by rules"));
        }
        decision = d;
    }

    let proxy = default_proxy();
    let opts = ConnectOpts::default();
    let mut upstream = match decision {
        RDecision::Direct => direct_connect_hostport(&host, port, &opts).await?,
        RDecision::Proxy(Some(name)) => {
            let sel = PoolSelector::new("ss".into(), "default".into());
            if let Some(reg) = registry::global() {
                if reg.pools.contains_key(&name) {
                    if let Some(ep) = sel.select(&name, peer, &format!("{}:{}", host, port), &()) {
                        match ep.kind {
                            sb_core::outbound::endpoint::ProxyKind::Http => {
                                http_proxy_connect_through_proxy(
                                    &ep.addr.to_string(),
                                    &host,
                                    port,
                                    &opts,
                                )
                                .await?
                            }
                            sb_core::outbound::endpoint::ProxyKind::Socks5 => {
                                socks5_connect_through_socks5(
                                    &ep.addr.to_string(),
                                    &host,
                                    port,
                                    &opts,
                                )
                                .await?
                            }
                        }
                    } else {
                        match proxy {
                            ProxyChoice::Direct => {
                                direct_connect_hostport(&host, port, &opts).await?
                            }
                            ProxyChoice::Http(addr) => {
                                http_proxy_connect_through_proxy(addr, &host, port, &opts).await?
                            }
                            ProxyChoice::Socks5(addr) => {
                                socks5_connect_through_socks5(addr, &host, port, &opts).await?
                            }
                        }
                    }
                } else {
                    match proxy {
                        ProxyChoice::Direct => direct_connect_hostport(&host, port, &opts).await?,
                        ProxyChoice::Http(addr) => {
                            http_proxy_connect_through_proxy(addr, &host, port, &opts).await?
                        }
                        ProxyChoice::Socks5(addr) => {
                            socks5_connect_through_socks5(addr, &host, port, &opts).await?
                        }
                    }
                }
            } else {
                match proxy {
                    ProxyChoice::Direct => direct_connect_hostport(&host, port, &opts).await?,
                    ProxyChoice::Http(addr) => {
                        http_proxy_connect_through_proxy(addr, &host, port, &opts).await?
                    }
                    ProxyChoice::Socks5(addr) => {
                        socks5_connect_through_socks5(addr, &host, port, &opts).await?
                    }
                }
            }
        }
        RDecision::Proxy(None) => match proxy {
            ProxyChoice::Direct => direct_connect_hostport(&host, port, &opts).await?,
            ProxyChoice::Http(addr) => {
                http_proxy_connect_through_proxy(addr, &host, port, &opts).await?
            }
            ProxyChoice::Socks5(addr) => {
                socks5_connect_through_socks5(addr, &host, port, &opts).await?
            }
        },
        RDecision::Reject => return Err(anyhow!("ss: rejected by rules")),
    };

    // Step 4: server salt + data plane
    // 步骤 4：服务端 salt + 数据平面
    let ssalt = {
        let mut s = vec![0u8; cipher.salt_len()];
        use rand::Rng;
        rand::thread_rng().fill(&mut s[..]);
        s
    };
    let s_subkey = hkdf_subkey(master_key, &ssalt)?;
    let s_write_nonce: u64 = 0;

    // Send server salt first
    // 先发送服务端 salt
    cli.write_all(&ssalt).await?;

    // Relay loops
    // 中继循环
    let (mut cr, mut cw) = tokio::io::split(cli);
    let (mut ur, mut uw) = tokio::io::split(&mut upstream);

    // Client->Upstream decrypt
    // 客户端->上游 解密
    let cipher_cu = cipher.clone();
    let ckey = c_subkey;
    let mut c_nonce = c_read_nonce;
    let cu = async move {
        loop {
            let chunk = match read_aead_chunk(&cipher_cu, &ckey, &mut c_nonce, &mut cr).await {
                Ok(v) => v,
                Err(_) => break,
            };
            if uw.write_all(&chunk).await.is_err() {
                break;
            }
        }
    };

    // Upstream->Client encrypt
    // 上游->客户端 加密
    let cipher_uc = cipher.clone();
    let skey = s_subkey;
    let mut s_nonce = s_write_nonce;
    let uc = async move {
        let mut buf = [0u8; 16384];
        loop {
            let n: usize = (ur.read(&mut buf).await).unwrap_or_default();
            if n == 0 {
                break;
            }
            if write_aead_chunk(&cipher_uc, &skey, &mut s_nonce, &mut cw, &buf[..n])
                .await
                .is_err()
            {
                break;
            }
        }
    };

    tokio::join!(cu, uc);
    Ok(())
}
