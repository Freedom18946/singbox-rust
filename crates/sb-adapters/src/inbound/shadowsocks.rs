//! Shadowsocks AEAD inbound (TCP + UDP) server
//! Shadowsocks AEAD 入站（TCP + UDP）服务端
//! Supports AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305, and AEAD-2022
//! 支持 AES-128-GCM、AES-256-GCM、ChaCha20-Poly1305 和 AEAD-2022

use anyhow::{anyhow, Result};
use hkdf::Hkdf;
use sha1::Sha1;
type HkdfSha1 = Hkdf<Sha1>;

use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce as AesNonce,
};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaNonce};

use sb_core::net::metered;
use sb_core::net::metered::TrafficRecorder;
use sb_core::net::rate_limit_metrics;
use sb_core::net::tcp_rate_limit::{TcpRateLimitConfig, TcpRateLimiter};
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
use sb_core::services::v2ray_api::StatsManager;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
	use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
	use tokio::io::{AsyncReadExt, AsyncWriteExt};
	use tokio::select;
	use tokio::sync::mpsc;
	use tokio::sync::oneshot;
	use tokio::time::{interval, Duration};
	use tracing::debug;
	use tracing::{info, warn};

#[derive(Clone, Debug)]
pub enum AeadCipherKind {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20Poly1305,
    // AEAD-2022 ciphers
    Aes128Gcm2022,
    Aes256Gcm2022,
}

impl AeadCipherKind {
    pub fn from_method(m: &str) -> Option<Self> {
        match m {
            "aes-128-gcm" => Some(Self::Aes128Gcm),
            "aes-256-gcm" => Some(Self::Aes256Gcm),
            "chacha20-poly1305" | "chacha20-ietf-poly1305" => Some(Self::Chacha20Poly1305),
            "2022-blake3-aes-128-gcm" => Some(Self::Aes128Gcm2022),
            "2022-blake3-aes-256-gcm" => Some(Self::Aes256Gcm2022),
            _ => None,
        }
    }
    pub fn key_len(&self) -> usize {
        match self {
            Self::Aes128Gcm | Self::Aes128Gcm2022 => 16,
            Self::Aes256Gcm | Self::Chacha20Poly1305 | Self::Aes256Gcm2022 => 32,
        }
    }
    pub fn salt_len(&self) -> usize {
        match self {
            Self::Aes128Gcm | Self::Aes128Gcm2022 => 16,
            Self::Aes256Gcm | Self::Chacha20Poly1305 | Self::Aes256Gcm2022 => 32,
        }
    }
    pub fn tag_len(&self) -> usize {
        16
    }
    pub fn is_aead2022(&self) -> bool {
        matches!(self, Self::Aes128Gcm2022 | Self::Aes256Gcm2022)
    }
}

/// User configuration for multi-user Shadowsocks
#[derive(Clone, Debug)]
pub struct ShadowsocksUser {
    /// Username for identification
    pub name: String,
    /// User-specific password
    pub password: String,
}

impl ShadowsocksUser {
    pub fn new(name: String, password: String) -> Self {
        Self { name, password }
    }
}

#[derive(Clone, Debug)]
pub struct ShadowsocksInboundConfig {
    pub listen: SocketAddr,
    /// Encryption method (cipher)
    pub method: String,
    /// Single password for backward compatibility (deprecated)
    #[deprecated(note = "Use users field for multi-user support")]
    pub password: Option<String>,
    /// Multi-user configuration
    pub users: Vec<ShadowsocksUser>,
    pub router: Arc<router::RouterHandle>,
    pub tag: Option<String>,
    pub stats: Option<Arc<StatsManager>>,
    /// Optional Multiplex configuration
    pub multiplex: Option<sb_transport::multiplex::MultiplexServerConfig>,
    /// V2Ray transport layer configuration (WebSocket, gRPC, HTTPUpgrade)
    /// V2Ray 传输层配置（WebSocket, gRPC, HTTPUpgrade）
    /// If None, defaults to TCP
    /// 如果为 None，默认为 TCP
    pub transport_layer: Option<crate::transport_config::TransportConfig>,
}

impl ShadowsocksInboundConfig {
    /// Build user password map for O(1) lookup
    /// Returns map of (master_key -> username)
    fn build_user_map(&self, cipher: &AeadCipherKind) -> HashMap<Vec<u8>, String> {
        let mut map = HashMap::new();

        // Add configured users
        for user in &self.users {
            let key = evp_bytes_to_key(&user.password, cipher.key_len());
            map.insert(key, user.name.clone());
        }

        // Backward compatibility: add single password if present
        #[allow(deprecated)]
        if let Some(ref pwd) = self.password {
            if !pwd.is_empty() {
                let key = evp_bytes_to_key(pwd, cipher.key_len());
                map.insert(key, "default".to_string());
            }
        }

        map
    }
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

fn hkdf_subkey(master: &[u8], salt: &[u8], out_len: usize) -> Result<Vec<u8>> {
    let hk = HkdfSha1::new(Some(salt), master);
    let mut okm = vec![0u8; out_len];
    hk.expand(b"ss-subkey", &mut okm)
        .map_err(|_| anyhow!("hkdf expand failed"))?;
    Ok(okm)
}

async fn read_exact_n(r: &mut (impl tokio::io::AsyncRead + Unpin), n: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

/// AsyncRead/AsyncWrite wrapper that replays a prefix before reading from the inner stream.
/// Used to "put back" bytes consumed during authentication.
struct PrefixStream<T> {
    prefix: Vec<u8>,
    pos: usize,
    inner: T,
}

impl<T> PrefixStream<T> {
    fn new(prefix: Vec<u8>, inner: T) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for PrefixStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.pos < self.prefix.len() {
            let remaining = &self.prefix[self.pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.pos += to_copy;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for PrefixStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[derive(Clone)]
struct RuntimeShared {
    user_keys: Arc<parking_lot::RwLock<HashMap<Vec<u8>, String>>>,
    #[cfg(feature = "service_ssmapi")]
    tracker: Arc<parking_lot::RwLock<Option<Arc<dyn TrafficTracker>>>>,
    #[cfg(feature = "service_ssmapi")]
    udp_sessions_seen: Arc<dashmap::DashMap<SocketAddr, String>>,
}

fn select_user_by_len_chunk(
    cipher: &AeadCipherKind,
    salt: &[u8],
    enc_len_chunk: &[u8],
    user_keys: &HashMap<Vec<u8>, String>,
) -> Option<(String, Vec<u8>)> {
    if enc_len_chunk.len() != 2 + cipher.tag_len() {
        return None;
    }
    for (master_key, username) in user_keys {
        let subkey = match hkdf_subkey(master_key, salt, cipher.key_len()) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let plain = match aead_decrypt(cipher, &subkey, 0, enc_len_chunk) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if plain.len() != 2 {
            continue;
        }
        let mut lbytes = [0u8; 2];
        lbytes.copy_from_slice(&plain);
        let plen = u16::from_be_bytes(lbytes) as usize;
        if plen == 0 {
            continue;
        }
        return Some((username.clone(), master_key.clone()));
    }
    None
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
        AeadCipherKind::Aes128Gcm | AeadCipherKind::Aes128Gcm2022 => {
            use aes_gcm::Aes128Gcm;
            let aead = Aes128Gcm::new_from_slice(key).map_err(|_| anyhow!("bad aes key"))?;
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
        AeadCipherKind::Aes256Gcm | AeadCipherKind::Aes256Gcm2022 => {
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
        AeadCipherKind::Aes128Gcm | AeadCipherKind::Aes128Gcm2022 => {
            use aes_gcm::Aes128Gcm;
            let aead = Aes128Gcm::new_from_slice(key).map_err(|_| anyhow!("bad aes key"))?;
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
        AeadCipherKind::Aes256Gcm | AeadCipherKind::Aes256Gcm2022 => {
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

/// Parse a Shadowsocks address header from raw bytes.
pub fn parse_ss_addr(buf: &[u8]) -> Result<(String, u16, usize)> {
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

/// Handle UDP relay for Shadowsocks
async fn handle_udp_relay(
    socket: Arc<tokio::net::UdpSocket>,
    cfg: ShadowsocksInboundConfig,
    cipher: AeadCipherKind,
    shared: RuntimeShared,
    _rate_limiter: TcpRateLimiter,
    mut stop_rx: mpsc::Receiver<()>,
) -> Result<()> {
    let mut buf = vec![0u8; 65536];

    loop {
        select! {
            _ = stop_rx.recv() => break,
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((n, peer)) => {
                        if n < cipher.salt_len() + 18 {
                            // Too small to be valid (salt + minimal AEAD)
                            continue;
                        }

                        // Extract salt
                        let salt = &buf[..cipher.salt_len()];

                        // Authenticate and decrypt.
                        let encrypted_data = &buf[cipher.salt_len()..n];
                        let mut auth_user: Option<String> = None;
                        let mut master_key: Option<Vec<u8>> = None;
                        let mut decrypted: Option<Vec<u8>> = None;
                        {
                            let user_keys = shared.user_keys.read();
                            for (mk, username) in user_keys.iter() {
                                if let Ok(subkey) = hkdf_subkey(mk, salt, cipher.key_len()) {
                                    if let Ok(plain) =
                                        aead_decrypt_udp(&cipher, &subkey, 0, encrypted_data)
                                    {
                                        auth_user = Some(username.clone());
                                        master_key = Some(mk.clone());
                                        decrypted = Some(plain);
                                        break;
                                    }
                                }
                            }
                        }

                        let Some(auth_user) = auth_user else {
                            debug!(?peer, "shadowsocks: UDP auth failed");
                            continue;
                        };
                        let master_key = master_key.expect("set alongside auth_user");
                        let decrypted = decrypted.expect("set alongside auth_user");

                        #[cfg(feature = "service_ssmapi")]
                        if let Some(tracker) = shared.tracker.read().clone() {
                            if shared
                                .udp_sessions_seen
                                .insert(peer, auth_user.clone())
                                .is_none()
                            {
                                tracker.increment_udp_sessions(&auth_user, 1);
                            }
                        }

                        debug!(?peer, user=%auth_user, "shadowsocks: UDP packet authenticated");

                        let traffic = cfg.stats.as_ref().and_then(|stats| {
                            stats.traffic_recorder(
                                cfg.tag.as_deref(),
                                Some("direct"),
                                Some(auth_user.as_str()),
                            )
                        });

                        // Spawn task for this UDP packet
                        let socket_clone = socket.clone();
                        let cipher_clone = cipher.clone();
                        let shared_clone = shared.clone();

                        tokio::spawn(async move {
                            if let Err(e) = handle_udp_packet(
                                socket_clone,
                                cipher_clone,
                                decrypted,
                                peer,
                                master_key,
                                auth_user,
                                traffic,
                                shared_clone,
                            ).await {
                                debug!(error=%e, ?peer, "shadowsocks: UDP packet error");
                            }
                        });
                    }
                    Err(e) => {
                        warn!(error=%e, "shadowsocks: UDP recv error");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }
    }

    Ok(())
}

/// Handle individual UDP packet
async fn handle_udp_packet(
    listen_socket: Arc<tokio::net::UdpSocket>,
    cipher: AeadCipherKind,
    decrypted: Vec<u8>,
    peer: SocketAddr,
    master_key: Vec<u8>,
    auth_user: String,
    traffic: Option<Arc<dyn TrafficRecorder>>,
    shared: RuntimeShared,
) -> Result<()> {
    // Parse target address
    let (target_host, target_port, addr_len) = parse_ss_addr(&decrypted)?;
    let payload = &decrypted[addr_len..];

    if let Some(ref recorder) = traffic {
        recorder.record_up(payload.len() as u64);
        recorder.record_up_packet(1);
    }
    #[cfg(feature = "service_ssmapi")]
    if let Some(tracker) = shared.tracker.read().clone() {
        tracker.record_uplink(&auth_user, payload.len() as i64, 1);
    }

    // Create upstream socket and send
    let upstream = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    upstream
        .connect((target_host.as_str(), target_port))
        .await?;
    upstream.send(payload).await?;

    // Receive response
    let mut resp_buf = vec![0u8; 65536];
    match tokio::time::timeout(Duration::from_secs(5), upstream.recv(&mut resp_buf)).await {
        Ok(Ok(n)) => {
            // Encrypt and send back to client
            let response_data = &resp_buf[..n];

            // Generate new salt for response
            let mut resp_salt = vec![0u8; cipher.salt_len()];
            use rand::Rng;
            rand::thread_rng().fill(&mut resp_salt[..]);

            let resp_subkey = hkdf_subkey(&master_key, &resp_salt, cipher.key_len())?;
            let encrypted_resp = aead_encrypt_udp(&cipher, &resp_subkey, 0, response_data)?;

            let mut full_resp = Vec::new();
            full_resp.extend_from_slice(&resp_salt);
            full_resp.extend_from_slice(&encrypted_resp);

            if listen_socket.send_to(&full_resp, peer).await.is_ok() {
                if let Some(ref recorder) = traffic {
                    recorder.record_down(response_data.len() as u64);
                    recorder.record_down_packet(1);
                }
                #[cfg(feature = "service_ssmapi")]
                if let Some(tracker) = shared.tracker.read().clone() {
                    tracker.record_downlink(&auth_user, response_data.len() as i64, 1);
                }
            }
        }
        _ => {
            // Timeout or error, ignore
        }
    }

    Ok(())
}

/// Decrypt UDP packet (simpler than TCP chunks)
fn aead_decrypt_udp(
    cipher: &AeadCipherKind,
    key: &[u8],
    nonce_val: u64,
    data: &[u8],
) -> Result<Vec<u8>> {
    aead_decrypt(cipher, key, nonce_val, data)
}

/// Encrypt UDP packet
fn aead_encrypt_udp(
    cipher: &AeadCipherKind,
    key: &[u8],
    nonce_val: u64,
    data: &[u8],
) -> Result<Vec<u8>> {
    aead_encrypt(cipher, key, nonce_val, data)
}

	pub async fn serve(cfg: ShadowsocksInboundConfig, stop_rx: mpsc::Receiver<()>) -> Result<()> {
	    let method =
	        AeadCipherKind::from_method(&cfg.method).ok_or_else(|| anyhow!("unsupported method"))?;

	    let user_map = cfg.build_user_map(&method);
	    let shared = RuntimeShared {
	        user_keys: Arc::new(parking_lot::RwLock::new(user_map)),
	        #[cfg(feature = "service_ssmapi")]
	        tracker: Arc::new(parking_lot::RwLock::new(None)),
	        #[cfg(feature = "service_ssmapi")]
	        udp_sessions_seen: Arc::new(dashmap::DashMap::new()),
	    };

	    serve_run(cfg, stop_rx, method, shared, None).await
	}

	/// Like [`serve`], but also sends the actual bound TCP address back to the caller.
	///
	/// This is primarily useful for tests that want to bind to port 0 without racing on a
	/// pre-selected port.
	pub async fn serve_with_ready(
	    cfg: ShadowsocksInboundConfig,
	    stop_rx: mpsc::Receiver<()>,
	    ready_tx: oneshot::Sender<SocketAddr>,
	) -> Result<()> {
	    let method =
	        AeadCipherKind::from_method(&cfg.method).ok_or_else(|| anyhow!("unsupported method"))?;

	    let user_map = cfg.build_user_map(&method);
	    let shared = RuntimeShared {
	        user_keys: Arc::new(parking_lot::RwLock::new(user_map)),
	        #[cfg(feature = "service_ssmapi")]
	        tracker: Arc::new(parking_lot::RwLock::new(None)),
	        #[cfg(feature = "service_ssmapi")]
	        udp_sessions_seen: Arc::new(dashmap::DashMap::new()),
	    };

	    serve_run(cfg, stop_rx, method, shared, Some(ready_tx)).await
	}

	#[cfg(feature = "service_ssmapi")]
	async fn serve_with_shared(
	    cfg: ShadowsocksInboundConfig,
	    stop_rx: mpsc::Receiver<()>,
	    shared: RuntimeShared,
	) -> Result<()> {
	    let method =
	        AeadCipherKind::from_method(&cfg.method).ok_or_else(|| anyhow!("unsupported method"))?;
	    serve_run(cfg, stop_rx, method, shared, None).await
	}

	async fn serve_run(
	    cfg: ShadowsocksInboundConfig,
	    mut stop_rx: mpsc::Receiver<()>,
	    method: AeadCipherKind,
	    shared: RuntimeShared,
	    ready_tx: Option<oneshot::Sender<SocketAddr>>,
	) -> Result<()> {
	    if shared.user_keys.read().is_empty() {
	        return Err(anyhow!("shadowsocks: no users configured"));
	    }

    // Create TCP listener based on transport configuration
	    let transport = cfg.transport_layer.clone().unwrap_or_default();
	    let listener = transport.create_inbound_listener(cfg.listen).await?;
	    let actual = listener.local_addr().unwrap_or(cfg.listen);

	    // Create UDP socket for UDP relay
	    let udp_bind_addr = if cfg.listen.port() == 0 {
	        SocketAddr::new(cfg.listen.ip(), actual.port())
	    } else {
	        cfg.listen
	    };
	    let udp_socket = Arc::new(tokio::net::UdpSocket::bind(udp_bind_addr).await?);
	    let udp_addr = udp_socket.local_addr()?;

	    // Initialize rate limiter
	    let rate_limiter = TcpRateLimiter::new(TcpRateLimitConfig::from_env());

	    if let Some(tx) = ready_tx {
	        let _ = tx.send(actual);
	    }

	    info!(
	        addr=?cfg.listen,
	        tcp_actual=?actual,
	        udp_actual=?udp_addr,
        transport=?transport.transport_type(),
        multiplex=?cfg.multiplex.is_some(),
        "shadowsocks: TCP+UDP inbound bound"
    );

    // Spawn UDP relay task with separate stop channel
    let (_udp_stop_tx, udp_stop_rx) = mpsc::channel(1);
    let udp_cfg = cfg.clone();
    let udp_method = method.clone();
    let udp_shared = shared.clone();
    let udp_rate_limiter = rate_limiter.clone();

    tokio::spawn(async move {
        if let Err(e) = handle_udp_relay(
            udp_socket,
            udp_cfg,
            udp_method,
            udp_shared,
            udp_rate_limiter,
            udp_stop_rx,
        )
        .await
        {
            warn!(error=%e, "shadowsocks: UDP relay error");
        }
    });

    // Handle TCP connections (multiplex is handled *inside* the Shadowsocks session after
    // successful authentication and establishing the encrypted tunnel).
    let mut hb = interval(Duration::from_secs(5));
    loop {
        select! {
            _ = stop_rx.recv() => break,
            _ = hb.tick() => {}
            r = listener.accept() => {
                let (stream, peer) = match r {
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
                let shared_clone = shared.clone();
                let rate_limiter_clone = rate_limiter.clone();

                rate_limit_metrics::inc_active_connections("shadowsocks");

                tokio::spawn(async move {
                    let _guard = scopeguard::guard((), |_| {
                        rate_limit_metrics::dec_active_connections("shadowsocks");
                    });
                    if let Err(e) = handle_conn_stream(
                        &cfg_clone,
                        method_clone,
                        stream,
                        peer,
                        &rate_limiter_clone,
                        shared_clone,
                    )
                    .await
                    {
                        sb_core::metrics::http::record_error_display(&e);
                        sb_core::metrics::record_inbound_error_display("shadowsocks", &e);
                        warn!(%peer, error=%e, "ss: session error");
                    }
                });
            }
        }
    }
    Ok(())
}

// Helper function to handle connections from generic streams (for multiplex support)
// 处理来自通用流的连接的辅助函数（用于多路复用支持）
async fn handle_conn_stream<T>(
    _cfg: &ShadowsocksInboundConfig,
    cipher: AeadCipherKind,
    cli: T,
    peer: SocketAddr,
    rate_limiter: &TcpRateLimiter,
    shared: RuntimeShared,
) -> Result<()>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    handle_conn_impl(_cfg, cipher, cli, peer, rate_limiter, shared).await
}

async fn handle_conn_impl<T>(
    _cfg: &ShadowsocksInboundConfig,
    cipher: AeadCipherKind,
    mut cli: T,
    peer: SocketAddr,
    rate_limiter: &TcpRateLimiter,
    shared: RuntimeShared,
) -> Result<()>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // Step 1: authenticate user using salt + encrypted length chunk.
    let csalt = read_exact_n(&mut cli, cipher.salt_len()).await?;
    let enc_len_chunk = read_exact_n(&mut cli, 2 + cipher.tag_len()).await?;
    let (auth_user, master_key) = {
        let user_keys = shared.user_keys.read();
        if let Some(v) = select_user_by_len_chunk(&cipher, &csalt, &enc_len_chunk, &user_keys) {
            v
        } else {
            let banned = rate_limiter.record_auth_failure(peer.ip());
            if banned {
                debug!(%peer, "ss: IP banned due to excessive auth failures");
            }
            return Err(anyhow!("ss: auth failed"));
        }
    };

    #[cfg(feature = "service_ssmapi")]
    let tracker = shared.tracker.read().clone();
    #[cfg(feature = "service_ssmapi")]
    if let Some(t) = &tracker {
        t.increment_tcp_sessions(&auth_user, 1);
    }

    let c_subkey = hkdf_subkey(&master_key, &csalt, cipher.key_len())?;
    let cli = PrefixStream::new(enc_len_chunk, cli);

    // Create duplex pipe for cleartext traffic
    // 创建用于明文流量的双工管道
    let (mut clear_local, clear_remote) = tokio::io::duplex(65536);
    let (mut cli_r, mut cli_w) = tokio::io::split(cli);
    let (mut remote_r, mut remote_w) = tokio::io::split(clear_remote);

    let cipher_read = cipher.clone();

    // Spawn Decrypt Pump: CLI(Encrypted) -> Remote(Clear)
    // 启动解密泵：CLI(加密) -> Remote(明文)
    let auth_user_uplink = auth_user.clone();
    #[cfg(feature = "service_ssmapi")]
    let tracker_uplink = tracker.clone();
    tokio::spawn(async move {
        let mut nonce = 0u64;
        while let Ok(payload) =
            read_aead_chunk(&cipher_read, &c_subkey, &mut nonce, &mut cli_r).await
        {
            #[cfg(feature = "service_ssmapi")]
            if let Some(t) = &tracker_uplink {
                t.record_uplink(&auth_user_uplink, payload.len() as i64, 0);
            }
            if remote_w.write_all(&payload).await.is_err() {
                break;
            }
        }
    });

    // Prepare for Encryption Pump (will be spawned after we determine server salt)
    // 准备加密泵 (将在确定服务端 salt 后启动)
    // But we need to send server salt FIRST.
    // However, we don't know the server salt until we decide to accept the connection?
    // In original code:
    // 1. Read first chunk -> parse addr.
    // 2. Router decision.
    // 3. Connect upstream.
    // 4. Generate server salt.
    // 5. Send server salt.
    // 6. Relay loop.

    // With Mux, we might accept the connection BEFORE router decision (if Mux).
    // If Mux, we accept the connection, establish Mux session.
    // The Mux session establishment implies we are "accepting" the TCP connection.
    // So we should generate server salt and start the encryption pump immediately?
    // Yes, for Mux to work, we need a bidirectional cleartext stream.
    // So we must send the server salt and start encrypting.

    // Generate server salt
    let mut ssalt = vec![0u8; cipher.salt_len()];
    use rand::Rng;
    rand::thread_rng().fill(&mut ssalt[..]);
    let s_subkey = hkdf_subkey(&master_key, &ssalt, cipher.key_len())?;

    // Send server salt to client
    cli_w.write_all(&ssalt).await?;

    let cipher_write = cipher.clone();
    let key_write = s_subkey;

    // Spawn Encrypt Pump: Remote(Clear) -> CLI(Encrypted)
    // 启动加密泵：Remote(明文) -> CLI(加密)
    let auth_user_downlink = auth_user.clone();
    #[cfg(feature = "service_ssmapi")]
    let tracker_downlink = tracker.clone();
    tokio::spawn(async move {
        let mut nonce = 0u64;
        let mut buf = vec![0u8; 65536];
        loop {
            match remote_r.read(&mut buf).await {
                Ok(0) => break, // EOF
                Ok(n) => {
                    #[cfg(feature = "service_ssmapi")]
                    if let Some(t) = &tracker_downlink {
                        t.record_downlink(&auth_user_downlink, n as i64, 0);
                    }
                    if write_aead_chunk(
                        &cipher_write,
                        &key_write,
                        &mut nonce,
                        &mut cli_w,
                        &buf[..n],
                    )
                    .await
                    .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Now `clear_local` is our cleartext stream.
    // 现在 `clear_local` 是我们的明文流。

    // Check Mux
    if let Some(mux_cfg) = _cfg.multiplex.clone() {
        // Mux enabled
        use futures::future::poll_fn;
        use sb_transport::yamux::{Config, Connection, Mode};
        use tokio_util::compat::TokioAsyncReadCompatExt;

        let mut config = Config::default();
        config.set_max_num_streams(mux_cfg.max_num_streams);

        let compat_stream = clear_local.compat();
        let mut connection = Connection::new(compat_stream, config, Mode::Server);

        debug!(%peer, "ss: mux session started");

        while let Some(result) = poll_fn(|cx| connection.poll_next_inbound(cx)).await {
            match result {
                Ok(stream) => {
                    let cfg_inner = _cfg.clone();
                    let limiter_inner = rate_limiter.clone();
                    tokio::spawn(async move {
                        use tokio_util::compat::FuturesAsyncReadCompatExt;
                        let mut tokio_stream = stream.compat();
                        // Handle inner stream (read addr, route, relay)
                        if let Err(e) = handle_cleartext_stream(
                            &cfg_inner,
                            &mut tokio_stream,
                            peer,
                            &limiter_inner,
                        )
                        .await
                        {
                            debug!(%peer, error=%e, "ss: mux stream error");
                        }
                    });
                }
                Err(e) => {
                    warn!(%peer, error=%e, "ss: mux connection error");
                    break;
                }
            }
        }
        return Ok(());
    }

    // No Mux - handle as standard SS stream
    handle_cleartext_stream(_cfg, &mut clear_local, peer, rate_limiter).await
}

use parking_lot::Mutex;
use sb_core::adapter::InboundService;

#[cfg(feature = "service_ssmapi")]
use sb_core::services::ssmapi::{ManagedSSMServer, TrafficTracker};

pub struct ShadowsocksInboundAdapter {
    config: ShadowsocksInboundConfig,
    stop_tx: Mutex<Option<mpsc::Sender<()>>>,
    tag: String,
    #[cfg(feature = "service_ssmapi")]
    tracker: Arc<parking_lot::RwLock<Option<Arc<dyn TrafficTracker>>>>,
    /// Dynamic user map for SSMAPI integration: username -> password
    /// Updated via ManagedSSMServer::update_users()
    #[cfg(feature = "service_ssmapi")]
    users_map: Arc<parking_lot::RwLock<HashMap<String, String>>>,
    /// Map of (master_key -> username) for auth selection.
    #[cfg(feature = "service_ssmapi")]
    user_keys: Arc<parking_lot::RwLock<HashMap<Vec<u8>, String>>>,
    /// Best-effort UDP "session" approximation: peer -> username.
    #[cfg(feature = "service_ssmapi")]
    udp_sessions_seen: Arc<dashmap::DashMap<SocketAddr, String>>,
}

impl std::fmt::Debug for ShadowsocksInboundAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShadowsocksInboundAdapter")
            .field("config", &self.config)
            .field("tag", &self.tag)
            .finish_non_exhaustive()
    }
}

impl ShadowsocksInboundAdapter {
    pub fn new(config: ShadowsocksInboundConfig) -> Self {
        Self::with_tag(config, "shadowsocks".to_string())
    }

    pub fn with_tag(config: ShadowsocksInboundConfig, tag: String) -> Self {
        // Initialize users_map + user_keys from config.
        #[cfg(feature = "service_ssmapi")]
        let (tracker, users_map, user_keys, udp_sessions_seen) = {
            let tracker = Arc::new(parking_lot::RwLock::new(None));
            let mut map = HashMap::new();
            for user in &config.users {
                map.insert(user.name.clone(), user.password.clone());
            }
            let users_map = Arc::new(parking_lot::RwLock::new(map));

            let key_len = AeadCipherKind::from_method(&config.method)
                .map(|c| c.key_len())
                .unwrap_or(32);

            let mut keys = HashMap::new();
            for (username, password) in users_map.read().iter() {
                keys.insert(evp_bytes_to_key(password, key_len), username.clone());
            }
            #[allow(deprecated)]
            if let Some(ref pwd) = config.password {
                if !pwd.is_empty() {
                    keys.insert(evp_bytes_to_key(pwd, key_len), "default".to_string());
                }
            }
            let user_keys = Arc::new(parking_lot::RwLock::new(keys));
            let udp_sessions_seen = Arc::new(dashmap::DashMap::new());
            (tracker, users_map, user_keys, udp_sessions_seen)
        };

        Self {
            config,
            stop_tx: Mutex::new(None),
            tag,
            #[cfg(feature = "service_ssmapi")]
            tracker,
            #[cfg(feature = "service_ssmapi")]
            users_map,
            #[cfg(feature = "service_ssmapi")]
            user_keys,
            #[cfg(feature = "service_ssmapi")]
            udp_sessions_seen,
        }
    }
}

#[cfg(feature = "service_ssmapi")]
impl ManagedSSMServer for ShadowsocksInboundAdapter {
    fn set_tracker(&self, tracker: Arc<dyn TrafficTracker>) {
        *self.tracker.write() = Some(tracker);
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    fn inbound_type(&self) -> &str {
        "shadowsocks"
    }

    fn update_users(&self, users: Vec<String>, passwords: Vec<String>) -> Result<(), String> {
        if users.len() != passwords.len() {
            return Err("users and passwords must have the same length".to_string());
        }

        let Some(kind) = AeadCipherKind::from_method(&self.config.method) else {
            return Err("unsupported method".to_string());
        };

        {
            let mut map = self.users_map.write();
            map.clear();
            for (username, password) in users.into_iter().zip(passwords.into_iter()) {
                map.insert(username, password);
            }
        }

        {
            let mut keys = self.user_keys.write();
            keys.clear();
            for (username, password) in self.users_map.read().iter() {
                keys.insert(evp_bytes_to_key(password, kind.key_len()), username.clone());
            }
            #[allow(deprecated)]
            if let Some(ref pwd) = self.config.password {
                if !pwd.is_empty() {
                    keys.insert(evp_bytes_to_key(pwd, kind.key_len()), "default".to_string());
                }
            }
        }

        // Clear UDP session cache to avoid attributing new users to old peers.
        self.udp_sessions_seen.clear();

        tracing::debug!(
            tag = self.tag,
            user_count = self.users_map.read().len(),
            "SS inbound: updated users via SSMAPI"
        );

        Ok(())
    }
}

impl InboundService for ShadowsocksInboundAdapter {
    fn serve(&self) -> std::io::Result<()> {
        let (tx, rx) = mpsc::channel(1);
        *self.stop_tx.lock() = Some(tx);

        let rt = tokio::runtime::Handle::current();
        #[cfg(feature = "service_ssmapi")]
        {
            let shared = RuntimeShared {
                user_keys: self.user_keys.clone(),
                tracker: self.tracker.clone(),
                udp_sessions_seen: self.udp_sessions_seen.clone(),
            };
            rt.block_on(async { serve_with_shared(self.config.clone(), rx, shared).await })
                .map_err(|e| std::io::Error::other(e.to_string()))
        }
        #[cfg(not(feature = "service_ssmapi"))]
        {
            rt.block_on(async { serve(self.config.clone(), rx).await })
                .map_err(|e| std::io::Error::other(e.to_string()))
        }
    }

    fn request_shutdown(&self) {
        if let Some(tx) = self.stop_tx.lock().take() {
            let _ = tx.try_send(());
        }
    }
}

async fn handle_cleartext_stream<T>(
    cfg: &ShadowsocksInboundConfig,
    stream: &mut T,
    peer: SocketAddr,
    _rate_limiter: &TcpRateLimiter,
) -> Result<()>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // Step 2: read target address (from cleartext stream)
    // 步骤 2：读取目标地址 (从明文流)
    // Note: parse_ss_addr expects the buffer, but here we need to read from stream.
    // parse_ss_addr logic needs to be adapted or we read a chunk?
    // Wait, parse_ss_addr takes `&[u8]`.
    // In original code, `read_aead_chunk` returned a `Vec<u8>`.
    // Here `stream` is a byte stream.
    // We need to read address from it.
    // Address format: [ATYP][ADDR][PORT]

    let mut atyp = [0u8; 1];
    stream.read_exact(&mut atyp).await?;

    let (host, _port) = match atyp[0] {
        1 => {
            // IPv4
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await?;
            (IpAddr::V4(Ipv4Addr::from(buf)).to_string(), 0) // Port read later
        }
        3 => {
            // Domain
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut buf = vec![0u8; len[0] as usize];
            stream.read_exact(&mut buf).await?;
            (String::from_utf8_lossy(&buf).to_string(), 0)
        }
        4 => {
            // IPv6
            let mut buf = [0u8; 16];
            stream.read_exact(&mut buf).await?;
            (IpAddr::V6(Ipv6Addr::from(buf)).to_string(), 0)
        }
        _ => return Err(anyhow!("bad atyp")),
    };

    // Read port
    let mut port_buf = [0u8; 2];
    stream.read_exact(&mut port_buf).await?;
    let port_val = u16::from_be_bytes(port_buf);

    let _ = host;
    let port = port_val;

    // Step 3: router decision
    // 步骤 3：路由决策
    let mut decision = RDecision::Direct;
    if let Some(eng) = rules_global::global() {
        let ctx = RouteCtx {
            domain: Some(&host),
            ip: None,
            transport_udp: false,
            port: Some(port),
            inbound_tag: cfg.tag.as_deref().or(Some("shadowsocks")),
            network: Some("tcp"),
            ..Default::default()
        };
        let d = eng.decide(&ctx);
        if matches!(d, RDecision::Reject) {
            return Err(anyhow!("ss: rejected by rules"));
        }
        decision = d;
    }

    let proxy = default_proxy();
    let opts = ConnectOpts::default();
    let (mut upstream, outbound_tag) = match decision {
        RDecision::Direct => {
            let s = direct_connect_hostport(&host, port, &opts).await?;
            (s, Some("direct".to_string()))
        }
        RDecision::Proxy(Some(name)) => {
            let sel = PoolSelector::new("ss".into(), "default".into());
            if let Some(reg) = registry::global() {
                if reg.pools.contains_key(&name) {
                    if let Some(ep) = sel.select(&name, peer, &format!("{}:{}", host, port), &()) {
                        match ep.kind {
                            sb_core::outbound::endpoint::ProxyKind::Http => {
                                let s = http_proxy_connect_through_proxy(
                                    &ep.addr.to_string(),
                                    &host,
                                    port,
                                    &opts,
                                )
                                .await?;
                                (s, Some("http".to_string()))
                            }
                            sb_core::outbound::endpoint::ProxyKind::Socks5 => {
                                let s = socks5_connect_through_socks5(
                                    &ep.addr.to_string(),
                                    &host,
                                    port,
                                    &opts,
                                )
                                .await?;
                                (s, Some("socks5".to_string()))
                            }
                        }
                    } else {
                        match proxy {
                            ProxyChoice::Direct => {
                                let s = direct_connect_hostport(&host, port, &opts).await?;
                                (s, Some("direct".to_string()))
                            }
                            ProxyChoice::Http(addr) => {
                                let s = http_proxy_connect_through_proxy(addr, &host, port, &opts)
                                    .await?;
                                (s, Some("http".to_string()))
                            }
                            ProxyChoice::Socks5(addr) => {
                                let s =
                                    socks5_connect_through_socks5(addr, &host, port, &opts).await?;
                                (s, Some("socks5".to_string()))
                            }
                        }
                    }
                } else {
                    match proxy {
                        ProxyChoice::Direct => {
                            let s = direct_connect_hostport(&host, port, &opts).await?;
                            (s, Some("direct".to_string()))
                        }
                        ProxyChoice::Http(addr) => {
                            let s =
                                http_proxy_connect_through_proxy(addr, &host, port, &opts).await?;
                            (s, Some("http".to_string()))
                        }
                        ProxyChoice::Socks5(addr) => {
                            let s = socks5_connect_through_socks5(addr, &host, port, &opts).await?;
                            (s, Some("socks5".to_string()))
                        }
                    }
                }
            } else {
                match proxy {
                    ProxyChoice::Direct => {
                        let s = direct_connect_hostport(&host, port, &opts).await?;
                        (s, Some("direct".to_string()))
                    }
                    ProxyChoice::Http(addr) => {
                        let s = http_proxy_connect_through_proxy(addr, &host, port, &opts).await?;
                        (s, Some("http".to_string()))
                    }
                    ProxyChoice::Socks5(addr) => {
                        let s = socks5_connect_through_socks5(addr, &host, port, &opts).await?;
                        (s, Some("socks5".to_string()))
                    }
                }
            }
        }
        RDecision::Proxy(None) => match proxy {
            ProxyChoice::Direct => {
                let s = direct_connect_hostport(&host, port, &opts).await?;
                (s, Some("direct".to_string()))
            }
            ProxyChoice::Http(addr) => {
                let s = http_proxy_connect_through_proxy(addr, &host, port, &opts).await?;
                (s, Some("http".to_string()))
            }
            ProxyChoice::Socks5(addr) => {
                let s = socks5_connect_through_socks5(addr, &host, port, &opts).await?;
                (s, Some("socks5".to_string()))
            }
        },
        RDecision::Reject => return Err(anyhow!("ss: rejected by rules")),
        // Handle other variants (Hijack, Sniff, Resolve) as direct for now
        _ => {
            let s = direct_connect_hostport(&host, port, &opts).await?;
            (s, Some("direct".to_string()))
        }
    };

    // Step 4: Relay
    let traffic = cfg.stats.as_ref().and_then(|stats| {
        stats.traffic_recorder(cfg.tag.as_deref(), outbound_tag.as_deref(), None)
    });
    let _ = metered::copy_bidirectional_streaming_ctl(
        stream,
        &mut upstream,
        "shadowsocks",
        Duration::from_secs(1),
        None,
        None,
        None,
        traffic,
    )
    .await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticate_len_chunk_selects_correct_user() {
        let cipher = AeadCipherKind::Aes256Gcm;
        let salt = vec![7u8; cipher.salt_len()];

        let mk1 = evp_bytes_to_key("p1", cipher.key_len());
        let mk2 = evp_bytes_to_key("p2", cipher.key_len());

        let subkey2 = hkdf_subkey(&mk2, &salt, cipher.key_len()).unwrap();
        let len_be = (123u16).to_be_bytes();
        let enc_len = aead_encrypt(&cipher, &subkey2, 0, &len_be).unwrap();

        let mut keys = HashMap::new();
        keys.insert(mk1, "u1".to_string());
        keys.insert(mk2.clone(), "u2".to_string());

        let (user, picked_mk) = select_user_by_len_chunk(&cipher, &salt, &enc_len, &keys).unwrap();
        assert_eq!(user, "u2");
        assert_eq!(picked_mk, mk2);
    }

    #[cfg(feature = "service_ssmapi")]
    #[test]
    fn update_users_rebuilds_user_keys() {
        use sb_core::services::ssmapi::ManagedSSMServer;

        let router = Arc::new(sb_core::router::RouterHandle::from_env());
        let cfg = ShadowsocksInboundConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            method: "aes-256-gcm".to_string(),
            #[allow(deprecated)]
            password: None,
            users: vec![ShadowsocksUser::new("old".to_string(), "oldpwd".to_string())],
            router,
            tag: Some("ss-in".to_string()),
            stats: None,
            multiplex: None,
            transport_layer: None,
        };

        let adapter = ShadowsocksInboundAdapter::with_tag(cfg, "ss-in".to_string());
        let key_len = AeadCipherKind::from_method("aes-256-gcm").unwrap().key_len();
        let old_key = evp_bytes_to_key("oldpwd", key_len);
        assert!(adapter.user_keys.read().contains_key(&old_key));

        adapter
            .update_users(vec!["new".to_string()], vec!["newpwd".to_string()])
            .unwrap();
        let new_key = evp_bytes_to_key("newpwd", key_len);
        assert!(adapter.user_keys.read().contains_key(&new_key));
        assert!(!adapter.user_keys.read().contains_key(&old_key));
    }
}
