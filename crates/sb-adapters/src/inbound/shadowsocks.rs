//! Shadowsocks AEAD inbound (TCP) minimal server
//! Supports AES-256-GCM and CHACHA20-POLY1305

use anyhow::{anyhow, Result};
use hkdf::Hkdf;
use sha1::Sha1;
type HkdfSha1 = Hkdf<Sha1>;

use aes_gcm::{aead::{Aead, Payload}, Aes256Gcm, KeyInit, Nonce as AesNonce};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaNonce};

use sb_core::router;
use sb_core::router::rules as rules_global;
use sb_core::router::rules::{Decision as RDecision, RouteCtx};
use sb_core::router::runtime::{default_proxy, ProxyChoice};
use sb_core::outbound::{
    direct_connect_hostport, http_proxy_connect_through_proxy, socks5_connect_through_socks5, ConnectOpts,
};
use sb_core::outbound::selector::PoolSelector;
use sb_core::outbound::registry;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::select;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::{info, warn};

#[derive(Clone, Debug)]
pub enum AeadCipherKind { Aes256Gcm, Chacha20Poly1305 }

impl AeadCipherKind {
    fn from_method(m: &str) -> Option<Self> {
        match m.to_ascii_lowercase().as_str() {
            "aes-256-gcm" => Some(Self::Aes256Gcm),
            "chacha20-ietf-poly1305" | "chacha20-poly1305" => Some(Self::Chacha20Poly1305),
            _ => None,
        }
    }
    fn key_len(&self) -> usize { 32 }
    fn salt_len(&self) -> usize { 32 }
    fn tag_len(&self) -> usize { 16 }
}

#[derive(Clone, Debug)]
pub struct ShadowsocksInboundConfig {
    pub listen: SocketAddr,
    pub method: String,    // e.g., aes-256-gcm, chacha20-ietf-poly1305
    pub password: String,  // master key (derived to 32 bytes via KDF below)
    pub router: Arc<router::RouterHandle>,
}

fn evp_bytes_to_key(password: &str, key_len: usize) -> Vec<u8> {
    // Minimal EVP_BytesToKey-like derivation using SHA1 (not identical but deterministic)
    // For production, prefer scrypt/argon2 or standard SS KDF; here we ensure 32 bytes key.
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

fn hkdf_subkey(master: &[u8], salt: &[u8]) -> [u8; 32] {
    let hk = HkdfSha1::new(Some(salt), master);
    let mut okm = [0u8; 32];
    hk.expand(b"ss-subkey", &mut okm).expect("hkdf expand");
    okm
}

async fn read_exact_n(r: &mut (impl tokio::io::AsyncRead + Unpin), n: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

fn aead_decrypt(cipher: &AeadCipherKind, key: &[u8], nonce_ctr: u64, data: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&nonce_ctr.to_le_bytes());
    match cipher {
        AeadCipherKind::Aes256Gcm => {
            let aead = Aes256Gcm::new_from_slice(key).map_err(|_| anyhow!("bad aes key"))?;
            Ok(aead.decrypt(AesNonce::from_slice(&nonce), Payload { msg: data, aad: &[] }).map_err(|_| anyhow!("decrypt"))?)
        }
        AeadCipherKind::Chacha20Poly1305 => {
            let aead = ChaCha20Poly1305::new_from_slice(key).map_err(|_| anyhow!("bad chacha key"))?;
            Ok(aead.decrypt(ChaNonce::from_slice(&nonce), Payload { msg: data, aad: &[] }).map_err(|_| anyhow!("decrypt"))?)
        }
    }
}

fn aead_encrypt(cipher: &AeadCipherKind, key: &[u8], nonce_ctr: u64, data: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&nonce_ctr.to_le_bytes());
    match cipher {
        AeadCipherKind::Aes256Gcm => {
            let aead = Aes256Gcm::new_from_slice(key).map_err(|_| anyhow!("bad aes key"))?;
            Ok(aead.encrypt(AesNonce::from_slice(&nonce), Payload { msg: data, aad: &[] }).map_err(|_| anyhow!("encrypt"))?)
        }
        AeadCipherKind::Chacha20Poly1305 => {
            let aead = ChaCha20Poly1305::new_from_slice(key).map_err(|_| anyhow!("bad chacha key"))?;
            Ok(aead.encrypt(ChaNonce::from_slice(&nonce), Payload { msg: data, aad: &[] }).map_err(|_| anyhow!("encrypt"))?)
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
    let enc_len = read_exact_n(r, 2 + tag).await?;
    let len_plain = aead_decrypt(cipher, key, *nonce_ctr, &enc_len)?;
    *nonce_ctr += 1;
    if len_plain.len() != 2 { return Err(anyhow!("bad len")); }
    let mut lbytes = [0u8; 2];
    lbytes.copy_from_slice(&len_plain);
    let plen = u16::from_be_bytes(lbytes) as usize;
    // read encrypted payload
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
    let enc_len = aead_encrypt(cipher, key, *nonce_ctr, &len_be)?; *nonce_ctr += 1;
    let enc_payload = aead_encrypt(cipher, key, *nonce_ctr, data)?; *nonce_ctr += 1;
    w.write_all(&enc_len).await?;
    w.write_all(&enc_payload).await?;
    Ok(())
}

fn parse_ss_addr(buf: &[u8]) -> Result<(String, u16, usize)> {
    if buf.is_empty() { return Err(anyhow!("empty addr")); }
    let atyp = buf[0];
    match atyp {
        1 => { // IPv4
            if buf.len() < 1+4+2 { return Err(anyhow!("trunc ipv4")); }
            let ip = IpAddr::V4(Ipv4Addr::new(buf[1],buf[2],buf[3],buf[4]));
            let port = u16::from_be_bytes([buf[5],buf[6]]);
            Ok((ip.to_string(), port, 1+4+2))
        }
        3 => { // domain
            if buf.len() < 2 { return Err(anyhow!("trunc domain len")); }
            let dlen = buf[1] as usize;
            if buf.len() < 2 + dlen + 2 { return Err(anyhow!("trunc domain")); }
            let domain = String::from_utf8_lossy(&buf[2..2+dlen]).to_string();
            let port = u16::from_be_bytes([buf[2+dlen], buf[2+dlen+1]]);
            Ok((domain, port, 2+dlen+2))
        }
        4 => { // IPv6
            if buf.len() < 1+16+2 { return Err(anyhow!("trunc ipv6")); }
            let mut ipb = [0u8;16]; ipb.copy_from_slice(&buf[1..17]);
            let ip = IpAddr::V6(Ipv6Addr::from(ipb));
            let port = u16::from_be_bytes([buf[17], buf[18]]);
            Ok((ip.to_string(), port, 1+16+2))
        }
        _ => Err(anyhow!("bad atyp")),
    }
}

pub async fn serve(cfg: ShadowsocksInboundConfig, mut stop_rx: mpsc::Receiver<()>) -> Result<()> {
    let method = AeadCipherKind::from_method(&cfg.method).ok_or_else(|| anyhow!("unsupported method"))?;
    let master = evp_bytes_to_key(&cfg.password, method.key_len());

    let listener = TcpListener::bind(cfg.listen).await?;
    let actual = listener.local_addr().unwrap_or(cfg.listen);
    info!(addr=?cfg.listen, actual=?actual, "shadowsocks: inbound bound");

    let mut hb = interval(Duration::from_secs(5));
    loop {
        select! {
            _ = stop_rx.recv() => break,
            _ = hb.tick() => { tracing::debug!("shadowsocks: accept-loop heartbeat"); }
            r = listener.accept() => {
                let (mut cli, peer) = match r { Ok(v) => v, Err(e) => { warn!(error=%e, "ss: accept error"); continue; } };
                let cfg_clone = cfg.clone();
                let method_clone = method.clone();
                let master_clone = master.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_conn(&cfg_clone, method_clone, &master_clone, &mut cli, peer).await {
                        warn!(%peer, error=%e, "ss: session error");
                        let _ = cli.shutdown().await;
                    }
                });
            }
        }
    }
    Ok(())
}

async fn handle_conn(
    _cfg: &ShadowsocksInboundConfig,
    cipher: AeadCipherKind,
    master_key: &[u8],
    cli: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
    peer: SocketAddr,
) -> Result<()> {
    // Step 1: read client salt
    let csalt = read_exact_n(cli, cipher.salt_len()).await?;
    let c_subkey = hkdf_subkey(master_key, &csalt);
    let mut c_read_nonce: u64 = 0;

    // Step 2: read first AEAD chunk -> target address
    let first = read_aead_chunk(&cipher, &c_subkey, &mut c_read_nonce, cli).await?;
    let (host, port, _consumed) = parse_ss_addr(&first)?;

    // Step 3: router decision
    let mut decision = RDecision::Direct;
    if let Some(eng) = rules_global::global() {
        let ctx = RouteCtx { domain: Some(&host), ip: None, transport_udp: false, port: Some(port), process_name: None, process_path: None };
        let d = eng.decide(&ctx);
        if matches!(d, RDecision::Reject) { return Err(anyhow!("ss: rejected by rules")); }
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
                                http_proxy_connect_through_proxy(&ep.addr.to_string(), &host, port, &opts).await?
                            }
                            sb_core::outbound::endpoint::ProxyKind::Socks5 => {
                                socks5_connect_through_socks5(&ep.addr.to_string(), &host, port, &opts).await?
                            }
                        }
                    } else {
                        match proxy {
                            ProxyChoice::Direct => direct_connect_hostport(&host, port, &opts).await?,
                            ProxyChoice::Http(addr) => http_proxy_connect_through_proxy(addr, &host, port, &opts).await?,
                            ProxyChoice::Socks5(addr) => socks5_connect_through_socks5(addr, &host, port, &opts).await?,
                        }
                    }
                } else {
                    match proxy {
                        ProxyChoice::Direct => direct_connect_hostport(&host, port, &opts).await?,
                        ProxyChoice::Http(addr) => http_proxy_connect_through_proxy(addr, &host, port, &opts).await?,
                        ProxyChoice::Socks5(addr) => socks5_connect_through_socks5(addr, &host, port, &opts).await?,
                    }
                }
            } else {
                match proxy {
                    ProxyChoice::Direct => direct_connect_hostport(&host, port, &opts).await?,
                    ProxyChoice::Http(addr) => http_proxy_connect_through_proxy(addr, &host, port, &opts).await?,
                    ProxyChoice::Socks5(addr) => socks5_connect_through_socks5(addr, &host, port, &opts).await?,
                }
            }
        }
        RDecision::Proxy(None) => {
            match proxy {
                ProxyChoice::Direct => direct_connect_hostport(&host, port, &opts).await?,
                ProxyChoice::Http(addr) => http_proxy_connect_through_proxy(addr, &host, port, &opts).await?,
                ProxyChoice::Socks5(addr) => socks5_connect_through_socks5(addr, &host, port, &opts).await?,
            }
        }
        RDecision::Reject => unreachable!(),
    };

    // Step 4: server salt + data plane
    let ssalt = {
        let mut s = vec![0u8; cipher.salt_len()];
        use rand::Rng;
        rand::thread_rng().fill(&mut s[..]);
        s
    };
    let s_subkey = hkdf_subkey(master_key, &ssalt);
    let s_write_nonce: u64 = 0;

    // Send server salt first
    cli.write_all(&ssalt).await?;

    // Relay loops
    let (mut cr, mut cw) = tokio::io::split(cli);
    let (mut ur, mut uw) = tokio::io::split(&mut upstream);

    // Client->Upstream decrypt
    let cipher_cu = cipher.clone();
    let ckey = c_subkey.clone();
    let mut c_nonce = c_read_nonce;
    let cu = async move {
        loop {
            let chunk = match read_aead_chunk(&cipher_cu, &ckey, &mut c_nonce, &mut cr).await {
                Ok(v) => v,
                Err(_) => break,
            };
            if uw.write_all(&chunk).await.is_err() { break; }
        }
    };

    // Upstream->Client encrypt
    let cipher_uc = cipher.clone();
    let skey = s_subkey.clone();
    let mut s_nonce = s_write_nonce;
    let uc = async move {
        let mut buf = [0u8; 16384];
        loop {
            let n = match ur.read(&mut buf).await { Ok(n) => n, Err(_) => 0 };
            if n == 0 { break; }
            if write_aead_chunk(&cipher_uc, &skey, &mut s_nonce, &mut cw, &buf[..n]).await.is_err() { break; }
        }
    };

    tokio::join!(cu, uc);
    Ok(())
}
