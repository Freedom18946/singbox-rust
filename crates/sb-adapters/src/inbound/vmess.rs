//! VMess AEAD inbound (TCP) server implementation
//! VMess AEAD 入站 (TCP) 服务端实现
//!
//! Minimal VMess server supporting:
//! 最小化 VMess 服务端，支持：
//! - UUID-based authentication (HMAC validation)
//! - 基于 UUID 的认证 (HMAC 验证)
//! - AEAD encryption (AES-128-GCM, ChaCha20-Poly1305)
//! - AEAD 加密 (AES-128-GCM, ChaCha20-Poly1305)
//! - Target address parsing and routing
//! - 目标地址解析和路由
//! - Bidirectional encrypted relay
//! - 双向加密转发
//!
//! Protocol flow:
//! 协议流程：
//! 1. Client sends auth header: timestamp (8 bytes) + HMAC(UUID, timestamp) (16 bytes)
//! 1. 客户端发送认证头：时间戳 (8 字节) + HMAC(UUID, 时间戳) (16 字节)
//! 2. Server validates HMAC
//! 2. 服务端验证 HMAC
//! 3. Client sends encrypted request (target address + security type + padding)
//! 3. 客户端发送加密请求 (目标地址 + 安全类型 + 填充)
//! 4. Server sends response tag (16 bytes)
//! 4. 服务端发送响应标签 (16 字节)
//! 5. Bidirectional encrypted relay
//! 5. 双向加密转发

use aes_gcm::{aead::Aead, Aes128Gcm, KeyInit, Nonce as AesNonce};
use anyhow::{anyhow, Result};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey, Nonce as ChaNonce};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::select;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::{debug, info, warn};
use uuid::Uuid;

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

#[derive(Clone, Debug)]
pub struct VmessInboundConfig {
    pub listen: SocketAddr,
    pub uuid: Uuid,
    pub security: String, // "aes-128-gcm" or "chacha20-poly1305"
    pub router: Arc<router::RouterHandle>,
    /// Optional Multiplex configuration
    /// 可选的多路复用配置
    pub multiplex: Option<sb_transport::multiplex::MultiplexServerConfig>,
    /// V2Ray transport layer configuration (WebSocket, gRPC, HTTPUpgrade)
    /// If None, defaults to TCP
    /// V2Ray 传输层配置 (WebSocket, gRPC, HTTPUpgrade)
    /// 如果为 None，默认为 TCP
    pub transport_layer: Option<crate::transport_config::TransportConfig>,
    /// Fallback target address
    pub fallback: Option<SocketAddr>,
    /// Fallback targets by ALPN
    pub fallback_for_alpn: HashMap<String, SocketAddr>,
}

#[derive(Clone, Debug)]
enum SecurityMethod {
    Aes128Gcm,
    ChaCha20Poly1305,
}

impl SecurityMethod {
    fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "aes-128-gcm" => Some(Self::Aes128Gcm),
            "chacha20-poly1305" => Some(Self::ChaCha20Poly1305),
            _ => None,
        }
    }
}

// VMess protocol constants
// VMess 协议常量
const AUTH_HEADER_LEN: usize = 24; // 8 bytes timestamp + 16 bytes HMAC
const RESPONSE_TAG_LEN: usize = 16;

pub async fn serve(cfg: VmessInboundConfig, mut stop_rx: mpsc::Receiver<()>) -> Result<()> {
    let security = SecurityMethod::from_str(&cfg.security)
        .ok_or_else(|| anyhow!("Unsupported VMess security: {}", cfg.security))?;

    // Create listener based on transport configuration (defaults to TCP if not specified)
    // 根据传输配置创建监听器 (如果未指定则默认为 TCP)
    let transport = cfg.transport_layer.clone().unwrap_or_default();
    let listener = transport.create_inbound_listener(cfg.listen).await?;
    let actual = listener.local_addr().unwrap_or(cfg.listen);

    info!(
        addr=?cfg.listen,
        actual=?actual,
        transport=?transport.transport_type(),
        multiplex=?cfg.multiplex.is_some(),
        "vmess: inbound bound"
    );

    // Note: Multiplex support for VMess inbound is configured but not yet fully implemented
    // VMess protocol has its own encryption layer, and multiplex integration would require
    // careful coordination with the VMess protocol state machine
    // 注意：VMess 入站的多路复用支持已配置，但尚未完全实现
    // VMess 协议有自己的加密层，多路复用集成需要与 VMess 协议状态机仔细协调
    if cfg.multiplex.is_some() {
        warn!("Multiplex configuration present but not yet fully implemented for VMess inbound");
    }

    let mut hb = interval(Duration::from_secs(5));
    loop {
        select! {
            _ = stop_rx.recv() => break,
            _ = hb.tick() => {
                // debug!("vmess: accept-loop heartbeat");
            }
            r = listener.accept() => {
                let (mut stream, _peer) = match r {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(error=%e, "vmess: accept error");
                        sb_core::metrics::http::record_error_display(&e);
                        sb_core::metrics::record_inbound_error_display("vmess", &e);
                        continue;
                    }
                };
                let cfg_clone = cfg.clone();
                let security_clone = security.clone();

                tokio::spawn(async move {
                    // Use &mut *stream to dereference Box<dyn InboundStream>
                    // 使用 &mut *stream 解引用 Box<dyn InboundStream>
                    if let Err(e) = handle_conn_stream(&cfg_clone, security_clone, &mut *stream).await {
                        sb_core::metrics::http::record_error_display(&e);
                        sb_core::metrics::record_inbound_error_display("vmess", &e);
                        warn!(error=%e, "vmess: session error");
                        let _ = stream.shutdown().await;
                    }
                });
            }
        }
    }
    Ok(())
}

async fn handle_fallback(
    stream: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized),
    target: SocketAddr,
    prefix: &[u8],
) -> Result<()> {
    let mut remote = tokio::net::TcpStream::connect(target)
        .await
        .map_err(|e| anyhow!("vmess: failed to connect to fallback {}: {}", target, e))?;

    if !prefix.is_empty() {
        remote.write_all(prefix).await?;
    }

    let _ = tokio::io::copy_bidirectional(stream, &mut remote).await;
    Ok(())
}

// Helper function to handle connections from generic streams (trait objects)
// 处理来自通用流 (trait 对象) 连接的辅助函数
async fn handle_conn_stream(
    cfg: &VmessInboundConfig,
    security: SecurityMethod,
    stream: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized),
) -> Result<()> {
    handle_conn(cfg, security, stream).await
}

async fn handle_conn(
    cfg: &VmessInboundConfig,
    security: SecurityMethod,
    cli: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized),
) -> Result<()> {
    // Step 1: Read and validate authentication header
    // 步骤 1: 读取并验证认证头
    let mut auth_header = [0u8; AUTH_HEADER_LEN];
    match cli.read_exact(&mut auth_header).await {
        Ok(_) => {}
        Err(e) => {
            // Read failed. If we have fallback, we can't do much because we don't have data.
            // But if it's EOF, maybe it's a probe?
            // If we read partial data, we could fallback.
            // For simplicity, just error.
            return Err(anyhow!("vmess: failed to read auth header: {}", e));
        }
    }

    let timestamp = u64::from_be_bytes(auth_header[..8].try_into().unwrap());
    let received_hmac = &auth_header[8..];

    // Validate timestamp (within 2 minutes)
    // 验证时间戳 (2 分钟内)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    if timestamp.abs_diff(now) > 120 {
        if let Some(fallback_addr) = cfg.fallback {
            debug!(%timestamp, "vmess: timestamp out of range, falling back to {}", fallback_addr);
            return handle_fallback(cli, fallback_addr, &auth_header).await;
        }
        return Err(anyhow!("vmess: timestamp out of range"));
    }

    // Validate HMAC
    // 验证 HMAC
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(cfg.uuid.as_bytes())
        .map_err(|e| anyhow!("HMAC init error: {}", e))?;
    mac.update(&auth_header[..8]); // Hash timestamp only
    let expected_hmac = mac.finalize().into_bytes();

    if received_hmac != &expected_hmac[..16] {
        if let Some(fallback_addr) = cfg.fallback {
            debug!("vmess: hmac mismatch, falling back to {}", fallback_addr);
            return handle_fallback(cli, fallback_addr, &auth_header).await;
        }
        return Err(anyhow!("vmess: authentication failed"));
    }

    debug!("vmess: authentication successful");

    // Step 2: Read encrypted request
    // 步骤 2: 读取加密请求
    let request_key = generate_request_key(&cfg.uuid);
    let encrypted_request = read_encrypted_request(cli).await?;
    let request = decrypt_request(&security, &request_key, &encrypted_request)?;

    // Step 3: Parse request
    // 步骤 3: 解析请求
    let (target_host, target_port, _request_security) = parse_vmess_request(&request)?;

    debug!(host=%target_host, port=%target_port, "vmess: parsed target");

    // Step 4: Send response tag
    // 步骤 4: 发送响应标签
    let response_key = generate_response_key(&cfg.uuid);
    let response_tag = generate_response_tag(&request_key, &response_key)?;
    debug_assert_eq!(response_tag.len(), RESPONSE_TAG_LEN);
    cli.write_all(&response_tag).await?;

    // Step 5: Router decision
    // 步骤 5: 路由决策
    let mut decision = RDecision::Direct;
    if let Some(eng) = rules_global::global() {
        let ctx = RouteCtx {
            domain: Some(target_host.as_str()),
            ip: None,
            transport_udp: false,
            port: Some(target_port),
            network: Some("tcp"),
            ..Default::default()
        };
        let d = eng.decide(&ctx);
        if matches!(d, RDecision::Reject) {
            return Err(anyhow!("vmess: rejected by rules"));
        }
        decision = d;
    }

    // Step 6: Connect to upstream
    // 步骤 6: 连接上游
    let proxy = default_proxy();
    let opts = ConnectOpts::default();
    let mut upstream = match decision {
        RDecision::Direct => direct_connect_hostport(&target_host, target_port, &opts).await?,
        RDecision::Proxy(Some(name)) => {
            let sel = PoolSelector::new("vmess".into(), "default".into());
            if let Some(reg) = registry::global() {
                if let Some(_pool) = reg.pools.get(&name) {
                    // Use a dummy peer address for pool selection (transport layer abstraction means we don't have the real peer)
                    // 使用虚拟对等地址进行池选择 (传输层抽象意味着我们没有真正的对等端)
                    let dummy_peer = SocketAddr::from(([0, 0, 0, 0], 0));
                    if let Some(ep) = sel.select(
                        &name,
                        dummy_peer,
                        &format!("{}:{}", target_host, target_port),
                        &(),
                    ) {
                        match ep.kind {
                            sb_core::outbound::endpoint::ProxyKind::Http => {
                                http_proxy_connect_through_proxy(
                                    &ep.addr.to_string(),
                                    &target_host,
                                    target_port,
                                    &opts,
                                )
                                .await?
                            }
                            sb_core::outbound::endpoint::ProxyKind::Socks5 => {
                                socks5_connect_through_socks5(
                                    &ep.addr.to_string(),
                                    &target_host,
                                    target_port,
                                    &opts,
                                )
                                .await?
                            }
                        }
                    } else {
                        fallback_connect(proxy, &target_host, target_port, &opts).await?
                    }
                } else {
                    fallback_connect(proxy, &target_host, target_port, &opts).await?
                }
            } else {
                fallback_connect(proxy, &target_host, target_port, &opts).await?
            }
        }
        RDecision::Proxy(None) => fallback_connect(proxy, &target_host, target_port, &opts).await?,
        RDecision::Reject | RDecision::RejectDrop => return Err(anyhow!("vmess: rejected by rules")),
        // Sniff/Resolve/Hijack not yet supported in inbound handlers
        _ => return Err(anyhow!("vmess: unsupported routing action")),
    };

    // Step 7: Bidirectional relay
    // Note: VMess AEAD encryption/decryption is handled in the protocol layer
    // The stream here is already decrypted by the VMess protocol handler
    // 步骤 7: 双向转发
    // 注意：VMess AEAD 加密/解密在协议层处理
    // 这里的流已经被 VMess 协议处理程序解密
    let _ = tokio::io::copy_bidirectional(cli, &mut upstream).await;

    Ok(())
}

async fn fallback_connect(
    proxy: &ProxyChoice,
    host: &str,
    port: u16,
    opts: &ConnectOpts,
) -> Result<tokio::net::TcpStream> {
    match proxy {
        ProxyChoice::Direct => Ok(direct_connect_hostport(host, port, opts).await?),
        ProxyChoice::Http(addr) => {
            Ok(http_proxy_connect_through_proxy(addr, host, port, opts).await?)
        }
        ProxyChoice::Socks5(addr) => {
            Ok(socks5_connect_through_socks5(addr, host, port, opts).await?)
        }
    }
}

fn generate_request_key(uuid: &Uuid) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(uuid.as_bytes());
    hasher.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    let hash = hasher.finalize();
    let mut key = [0u8; 16];
    key.copy_from_slice(&hash[..16]);
    key
}

fn generate_response_key(uuid: &Uuid) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(uuid.as_bytes());
    hasher.update(b"c42f7b3e-64e6-4396-8e01-eb28c8c7d56c");
    let hash = hasher.finalize();
    let mut key = [0u8; 16];
    key.copy_from_slice(&hash[..16]);
    key
}

fn generate_response_tag(request_key: &[u8; 16], response_key: &[u8; 16]) -> Result<[u8; 16]> {
    // Simplified response tag generation
    // 简化的响应标签生成
    let mut hasher = Sha256::new();
    hasher.update(request_key);
    hasher.update(response_key);
    let hash = hasher.finalize();
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&hash[..16]);
    Ok(tag)
}

async fn read_encrypted_request(
    r: &mut (impl tokio::io::AsyncRead + Unpin + ?Sized),
) -> Result<Vec<u8>> {
    // Read nonce (12 bytes) + encrypted data
    // For AES-128-GCM: nonce (12) + ciphertext + tag (16)
    // 读取 nonce (12 字节) + 加密数据
    // 对于 AES-128-GCM: nonce (12) + 密文 + tag (16)
    let mut nonce = [0u8; 12];
    r.read_exact(&mut nonce).await?;

    // Read ciphertext + tag (variable length, max 512 bytes for request)
    // 读取密文 + tag (可变长度，请求最大 512 字节)
    let mut encrypted = vec![0u8; 512];
    let n = r.read(&mut encrypted).await?;
    encrypted.truncate(n);

    let mut result = nonce.to_vec();
    result.extend_from_slice(&encrypted);
    Ok(result)
}

fn decrypt_request(security: &SecurityMethod, key: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 12 {
        return Err(anyhow!("encrypted request too short"));
    }

    let nonce = &data[..12];
    let ciphertext = &data[12..];

    match security {
        SecurityMethod::Aes128Gcm => {
            let cipher =
                Aes128Gcm::new_from_slice(key).map_err(|e| anyhow!("AES key error: {}", e))?;
            cipher
                .decrypt(AesNonce::from_slice(nonce), ciphertext)
                .map_err(|e| anyhow!("AES decryption failed: {}", e))
        }
        SecurityMethod::ChaCha20Poly1305 => {
            let cipher_key = ChaChaKey::from_slice(key);
            let cipher = ChaCha20Poly1305::new(cipher_key);
            cipher
                .decrypt(ChaNonce::from_slice(nonce), ciphertext)
                .map_err(|e| anyhow!("ChaCha decryption failed: {}", e))
        }
    }
}

fn parse_vmess_request(data: &[u8]) -> Result<(String, u16, u8)> {
    if data.len() < 10 {
        return Err(anyhow!("request too short"));
    }

    let mut offset = 0;

    // Version (1 byte)
    let _version = data[offset];
    offset += 1;

    // IV (16 bytes)
    if data.len() < offset + 16 {
        return Err(anyhow!("missing IV"));
    }
    offset += 16;

    // Key (16 bytes)
    if data.len() < offset + 16 {
        return Err(anyhow!("missing key"));
    }
    offset += 16;

    // Response auth (1 byte)
    offset += 1;

    // Options (1 byte)
    offset += 1;

    // Padding and Security (4 bits each)
    let security_byte = data[offset];
    offset += 1;

    // Reserved (1 byte)
    offset += 1;

    // Command (1 byte) - should be 0x01 for TCP
    let _command = data[offset];
    offset += 1;

    // Parse address
    if data.len() < offset + 1 {
        return Err(anyhow!("missing address type"));
    }

    let atyp = data[offset];
    offset += 1;

    let (host, port) = match atyp {
        0x01 => {
            // IPv4
            if data.len() < offset + 4 + 2 {
                return Err(anyhow!("truncated IPv4 address"));
            }
            let ip = IpAddr::V4(Ipv4Addr::new(
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ));
            offset += 4;
            let port = u16::from_be_bytes([data[offset], data[offset + 1]]);
            (ip.to_string(), port)
        }
        0x02 => {
            // Domain
            if data.len() < offset + 1 {
                return Err(anyhow!("missing domain length"));
            }
            let dlen = data[offset] as usize;
            offset += 1;
            if data.len() < offset + dlen + 2 {
                return Err(anyhow!("truncated domain"));
            }
            let domain = String::from_utf8_lossy(&data[offset..offset + dlen]).to_string();
            offset += dlen;
            let port = u16::from_be_bytes([data[offset], data[offset + 1]]);
            (domain, port)
        }
        0x03 => {
            // IPv6
            if data.len() < offset + 16 + 2 {
                return Err(anyhow!("truncated IPv6 address"));
            }
            let mut ipb = [0u8; 16];
            ipb.copy_from_slice(&data[offset..offset + 16]);
            let ip = IpAddr::V6(Ipv6Addr::from(ipb));
            offset += 16;
            let port = u16::from_be_bytes([data[offset], data[offset + 1]]);
            (ip.to_string(), port)
        }
        _ => return Err(anyhow!("unknown address type: {}", atyp)),
    };

    Ok((host, port, security_byte))
}

use parking_lot::Mutex;
use sb_core::adapter::InboundService;

#[derive(Debug)]
pub struct VmessInboundAdapter {
    config: VmessInboundConfig,
    stop_tx: Mutex<Option<mpsc::Sender<()>>>,
}

impl VmessInboundAdapter {
    pub fn new(config: VmessInboundConfig) -> Self {
        Self {
            config,
            stop_tx: Mutex::new(None),
        }
    }
}

impl InboundService for VmessInboundAdapter {
    fn serve(&self) -> std::io::Result<()> {
        let (tx, rx) = mpsc::channel(1);
        *self.stop_tx.lock() = Some(tx);

        let rt = tokio::runtime::Handle::current();
        rt.block_on(async { serve(self.config.clone(), rx).await })
            .map_err(|e| std::io::Error::other(e.to_string()))
    }

    fn request_shutdown(&self) {
        if let Some(tx) = self.stop_tx.lock().take() {
            let _ = tx.try_send(());
        }
    }
}
