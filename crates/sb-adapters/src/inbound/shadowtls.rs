//! ShadowTLS inbound (transport-wrapper server) implementation.
//!
//! This models ShadowTLS as a transport wrapper that authenticates/masks the
//! incoming TCP stream and then hands the recovered raw stream to a detour
//! inbound. The first supported consumer is Shadowsocks inbound.

use crate::inbound::shadowsocks::ShadowsocksInboundAdapter;
use anyhow::{anyhow, Context, Result};
use hmac::{Hmac, Mac};
use sb_core::adapter::{registry, InboundService};
use sb_core::router;
use sb_core::services::v2ray_api::StatsManager;
use serde::Deserialize;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io as std_io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io::{
    copy_bidirectional, duplex, split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt,
    DuplexStream, ReadBuf, ReadHalf, WriteHalf,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::select;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{interval, Duration};
use tracing::{info, warn};

type HmacSha1 = Hmac<Sha1>;

const TLS_HEADER_SIZE: usize = 5;
const TLS_RANDOM_SIZE: usize = 32;
const TLS_SESSION_ID_SIZE: usize = 32;
const SHADOWTLS_V3_HMAC_SIZE: usize = 4;
const HANDSHAKE: u8 = 22;
const ALERT: u8 = 21;
const APPLICATION_DATA: u8 = 23;
const CLIENT_HELLO: u8 = 1;
const SERVER_HELLO: u8 = 2;

#[derive(Clone, Debug, Deserialize)]
pub struct ShadowTlsUser {
    #[serde(default)]
    pub name: Option<String>,
    pub password: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ShadowTlsHandshakeConfig {
    pub server: String,
    #[serde(rename = "server_port")]
    pub server_port: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShadowTlsWildcardSniMode {
    Off,
    Authed,
    All,
}

impl ShadowTlsWildcardSniMode {
    pub fn parse(value: Option<&str>) -> Result<Self> {
        match value.unwrap_or("off").to_ascii_lowercase().as_str() {
            "" | "off" => Ok(Self::Off),
            "authed" => Ok(Self::Authed),
            "all" => Ok(Self::All),
            other => Err(anyhow!("unsupported wildcard_sni mode '{other}'")),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ShadowTlsInboundConfig {
    pub listen: SocketAddr,
    pub detour: String,
    pub version: u8,
    pub password: Option<String>,
    pub users: Vec<ShadowTlsUser>,
    pub handshake: Option<ShadowTlsHandshakeConfig>,
    pub handshake_for_server_name: HashMap<String, ShadowTlsHandshakeConfig>,
    pub strict_mode: bool,
    pub wildcard_sni: ShadowTlsWildcardSniMode,
    pub tag: Option<String>,
    // Legacy fields kept for compatibility with older constructors; ignored by
    // the runtime remodel implementation.
    pub tls: Option<sb_transport::TlsConfig>,
    pub router: Option<Arc<router::RouterHandle>>,
    pub stats: Option<Arc<StatsManager>>,
}

pub async fn serve(cfg: ShadowTlsInboundConfig, mut stop_rx: mpsc::Receiver<()>) -> Result<()> {
    let listener = TcpListener::bind(cfg.listen).await?;
    let actual = listener.local_addr().unwrap_or(cfg.listen);
    info!(
        addr = ?cfg.listen,
        actual = ?actual,
        detour = %cfg.detour,
        version = cfg.version,
        "shadowtls: inbound bound"
    );

    let mut hb = interval(Duration::from_secs(5));
    loop {
        select! {
            _ = stop_rx.recv() => break,
            _ = hb.tick() => {}
            r = listener.accept() => {
                let (stream, peer) = match r {
                    Ok(v) => v,
                    Err(err) => {
                        sb_core::metrics::record_inbound_error_display("shadowtls", &err);
                        warn!(error=%err, "shadowtls: accept error");
                        continue;
                    }
                };
                let cfg_clone = cfg.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_conn(cfg_clone, stream, peer).await {
                        sb_core::metrics::record_inbound_error_display("shadowtls", &err);
                        warn!(%peer, error=%err, "shadowtls: session error");
                    }
                });
            }
        }
    }
    Ok(())
}

async fn handle_conn(
    cfg: ShadowTlsInboundConfig,
    stream: TcpStream,
    peer: SocketAddr,
) -> Result<()> {
    match cfg.version {
        2 => handle_v2(cfg, stream, peer).await,
        3 => handle_v3(cfg, stream, peer).await,
        1 => Err(anyhow!(
            "shadowtls inbound version 1 runtime remodel is not implemented; use version 2/3 detour mode"
        )),
        other => Err(anyhow!("unsupported shadowtls inbound version {other}")),
    }
}

async fn handle_v2(
    cfg: ShadowTlsInboundConfig,
    mut stream: TcpStream,
    peer: SocketAddr,
) -> Result<()> {
    let password = cfg
        .password
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("shadowtls inbound v2 requires password"))?;
    let client_hello = extract_frame(&mut stream).await?;
    let server_name = extract_server_name(&client_hello).ok();
    let handshake = select_v2_handshake(&cfg, server_name.as_deref())?;
    let handshake_conn = dial_handshake_target(&handshake).await?;

    let (cli_read, cli_write) = split(stream);
    let (hs_read, mut hs_write) = split(handshake_conn);
    let mut client_reader = PrefixStream::new(client_hello, cli_read);
    let hash_state = Arc::new(Mutex::new(V2HashState::new(password)));
    let (stop_tx, stop_rx) = oneshot::channel();
    let server_task = tokio::spawn(relay_server_to_client_hash(
        hs_read,
        cli_write,
        hash_state.clone(),
        stop_rx,
    ));

    match copy_until_handshake_finished_v2(&mut client_reader, &mut hs_write, hash_state.clone(), 2)
        .await
    {
        Ok(first_payload) => {
            let _ = stop_tx.send(());
            let (_hs_read, cli_write) = await_server_task(server_task).await?;
            let local = spawn_v2_bridge(client_reader.into_inner(), cli_write, first_payload);
            dispatch_detour_stream(&cfg.detour, local, peer).await
        }
        Err(err) if err.kind() == std_io::ErrorKind::PermissionDenied => {
            {
                let mut guard = hash_state.lock().unwrap();
                guard.disable();
            }
            let _ = stop_tx.send(());
            let (hs_read, cli_write) = await_server_task(server_task).await?;
            let mut client_stream = SplitStream::new(client_reader, cli_write);
            let mut server_stream = SplitStream::new(hs_read, hs_write);
            copy_bidirectional(&mut client_stream, &mut server_stream).await?;
            Ok(())
        }
        Err(err) => {
            let _ = stop_tx.send(());
            let _ = server_task.await;
            Err(err.into())
        }
    }
}

async fn handle_v3(
    cfg: ShadowTlsInboundConfig,
    mut stream: TcpStream,
    peer: SocketAddr,
) -> Result<()> {
    let client_hello = extract_frame(&mut stream).await?;
    let server_name = extract_server_name(&client_hello).context("extract server name")?;
    let chosen = select_v3_handshake(&cfg, &server_name)?;
    let user = verify_client_hello(&client_hello, &cfg.users);
    if let Some(user) = user {
        let mut handshake_conn = dial_handshake_target(&chosen.target).await?;
        handshake_conn.write_all(&client_hello).await?;

        let server_hello = extract_frame(&mut handshake_conn).await?;
        let server_random =
            extract_server_random(&server_hello).ok_or_else(|| anyhow!("missing server random"))?;
        let tls13 = server_hello_supports_tls13(&server_hello);

        let (cli_read, mut cli_write) = split(stream);
        cli_write.write_all(&server_hello).await?;
        if cfg.strict_mode && !tls13 {
            let mut client_stream = SplitStream::new(cli_read, cli_write);
            let mut server_stream = handshake_conn;
            copy_bidirectional(&mut client_stream, &mut server_stream).await?;
            return Ok(());
        }

        let (hs_read, mut hs_write) = split(handshake_conn);
        let (stop_tx, stop_rx) = oneshot::channel();
        let server_task = tokio::spawn(relay_v3_server_handshake(
            hs_read,
            cli_write,
            user.password.clone(),
            server_random,
            stop_rx,
        ));

        let mut verify_state = new_v3_client_verify_state(&user.password, server_random);
        let (cli_read, first_payload, verify_state) =
            copy_until_v3_authenticated(cli_read, &mut hs_write, &mut verify_state).await?;
        let _ = stop_tx.send(());
        let (_hs_read, cli_write) = await_server_task(server_task).await?;
        let local = spawn_v3_bridge(
            cli_read,
            cli_write,
            first_payload,
            verify_state,
            new_v3_server_add_state(&user.password, server_random),
        );
        dispatch_detour_stream(&cfg.detour, local, peer).await
    } else {
        let fallback_target = fallback_v3_handshake(&cfg, chosen)?;
        let mut handshake_conn = dial_handshake_target(&fallback_target).await?;
        let mut client_stream = PrefixStream::new(client_hello, stream);
        copy_bidirectional(&mut client_stream, &mut handshake_conn).await?;
        Ok(())
    }
}

async fn dispatch_detour_stream<S>(tag: &str, stream: S, peer: SocketAddr) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if tag.trim().is_empty() {
        return Err(anyhow!(
            "shadowtls: proxy decision without outbound tag is unsupported; implicit fallback is disabled; provide explicit outbound in routing"
        ));
    }
    let runtime = registry::runtime_inbounds()
        .ok_or_else(|| {
            anyhow!(
                "shadowtls: named proxy decision '{}' cannot be resolved because registry is unavailable; implicit fallback is disabled; use adapter bridge/supervisor path; implicit direct fallback is disabled",
                tag
            )
        })?;
    let service = runtime
        .get(tag)
        .ok_or_else(|| {
            anyhow!(
                "shadowtls: named proxy decision '{}' not found in registry; implicit fallback is disabled; use adapter bridge/supervisor path",
                tag
            )
        })?;
    if let Some(adapter) = service
        .as_any()
        .and_then(|any| any.downcast_ref::<ShadowsocksInboundAdapter>())
    {
        adapter.accept_detour_stream(stream, peer).await
    } else {
        Err(anyhow!(
            "shadowtls: named proxy decision '{}' has no selectable endpoint; implicit fallback is disabled; use adapter bridge/supervisor path",
            tag
        ))
    }
}

async fn dial_handshake_target(target: &ShadowTlsHandshakeConfig) -> Result<TcpStream> {
    TcpStream::connect((target.server.as_str(), target.server_port))
        .await
        .with_context(|| {
            format!(
                "connect handshake target {}:{}",
                target.server, target.server_port
            )
        })
}

fn select_v2_handshake(
    cfg: &ShadowTlsInboundConfig,
    server_name: Option<&str>,
) -> Result<ShadowTlsHandshakeConfig> {
    if let Some(server_name) = server_name {
        if let Some(custom) = cfg.handshake_for_server_name.get(server_name) {
            return Ok(custom.clone());
        }
    }
    default_handshake(cfg)
}

fn default_handshake(cfg: &ShadowTlsInboundConfig) -> Result<ShadowTlsHandshakeConfig> {
    cfg.handshake
        .clone()
        .ok_or_else(|| anyhow!("shadowtls inbound requires handshake target"))
}

struct SelectedV3Handshake {
    target: ShadowTlsHandshakeConfig,
    is_custom: bool,
}

fn select_v3_handshake(
    cfg: &ShadowTlsInboundConfig,
    server_name: &str,
) -> Result<SelectedV3Handshake> {
    if let Some(custom) = cfg.handshake_for_server_name.get(server_name) {
        return Ok(SelectedV3Handshake {
            target: custom.clone(),
            is_custom: true,
        });
    }
    if cfg.wildcard_sni != ShadowTlsWildcardSniMode::Off {
        return Ok(SelectedV3Handshake {
            target: ShadowTlsHandshakeConfig {
                server: server_name.to_string(),
                server_port: 443,
            },
            is_custom: false,
        });
    }
    Ok(SelectedV3Handshake {
        target: default_handshake(cfg)?,
        is_custom: false,
    })
}

fn fallback_v3_handshake(
    cfg: &ShadowTlsInboundConfig,
    chosen: SelectedV3Handshake,
) -> Result<ShadowTlsHandshakeConfig> {
    if chosen.is_custom || cfg.wildcard_sni == ShadowTlsWildcardSniMode::All {
        Ok(chosen.target)
    } else {
        default_handshake(cfg)
    }
}

struct VerifiedUser {
    password: String,
}

fn verify_client_hello(frame: &[u8], users: &[ShadowTlsUser]) -> Option<VerifiedUser> {
    let session_id_length_index = TLS_HEADER_SIZE + 1 + 3 + 2 + TLS_RANDOM_SIZE;
    let hmac_index = session_id_length_index + 1 + TLS_SESSION_ID_SIZE - SHADOWTLS_V3_HMAC_SIZE;
    if frame.len() < hmac_index + SHADOWTLS_V3_HMAC_SIZE {
        return None;
    }
    if frame.first().copied()? != HANDSHAKE || frame.get(TLS_HEADER_SIZE).copied()? != CLIENT_HELLO
    {
        return None;
    }
    if frame.get(session_id_length_index).copied()? != TLS_SESSION_ID_SIZE as u8 {
        return None;
    }
    for user in users {
        let mut hmac = HmacSha1::new_from_slice(user.password.as_bytes()).ok()?;
        hmac.update(&frame[TLS_HEADER_SIZE..hmac_index]);
        hmac.update(&[0, 0, 0, 0]);
        hmac.update(&frame[hmac_index + SHADOWTLS_V3_HMAC_SIZE..]);
        if hmac.finalize().into_bytes()[..SHADOWTLS_V3_HMAC_SIZE]
            == frame[hmac_index..hmac_index + SHADOWTLS_V3_HMAC_SIZE]
        {
            return Some(VerifiedUser {
                password: user.password.clone(),
            });
        }
    }
    None
}

async fn extract_frame<R>(reader: &mut R) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; TLS_HEADER_SIZE];
    reader.read_exact(&mut header).await?;
    let length = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut frame = Vec::with_capacity(TLS_HEADER_SIZE + length);
    frame.extend_from_slice(&header);
    frame.resize(TLS_HEADER_SIZE + length, 0);
    reader.read_exact(&mut frame[TLS_HEADER_SIZE..]).await?;
    Ok(frame)
}

fn extract_server_name(frame: &[u8]) -> Result<String> {
    if frame.len() < TLS_HEADER_SIZE + 4 + 2 + TLS_RANDOM_SIZE + 1 {
        return Err(anyhow!("client hello too short"));
    }
    if frame[0] != HANDSHAKE || frame[TLS_HEADER_SIZE] != CLIENT_HELLO {
        return Err(anyhow!("not a client hello"));
    }

    let mut cursor = TLS_HEADER_SIZE + 4 + 2 + TLS_RANDOM_SIZE;
    let session_id_len = *frame
        .get(cursor)
        .ok_or_else(|| anyhow!("missing session id length"))? as usize;
    cursor += 1 + session_id_len;
    let cipher_len = u16::from_be_bytes([
        *frame
            .get(cursor)
            .ok_or_else(|| anyhow!("missing cipher length"))?,
        *frame
            .get(cursor + 1)
            .ok_or_else(|| anyhow!("missing cipher length"))?,
    ]) as usize;
    cursor += 2 + cipher_len;
    let compression_len = *frame
        .get(cursor)
        .ok_or_else(|| anyhow!("missing compression length"))? as usize;
    cursor += 1 + compression_len;
    let extensions_len = u16::from_be_bytes([
        *frame
            .get(cursor)
            .ok_or_else(|| anyhow!("missing extensions length"))?,
        *frame
            .get(cursor + 1)
            .ok_or_else(|| anyhow!("missing extensions length"))?,
    ]) as usize;
    cursor += 2;
    let end = cursor + extensions_len;
    while cursor + 4 <= end && end <= frame.len() {
        let ext_type = u16::from_be_bytes([frame[cursor], frame[cursor + 1]]);
        let ext_len = u16::from_be_bytes([frame[cursor + 2], frame[cursor + 3]]) as usize;
        cursor += 4;
        if cursor + ext_len > frame.len() {
            return Err(anyhow!("truncated extension"));
        }
        if ext_type == 0 {
            if ext_len < 5 {
                return Err(anyhow!("truncated server_name extension"));
            }
            let list_len = u16::from_be_bytes([frame[cursor], frame[cursor + 1]]) as usize;
            if cursor + 2 + list_len > frame.len() {
                return Err(anyhow!("truncated server_name list"));
            }
            let name_type = frame[cursor + 2];
            if name_type != 0 {
                return Err(anyhow!("unsupported server_name type"));
            }
            let name_len = u16::from_be_bytes([frame[cursor + 3], frame[cursor + 4]]) as usize;
            let name_start = cursor + 5;
            let name_end = name_start + name_len;
            if name_end > frame.len() {
                return Err(anyhow!("truncated server_name"));
            }
            return Ok(String::from_utf8(frame[name_start..name_end].to_vec())?);
        }
        cursor += ext_len;
    }
    Err(anyhow!("server_name extension missing"))
}

fn extract_server_random(frame: &[u8]) -> Option<[u8; TLS_RANDOM_SIZE]> {
    if frame.len() < TLS_HEADER_SIZE + 4 + 2 + TLS_RANDOM_SIZE {
        return None;
    }
    if frame[0] != HANDSHAKE || frame[TLS_HEADER_SIZE] != SERVER_HELLO {
        return None;
    }
    let mut random = [0u8; TLS_RANDOM_SIZE];
    random.copy_from_slice(
        &frame[TLS_HEADER_SIZE + 4 + 2..TLS_HEADER_SIZE + 4 + 2 + TLS_RANDOM_SIZE],
    );
    Some(random)
}

fn server_hello_supports_tls13(frame: &[u8]) -> bool {
    if frame.len() < TLS_HEADER_SIZE + 4 + 2 + TLS_RANDOM_SIZE + 1 {
        return false;
    }
    let mut cursor = TLS_HEADER_SIZE + 4 + 2 + TLS_RANDOM_SIZE;
    let session_id_len = match frame.get(cursor) {
        Some(value) => *value as usize,
        None => return false,
    };
    cursor += 1 + session_id_len + 2 + 1;
    if cursor + 2 > frame.len() {
        return false;
    }
    let extensions_len = u16::from_be_bytes([frame[cursor], frame[cursor + 1]]) as usize;
    cursor += 2;
    let end = cursor + extensions_len;
    while cursor + 4 <= end && end <= frame.len() {
        let ext_type = u16::from_be_bytes([frame[cursor], frame[cursor + 1]]);
        let ext_len = u16::from_be_bytes([frame[cursor + 2], frame[cursor + 3]]) as usize;
        cursor += 4;
        if cursor + ext_len > frame.len() {
            return false;
        }
        if ext_type == 43 && ext_len == 2 {
            return u16::from_be_bytes([frame[cursor], frame[cursor + 1]]) == 0x0304;
        }
        cursor += ext_len;
    }
    false
}

#[derive(Default)]
struct PrefixStream<T> {
    prefix: Vec<u8>,
    offset: usize,
    inner: T,
}

impl<T> PrefixStream<T> {
    fn new(prefix: Vec<u8>, inner: T) -> Self {
        Self {
            prefix,
            offset: 0,
            inner,
        }
    }

    fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for PrefixStream<T> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std_io::Result<()>> {
        if self.offset < self.prefix.len() {
            let remaining = &self.prefix[self.offset..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.offset += to_copy;
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for PrefixStream<T> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std_io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std_io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std_io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct SplitStream<R, W> {
    reader: R,
    writer: W,
}

impl<R, W> SplitStream<R, W> {
    fn new(reader: R, writer: W) -> Self {
        Self { reader, writer }
    }
}

impl<R: AsyncRead + Unpin, W: Unpin> AsyncRead for SplitStream<R, W> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std_io::Result<()>> {
        std::pin::Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl<R: Unpin, W: AsyncWrite + Unpin> AsyncWrite for SplitStream<R, W> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std_io::Result<usize>> {
        std::pin::Pin::new(&mut self.writer).poll_write(cx, data)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std_io::Result<()>> {
        std::pin::Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std_io::Result<()>> {
        std::pin::Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

struct V2HashState {
    hasher: HmacSha1,
    last_sum: Option<[u8; 8]>,
    has_content: bool,
    enabled: bool,
}

impl V2HashState {
    fn new(password: &str) -> Self {
        Self {
            hasher: HmacSha1::new_from_slice(password.as_bytes()).expect("hmac init"),
            last_sum: None,
            has_content: false,
            enabled: true,
        }
    }

    fn update(&mut self, chunk: &[u8]) {
        if !self.enabled {
            return;
        }
        if self.has_content {
            self.last_sum = self.current_sum();
        }
        self.hasher.update(chunk);
        self.has_content = true;
    }

    fn current_sum(&self) -> Option<[u8; 8]> {
        if !self.enabled || !self.has_content {
            return None;
        }
        let digest = self.hasher.clone().finalize().into_bytes();
        let mut out = [0u8; 8];
        out.copy_from_slice(&digest[..8]);
        Some(out)
    }

    fn last_sum(&self) -> Option<[u8; 8]> {
        self.last_sum
    }

    fn disable(&mut self) {
        self.enabled = false;
    }
}

async fn relay_server_to_client_hash(
    mut hs_read: ReadHalf<TcpStream>,
    mut cli_write: WriteHalf<TcpStream>,
    hash_state: Arc<Mutex<V2HashState>>,
    mut stop_rx: oneshot::Receiver<()>,
) -> std_io::Result<(ReadHalf<TcpStream>, WriteHalf<TcpStream>)> {
    let mut buf = [0u8; 16 * 1024];
    loop {
        select! {
            _ = &mut stop_rx => return Ok((hs_read, cli_write)),
            read = hs_read.read(&mut buf) => {
                let n = read?;
                if n == 0 {
                    return Ok((hs_read, cli_write));
                }
                cli_write.write_all(&buf[..n]).await?;
                let mut guard = hash_state.lock().unwrap();
                guard.update(&buf[..n]);
            }
        }
    }
}

async fn await_server_task(
    task: tokio::task::JoinHandle<std_io::Result<(ReadHalf<TcpStream>, WriteHalf<TcpStream>)>>,
) -> Result<(ReadHalf<TcpStream>, WriteHalf<TcpStream>)> {
    task.await
        .map_err(|err| anyhow!("shadowtls relay task aborted: {err}"))?
        .map_err(anyhow::Error::from)
}

async fn copy_until_handshake_finished_v2<R, W>(
    client_reader: &mut R,
    server_writer: &mut W,
    hash_state: Arc<Mutex<V2HashState>>,
    fallback_after: usize,
) -> std_io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut application_data_count = 0usize;
    loop {
        let frame = read_tls_frame(client_reader).await?;
        if frame[0] == APPLICATION_DATA {
            let payload = &frame[TLS_HEADER_SIZE..];
            if payload.len() >= 8 {
                let guard = hash_state.lock().unwrap();
                if guard.current_sum().is_some_and(|sum| payload[..8] == sum)
                    || guard.last_sum().is_some_and(|sum| payload[..8] == sum)
                {
                    return Ok(payload[8..].to_vec());
                }
            }
            application_data_count += 1;
        }
        server_writer.write_all(&frame).await?;
        if application_data_count > fallback_after {
            return Err(std_io::Error::new(
                std_io::ErrorKind::PermissionDenied,
                "shadowtls v2 fallback triggered",
            ));
        }
    }
}

async fn read_tls_frame<R>(reader: &mut R) -> std_io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; TLS_HEADER_SIZE];
    reader.read_exact(&mut header).await?;
    let length = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut frame = Vec::with_capacity(TLS_HEADER_SIZE + length);
    frame.extend_from_slice(&header);
    frame.resize(TLS_HEADER_SIZE + length, 0);
    reader.read_exact(&mut frame[TLS_HEADER_SIZE..]).await?;
    Ok(frame)
}

fn spawn_v2_bridge(
    client_reader: ReadHalf<TcpStream>,
    client_writer: WriteHalf<TcpStream>,
    first_payload: Vec<u8>,
) -> DuplexStream {
    let (local, mut remote) = duplex(64 * 1024);
    tokio::spawn(async move {
        let (mut local_read, mut local_write) = split(&mut remote);
        let mut client_read = client_reader;
        let mut client_write = client_writer;
        let client_to_local = async {
            if !first_payload.is_empty() {
                local_write.write_all(&first_payload).await?;
            }
            while let Some(payload) = read_shadowtls_application_payload(&mut client_read).await? {
                local_write.write_all(&payload).await?;
            }
            local_write.shutdown().await
        };
        let local_to_client = async {
            let mut buf = [0u8; 16 * 1024];
            loop {
                let n = local_read.read(&mut buf).await?;
                if n == 0 {
                    client_write.shutdown().await?;
                    return Ok::<(), std_io::Error>(());
                }
                write_chunked_tls12_records(&mut client_write, &buf[..n]).await?;
            }
        };
        let _ = tokio::try_join!(client_to_local, local_to_client);
    });
    local
}

async fn read_shadowtls_application_payload<R>(reader: &mut R) -> std_io::Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let frame = match read_exact_or_eof(reader, TLS_HEADER_SIZE).await? {
        Some(header) => header,
        None => return Ok(None),
    };
    if frame[0] == ALERT {
        let length = u16::from_be_bytes([frame[3], frame[4]]) as usize;
        let _ = read_exact_or_eof(reader, length).await?;
        return Ok(None);
    }
    if frame[0] != APPLICATION_DATA {
        return Err(std_io::Error::new(
            std_io::ErrorKind::InvalidData,
            format!("unexpected TLS record type {}", frame[0]),
        ));
    }
    let length = u16::from_be_bytes([frame[3], frame[4]]) as usize;
    read_exact_or_eof(reader, length).await
}

async fn read_exact_or_eof<R>(reader: &mut R, length: usize) -> std_io::Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let mut buf = vec![0u8; length];
    let mut filled = 0usize;
    while filled < length {
        let n = reader.read(&mut buf[filled..]).await?;
        if n == 0 {
            if filled == 0 {
                return Ok(None);
            }
            return Err(std_io::Error::new(
                std_io::ErrorKind::UnexpectedEof,
                "early eof",
            ));
        }
        filled += n;
    }
    Ok(Some(buf))
}

async fn write_chunked_tls12_records<W>(writer: &mut W, payload: &[u8]) -> std_io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    for chunk in payload.chunks(16 * 1024) {
        let mut header = [0u8; TLS_HEADER_SIZE];
        header[0] = APPLICATION_DATA;
        header[1] = 0x03;
        header[2] = 0x03;
        header[3..5].copy_from_slice(&(chunk.len() as u16).to_be_bytes());
        writer.write_all(&header).await?;
        writer.write_all(chunk).await?;
    }
    Ok(())
}

fn new_v3_client_verify_state(password: &str, server_random: [u8; TLS_RANDOM_SIZE]) -> HmacSha1 {
    let mut hmac = HmacSha1::new_from_slice(password.as_bytes()).expect("hmac init");
    hmac.update(&server_random);
    hmac.update(b"C");
    hmac
}

fn new_v3_server_add_state(password: &str, server_random: [u8; TLS_RANDOM_SIZE]) -> HmacSha1 {
    let mut hmac = HmacSha1::new_from_slice(password.as_bytes()).expect("hmac init");
    hmac.update(&server_random);
    hmac.update(b"S");
    hmac
}

fn next_v3_tag(state: &mut HmacSha1, payload: &[u8]) -> [u8; SHADOWTLS_V3_HMAC_SIZE] {
    state.update(payload);
    let digest = state.clone().finalize().into_bytes();
    let mut tag = [0u8; SHADOWTLS_V3_HMAC_SIZE];
    tag.copy_from_slice(&digest[..SHADOWTLS_V3_HMAC_SIZE]);
    state.update(&tag);
    tag
}

fn verify_v3_payload(state: &mut HmacSha1, payload: &[u8], tag: &[u8]) -> bool {
    let mut check = state.clone();
    check.update(payload);
    let digest = check.finalize().into_bytes();
    if &digest[..SHADOWTLS_V3_HMAC_SIZE] == tag {
        state.update(payload);
        state.update(tag);
        true
    } else {
        false
    }
}

async fn relay_v3_server_handshake(
    mut hs_read: ReadHalf<TcpStream>,
    mut cli_write: WriteHalf<TcpStream>,
    password: String,
    server_random: [u8; TLS_RANDOM_SIZE],
    mut stop_rx: oneshot::Receiver<()>,
) -> std_io::Result<(ReadHalf<TcpStream>, WriteHalf<TcpStream>)> {
    let mut hmac = HmacSha1::new_from_slice(password.as_bytes()).expect("hmac init");
    hmac.update(&server_random);
    let write_key = kdf(&password, &server_random);
    loop {
        select! {
            _ = &mut stop_rx => return Ok((hs_read, cli_write)),
            frame = read_tls_frame(&mut hs_read) => {
                let frame = frame?;
                if frame[0] == APPLICATION_DATA {
                    let mut payload = frame[TLS_HEADER_SIZE..].to_vec();
                    xor_slice(&mut payload, &write_key);
                    hmac.update(&payload);
                    let digest = hmac.clone().finalize().into_bytes();
                    let tag = &digest[..SHADOWTLS_V3_HMAC_SIZE];
                    let mut header = [0u8; TLS_HEADER_SIZE];
                    header[..3].copy_from_slice(&frame[..3]);
                    header[3..5].copy_from_slice(&((payload.len() + SHADOWTLS_V3_HMAC_SIZE) as u16).to_be_bytes());
                    cli_write.write_all(&header).await?;
                    cli_write.write_all(tag).await?;
                    cli_write.write_all(&payload).await?;
                } else {
                    cli_write.write_all(&frame).await?;
                }
            }
        }
    }
}

async fn copy_until_v3_authenticated(
    mut cli_read: ReadHalf<TcpStream>,
    hs_write: &mut WriteHalf<TcpStream>,
    base_verify: &mut HmacSha1,
) -> Result<(ReadHalf<TcpStream>, Vec<u8>, HmacSha1)> {
    loop {
        let frame = read_tls_frame(&mut cli_read).await?;
        if frame[0] == APPLICATION_DATA && frame.len() >= TLS_HEADER_SIZE + SHADOWTLS_V3_HMAC_SIZE {
            let tag = &frame[TLS_HEADER_SIZE..TLS_HEADER_SIZE + SHADOWTLS_V3_HMAC_SIZE];
            let payload = &frame[TLS_HEADER_SIZE + SHADOWTLS_V3_HMAC_SIZE..];
            let mut verify = base_verify.clone();
            if verify_v3_payload(&mut verify, payload, tag) {
                return Ok((cli_read, payload.to_vec(), verify));
            }
        }
        hs_write.write_all(&frame).await?;
    }
}

fn spawn_v3_bridge(
    client_read: ReadHalf<TcpStream>,
    mut client_write: WriteHalf<TcpStream>,
    first_payload: Vec<u8>,
    verify_state: HmacSha1,
    add_state: HmacSha1,
) -> DuplexStream {
    let (local, mut remote) = duplex(64 * 1024);
    tokio::spawn(async move {
        let (mut local_read, mut local_write) = split(&mut remote);
        let mut client_read = client_read;
        let mut verify_state = verify_state;
        let mut add_state = add_state;

        let client_to_local = async {
            if !first_payload.is_empty() {
                local_write.write_all(&first_payload).await?;
            }
            while let Some(payload) =
                read_v3_application_payload(&mut client_read, &mut verify_state).await?
            {
                local_write.write_all(&payload).await?;
            }
            local_write.shutdown().await
        };

        let local_to_client = async {
            let mut buf = [0u8; 16 * 1024];
            loop {
                let n = local_read.read(&mut buf).await?;
                if n == 0 {
                    client_write.shutdown().await?;
                    return Ok::<(), std_io::Error>(());
                }
                for chunk in buf[..n].chunks(16 * 1024) {
                    let tag = next_v3_tag(&mut add_state, chunk);
                    let mut header = [0u8; TLS_HEADER_SIZE];
                    header[0] = APPLICATION_DATA;
                    header[1] = 0x03;
                    header[2] = 0x03;
                    header[3..5].copy_from_slice(
                        &((chunk.len() + SHADOWTLS_V3_HMAC_SIZE) as u16).to_be_bytes(),
                    );
                    client_write.write_all(&header).await?;
                    client_write.write_all(&tag).await?;
                    client_write.write_all(chunk).await?;
                }
            }
        };

        let _ = tokio::try_join!(client_to_local, local_to_client);
    });
    local
}

async fn read_v3_application_payload<R>(
    reader: &mut R,
    verify_state: &mut HmacSha1,
) -> std_io::Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let frame = match read_tls_frame(reader).await {
        Ok(frame) => frame,
        Err(err) if err.kind() == std_io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err),
    };
    if frame[0] == ALERT {
        return Ok(None);
    }
    if frame[0] != APPLICATION_DATA || frame.len() < TLS_HEADER_SIZE + SHADOWTLS_V3_HMAC_SIZE {
        return Err(std_io::Error::new(
            std_io::ErrorKind::InvalidData,
            "invalid shadowtls v3 application frame",
        ));
    }
    let tag = &frame[TLS_HEADER_SIZE..TLS_HEADER_SIZE + SHADOWTLS_V3_HMAC_SIZE];
    let payload = &frame[TLS_HEADER_SIZE + SHADOWTLS_V3_HMAC_SIZE..];
    if verify_v3_payload(verify_state, payload, tag) {
        Ok(Some(payload.to_vec()))
    } else {
        Err(std_io::Error::new(
            std_io::ErrorKind::InvalidData,
            "shadowtls v3 application verification failed",
        ))
    }
}

fn kdf(password: &str, server_random: &[u8; TLS_RANDOM_SIZE]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(server_random);
    hasher.finalize().into()
}

fn xor_slice(data: &mut [u8], key: &[u8; 32]) {
    for (index, byte) in data.iter_mut().enumerate() {
        *byte ^= key[index % key.len()];
    }
}

#[derive(Debug)]
pub struct ShadowTlsInboundAdapter {
    cfg: ShadowTlsInboundConfig,
    stop_tx: Mutex<Option<mpsc::Sender<()>>>,
}

impl ShadowTlsInboundAdapter {
    pub fn new(cfg: ShadowTlsInboundConfig) -> Self {
        Self {
            cfg,
            stop_tx: Mutex::new(None),
        }
    }
}

impl InboundService for ShadowTlsInboundAdapter {
    fn serve(&self) -> std_io::Result<()> {
        let (tx, rx) = mpsc::channel(1);
        *self.stop_tx.lock().unwrap() = Some(tx);
        tokio::runtime::Handle::current()
            .block_on(async { serve(self.cfg.clone(), rx).await })
            .map_err(std_io::Error::other)
    }

    fn request_shutdown(&self) {
        if let Some(tx) = self.stop_tx.lock().unwrap().take() {
            let _ = tx.try_send(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_config(wildcard_sni: ShadowTlsWildcardSniMode) -> ShadowTlsInboundConfig {
        ShadowTlsInboundConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            detour: "ss-detour".to_string(),
            version: 3,
            password: None,
            users: vec![ShadowTlsUser {
                name: Some("u".to_string()),
                password: "p".to_string(),
            }],
            handshake: Some(ShadowTlsHandshakeConfig {
                server: "default.example".to_string(),
                server_port: 443,
            }),
            handshake_for_server_name: HashMap::from([(
                "custom.example".to_string(),
                ShadowTlsHandshakeConfig {
                    server: "custom-target.example".to_string(),
                    server_port: 8443,
                },
            )]),
            strict_mode: false,
            wildcard_sni,
            tag: Some("shadowtls-in".to_string()),
            tls: None,
            router: None,
            stats: None,
        }
    }

    #[test]
    fn shadowtls_v3_handshake_selection_honors_custom_and_wildcard() {
        let custom = select_v3_handshake(
            &base_config(ShadowTlsWildcardSniMode::All),
            "custom.example",
        )
        .unwrap();
        assert!(custom.is_custom);
        assert_eq!(custom.target.server, "custom-target.example");
        assert_eq!(custom.target.server_port, 8443);

        let wildcard = select_v3_handshake(
            &base_config(ShadowTlsWildcardSniMode::Authed),
            "wild.example",
        )
        .unwrap();
        assert!(!wildcard.is_custom);
        assert_eq!(wildcard.target.server, "wild.example");
        assert_eq!(wildcard.target.server_port, 443);

        let default =
            select_v3_handshake(&base_config(ShadowTlsWildcardSniMode::Off), "wild.example")
                .unwrap();
        assert!(!default.is_custom);
        assert_eq!(default.target.server, "default.example");
        assert_eq!(default.target.server_port, 443);
    }

    #[test]
    fn shadowtls_v3_fallback_handshake_honors_wildcard_mode() {
        let custom = SelectedV3Handshake {
            target: ShadowTlsHandshakeConfig {
                server: "custom-target.example".to_string(),
                server_port: 8443,
            },
            is_custom: true,
        };
        let custom_fallback =
            fallback_v3_handshake(&base_config(ShadowTlsWildcardSniMode::Off), custom).unwrap();
        assert_eq!(custom_fallback.server, "custom-target.example");
        assert_eq!(custom_fallback.server_port, 8443);

        let authed = SelectedV3Handshake {
            target: ShadowTlsHandshakeConfig {
                server: "wild.example".to_string(),
                server_port: 443,
            },
            is_custom: false,
        };
        let authed_fallback =
            fallback_v3_handshake(&base_config(ShadowTlsWildcardSniMode::Authed), authed).unwrap();
        assert_eq!(authed_fallback.server, "default.example");
        assert_eq!(authed_fallback.server_port, 443);

        let all = SelectedV3Handshake {
            target: ShadowTlsHandshakeConfig {
                server: "wild.example".to_string(),
                server_port: 443,
            },
            is_custom: false,
        };
        let all_fallback =
            fallback_v3_handshake(&base_config(ShadowTlsWildcardSniMode::All), all).unwrap();
        assert_eq!(all_fallback.server, "wild.example");
        assert_eq!(all_fallback.server_port, 443);
    }
}
