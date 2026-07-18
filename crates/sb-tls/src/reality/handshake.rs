//! REALITY client handshake built on rustls hooks.

use super::auth::{compute_temp_cert_signature, derive_auth_key};
use super::client::RealityClientTlsStream;
use super::config::RealityClientConfig;
use super::tls_record::{ClientHello, ExtensionType};
use super::{RealityError, RealityResult};
#[cfg(feature = "utls")]
use crate::{UtlsConfig, UtlsFingerprint};
use parking_lot::Mutex;
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use rustls::client::{ClientHelloFingerprint, SessionIdGenerator, WebPkiServerVerifier};
use rustls::crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{ClientConfig, NamedGroup, SupportedCipherSuite};
use rustls_pki_types::ServerName;
use std::collections::HashMap;
use std::io::Read as _;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::task::{Context, Poll};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector as RustlsConnector;
use tracing::debug;
use x509_parser::oid_registry::OID_SIG_ED25519;
use x509_parser::prelude::parse_x509_certificate;
use x25519_dalek::{PublicKey, StaticSecret};

const REALITY_SESSION_ID_LEN: usize = 32;
const REALITY_SESSION_PLAINTEXT_LEN: usize = 16;
const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_STATUS_REQUEST: u16 = 0x0005;
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_EC_POINT_FORMATS: u16 = 0x000b;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_ALPN: u16 = 0x0010;
const EXT_SCT: u16 = 0x0012;
const EXT_COMPRESS_CERTIFICATE: u16 = 0x001b;
const EXT_EXTENDED_MASTER_SECRET: u16 = 0x0017;
const EXT_SESSION_TICKET: u16 = 0x0023;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_TRUST_ANCHORS: u16 = 0xca34;
const EXT_APPLICATION_SETTINGS: u16 = 0x44cd;
const EXT_ECH_OUTER: u16 = 0xfe0d;
const EXT_RENEGOTIATION_INFO: u16 = 0xff01;
/// RFC 8701 GREASE reserved values (the sixteen `0x?a?a` code points). Chrome
/// draws fresh GREASE values for every ClientHello; the per-handshake selector
/// (`ChromeGreaseProfile`) picks from this table so REALITY reproduces that
/// behaviour instead of pinning one value per slot.
const GREASE_VALUES: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];
const UTLS_GREASE_ECH_OUTER_CLIENT_HELLO: u8 = 0x00;
const UTLS_GREASE_ECH_KDF_ID: u16 = 0x0001;
const UTLS_GREASE_ECH_AEAD_ID: u16 = 0x0001;
const UTLS_GREASE_ECH_ENCAPSULATED_KEY_LEN: usize = 32;
const UTLS_GREASE_ECH_PAYLOAD_LENS: [usize; 4] = [144, 176, 208, 240];
/// Chrome 150 stable full-browser extension set after REALITY removes the
/// X25519MLKEM768 supported-group/key-share entries.
const CHROME_CURRENT_MIDDLE_EXTENSIONS: [u16; 17] = [
    EXT_SERVER_NAME,
    EXT_STATUS_REQUEST,
    EXT_SUPPORTED_GROUPS,
    EXT_EC_POINT_FORMATS,
    EXT_SIGNATURE_ALGORITHMS,
    EXT_ALPN,
    EXT_SCT,
    EXT_EXTENDED_MASTER_SECRET,
    EXT_COMPRESS_CERTIFICATE,
    EXT_SESSION_TICKET,
    EXT_SUPPORTED_VERSIONS,
    EXT_PSK_KEY_EXCHANGE_MODES,
    EXT_KEY_SHARE,
    EXT_TRUST_ANCHORS,
    EXT_APPLICATION_SETTINGS,
    EXT_ECH_OUTER,
    EXT_RENEGOTIATION_INFO,
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SocketTraceChunk {
    pub index: usize,
    pub len: usize,
    pub offset_micros: u64,
    pub record_type: Option<String>,
    pub record_version: Option<String>,
    pub hex: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SocketTraceEvent {
    pub offset_micros: u64,
    pub kind: String,
    pub len: Option<usize>,
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalSocketTrace {
    pub listener_addr: String,
    pub client_error: Option<String>,
    pub client_connect_elapsed_micros: Option<u64>,
    pub client_handshake_elapsed_micros: Option<u64>,
    pub client_first_write_after_connect_micros: Option<u64>,
    pub client_first_read_after_connect_micros: Option<u64>,
    pub client_event_trace: Vec<SocketTraceEvent>,
    pub server_read_count: usize,
    pub server_total_len: usize,
    pub server_first_read_delay_micros: Option<u64>,
    pub server_trace_elapsed_micros: u64,
    pub server_first_read_to_end_micros: Option<u64>,
    pub server_end_reason: String,
    pub server_timed_out_waiting_for_more: bool,
    pub server_chunks: Vec<SocketTraceChunk>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientSocketTrace {
    pub remote_addr: String,
    pub client_error: Option<String>,
    pub client_connect_elapsed_micros: Option<u64>,
    pub client_handshake_elapsed_micros: Option<u64>,
    pub client_first_write_after_connect_micros: Option<u64>,
    pub client_first_read_after_connect_micros: Option<u64>,
    pub client_event_trace: Vec<SocketTraceEvent>,
}

static EPHEMERAL_X25519_SECRETS: LazyLock<Mutex<HashMap<[u8; 32], [u8; 32]>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

static REALITY_X25519_KX_GROUP: RealityX25519KxGroup = RealityX25519KxGroup;

pub(super) struct RealityHandshake {
    config: Arc<RealityClientConfig>,
    server_public_key: [u8; 32],
    short_id: [u8; 8],
}

impl RealityHandshake {
    pub(super) fn new(config: Arc<RealityClientConfig>) -> RealityResult<Self> {
        let server_public_key = config
            .public_key_bytes()
            .map_err(RealityError::InvalidConfig)?;
        let short_id = short_id_bytes(config.short_id_bytes());

        Ok(Self {
            config,
            server_public_key,
            short_id,
        })
    }

    pub(super) async fn perform<S>(&self, stream: S) -> RealityResult<crate::TlsIoStream>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Ok(Box::new(self.perform_stream(stream).await?))
    }

    pub(super) async fn perform_stream<S>(
        &self,
        stream: S,
    ) -> RealityResult<RealityClientTlsStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        debug!("Starting REALITY handshake via rustls session-id hooks");

        let state = Arc::new(RealityHandshakeState::default());
        let verifier = Arc::new(RealityVerifier::new(
            self.config.server_name.clone(),
            state.clone(),
        )?);

        let tls_config = Arc::new(self.build_client_config(verifier, state.clone())?);
        let server_name = ServerName::try_from(self.config.server_name.clone())
            .map_err(|e| RealityError::HandshakeFailed(format!("Invalid server name: {e:?}")))?;

        let connector = RustlsConnector::from(tls_config);
        let tls_stream = connector
            .connect(server_name, stream)
            .await
            .map_err(|e| RealityError::HandshakeFailed(format!("TLS handshake failed: {e}")))?;

        if !state.temporary_cert_verified() {
            return Err(RealityError::AuthFailed(
                "reality verification failed".to_string(),
            ));
        }

        debug!("REALITY handshake completed successfully");
        Ok(RealityClientTlsStream::new(tls_stream))
    }

    pub(super) fn emit_client_hello_record(&self) -> RealityResult<Vec<u8>> {
        let state = Arc::new(RealityHandshakeState::default());
        let verifier = Arc::new(RealityVerifier::new(
            self.config.server_name.clone(),
            state,
        )?);
        let tls_config = Arc::new(
            self.build_client_config(verifier, Arc::new(RealityHandshakeState::default()))?,
        );
        let server_name = ServerName::try_from(self.config.server_name.clone())
            .map_err(|e| RealityError::HandshakeFailed(format!("Invalid server name: {e:?}")))?;

        let mut conn = rustls::client::ClientConnection::new(tls_config, server_name)
            .map_err(|e| RealityError::HandshakeFailed(format!("build client hello: {e}")))?;
        let mut wire = Vec::new();
        conn.write_tls(&mut wire)
            .map_err(|e| RealityError::HandshakeFailed(format!("encode client hello: {e}")))?;
        Ok(wire)
    }

    pub(super) fn trace_client_hello_writes(&self) -> RealityResult<Vec<Vec<u8>>> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| RealityError::HandshakeFailed(format!("build trace runtime: {e}")))?;
        runtime.block_on(self.trace_client_hello_writes_async())
    }

    pub(super) fn trace_local_socket_handshake(&self) -> RealityResult<LocalSocketTrace> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| {
                RealityError::HandshakeFailed(format!("build socket trace runtime: {e}"))
            })?;
        runtime.block_on(self.trace_local_socket_handshake_async())
    }

    pub(super) fn trace_remote_socket_handshake(
        &self,
        remote_addr: SocketAddr,
    ) -> RealityResult<ClientSocketTrace> {
        self.trace_remote_socket_handshake_with_timeout(remote_addr, Duration::from_secs(2))
    }

    pub(super) fn trace_remote_socket_handshake_with_timeout(
        &self,
        remote_addr: SocketAddr,
        handshake_timeout: Duration,
    ) -> RealityResult<ClientSocketTrace> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| {
                RealityError::HandshakeFailed(format!("build remote socket trace runtime: {e}"))
            })?;
        runtime.block_on(self.trace_remote_socket_handshake_async(remote_addr, handshake_timeout))
    }

    async fn trace_client_hello_writes_async(&self) -> RealityResult<Vec<Vec<u8>>> {
        let recorder = RecordingAsyncIo::default();
        let _ = self.perform(recorder.clone()).await;
        let writes = recorder.take_writes();
        if writes.is_empty() {
            return Err(RealityError::HandshakeFailed(
                "trace captured no client writes".to_string(),
            ));
        }
        Ok(writes)
    }

    async fn trace_remote_socket_handshake_async(
        &self,
        remote_addr: SocketAddr,
        handshake_timeout: Duration,
    ) -> RealityResult<ClientSocketTrace> {
        let client_connect_started_at = Instant::now();
        let client_stream = TcpStream::connect(remote_addr)
            .await
            .map_err(RealityError::Io)?;
        let client_connect_elapsed_micros =
            Some(client_connect_started_at.elapsed().as_micros() as u64);
        let (client_stream, client_trace_recorder) = TracingAsyncIo::new(client_stream);

        let client_handshake_started_at = Instant::now();
        let client_error = timeout(handshake_timeout, self.perform(client_stream))
            .await
            .map_err(|_| {
                RealityError::HandshakeFailed(
                    "remote socket trace client handshake timed out".to_string(),
                )
            })?
            .err()
            .map(|error| error.to_string());
        let client_handshake_elapsed_micros =
            Some(client_handshake_started_at.elapsed().as_micros() as u64);
        let client_trace_snapshot = client_trace_recorder.snapshot();

        Ok(ClientSocketTrace {
            remote_addr: remote_addr.to_string(),
            client_error,
            client_connect_elapsed_micros,
            client_handshake_elapsed_micros,
            client_first_write_after_connect_micros: client_trace_snapshot
                .first_write_after_connect_micros,
            client_first_read_after_connect_micros: client_trace_snapshot
                .first_read_after_connect_micros,
            client_event_trace: client_trace_snapshot.events,
        })
    }

    async fn trace_local_socket_handshake_async(&self) -> RealityResult<LocalSocketTrace> {
        let listener = StdTcpListener::bind(("127.0.0.1", 0)).map_err(RealityError::Io)?;
        let listener_addr = listener.local_addr().map_err(RealityError::Io)?;
        let listener_addr_text = listener_addr.to_string();
        let server_listener_addr_text = listener_addr_text.clone();
        let (server_ready_tx, server_ready_rx) = mpsc::channel();

        let server = thread::spawn(move || {
            let _ = server_ready_tx.send(());
            let (mut socket, _) = listener.accept().map_err(RealityError::Io)?;
            let accept_at = Instant::now();
            let mut buffer = [0u8; 4096];
            let mut total = Vec::new();
            let mut chunks = Vec::new();
            let mut first_read_delay_micros = None;
            let mut timed_out_waiting_for_more = false;
            let mut end_reason = "eof".to_string();

            loop {
                let wait = if chunks.is_empty() {
                    Duration::from_millis(500)
                } else {
                    Duration::from_millis(25)
                };
                socket
                    .set_read_timeout(Some(wait))
                    .map_err(RealityError::Io)?;
                match socket.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(read_len) => {
                        if first_read_delay_micros.is_none() {
                            first_read_delay_micros = Some(accept_at.elapsed().as_micros() as u64);
                        }
                        let offset_micros = accept_at.elapsed().as_micros() as u64;
                        let payload = &buffer[..read_len];
                        chunks.push(SocketTraceChunk {
                            index: chunks.len(),
                            len: read_len,
                            offset_micros,
                            record_type: payload.first().map(|value| format!("0x{value:02x}")),
                            record_version: (payload.len() >= 3)
                                .then(|| format!("0x{:02x}{:02x}", payload[1], payload[2])),
                            hex: hex::encode(payload),
                        });
                        total.extend_from_slice(payload);
                    }
                    Err(error) => {
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            || error.kind() == std::io::ErrorKind::TimedOut
                        {
                            timed_out_waiting_for_more = !chunks.is_empty();
                            end_reason = "timeout".to_string();
                            break;
                        }
                        return Err(RealityError::HandshakeFailed(format!(
                            "socket trace server read failed: {error}"
                        )));
                    }
                }
            }

            let server_trace_elapsed_micros = accept_at.elapsed().as_micros() as u64;
            Ok::<LocalSocketTrace, RealityError>(LocalSocketTrace {
                listener_addr: server_listener_addr_text,
                client_error: None,
                client_connect_elapsed_micros: None,
                client_handshake_elapsed_micros: None,
                client_first_write_after_connect_micros: None,
                client_first_read_after_connect_micros: None,
                client_event_trace: Vec::new(),
                server_read_count: chunks.len(),
                server_total_len: total.len(),
                server_first_read_delay_micros: first_read_delay_micros,
                server_trace_elapsed_micros,
                server_first_read_to_end_micros: first_read_delay_micros
                    .map(|first| server_trace_elapsed_micros.saturating_sub(first)),
                server_end_reason: end_reason,
                server_timed_out_waiting_for_more: timed_out_waiting_for_more,
                server_chunks: chunks,
            })
        });
        server_ready_rx.recv().map_err(|_| {
            RealityError::HandshakeFailed("socket trace server ready signal failed".to_string())
        })?;

        let client_trace = self
            .trace_remote_socket_handshake_async(listener_addr, Duration::from_secs(2))
            .await?;

        let mut server_trace = server.join().map_err(|_| {
            RealityError::HandshakeFailed("socket trace server thread panicked".to_string())
        })??;
        server_trace.client_error = client_trace.client_error;
        server_trace.client_connect_elapsed_micros = client_trace.client_connect_elapsed_micros;
        server_trace.client_handshake_elapsed_micros = client_trace.client_handshake_elapsed_micros;
        server_trace.client_first_write_after_connect_micros =
            client_trace.client_first_write_after_connect_micros;
        server_trace.client_first_read_after_connect_micros =
            client_trace.client_first_read_after_connect_micros;
        server_trace.client_event_trace = client_trace.client_event_trace;
        Ok(server_trace)
    }

    fn build_client_config(
        &self,
        verifier: Arc<RealityVerifier>,
        state: Arc<RealityHandshakeState>,
    ) -> RealityResult<ClientConfig> {
        crate::ensure_crypto_provider();

        let mut config =
            ClientConfig::builder_with_provider(Arc::new(build_crypto_provider(&self.config)))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(|e| RealityError::HandshakeFailed(format!("TLS config init failed: {e}")))?
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth();

        config.session_id_generator = Some(Arc::new(RealitySessionIdGenerator {
            server_public_key: self.server_public_key,
            short_id: self.short_id,
            state,
        }));
        config.fingerprint = build_chrome_client_hello_fingerprint(&self.config);
        config.alpn_protocols = build_alpn_protocols(&self.config);

        Ok(config)
    }
}

fn build_chrome_client_hello_fingerprint(
    config: &RealityClientConfig,
) -> Option<ClientHelloFingerprint> {
    if !uses_chrome_like_fingerprint(config.fingerprint.as_str()) {
        return None;
    }

    let mut rng = OsRng;
    let payload_len = select_chrome_ech_payload_len(&mut rng);
    debug!(
        fe0d_len = payload_len + 1 + 2 + 2 + 1 + 2 + UTLS_GREASE_ECH_ENCAPSULATED_KEY_LEN + 2,
        profile = "chrome-150-stable-reality",
        "REALITY chrome fingerprint selected"
    );
    Some(build_chrome_client_hello_fingerprint_with_rng(
        payload_len,
        &mut rng,
    ))
}

fn build_chrome_client_hello_fingerprint_with_rng(
    payload_len: usize,
    rng: &mut (impl RngCore + CryptoRng),
) -> ClientHelloFingerprint {
    let grease = ChromeGreaseProfile::random(rng);
    ClientHelloFingerprint {
        opaque_extensions: vec![
            (grease.ext_head, Vec::new()),
            (EXT_SCT, Vec::new()),
            (EXT_COMPRESS_CERTIFICATE, vec![0x02, 0x00, 0x02]),
            (EXT_APPLICATION_SETTINGS, vec![0x00, 0x03, 0x02, b'h', b'2']),
            (
                EXT_ECH_OUTER,
                build_utls_boring_grease_ech_extension(payload_len, rng),
            ),
            (EXT_TRUST_ANCHORS, vec![0x00, 0x00]),
            (grease.ext_tail, vec![0x00]),
        ],
        // Forced order is already randomized with independent wide entropy. Leaving rustls'
        // legacy u16 seed unset prevents accidental second-stage reshuffling or coupling.
        randomization_seed: None,
        extension_order: build_chrome_extension_order(rng, grease.ext_head, grease.ext_tail),
        prefix_extension_order: vec![],
        suffix_extension_order: vec![],
        grease_ciphersuite: Some(grease.cipher),
        extra_cipher_suites: vec![
            0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
        ],
        include_empty_session_ticket: true,
        include_renegotiation_info: true,
        supported_versions_override: Some(vec![grease.supported_versions, 0x0304, 0x0303]),
        supported_groups_override: Some(vec![grease.group, 0x001d, 0x0017, 0x0018]),
        key_share_grease: Some((grease.group, vec![0x00])),
        // Chrome 150 advertises ML-DSA before conventional schemes. This is wire shaping;
        // current rustls provider does not verify ML-DSA certificates. Ordinary WebPKI peers
        // select one of the conventional schemes below (covered by the local REALITY gate).
        signature_algorithms_override: Some(vec![
            0x0904, 0x0905, 0x0906, 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ]),
    }
}

/// Per-ClientHello GREASE value selection (RFC 8701).
///
/// Chrome draws fresh GREASE values for every
/// ClientHello. The logical slots — cipher, supported_versions, group, ext_head,
/// ext_tail — are drawn **independently** from [`GREASE_VALUES`]; `group` is shared by
/// supported_groups and key_share so the two stay correlated (as Chrome emits them), and
/// `ext_tail` is re-drawn until it differs from `ext_head` so the two GREASE extension
/// types never collide. Every other slot may collide naturally, matching Chrome's 4–5
/// distinct-value behaviour. The production entropy is an **independent per-ClientHello
/// `OsRng` draw**. Extension order and ECH bucket consume independent draws rather than
/// sharing rustls' legacy u16 randomization seed.
/// No global mutable state, no timestamp seed, no static counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ChromeGreaseProfile {
    cipher: u16,
    supported_versions: u16,
    group: u16,
    ext_head: u16,
    ext_tail: u16,
}

impl ChromeGreaseProfile {
    /// Build a profile by pulling indices from `next_index`; each call must yield
    /// a fresh index into [`GREASE_VALUES`]. `ext_tail` re-draws while it collides
    /// with `ext_head`, bounded by the table length so a degenerate (always
    /// colliding) source still terminates with a guaranteed-distinct fallback.
    /// The injectable source makes the correlation rules deterministically
    /// testable without probabilistic assertions.
    fn from_index_source(mut next_index: impl FnMut() -> usize) -> Self {
        let n = GREASE_VALUES.len();
        let cipher = GREASE_VALUES[next_index() % n];
        let supported_versions = GREASE_VALUES[next_index() % n];
        let group = GREASE_VALUES[next_index() % n];
        let head_idx = next_index() % n;
        let mut tail_idx = next_index() % n;
        let mut guard = 0;
        while tail_idx == head_idx && guard < n {
            tail_idx = next_index() % n;
            guard += 1;
        }
        if tail_idx == head_idx {
            tail_idx = (head_idx + 1) % n;
        }
        Self {
            cipher,
            supported_versions,
            group,
            ext_head: GREASE_VALUES[head_idx],
            ext_tail: GREASE_VALUES[tail_idx],
        }
    }

    /// Draw a fresh per-ClientHello profile from an independent RNG. Each logical slot
    /// pulls its own uniform nibble — `GREASE_VALUES` has 16 entries and 16 divides 2^32,
    /// so `next_u32() & 0x0f` is unbiased — making the slots mutually independent (unlike a
    /// single-seed derivation, whose GF(2)-linear mixing forced an affine cross-slot
    /// relationship; T3-1C.1). Production passes `&mut OsRng`; tests inject a deterministic
    /// RNG. The bounded ext_tail re-draw is plain rejection sampling here, so ext_tail is
    /// uniform over the fifteen non-`ext_head` values; the deterministic fallback only ever
    /// fires for a degenerate injected source, never on the OsRng path.
    fn random(rng: &mut impl RngCore) -> Self {
        Self::from_index_source(|| (rng.next_u32() & 0x0f) as usize)
    }
}

fn select_chrome_ech_payload_len(rng: &mut impl RngCore) -> usize {
    UTLS_GREASE_ECH_PAYLOAD_LENS[(rng.next_u32() as usize) % UTLS_GREASE_ECH_PAYLOAD_LENS.len()]
}

/// BoringSSL `ssl_setup_extension_permutation`: reverse Fisher-Yates using one
/// independent u32 random word per swap and modulo `(i + 1)`. GREASE extensions
/// remain fixed at both ends, matching Chrome's separate write path.
fn build_chrome_extension_order(
    rng: &mut impl RngCore,
    grease_head: u16,
    grease_tail: u16,
) -> Vec<u16> {
    let mut middle = CHROME_CURRENT_MIDDLE_EXTENSIONS.to_vec();
    for i in (1..middle.len()).rev() {
        let j = (rng.next_u32() as usize) % (i + 1);
        middle.swap(i, j);
    }
    let mut extension_order = Vec::with_capacity(middle.len() + 2);
    extension_order.push(grease_head);
    extension_order.extend(middle);
    extension_order.push(grease_tail);
    extension_order
}
fn build_utls_boring_grease_ech_extension(
    payload_len: usize,
    rng: &mut (impl RngCore + CryptoRng),
) -> Vec<u8> {
    let mut config_id = [0u8; 1];
    rng.fill_bytes(&mut config_id);

    let encapsulated_key = PublicKey::from(&StaticSecret::random_from_rng(&mut *rng)).to_bytes();
    let mut payload = vec![0u8; payload_len];
    rng.fill_bytes(&mut payload);

    let mut extension = Vec::with_capacity(
        1 + 2 + 2 + 1 + 2 + UTLS_GREASE_ECH_ENCAPSULATED_KEY_LEN + 2 + payload_len,
    );
    extension.push(UTLS_GREASE_ECH_OUTER_CLIENT_HELLO);
    extension.extend_from_slice(&UTLS_GREASE_ECH_KDF_ID.to_be_bytes());
    extension.extend_from_slice(&UTLS_GREASE_ECH_AEAD_ID.to_be_bytes());
    extension.push(config_id[0]);
    extension.extend_from_slice(&(encapsulated_key.len() as u16).to_be_bytes());
    extension.extend_from_slice(&encapsulated_key);
    extension.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    extension.extend_from_slice(&payload);
    extension
}

#[cfg(test)]
fn parse_utls_boring_grease_ech_extension(data: &[u8]) -> Option<(u8, u16, u16, u8, usize, usize)> {
    if data.len() < 1 + 2 + 2 + 1 + 2 + 2 {
        return None;
    }

    let client_hello_type = data[0];
    let kdf_id = u16::from_be_bytes([data[1], data[2]]);
    let aead_id = u16::from_be_bytes([data[3], data[4]]);
    let config_id = data[5];
    let encapsulated_key_len = usize::from(u16::from_be_bytes([data[6], data[7]]));
    let payload_len_offset = 8 + encapsulated_key_len;
    if data.len() < payload_len_offset + 2 {
        return None;
    }

    let payload_len = usize::from(u16::from_be_bytes([
        data[payload_len_offset],
        data[payload_len_offset + 1],
    ]));
    let total_len = payload_len_offset + 2 + payload_len;
    if data.len() != total_len {
        return None;
    }

    Some((
        client_hello_type,
        kdf_id,
        aead_id,
        config_id,
        encapsulated_key_len,
        payload_len,
    ))
}

fn uses_chrome_like_fingerprint(fingerprint: &str) -> bool {
    matches!(
        fingerprint.to_ascii_lowercase().as_str(),
        "" | "chrome"
            | "chrome110"
            | "chrome_psk"
            | "chrome_psk_shuffle"
            | "chrome_padding_psk_shuffle"
            | "chrome_pq"
            | "chrome_pq_psk"
            | "android"
            | "android11"
            | "android_11"
            | "random"
            | "randomized"
            | "randomchrome"
            | "random_chrome"
            | "360"
            | "360browser"
            | "qq"
            | "qqbrowser"
    )
}

fn build_crypto_provider(config: &RealityClientConfig) -> rustls::crypto::CryptoProvider {
    let mut provider = rustls::crypto::ring::default_provider();

    #[cfg(feature = "utls")]
    {
        if let Ok(fingerprint) = config.fingerprint.parse::<UtlsFingerprint>() {
            let utls = UtlsConfig::new(config.server_name.clone()).with_fingerprint(fingerprint);
            let params = utls.get_fingerprint_params();
            provider.cipher_suites = map_fingerprint_cipher_suites(&params.cipher_suites);
            provider.kx_groups = build_kx_groups(&params.curves);
            return provider;
        }
    }

    provider.kx_groups = build_kx_groups(&[]);
    provider
}

fn build_kx_groups(curves: &[u16]) -> Vec<&'static dyn SupportedKxGroup> {
    let mut groups: Vec<&'static dyn SupportedKxGroup> = vec![&REALITY_X25519_KX_GROUP];

    for curve in curves {
        let group = match curve {
            0x001d => Some(&REALITY_X25519_KX_GROUP as &'static dyn SupportedKxGroup),
            0x0017 => {
                Some(rustls::crypto::ring::kx_group::SECP256R1 as &'static dyn SupportedKxGroup)
            }
            0x0018 => {
                Some(rustls::crypto::ring::kx_group::SECP384R1 as &'static dyn SupportedKxGroup)
            }
            _ => None,
        };

        if let Some(group) = group
            && !groups
                .iter()
                .any(|existing| existing.name() == group.name())
        {
            groups.push(group);
        }
    }

    if !groups
        .iter()
        .any(|group| group.name() == NamedGroup::secp256r1)
    {
        groups.push(rustls::crypto::ring::kx_group::SECP256R1);
    }

    if !groups
        .iter()
        .any(|group| group.name() == NamedGroup::secp384r1)
    {
        groups.push(rustls::crypto::ring::kx_group::SECP384R1);
    }

    groups
}

fn build_alpn_protocols(config: &RealityClientConfig) -> Vec<Vec<u8>> {
    #[cfg(feature = "utls")]
    {
        if let Ok(fingerprint) = config.fingerprint.parse::<UtlsFingerprint>() {
            let utls = UtlsConfig::new(config.server_name.clone()).with_fingerprint(fingerprint);
            let params = utls.get_fingerprint_params();
            if config.alpn.is_empty() {
                return params.alpn.into_iter().map(String::into_bytes).collect();
            }
        }
    }

    config
        .alpn
        .iter()
        .map(|protocol| protocol.as_bytes().to_vec())
        .collect()
}

fn map_fingerprint_cipher_suites(ids: &[u16]) -> Vec<SupportedCipherSuite> {
    use rustls::crypto::ring::cipher_suite;

    let mut suites = Vec::with_capacity(ids.len());

    for id in ids {
        let suite = match id {
            0x1301 => Some(cipher_suite::TLS13_AES_128_GCM_SHA256),
            0x1302 => Some(cipher_suite::TLS13_AES_256_GCM_SHA384),
            0x1303 => Some(cipher_suite::TLS13_CHACHA20_POLY1305_SHA256),
            0xc02b => Some(cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
            0xc02f => Some(cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
            0xc02c => Some(cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384),
            0xc030 => Some(cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384),
            _ => None,
        };

        if let Some(suite) = suite {
            suites.push(suite);
        }
    }

    if suites.is_empty() {
        vec![
            cipher_suite::TLS13_AES_256_GCM_SHA384,
            cipher_suite::TLS13_AES_128_GCM_SHA256,
        ]
    } else {
        suites
    }
}

#[derive(Debug, Default)]
struct RealityHandshakeState {
    auth_key: Mutex<Option<[u8; 32]>>,
    temporary_cert_verified: AtomicBool,
}

impl RealityHandshakeState {
    fn set_auth_key(&self, auth_key: [u8; 32]) {
        *self.auth_key.lock() = Some(auth_key);
    }

    fn auth_key(&self) -> Option<[u8; 32]> {
        *self.auth_key.lock()
    }

    fn mark_temporary_cert_verified(&self) {
        self.temporary_cert_verified.store(true, Ordering::Release);
    }

    fn temporary_cert_verified(&self) -> bool {
        self.temporary_cert_verified.load(Ordering::Acquire)
    }
}

#[derive(Debug)]
struct RealitySessionIdGenerator {
    server_public_key: [u8; 32],
    short_id: [u8; 8],
    state: Arc<RealityHandshakeState>,
}

impl SessionIdGenerator for RealitySessionIdGenerator {
    fn generate(&self, client_hello: &[u8], session_id: &mut [u8]) -> Result<(), rustls::Error> {
        if session_id.len() != REALITY_SESSION_ID_LEN {
            return Err(rustls::Error::General(format!(
                "unexpected REALITY session_id length: {}",
                session_id.len()
            )));
        }

        let parsed = ClientHello::parse(client_hello).map_err(|e| {
            rustls::Error::General(format!("REALITY failed to parse client hello: {e}"))
        })?;
        let client_public_key = parse_client_key_share(&parsed)?;
        let private_key = take_ephemeral_secret(&client_public_key).ok_or_else(|| {
            rustls::Error::General(
                "REALITY missing matching TLS X25519 private key for session_id".to_string(),
            )
        })?;

        let shared_secret = StaticSecret::from(private_key)
            .diffie_hellman(&PublicKey::from(self.server_public_key))
            .to_bytes();
        let auth_key = derive_auth_key(shared_secret, &parsed.random)
            .map_err(|e| rustls::Error::General(format!("REALITY HKDF failed: {e}")))?;
        let plaintext = build_reality_plaintext_session_id(current_unix_seconds(), self.short_id);
        let sealed = seal_reality_session_id(&auth_key, &parsed.random, &plaintext, client_hello)
            .map_err(|e| rustls::Error::General(format!("REALITY AES-GCM failed: {e}")))?;

        session_id.copy_from_slice(&sealed);
        self.state.set_auth_key(auth_key);

        Ok(())
    }
}

#[derive(Debug)]
struct RealityVerifier {
    expected_server_name: String,
    state: Arc<RealityHandshakeState>,
    webpki: Arc<WebPkiServerVerifier>,
}

impl RealityVerifier {
    fn new(
        expected_server_name: String,
        state: Arc<RealityHandshakeState>,
    ) -> Result<Self, RealityError> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let webpki = WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|e| {
                RealityError::HandshakeFailed(format!("WebPKI verifier init failed: {e}"))
            })?;

        Ok(Self {
            expected_server_name,
            state,
            webpki,
        })
    }

    fn verify_temporary_cert(
        &self,
        end_entity: &rustls_pki_types::CertificateDer<'_>,
    ) -> Result<bool, rustls::Error> {
        let Some(auth_key) = self.state.auth_key() else {
            return Ok(false);
        };

        let (_, cert) = parse_x509_certificate(end_entity.as_ref()).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;

        if cert.signature_algorithm.algorithm != OID_SIG_ED25519 {
            return Ok(false);
        }

        if cert.signature_value.unused_bits != 0 {
            return Ok(false);
        }

        let public_key = cert.subject_pki.subject_public_key.data.as_ref();
        let expected = compute_temp_cert_signature(&auth_key, public_key).map_err(|e| {
            rustls::Error::General(format!("REALITY temp cert signature failed: {e}"))
        })?;

        let matches = cert.signature_value.data.as_ref() == expected.as_slice();
        if matches {
            self.state.mark_temporary_cert_verified();
        }

        Ok(matches)
    }
}

impl rustls::client::danger::ServerCertVerifier for RealityVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls_pki_types::CertificateDer<'_>,
        intermediates: &[rustls_pki_types::CertificateDer<'_>],
        server_name: &rustls_pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let server_name_str = if let rustls_pki_types::ServerName::DnsName(name) = server_name {
            name.as_ref()
        } else {
            return Err(rustls::Error::General(
                "REALITY requires DNS server name".to_string(),
            ));
        };

        if server_name_str != self.expected_server_name {
            return Err(rustls::Error::General(format!(
                "REALITY server name mismatch: expected={}, got={}",
                self.expected_server_name, server_name_str
            )));
        }

        if self.verify_temporary_cert(end_entity)? {
            return Ok(rustls::client::danger::ServerCertVerified::assertion());
        }

        self.webpki
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.webpki.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.webpki.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.webpki.supported_verify_schemes()
    }
}

#[derive(Debug)]
struct RealityX25519KxGroup;

impl SupportedKxGroup for RealityX25519KxGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&secret).to_bytes();

        register_ephemeral_secret(public_key, secret.to_bytes());

        Ok(Box::new(RealityActiveKeyExchange { secret, public_key }))
    }

    fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
        None
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

struct RealityActiveKeyExchange {
    secret: StaticSecret,
    public_key: [u8; 32],
}

impl ActiveKeyExchange for RealityActiveKeyExchange {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, rustls::Error> {
        let peer_public_key: [u8; 32] = peer
            .try_into()
            .map_err(|_| rustls::Error::General("invalid REALITY X25519 key share".to_string()))?;
        let shared_secret = self
            .secret
            .diffie_hellman(&PublicKey::from(peer_public_key))
            .to_bytes();

        if shared_secret.iter().all(|byte| *byte == 0) {
            return Err(rustls::Error::General(
                "invalid REALITY X25519 shared secret".to_string(),
            ));
        }

        Ok(SharedSecret::from(shared_secret.as_slice()))
    }

    fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
        None
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }

    fn pub_key(&self) -> &[u8] {
        &self.public_key
    }
}

fn parse_client_key_share(client_hello: &ClientHello) -> Result<[u8; 32], rustls::Error> {
    let extension = client_hello
        .find_extension(ExtensionType::KeyShare as u16)
        .ok_or_else(|| rustls::Error::General("REALITY missing key_share extension".to_string()))?;
    let data = extension.data.as_slice();

    if data.len() < 2 {
        return Err(rustls::Error::General(
            "REALITY key_share extension too short".to_string(),
        ));
    }

    let list_len = usize::from(u16::from_be_bytes([data[0], data[1]]));
    if data.len() != list_len + 2 || list_len < 4 {
        return Err(rustls::Error::General(
            "REALITY key_share extension malformed".to_string(),
        ));
    }

    let mut cursor = 2usize;
    let end = list_len + 2;

    while cursor + 4 <= end {
        let group = u16::from_be_bytes([data[cursor], data[cursor + 1]]);
        let key_len = usize::from(u16::from_be_bytes([data[cursor + 2], data[cursor + 3]]));
        let key_start = cursor + 4;
        let key_end = key_start + key_len;
        if key_end > end {
            return Err(rustls::Error::General(
                "REALITY key_share extension malformed".to_string(),
            ));
        }

        if group == u16::from(NamedGroup::X25519) {
            if key_len != 32 {
                return Err(rustls::Error::General(
                    "REALITY X25519 key share must be 32 bytes".to_string(),
                ));
            }

            return data[key_start..key_end].try_into().map_err(|_| {
                rustls::Error::General("REALITY invalid X25519 key share".to_string())
            });
        }

        cursor = key_end;
    }

    Err(rustls::Error::General(
        "REALITY missing X25519 key share".to_string(),
    ))
}

fn build_reality_plaintext_session_id(unix_seconds: u64, short_id: [u8; 8]) -> [u8; 16] {
    let mut session_id = [0u8; 16];
    session_id[..8].copy_from_slice(&unix_seconds.to_be_bytes());
    session_id[0] = 1;
    session_id[1] = 8;
    session_id[2] = 1;
    session_id[4..8].copy_from_slice(&(unix_seconds as u32).to_be_bytes());
    session_id[8..16].copy_from_slice(&short_id);
    session_id
}

fn seal_reality_session_id(
    auth_key: &[u8; 32],
    client_random: &[u8; 32],
    plaintext: &[u8; REALITY_SESSION_PLAINTEXT_LEN],
    aad: &[u8],
) -> Result<[u8; REALITY_SESSION_ID_LEN], String> {
    let key = UnboundKey::new(&aead::AES_256_GCM, auth_key)
        .map_err(|_| "invalid REALITY AES-256-GCM key".to_string())?;
    let key = LessSafeKey::new(key);
    let nonce = Nonce::assume_unique_for_key(
        client_random[20..32]
            .try_into()
            .map_err(|_| "invalid REALITY nonce length".to_string())?,
    );
    let mut ciphertext = plaintext.to_vec();
    let tag = key
        .seal_in_place_separate_tag(nonce, Aad::from(aad), &mut ciphertext)
        .map_err(|_| "REALITY seal failed".to_string())?;
    ciphertext.extend_from_slice(tag.as_ref());

    ciphertext
        .try_into()
        .map_err(|_| "REALITY session_id must be 32 bytes".to_string())
}

/// Open a REALITY session_id sealed by a client (server side).
///
/// Mirror of [`seal_reality_session_id`]: AES-256-GCM with `auth_key`,
/// nonce = `client_random[20..32]`, AAD = the raw ClientHello handshake message
/// with its 32-byte session_id slot zeroed. Returns the 16-byte plaintext
/// (`version[0..3]`, unix seconds `[4..8]`, `short_id[8..16]`).
pub(crate) fn open_reality_session_id(
    auth_key: &[u8; 32],
    client_random: &[u8; 32],
    session_id_ciphertext: &[u8; REALITY_SESSION_ID_LEN],
    aad: &[u8],
) -> Result<[u8; REALITY_SESSION_PLAINTEXT_LEN], String> {
    let key = UnboundKey::new(&aead::AES_256_GCM, auth_key)
        .map_err(|_| "invalid REALITY AES-256-GCM key".to_string())?;
    let key = LessSafeKey::new(key);
    let nonce = Nonce::assume_unique_for_key(
        client_random[20..32]
            .try_into()
            .map_err(|_| "invalid REALITY nonce length".to_string())?,
    );
    let mut in_out = session_id_ciphertext.to_vec();
    let plaintext = key
        .open_in_place(nonce, Aad::from(aad), &mut in_out)
        .map_err(|_| "REALITY session_id open failed".to_string())?;
    plaintext
        .get(..REALITY_SESSION_PLAINTEXT_LEN)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| "REALITY plaintext too short".to_string())
}

/// Server-side REALITY authentication result extracted from a client ClientHello.
pub(crate) struct RealityServerAuth {
    /// HKDF-derived auth key (shared with the authenticated client).
    pub auth_key: [u8; 32],
    /// 8-byte (zero-padded) short_id carried in the session_id plaintext.
    pub short_id: [u8; 8],
    /// Client-declared unix seconds (from the session_id plaintext).
    pub unix_seconds: u32,
}

/// Byte offset of the 32-byte session_id inside a ClientHello handshake message:
/// type(1) + length(3) + version(2) + random(32) + session_id_len(1).
const REALITY_SESSION_ID_OFFSET: usize = 39;

/// Authenticate a client ClientHello against the server's REALITY private key.
///
/// `Ok` is returned only when the embedded session_id decrypts under the shared
/// key — i.e. the client possesses matching REALITY key material. SNI acceptance,
/// short_id policy, and any time-window check remain the caller's responsibility.
pub(crate) fn open_reality_client_auth(
    server_private_key: &[u8; 32],
    client_hello: &ClientHello,
    raw_handshake_message: &[u8],
) -> Result<RealityServerAuth, String> {
    if client_hello.session_id.len() != REALITY_SESSION_ID_LEN {
        return Err("REALITY session_id is not 32 bytes".to_string());
    }
    let client_public_key = parse_client_key_share(client_hello).map_err(|e| e.to_string())?;

    let shared_secret = StaticSecret::from(*server_private_key)
        .diffie_hellman(&PublicKey::from(client_public_key))
        .to_bytes();
    let auth_key = derive_auth_key(shared_secret, &client_hello.random)?;

    // AAD = raw ClientHello handshake message with the 32-byte session_id zeroed.
    if raw_handshake_message.len() < REALITY_SESSION_ID_OFFSET + REALITY_SESSION_ID_LEN
        || raw_handshake_message.get(REALITY_SESSION_ID_OFFSET - 1)
            != Some(&(REALITY_SESSION_ID_LEN as u8))
    {
        return Err("REALITY ClientHello session_id layout mismatch".to_string());
    }
    let mut aad = raw_handshake_message.to_vec();
    aad[REALITY_SESSION_ID_OFFSET..REALITY_SESSION_ID_OFFSET + REALITY_SESSION_ID_LEN].fill(0);

    let ciphertext: [u8; REALITY_SESSION_ID_LEN] = client_hello
        .session_id
        .as_slice()
        .try_into()
        .map_err(|_| "REALITY session_id is not 32 bytes".to_string())?;

    let plaintext = open_reality_session_id(&auth_key, &client_hello.random, &ciphertext, &aad)?;

    let mut short_id = [0u8; 8];
    short_id.copy_from_slice(&plaintext[8..16]);
    let unix_seconds = u32::from_be_bytes([plaintext[4], plaintext[5], plaintext[6], plaintext[7]]);

    Ok(RealityServerAuth {
        auth_key,
        short_id,
        unix_seconds,
    })
}

fn short_id_bytes(short_id: Option<Vec<u8>>) -> [u8; 8] {
    let mut padded = [0u8; 8];
    if let Some(short_id) = short_id {
        let len = short_id.len().min(padded.len());
        padded[..len].copy_from_slice(&short_id[..len]);
    }
    padded
}

fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn register_ephemeral_secret(public_key: [u8; 32], secret: [u8; 32]) {
    EPHEMERAL_X25519_SECRETS.lock().insert(public_key, secret);
}

fn take_ephemeral_secret(public_key: &[u8; 32]) -> Option<[u8; 32]> {
    EPHEMERAL_X25519_SECRETS.lock().remove(public_key)
}

#[derive(Clone, Default)]
struct RecordingAsyncIo {
    writes: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl RecordingAsyncIo {
    fn take_writes(&self) -> Vec<Vec<u8>> {
        self.writes.lock().clone()
    }
}

impl AsyncRead for RecordingAsyncIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for RecordingAsyncIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.writes.lock().push(buf.to_vec());
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[derive(Clone, Default)]
struct ClientIoTraceSnapshot {
    events: Vec<SocketTraceEvent>,
    first_write_after_connect_micros: Option<u64>,
    first_read_after_connect_micros: Option<u64>,
}

#[derive(Clone)]
struct ClientIoTraceRecorder {
    started_at: Instant,
    snapshot: Arc<Mutex<ClientIoTraceSnapshot>>,
}

impl ClientIoTraceRecorder {
    fn new() -> Self {
        Self {
            started_at: Instant::now(),
            snapshot: Arc::new(Mutex::new(ClientIoTraceSnapshot::default())),
        }
    }

    fn record_event(&self, kind: &str, len: Option<usize>, detail: Option<String>) {
        let offset_micros = self.started_at.elapsed().as_micros() as u64;
        let mut snapshot = self.snapshot.lock();
        if kind == "write" && snapshot.first_write_after_connect_micros.is_none() {
            snapshot.first_write_after_connect_micros = Some(offset_micros);
        }
        if (kind == "read" || kind == "read_eof")
            && snapshot.first_read_after_connect_micros.is_none()
        {
            snapshot.first_read_after_connect_micros = Some(offset_micros);
        }
        snapshot.events.push(SocketTraceEvent {
            offset_micros,
            kind: kind.to_string(),
            len,
            detail,
        });
    }

    fn snapshot(&self) -> ClientIoTraceSnapshot {
        self.snapshot.lock().clone()
    }
}

struct TracingAsyncIo<S> {
    inner: S,
    recorder: ClientIoTraceRecorder,
}

impl<S> TracingAsyncIo<S> {
    fn new(inner: S) -> (Self, ClientIoTraceRecorder) {
        let recorder = ClientIoTraceRecorder::new();
        (
            Self {
                inner,
                recorder: recorder.clone(),
            },
            recorder,
        )
    }
}

impl<S> AsyncRead for TracingAsyncIo<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let filled_before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let read_len = buf.filled().len().saturating_sub(filled_before);
                if read_len == 0 {
                    this.recorder.record_event("read_eof", Some(0), None);
                } else {
                    this.recorder.record_event("read", Some(read_len), None);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => {
                this.recorder
                    .record_event("read_error", None, Some(error.to_string()));
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S> AsyncWrite for TracingAsyncIo<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(written)) => {
                this.recorder.record_event("write", Some(written), None);
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(error)) => {
                this.recorder
                    .record_event("write_error", None, Some(error.to_string()));
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                this.recorder.record_event("flush", None, None);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => {
                this.recorder
                    .record_event("flush_error", None, Some(error.to_string()));
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => {
                this.recorder.record_event("shutdown", None, None);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => {
                this.recorder
                    .record_event("shutdown_error", None, Some(error.to_string()));
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use base64::Engine as _;

    /// True iff `value` is one of the sixteen RFC 8701 GREASE code points.
    /// Used in place of the old fixed-value assertions now that the per-handshake
    /// `ChromeGreaseProfile` draws GREASE values fresh for each ClientHello.
    fn is_grease(value: u16) -> bool {
        GREASE_VALUES.contains(&value)
    }

    fn test_config() -> RealityClientConfig {
        RealityClientConfig {
            target: "www.apple.com".to_string(),
            server_name: "www.apple.com".to_string(),
            public_key: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x11u8; 32]),
            short_id: Some("01ab".to_string()),
            fingerprint: "chrome".to_string(),
            alpn: vec![],
        }
    }

    #[test]
    fn test_build_reality_plaintext_session_id() {
        let session_id =
            build_reality_plaintext_session_id(0x1234_5678, [0xaa, 0xbb, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&session_id[..4], &[1, 8, 1, 0]);
        assert_eq!(&session_id[4..8], &0x1234_5678u32.to_be_bytes());
        assert_eq!(&session_id[8..10], &[0xaa, 0xbb]);
        assert_eq!(session_id.len(), REALITY_SESSION_PLAINTEXT_LEN);
    }

    #[test]
    fn test_seal_reality_session_id_matches_expected_length() {
        let sealed =
            seal_reality_session_id(&[0x22; 32], &[0x33; 32], &[0x44; 16], &[0x55; 64]).unwrap();
        assert_eq!(sealed.len(), REALITY_SESSION_ID_LEN);
        assert_ne!(&sealed[..16], &[0x44; 16]);
    }

    /// End-to-end crypto round trip: a client seals a session_id exactly as the
    /// REALITY client does, and the server-side `open_reality_client_auth` recovers
    /// the short_id and the identical auth key. This locks the AEAD parameters
    /// (AES-256-GCM, nonce = random[20..32], AAD = ClientHello with a zeroed
    /// session_id) shared with the Go server.
    #[test]
    fn test_reality_session_id_seal_open_round_trip() {
        let server_secret = StaticSecret::from([7u8; 32]);
        let server_public = PublicKey::from(&server_secret);
        let server_private_bytes = server_secret.to_bytes();

        let client_secret = StaticSecret::from([9u8; 32]);
        let client_public = PublicKey::from(&client_secret);
        let client_public_bytes = *client_public.as_bytes();

        let shared = client_secret.diffie_hellman(&server_public).to_bytes();
        let random = [0x5a_u8; 32];
        let auth_key = derive_auth_key(shared, &random).unwrap();

        let short_id = [0x01, 0x02, 0x03, 0x04, 0, 0, 0, 0];
        let plaintext = build_reality_plaintext_session_id(current_unix_seconds(), short_id);

        // key_share extension carrying the client's X25519 public key.
        let mut key_share = Vec::new();
        key_share.extend_from_slice(&36u16.to_be_bytes());
        key_share.extend_from_slice(&u16::from(NamedGroup::X25519).to_be_bytes());
        key_share.extend_from_slice(&32u16.to_be_bytes());
        key_share.extend_from_slice(&client_public_bytes);

        // SNI extension.
        let host = b"example.com";
        let mut sni = Vec::new();
        sni.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni.extend_from_slice(host);

        let mut hello = ClientHello {
            version: 0x0303,
            random,
            session_id: vec![0u8; REALITY_SESSION_ID_LEN],
            cipher_suites: vec![0x1301],
            compression_methods: vec![0x00],
            extensions: vec![],
        };
        hello.set_extension(ExtensionType::ServerName as u16, sni);
        hello.set_extension(ExtensionType::KeyShare as u16, key_share);

        // AAD = ClientHello handshake message with a zeroed session_id.
        let aad = hello.serialize().unwrap();
        let sealed = seal_reality_session_id(&auth_key, &random, &plaintext, &aad).unwrap();

        hello.session_id = sealed.to_vec();
        let wire = hello.serialize().unwrap();
        let parsed = ClientHello::parse(&wire).unwrap();

        let auth = open_reality_client_auth(&server_private_bytes, &parsed, &wire).unwrap();
        assert_eq!(auth.short_id, short_id);
        assert_eq!(auth.auth_key, auth_key);

        // A different server private key must not decrypt the session_id.
        assert!(open_reality_client_auth(&[1u8; 32], &parsed, &wire).is_err());
    }

    #[test]
    fn test_session_id_generator_stores_auth_key_and_emits_ciphertext() {
        let client_public_key = [0x42u8; 32];
        register_ephemeral_secret(client_public_key, [0x24u8; 32]);

        let mut hello = ClientHello {
            version: 0x0303,
            random: [0x11; 32],
            session_id: vec![0; 32],
            cipher_suites: vec![0x1301],
            compression_methods: vec![0x00],
            extensions: vec![super::super::tls_record::TlsExtension {
                extension_type: ExtensionType::KeyShare as u16,
                data: {
                    let mut data = Vec::new();
                    data.extend_from_slice(&36u16.to_be_bytes());
                    data.extend_from_slice(&u16::from(NamedGroup::X25519).to_be_bytes());
                    data.extend_from_slice(&32u16.to_be_bytes());
                    data.extend_from_slice(&client_public_key);
                    data
                },
            }],
        };
        let client_hello = hello.serialize().unwrap();
        hello.session_id = vec![0; 32];

        let state = Arc::new(RealityHandshakeState::default());
        let generator = RealitySessionIdGenerator {
            server_public_key: [0x77u8; 32],
            short_id: [0x01, 0xab, 0, 0, 0, 0, 0, 0],
            state: state.clone(),
        };
        let mut session_id = [0u8; 32];
        generator.generate(&client_hello, &mut session_id).unwrap();

        assert!(state.auth_key().is_some());
        assert!(session_id.iter().any(|byte| *byte != 0));
        assert!(take_ephemeral_secret(&client_public_key).is_none());
    }

    #[test]
    fn test_rustls_emits_encrypted_reality_session_id() {
        let config = Arc::new(test_config());
        let handshake = RealityHandshake::new(config).unwrap();
        let wire = handshake.emit_client_hello_record().unwrap();

        assert_eq!(wire[0], 22);
        let record_len = usize::from(u16::from_be_bytes([wire[3], wire[4]]));
        let parsed = ClientHello::parse(&wire[5..5 + record_len]).unwrap();
        assert_eq!(parsed.session_id.len(), REALITY_SESSION_ID_LEN);
        assert!(parsed.session_id.iter().any(|byte| *byte != 0));
    }

    #[test]
    fn test_trace_client_hello_writes_form_single_tls_record() {
        let config = Arc::new(test_config());
        let handshake = RealityHandshake::new(config).unwrap();
        let writes = handshake.trace_client_hello_writes().unwrap();

        assert_eq!(writes.len(), 1, "expected a single first-flight write");
        let flattened = writes.concat();
        assert_eq!(writes[0][0], 22);
        let record_len = usize::from(u16::from_be_bytes([flattened[3], flattened[4]]));
        assert_eq!(flattened.len(), 5 + record_len);
        let parsed = ClientHello::parse(&flattened[5..]).expect("parse client hello");
        assert_eq!(parsed.session_id.len(), REALITY_SESSION_ID_LEN);
        assert!(is_grease(parsed.cipher_suites[0]));
    }

    #[test]
    fn test_trace_local_socket_handshake_observes_first_flight_bytes() {
        let config = Arc::new(test_config());
        let handshake = RealityHandshake::new(config).unwrap();
        let trace = handshake.trace_local_socket_handshake().unwrap();

        assert!(!trace.listener_addr.is_empty());
        assert!(trace.server_read_count >= 1);
        assert!(trace.server_total_len > 0);
        assert!(trace.client_connect_elapsed_micros.is_some());
        assert!(trace.client_handshake_elapsed_micros.is_some());
        assert!(trace.client_first_write_after_connect_micros.is_some());
        assert!(trace.client_first_read_after_connect_micros.is_some());
        assert!(trace.server_first_read_delay_micros.is_some());
        assert!(trace.server_trace_elapsed_micros > 0);
        assert!(trace.server_first_read_to_end_micros.is_some());
        assert!(
            matches!(trace.server_end_reason.as_str(), "eof" | "timeout"),
            "unexpected end reason: {}",
            trace.server_end_reason
        );
        assert!(
            trace
                .server_chunks
                .iter()
                .all(|chunk| !chunk.hex.is_empty())
        );
        assert!(
            trace
                .client_event_trace
                .iter()
                .any(|event| event.kind == "write")
        );
        assert!(
            trace
                .client_event_trace
                .iter()
                .any(|event| event.kind == "read" || event.kind == "read_eof")
        );
        assert!(
            trace
                .server_chunks
                .iter()
                .all(|chunk| chunk.offset_micros <= trace.server_trace_elapsed_micros)
        );
        assert_eq!(
            trace
                .server_chunks
                .first()
                .and_then(|chunk| chunk.record_type.as_deref()),
            Some("0x16")
        );
        assert!(
            trace
                .client_error
                .as_deref()
                .is_some_and(|error| error.contains("TLS handshake failed"))
        );
    }

    #[test]
    fn test_trace_remote_socket_handshake_records_client_events() {
        let listener = StdTcpListener::bind(("127.0.0.1", 0)).expect("bind test listener");
        let listener_addr = listener.local_addr().expect("listener addr");
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept test client");
            socket
                .set_read_timeout(Some(Duration::from_millis(500)))
                .expect("set read timeout");
            let mut buffer = [0u8; 4096];
            let _ = socket.read(&mut buffer);
        });

        let config = Arc::new(test_config());
        let handshake = RealityHandshake::new(config).unwrap();
        let trace = handshake
            .trace_remote_socket_handshake(listener_addr)
            .unwrap();

        server.join().expect("join test server");

        assert_eq!(trace.remote_addr, listener_addr.to_string());
        assert!(trace.client_connect_elapsed_micros.is_some());
        assert!(trace.client_handshake_elapsed_micros.is_some());
        assert!(trace.client_first_write_after_connect_micros.is_some());
        assert!(
            trace
                .client_event_trace
                .iter()
                .any(|event| event.kind == "write")
        );
        assert!(
            trace
                .client_event_trace
                .iter()
                .any(|event| event.kind == "read" || event.kind == "read_eof")
        );
        assert!(
            trace
                .client_error
                .as_deref()
                .is_some_and(|error| error.contains("TLS handshake failed"))
        );
    }

    #[test]
    fn test_trace_remote_socket_handshake_respects_timeout_override() {
        let listener = StdTcpListener::bind(("127.0.0.1", 0)).expect("bind test listener");
        let listener_addr = listener.local_addr().expect("listener addr");
        let server = thread::spawn(move || {
            let (_socket, _) = listener.accept().expect("accept test client");
            thread::sleep(Duration::from_millis(200));
        });

        let config = Arc::new(test_config());
        let handshake = RealityHandshake::new(config).unwrap();
        let error = handshake
            .trace_remote_socket_handshake_with_timeout(listener_addr, Duration::from_millis(50))
            .unwrap_err();

        server.join().expect("join test server");

        assert!(
            error
                .to_string()
                .contains("remote socket trace client handshake timed out")
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // one cohesive wire-format assertion over every injected extension
    fn test_chrome_baseline_extensions_are_injected() {
        let config = Arc::new(test_config());
        let handshake = RealityHandshake::new(config).unwrap();
        let wire = handshake.emit_client_hello_record().unwrap();

        let record_len = usize::from(u16::from_be_bytes([wire[3], wire[4]]));
        let parsed = ClientHello::parse(&wire[5..5 + record_len]).unwrap();
        let extension_types = parsed
            .extensions
            .iter()
            .map(|ext| ext.extension_type)
            .collect::<Vec<_>>();

        assert!(is_grease(parsed.cipher_suites[0]));
        assert!(parsed.cipher_suites.ends_with(&[
            0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
        ]));
        let grease_head = extension_types.first().copied().unwrap();
        let grease_tail = extension_types.last().copied().unwrap();
        assert!(is_grease(grease_head));
        assert!(is_grease(grease_tail));
        assert_ne!(grease_head, grease_tail);
        let mut sorted_extension_types = extension_types;
        sorted_extension_types.sort_unstable();
        let mut expected_extension_types = vec![
            EXT_SERVER_NAME,
            EXT_STATUS_REQUEST,
            EXT_SUPPORTED_GROUPS,
            EXT_EC_POINT_FORMATS,
            EXT_SIGNATURE_ALGORITHMS,
            EXT_ALPN,
            EXT_SCT,
            EXT_COMPRESS_CERTIFICATE,
            EXT_EXTENDED_MASTER_SECRET,
            EXT_SESSION_TICKET,
            EXT_SUPPORTED_VERSIONS,
            EXT_PSK_KEY_EXCHANGE_MODES,
            EXT_KEY_SHARE,
            EXT_TRUST_ANCHORS,
            EXT_APPLICATION_SETTINGS,
            grease_head,
            EXT_ECH_OUTER,
            EXT_RENEGOTIATION_INFO,
            grease_tail,
        ];
        expected_extension_types.sort_unstable();
        assert_eq!(sorted_extension_types, expected_extension_types);
        assert_eq!(
            parsed
                .find_extension(EXT_COMPRESS_CERTIFICATE)
                .unwrap()
                .data,
            vec![0x02, 0x00, 0x02]
        );
        assert_eq!(
            parsed
                .find_extension(EXT_APPLICATION_SETTINGS)
                .unwrap()
                .data,
            vec![0x00, 0x03, 0x02, b'h', b'2']
        );
        assert_eq!(
            parsed.find_extension(EXT_TRUST_ANCHORS).unwrap().data,
            vec![0x00, 0x00]
        );
        let (client_hello_type, kdf_id, aead_id, _config_id, encapsulated_key_len, payload_len) =
            parse_utls_boring_grease_ech_extension(
                &parsed.find_extension(EXT_ECH_OUTER).unwrap().data,
            )
            .expect("uTLS BoringGREASEECH-like extension");
        assert_eq!(client_hello_type, UTLS_GREASE_ECH_OUTER_CLIENT_HELLO);
        assert_eq!(kdf_id, UTLS_GREASE_ECH_KDF_ID);
        assert_eq!(aead_id, UTLS_GREASE_ECH_AEAD_ID);
        assert_eq!(encapsulated_key_len, UTLS_GREASE_ECH_ENCAPSULATED_KEY_LEN);
        assert!(UTLS_GREASE_ECH_PAYLOAD_LENS.contains(&payload_len));
        assert_eq!(
            parsed.find_extension(EXT_RENEGOTIATION_INFO).unwrap().data,
            vec![0x00]
        );
        assert_eq!(
            parsed
                .find_extension(EXT_SESSION_TICKET)
                .unwrap()
                .data
                .len(),
            0
        );
        let supported_versions = &parsed.find_extension(EXT_SUPPORTED_VERSIONS).unwrap().data;
        assert_eq!(supported_versions[0], 0x06);
        assert!(is_grease(u16::from_be_bytes([
            supported_versions[1],
            supported_versions[2],
        ])));
        assert_eq!(&supported_versions[3..], &[0x03, 0x04, 0x03, 0x03]);
        let supported_groups = &parsed.find_extension(EXT_SUPPORTED_GROUPS).unwrap().data;
        assert_eq!(&supported_groups[..2], &[0x00, 0x08]);
        let groups_grease = u16::from_be_bytes([supported_groups[2], supported_groups[3]]);
        assert!(is_grease(groups_grease));
        assert_eq!(
            &supported_groups[4..],
            &[0x00, 0x1d, 0x00, 0x17, 0x00, 0x18]
        );
        assert_eq!(
            parsed
                .find_extension(EXT_SIGNATURE_ALGORITHMS)
                .unwrap()
                .data,
            vec![
                0x00, 0x16, 0x09, 0x04, 0x09, 0x05, 0x09, 0x06, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01,
                0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01,
            ]
        );
        let key_share = &parsed.find_extension(EXT_KEY_SHARE).unwrap().data;
        assert_eq!(&key_share[..2], &[0x00, 0x29]);
        let key_share_grease = u16::from_be_bytes([key_share[2], key_share[3]]);
        assert!(is_grease(key_share_grease));
        assert_eq!(&key_share[4..7], &[0x00, 0x01, 0x00]);
        assert_eq!(
            key_share_grease, groups_grease,
            "key_share GREASE must equal supported_groups GREASE"
        );
    }

    #[test]
    fn test_chrome_current_fisher_yates_matches_boringssl_word_semantics() {
        let mut rng = SeqRng {
            vals: (0..64).collect(),
            i: 0,
        };
        let order = build_chrome_extension_order(&mut rng, 0x0a0a, 0x1a1a);
        let mut expected_middle = CHROME_CURRENT_MIDDLE_EXTENSIONS.to_vec();
        for (word, i) in (1..expected_middle.len()).rev().enumerate() {
            expected_middle.swap(i, word % (i + 1));
        }
        assert_eq!(order[0], 0x0a0a);
        assert_eq!(order[order.len() - 1], 0x1a1a);
        assert_eq!(&order[1..order.len() - 1], expected_middle);
    }

    #[test]
    fn test_chrome_current_ech_bucket_is_independent_from_order_words() {
        let mut bucket_rng = SeqRng {
            vals: vec![2],
            i: 0,
        };
        assert_eq!(select_chrome_ech_payload_len(&mut bucket_rng), 208);

        let mut order_a = SeqRng {
            vals: vec![0],
            i: 0,
        };
        let mut order_b = SeqRng {
            vals: vec![1],
            i: 0,
        };
        assert_ne!(
            build_chrome_extension_order(&mut order_a, 0x0a0a, 0x1a1a),
            build_chrome_extension_order(&mut order_b, 0x0a0a, 0x1a1a)
        );
    }

    #[test]
    fn test_chrome_baseline_extension_order_varies_across_runs() {
        let config = Arc::new(test_config());
        let handshake = RealityHandshake::new(config).unwrap();
        let mut orders = std::collections::BTreeSet::new();

        for _ in 0..8 {
            let wire = handshake.emit_client_hello_record().unwrap();
            let record_len = usize::from(u16::from_be_bytes([wire[3], wire[4]]));
            let parsed = ClientHello::parse(&wire[5..5 + record_len]).unwrap();
            let extension_types = parsed
                .extensions
                .iter()
                .map(|ext| ext.extension_type)
                .collect::<Vec<_>>();

            let head = extension_types.first().copied().unwrap();
            let tail = extension_types.last().copied().unwrap();
            assert!(is_grease(head));
            assert!(is_grease(tail));
            assert_ne!(head, tail);
            orders.insert(extension_types);
        }

        assert!(
            orders.len() > 1,
            "expected randomized extension order family"
        );
    }

    #[test]
    fn test_chrome_baseline_opaque_extensions_are_not_pinned_to_tail_block() {
        let config = Arc::new(test_config());
        let handshake = RealityHandshake::new(config).unwrap();
        let mut fe0d_positions = std::collections::BTreeSet::new();
        let mut opaque_position_tuples = std::collections::BTreeSet::new();

        for _ in 0..24 {
            let wire = handshake.emit_client_hello_record().unwrap();
            let record_len = usize::from(u16::from_be_bytes([wire[3], wire[4]]));
            let parsed = ClientHello::parse(&wire[5..5 + record_len]).unwrap();
            let extension_types = parsed
                .extensions
                .iter()
                .map(|ext| ext.extension_type)
                .collect::<Vec<_>>();
            let positions = [
                extension_types
                    .iter()
                    .position(|ext| *ext == EXT_SCT)
                    .expect("sct extension present"),
                extension_types
                    .iter()
                    .position(|ext| *ext == EXT_COMPRESS_CERTIFICATE)
                    .expect("compress_certificate extension present"),
                extension_types
                    .iter()
                    .position(|ext| *ext == EXT_APPLICATION_SETTINGS)
                    .expect("application_settings extension present"),
                extension_types
                    .iter()
                    .position(|ext| *ext == EXT_ECH_OUTER)
                    .expect("ech outer extension present"),
            ];

            fe0d_positions.insert(positions[3]);
            opaque_position_tuples.insert(positions);
        }

        assert!(
            fe0d_positions.len() > 1,
            "expected 0xfe0d to move within the middle extension family"
        );
        assert!(
            opaque_position_tuples.len() > 1,
            "expected opaque extension positions to vary across runs"
        );
        assert!(
            fe0d_positions.iter().any(|pos| *pos < 16),
            "expected 0xfe0d to appear before the tail slot in some runs"
        );
    }

    #[test]
    fn test_chrome_baseline_ech_outer_matches_utls_boring_grease_family() {
        let config = Arc::new(test_config());
        let handshake = RealityHandshake::new(config).unwrap();
        let mut record_lens = std::collections::BTreeSet::new();
        let mut ech_outer_lens = std::collections::BTreeSet::new();
        let mut ech_payload_lens = std::collections::BTreeSet::new();

        for _ in 0..16 {
            let wire = handshake.emit_client_hello_record().unwrap();
            let record_len = usize::from(u16::from_be_bytes([wire[3], wire[4]]));
            let parsed = ClientHello::parse(&wire[5..5 + record_len]).unwrap();
            let ech_outer = parsed.find_extension(EXT_ECH_OUTER).unwrap();
            let (client_hello_type, kdf_id, aead_id, config_id, encapsulated_key_len, payload_len) =
                parse_utls_boring_grease_ech_extension(&ech_outer.data)
                    .expect("uTLS BoringGREASEECH-like extension");

            assert_eq!(client_hello_type, UTLS_GREASE_ECH_OUTER_CLIENT_HELLO);
            assert_eq!(kdf_id, UTLS_GREASE_ECH_KDF_ID);
            assert_eq!(aead_id, UTLS_GREASE_ECH_AEAD_ID);
            assert_eq!(encapsulated_key_len, UTLS_GREASE_ECH_ENCAPSULATED_KEY_LEN);
            assert!(UTLS_GREASE_ECH_PAYLOAD_LENS.contains(&payload_len));
            let _ = config_id;

            record_lens.insert(record_len);
            ech_outer_lens.insert(ech_outer.data.len());
            ech_payload_lens.insert(payload_len);
        }

        assert!(
            record_lens
                .iter()
                .all(|len| [508, 540, 572, 604].contains(len)),
            "unexpected record length family: {record_lens:?}"
        );
        assert!(
            ech_outer_lens
                .iter()
                .all(|len| [186, 218, 250, 282].contains(len)),
            "unexpected 0xfe0d length family: {ech_outer_lens:?}"
        );
        assert!(
            ech_payload_lens
                .iter()
                .all(|len| UTLS_GREASE_ECH_PAYLOAD_LENS.contains(len)),
            "unexpected GREASE ECH payload family: {ech_payload_lens:?}"
        );
        assert!(
            record_lens.len() > 1,
            "expected dynamic record length family"
        );
        assert!(
            ech_outer_lens.len() > 1,
            "expected dynamic 0xfe0d length family"
        );
        assert!(
            ech_payload_lens.len() > 1,
            "expected dynamic GREASE ECH payload family"
        );
    }

    // --- T3-1C coordinated per-ClientHello GREASE selector (deterministic) ---
    // T3-1C.1: GREASE uses an INDEPENDENT per-ClientHello OsRng draw, NOT the
    // randomization_seed. Tests inject a deterministic RNG / index source — no probabilistic gate.

    /// Deterministic `RngCore` yielding a fixed u32 sequence (cycled) so the OsRng-backed
    /// `ChromeGreaseProfile::random` path is exercised reproducibly. `random` consumes the
    /// low nibble of each draw.
    struct SeqRng {
        vals: Vec<u32>,
        i: usize,
    }
    impl rand::RngCore for SeqRng {
        fn next_u32(&mut self) -> u32 {
            let v = self.vals[self.i % self.vals.len()];
            self.i += 1;
            v
        }
        fn next_u64(&mut self) -> u64 {
            u64::from(self.next_u32())
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for b in dest.iter_mut() {
                *b = self.next_u32() as u8;
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }
    impl rand::CryptoRng for SeqRng {}

    #[test]
    fn exhaustive_or_table_driven_slot_membership() {
        // Every table entry is a GREASE code point.
        for v in GREASE_VALUES {
            assert!(is_grease(v));
        }
        // Table-driven: every constant index source yields an all-GREASE profile.
        for idx in 0..GREASE_VALUES.len() {
            let g = ChromeGreaseProfile::from_index_source(|| idx);
            for value in [
                g.cipher,
                g.supported_versions,
                g.group,
                g.ext_head,
                g.ext_tail,
            ] {
                assert!(
                    is_grease(value),
                    "idx {idx} produced non-GREASE {value:#06x}"
                );
            }
        }
        // Production RNG path (deterministic SeqRng) stays in-table for every draw.
        let mut rng = SeqRng {
            vals: vec![0, 3, 6, 9, 12, 15, 1, 4],
            i: 0,
        };
        for _ in 0..64 {
            let g = ChromeGreaseProfile::random(&mut rng);
            for value in [
                g.cipher,
                g.supported_versions,
                g.group,
                g.ext_head,
                g.ext_tail,
            ] {
                assert!(is_grease(value));
            }
        }
    }

    #[test]
    fn group_and_key_share_share_exactly_one_draw() {
        // The selector draws `group` with exactly one index pull (the 3rd), and that single
        // value feeds BOTH supported_groups[0] and the key_share group.
        let mut pulls = 0usize;
        let seq = [1usize, 4, 7, 10, 13];
        let g = ChromeGreaseProfile::from_index_source(|| {
            let v = seq[pulls.min(seq.len() - 1)];
            pulls += 1;
            v
        });
        assert_eq!(g.group, GREASE_VALUES[7], "group is the single 3rd draw");
        let mut rng = SeqRng {
            vals: vec![1, 4, 7, 10, 13, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            i: 0,
        };
        let fp = build_chrome_client_hello_fingerprint_with_rng(144, &mut rng);
        let supported_groups = fp.supported_groups_override.expect("supported_groups");
        let (key_share_group, _) = fp.key_share_grease.expect("key_share_grease");
        assert!(is_grease(supported_groups[0]));
        assert_eq!(supported_groups[0], g.group);
        assert_eq!(key_share_group, g.group);
    }

    #[test]
    fn ext_tail_collision_path_is_bounded_and_distinct() {
        // Draw order: cipher, supported_versions, group, ext_head, ext_tail(, retries).
        // Force the first ext_tail candidate (5th draw) to collide with ext_head
        // (4th draw, index 5); the retry then yields a distinct index (9).
        let mut it = [0usize, 1, 2, 5, 5, 9].into_iter();
        let g = ChromeGreaseProfile::from_index_source(|| it.next().unwrap());
        assert_eq!(g.ext_head, GREASE_VALUES[5]);
        assert_eq!(g.ext_tail, GREASE_VALUES[9]);
        assert_ne!(g.ext_head, g.ext_tail);

        // A degenerate source that always collides must still terminate with a
        // guaranteed-distinct fallback of (head_idx + 1) % 16.
        let g2 = ChromeGreaseProfile::from_index_source(|| 3);
        assert_eq!(g2.ext_head, GREASE_VALUES[3]);
        assert_eq!(g2.ext_tail, GREASE_VALUES[4]);
        assert_ne!(g2.ext_head, g2.ext_tail);
    }

    #[test]
    fn unrelated_slots_can_collide() {
        // cipher, supported_versions and group all draw index 7 → identical values.
        // This is permitted; only ext_head != ext_tail is enforced (no six-slot dedup).
        let mut it = [7usize, 7, 7, 0, 1].into_iter();
        let g = ChromeGreaseProfile::from_index_source(|| it.next().unwrap());
        assert_eq!(g.cipher, GREASE_VALUES[7]);
        assert_eq!(g.supported_versions, GREASE_VALUES[7]);
        assert_eq!(g.group, GREASE_VALUES[7]);
        assert_eq!(g.cipher, g.group);
        assert_ne!(g.ext_head, g.ext_tail);
    }

    #[test]
    fn deterministic_sequences_produce_expected_profiles() {
        let mut a = [0usize, 2, 4, 6, 8].into_iter();
        let ga = ChromeGreaseProfile::from_index_source(|| a.next().unwrap());
        assert_eq!(
            ga,
            ChromeGreaseProfile {
                cipher: GREASE_VALUES[0],
                supported_versions: GREASE_VALUES[2],
                group: GREASE_VALUES[4],
                ext_head: GREASE_VALUES[6],
                ext_tail: GREASE_VALUES[8],
            }
        );
        let mut b = [1usize, 3, 5, 7, 9].into_iter();
        let gb = ChromeGreaseProfile::from_index_source(|| b.next().unwrap());
        assert_eq!(
            gb,
            ChromeGreaseProfile {
                cipher: GREASE_VALUES[1],
                supported_versions: GREASE_VALUES[3],
                group: GREASE_VALUES[5],
                ext_head: GREASE_VALUES[7],
                ext_tail: GREASE_VALUES[9],
            }
        );
        assert_ne!(ga, gb);
    }

    #[test]
    fn no_duplicate_grease_extension_type() {
        for first_word in [0u32, 5, 0x1234, 0xbeef, 0xffff] {
            let mut rng = SeqRng {
                vals: vec![first_word, 1, 2, 3, 4, 5, 6, 7, 8],
                i: 0,
            };
            let fp = build_chrome_client_hello_fingerprint_with_rng(144, &mut rng);
            let grease_exts: Vec<u16> = fp
                .extension_order
                .iter()
                .copied()
                .filter(|t| is_grease(*t))
                .collect();
            assert_eq!(grease_exts.len(), 2, "exactly two GREASE extension types");
            assert_ne!(grease_exts[0], grease_exts[1], "GREASE ext types distinct");
            // The opaque head/tail GREASE extensions match the order's head/tail.
            assert_eq!(fp.extension_order.first().copied(), Some(grease_exts[0]));
            assert_eq!(fp.extension_order.last().copied(), Some(grease_exts[1]));
            assert_eq!(
                fp.opaque_extensions.first().map(|(t, _)| *t),
                Some(grease_exts[0])
            );
            assert_eq!(
                fp.opaque_extensions.last().map(|(t, _)| *t),
                Some(grease_exts[1])
            );
        }
    }
}
