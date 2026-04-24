//! REALITY client handshake built on rustls hooks.

use super::auth::{compute_temp_cert_signature, derive_auth_key};
use super::client::RealityClientTlsStream;
use super::config::RealityClientConfig;
use super::tls_record::{ClientHello, ExtensionType};
use super::{RealityError, RealityResult};
#[cfg(feature = "utls")]
use crate::{UtlsConfig, UtlsFingerprint};
use parking_lot::Mutex;
use rand::RngCore;
use rand::rngs::OsRng;
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
const EXT_APPLICATION_SETTINGS: u16 = 0x44cd;
const EXT_ECH_OUTER: u16 = 0xfe0d;
const EXT_RENEGOTIATION_INFO: u16 = 0xff01;
const GREASE_EXT_HEAD: u16 = 0xcaca;
const GREASE_CIPHER_SUITE: u16 = 0xfafa;
const GREASE_EXT_TAIL: u16 = 0xaaaa;
const GREASE_SUPPORTED_VERSIONS: u16 = 0x6a6a;
const GREASE_NAMED_GROUP: u16 = 0x4a4a;
const UTLS_GREASE_ECH_OUTER_CLIENT_HELLO: u8 = 0x00;
const UTLS_GREASE_ECH_KDF_ID: u16 = 0x0001;
const UTLS_GREASE_ECH_AEAD_ID: u16 = 0x0001;
const UTLS_GREASE_ECH_ENCAPSULATED_KEY_LEN: usize = 32;
const UTLS_GREASE_ECH_PAYLOAD_LENS: [usize; 4] = [144, 176, 208, 240];
const CHROME_BASELINE_MIDDLE_EXTENSIONS: [u16; 16] = [
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
    EXT_APPLICATION_SETTINGS,
    EXT_ECH_OUTER,
    EXT_RENEGOTIATION_INFO,
];
const CHROME_FE0D_POSITIONS_186: [usize; 12] = [2, 3, 4, 4, 6, 6, 8, 9, 10, 12, 15, 15];
const CHROME_FE0D_POSITIONS_218: [usize; 14] = [2, 2, 3, 3, 5, 6, 6, 6, 9, 12, 12, 13, 16, 16];
const CHROME_FE0D_POSITIONS_250: [usize; 20] = [
    2, 3, 4, 6, 6, 9, 9, 11, 11, 12, 12, 14, 15, 15, 16, 16, 16, 16, 16, 16,
];
const CHROME_FE0D_POSITIONS_282: [usize; 14] = [2, 2, 3, 5, 5, 5, 6, 8, 10, 11, 13, 13, 15, 16];
const CHROME_BUCKET_TARGETS_186: [(u16, u8); 15] = [
    (EXT_SERVER_NAME, 6),
    (EXT_SESSION_TICKET, 7),
    (EXT_SUPPORTED_GROUPS, 8),
    (EXT_SCT, 8),
    (EXT_EC_POINT_FORMATS, 9),
    (EXT_COMPRESS_CERTIFICATE, 9),
    (EXT_STATUS_REQUEST, 9),
    (EXT_SIGNATURE_ALGORITHMS, 9),
    (EXT_RENEGOTIATION_INFO, 10),
    (EXT_PSK_KEY_EXCHANGE_MODES, 10),
    (EXT_KEY_SHARE, 10),
    (EXT_ALPN, 10),
    (EXT_EXTENDED_MASTER_SECRET, 11),
    (EXT_APPLICATION_SETTINGS, 12),
    (EXT_SUPPORTED_VERSIONS, 12),
];
const CHROME_BUCKET_TARGETS_218: [(u16, u8); 15] = [
    (EXT_SERVER_NAME, 7),
    (EXT_COMPRESS_CERTIFICATE, 7),
    (EXT_SESSION_TICKET, 7),
    (EXT_PSK_KEY_EXCHANGE_MODES, 8),
    (EXT_SCT, 8),
    (EXT_EXTENDED_MASTER_SECRET, 8),
    (EXT_EC_POINT_FORMATS, 8),
    (EXT_SUPPORTED_VERSIONS, 9),
    (EXT_KEY_SHARE, 9),
    (EXT_APPLICATION_SETTINGS, 10),
    (EXT_SUPPORTED_GROUPS, 11),
    (EXT_STATUS_REQUEST, 11),
    (EXT_SIGNATURE_ALGORITHMS, 12),
    (EXT_RENEGOTIATION_INFO, 12),
    (EXT_ALPN, 13),
];
const CHROME_BUCKET_TARGETS_250: [(u16, u8); 15] = [
    (EXT_ALPN, 7),
    (EXT_APPLICATION_SETTINGS, 8),
    (EXT_SIGNATURE_ALGORITHMS, 8),
    (EXT_RENEGOTIATION_INFO, 8),
    (EXT_SCT, 9),
    (EXT_EXTENDED_MASTER_SECRET, 9),
    (EXT_SUPPORTED_GROUPS, 9),
    (EXT_EC_POINT_FORMATS, 9),
    (EXT_SUPPORTED_VERSIONS, 10),
    (EXT_COMPRESS_CERTIFICATE, 10),
    (EXT_SESSION_TICKET, 10),
    (EXT_KEY_SHARE, 10),
    (EXT_SERVER_NAME, 11),
    (EXT_STATUS_REQUEST, 11),
    (EXT_PSK_KEY_EXCHANGE_MODES, 11),
];
const CHROME_BUCKET_TARGETS_282: [(u16, u8); 15] = [
    (EXT_RENEGOTIATION_INFO, 6),
    (EXT_APPLICATION_SETTINGS, 7),
    (EXT_SUPPORTED_GROUPS, 7),
    (EXT_PSK_KEY_EXCHANGE_MODES, 8),
    (EXT_SERVER_NAME, 9),
    (EXT_KEY_SHARE, 9),
    (EXT_SCT, 10),
    (EXT_SESSION_TICKET, 10),
    (EXT_ALPN, 10),
    (EXT_STATUS_REQUEST, 10),
    (EXT_COMPRESS_CERTIFICATE, 10),
    (EXT_SUPPORTED_VERSIONS, 11),
    (EXT_EXTENDED_MASTER_SECRET, 12),
    (EXT_EC_POINT_FORMATS, 12),
    (EXT_SIGNATURE_ALGORITHMS, 12),
];
const CHROME_SIGNATURE_MODE_WEIGHT: i16 = 18;
const CHROME_SIGNATURE_PERTURB_WEIGHT: i16 = 8;
const CHROME_SIGNATURE_PAIRS: [(u16, u16); 5] = [
    (EXT_SERVER_NAME, EXT_SUPPORTED_VERSIONS),
    (EXT_SCT, EXT_ECH_OUTER),
    (EXT_EXTENDED_MASTER_SECRET, EXT_ECH_OUTER),
    (EXT_SUPPORTED_VERSIONS, EXT_ECH_OUTER),
    (EXT_ECH_OUTER, EXT_RENEGOTIATION_INFO),
];
const CHROME_BUCKET_SIGNATURE_MODES_186: [[i8; 5]; 4] = [
    [1, -1, -1, -1, 1],
    [1, -1, -1, -1, -1],
    [1, -1, 1, -1, -1],
    [-1, -1, -1, -1, 1],
];
const CHROME_BUCKET_SIGNATURE_MODES_218: [[i8; 5]; 4] = [
    [1, 1, 1, -1, -1],
    [-1, 1, 1, 1, -1],
    [-1, -1, -1, -1, -1],
    [1, -1, -1, -1, 1],
];
const CHROME_BUCKET_SIGNATURE_MODES_250: [[i8; 5]; 4] = [
    [-1, -1, -1, -1, 1],
    [1, -1, -1, 1, -1],
    [1, 1, 1, 1, -1],
    [-1, -1, -1, 1, -1],
];
const CHROME_BUCKET_SIGNATURE_MODES_282: [[i8; 5]; 4] = [
    [-1, 1, 1, 1, -1],
    [-1, 1, -1, 1, -1],
    [1, -1, -1, -1, 1],
    [1, 1, 1, 1, -1],
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChromeFe0dPositionBand {
    Early,
    Mid,
    Late,
}

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

    let randomization_seed = generate_chrome_randomization_seed();
    Some(build_chrome_client_hello_fingerprint_with_seed(
        randomization_seed,
    ))
}

fn build_chrome_client_hello_fingerprint_with_seed(
    randomization_seed: u16,
) -> ClientHelloFingerprint {
    ClientHelloFingerprint {
        opaque_extensions: vec![
            (GREASE_EXT_HEAD, Vec::new()),
            (EXT_SCT, Vec::new()),
            (EXT_COMPRESS_CERTIFICATE, vec![0x02, 0x00, 0x02]),
            (EXT_APPLICATION_SETTINGS, vec![0x00, 0x03, 0x02, b'h', b'2']),
            (
                EXT_ECH_OUTER,
                build_utls_boring_grease_ech_extension(randomization_seed),
            ),
            (GREASE_EXT_TAIL, vec![0x00]),
        ],
        randomization_seed: Some(randomization_seed),
        extension_order: build_chrome_extension_order(randomization_seed),
        prefix_extension_order: vec![],
        suffix_extension_order: vec![],
        grease_ciphersuite: Some(GREASE_CIPHER_SUITE),
        extra_cipher_suites: vec![
            0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
        ],
        include_empty_session_ticket: true,
        include_renegotiation_info: true,
        supported_versions_override: Some(vec![GREASE_SUPPORTED_VERSIONS, 0x0304, 0x0303]),
        supported_groups_override: Some(vec![GREASE_NAMED_GROUP, 0x001d, 0x0017, 0x0018]),
        key_share_grease: Some((GREASE_NAMED_GROUP, vec![0x00])),
        signature_algorithms_override: Some(vec![
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ]),
    }
}

fn generate_chrome_randomization_seed() -> u16 {
    let mut rng = OsRng;
    rng.next_u32() as u16
}

fn chrome_ech_payload_len_from_seed(randomization_seed: u16) -> usize {
    UTLS_GREASE_ECH_PAYLOAD_LENS[(randomization_seed as usize) % UTLS_GREASE_ECH_PAYLOAD_LENS.len()]
}

fn chrome_fe0d_position_profile(payload_len: usize) -> &'static [usize] {
    match payload_len {
        144 => &CHROME_FE0D_POSITIONS_186,
        176 => &CHROME_FE0D_POSITIONS_218,
        208 => &CHROME_FE0D_POSITIONS_250,
        240 => &CHROME_FE0D_POSITIONS_282,
        _ => &CHROME_FE0D_POSITIONS_250,
    }
}

fn chrome_bucket_targets(payload_len: usize) -> &'static [(u16, u8)] {
    match payload_len {
        144 => &CHROME_BUCKET_TARGETS_186,
        176 => &CHROME_BUCKET_TARGETS_218,
        208 => &CHROME_BUCKET_TARGETS_250,
        240 => &CHROME_BUCKET_TARGETS_282,
        _ => &CHROME_BUCKET_TARGETS_250,
    }
}

fn chrome_bucket_target_position(payload_len: usize, ext_type: u16) -> u8 {
    chrome_bucket_targets(payload_len)
        .iter()
        .find(|(candidate, _)| *candidate == ext_type)
        .map(|(_, position)| *position)
        .unwrap_or(9)
}

fn chrome_bucket_signature_modes(payload_len: usize) -> &'static [[i8; 5]] {
    match payload_len {
        144 => &CHROME_BUCKET_SIGNATURE_MODES_186,
        176 => &CHROME_BUCKET_SIGNATURE_MODES_218,
        208 => &CHROME_BUCKET_SIGNATURE_MODES_250,
        240 => &CHROME_BUCKET_SIGNATURE_MODES_282,
        _ => &CHROME_BUCKET_SIGNATURE_MODES_250,
    }
}

fn chrome_apply_signature_mode_bias(mode: &[i8; 5], ext_type: u16, weight: i16) -> i16 {
    CHROME_SIGNATURE_PAIRS
        .iter()
        .zip(mode.iter())
        .fold(0, |bias, ((left, right), direction)| match *direction {
            1 if ext_type == *left => bias - weight,
            1 if ext_type == *right => bias + weight,
            -1 if ext_type == *left => bias + weight,
            -1 if ext_type == *right => bias - weight,
            _ => bias,
        })
}

fn chrome_signature_mode_index(randomization_seed: u16, payload_len: usize, salt: u16) -> usize {
    let modes = chrome_bucket_signature_modes(payload_len);
    mix_randomization_seed(randomization_seed ^ salt, payload_len as u16 ^ 0x53c1) as usize
        % modes.len()
}

fn chrome_bucket_pairwise_bias(randomization_seed: u16, payload_len: usize, ext_type: u16) -> i16 {
    let modes = chrome_bucket_signature_modes(payload_len);
    let primary_mode = &modes[chrome_signature_mode_index(randomization_seed, payload_len, 0x2f91)];
    let secondary_mode =
        &modes[chrome_signature_mode_index(randomization_seed, payload_len, 0x7b4d)];

    chrome_apply_signature_mode_bias(primary_mode, ext_type, CHROME_SIGNATURE_MODE_WEIGHT)
        + chrome_apply_signature_mode_bias(
            secondary_mode,
            ext_type,
            CHROME_SIGNATURE_PERTURB_WEIGHT,
        )
}

fn build_chrome_extension_order(randomization_seed: u16) -> Vec<u16> {
    let payload_len = chrome_ech_payload_len_from_seed(randomization_seed);
    let fe0d_full_position = select_fe0d_full_position(randomization_seed, payload_len);
    let fe0d_band = chrome_classify_fe0d_position_band(payload_len, fe0d_full_position);
    let fe0d_target_position = chrome_adjust_fe0d_target_position(
        blend_fe0d_target_position(fe0d_full_position as u8, payload_len) as u8,
        payload_len,
        fe0d_band,
    );
    let mut ranked_extensions = CHROME_BASELINE_MIDDLE_EXTENSIONS
        .iter()
        .copied()
        .map(|ext_type| {
            let target_position = if ext_type == EXT_ECH_OUTER {
                fe0d_target_position
            } else {
                chrome_bucket_target_position(payload_len, ext_type)
            };
            let jitter = i32::from(
                mix_randomization_seed(randomization_seed, ext_type ^ payload_len as u16) & 0x1f,
            );
            let pairwise_bias = i32::from(chrome_bucket_pairwise_bias(
                randomization_seed,
                payload_len,
                ext_type,
            ));
            (
                i32::from(target_position) * 32 + pairwise_bias + jitter,
                ext_type,
            )
        })
        .collect::<Vec<_>>();
    ranked_extensions.sort_by_key(|(score, ext_type)| (*score, *ext_type));

    let mut extension_order = Vec::with_capacity(ranked_extensions.len() + 2);
    extension_order.push(GREASE_EXT_HEAD);
    extension_order.extend(ranked_extensions.into_iter().map(|(_, ext_type)| ext_type));
    extension_order.push(GREASE_EXT_TAIL);
    extension_order
}

fn select_fe0d_full_position(randomization_seed: u16, payload_len: usize) -> usize {
    let fe0d_positions = chrome_fe0d_position_profile(payload_len);
    fe0d_positions[mix_randomization_seed(randomization_seed ^ 0x9e37, 0x7f4a) as usize
        % fe0d_positions.len()]
}

fn chrome_classify_fe0d_position_band(
    payload_len: usize,
    fe0d_full_position: usize,
) -> ChromeFe0dPositionBand {
    let mut sorted_profile = chrome_fe0d_position_profile(payload_len).to_vec();
    sorted_profile.sort_unstable();
    let count = sorted_profile.len();
    let early_cut = sorted_profile[(count - 1) / 3];
    let late_cut = sorted_profile[((count - 1) * 2) / 3];

    if fe0d_full_position <= early_cut {
        ChromeFe0dPositionBand::Early
    } else if fe0d_full_position >= late_cut {
        ChromeFe0dPositionBand::Late
    } else {
        ChromeFe0dPositionBand::Mid
    }
}

fn chrome_fe0d_band_target_bias(payload_len: usize, band: ChromeFe0dPositionBand) -> i8 {
    match (payload_len, band) {
        // Bucket 186 still lands too early. Nudge late-ish seeds a touch further back
        // without letting band directly choose the precedence mode.
        (144, ChromeFe0dPositionBand::Early | ChromeFe0dPositionBand::Mid) => 1,
        (144, ChromeFe0dPositionBand::Late) => 2,
        // Bucket 250 still over-samples mid/late clouds. Only early/mid raw bands get
        // a slight push forward so late-band seeds keep some spread.
        (208, ChromeFe0dPositionBand::Early | ChromeFe0dPositionBand::Mid) => -1,
        (208, ChromeFe0dPositionBand::Late) => 0,
        _ => 0,
    }
}

fn chrome_adjust_fe0d_target_position(
    base_target_position: u8,
    payload_len: usize,
    band: ChromeFe0dPositionBand,
) -> u8 {
    let adjusted = i16::from(base_target_position)
        + i16::from(chrome_fe0d_band_target_bias(payload_len, band));
    adjusted.clamp(1, CHROME_BASELINE_MIDDLE_EXTENSIONS.len() as i16) as u8
}

fn blend_fe0d_target_position(raw_position: u8, payload_len: usize) -> u8 {
    let anchor: u8 = match payload_len {
        144 => 11,
        176 => 12,
        208 => 10,
        240 => 10,
        _ => 10,
    };
    ((u16::from(raw_position) + u16::from(anchor) * 2) / 3) as u8
}

fn mix_randomization_seed(seed: u16, salt: u16) -> u16 {
    let mut state = u32::from(seed) << 16 | u32::from(salt);
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    (state as u16) ^ ((state >> 16) as u16)
}

fn build_utls_boring_grease_ech_extension(randomization_seed: u16) -> Vec<u8> {
    let mut rng = OsRng;
    let mut config_id = [0u8; 1];
    rng.fill_bytes(&mut config_id);

    let payload_len = chrome_ech_payload_len_from_seed(randomization_seed);
    let encapsulated_key = PublicKey::from(&StaticSecret::random_from_rng(&mut rng)).to_bytes();
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
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use base64::Engine as _;

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
        let handshake = RealityHandshake::new(config.clone()).unwrap();
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
        assert_eq!(parsed.cipher_suites[0], GREASE_CIPHER_SUITE);
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

        assert_eq!(parsed.cipher_suites[0], GREASE_CIPHER_SUITE);
        assert!(parsed.cipher_suites.ends_with(&[
            0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
        ]));
        assert_eq!(extension_types.first().copied(), Some(GREASE_EXT_HEAD));
        assert_eq!(extension_types.last().copied(), Some(GREASE_EXT_TAIL));
        let mut sorted_extension_types = extension_types.clone();
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
            EXT_APPLICATION_SETTINGS,
            GREASE_EXT_HEAD,
            EXT_ECH_OUTER,
            EXT_RENEGOTIATION_INFO,
            GREASE_EXT_TAIL,
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
        assert_eq!(
            parsed.find_extension(EXT_SUPPORTED_VERSIONS).unwrap().data,
            vec![0x06, 0x6a, 0x6a, 0x03, 0x04, 0x03, 0x03]
        );
        assert_eq!(
            parsed.find_extension(EXT_SUPPORTED_GROUPS).unwrap().data,
            vec![0x00, 0x08, 0x4a, 0x4a, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18]
        );
        assert_eq!(
            parsed
                .find_extension(EXT_SIGNATURE_ALGORITHMS)
                .unwrap()
                .data,
            vec![
                0x00, 0x10, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01,
                0x08, 0x06, 0x06, 0x01,
            ]
        );
        assert_eq!(
            &parsed.find_extension(EXT_KEY_SHARE).unwrap().data[..7],
            &[0x00, 0x29, 0x4a, 0x4a, 0x00, 0x01, 0x00]
        );
    }

    #[test]
    fn test_chrome_baseline_randomization_seed_selects_ech_family_bucket() {
        let expected = [
            (0u16, 144usize),
            (1u16, 176usize),
            (2u16, 208usize),
            (3u16, 240usize),
            (4u16, 144usize),
        ];

        for (seed, expected_payload_len) in expected {
            let fingerprint = build_chrome_client_hello_fingerprint_with_seed(seed);
            assert_eq!(fingerprint.randomization_seed, Some(seed));
            let ech_outer = fingerprint
                .opaque_extensions
                .iter()
                .find(|(ext_type, _)| *ext_type == EXT_ECH_OUTER)
                .map(|(_, payload)| payload)
                .expect("ech outer extension");
            let (
                _client_hello_type,
                _kdf_id,
                _aead_id,
                _config_id,
                _encapsulated_key_len,
                payload_len,
            ) = parse_utls_boring_grease_ech_extension(ech_outer)
                .expect("uTLS BoringGREASEECH-like extension");
            assert_eq!(payload_len, expected_payload_len);
        }
    }

    #[test]
    fn test_chrome_baseline_randomization_seed_preserves_family_constraints() {
        let fingerprint = build_chrome_client_hello_fingerprint_with_seed(0x1234);

        assert_eq!(fingerprint.randomization_seed, Some(0x1234));
        assert!(fingerprint.prefix_extension_order.is_empty());
        assert!(fingerprint.suffix_extension_order.is_empty());
        assert_eq!(
            fingerprint.extension_order.first().copied(),
            Some(GREASE_EXT_HEAD)
        );
        assert_eq!(
            fingerprint.extension_order.last().copied(),
            Some(GREASE_EXT_TAIL)
        );
        assert_eq!(
            fingerprint.extension_order.len(),
            CHROME_BASELINE_MIDDLE_EXTENSIONS.len() + 2
        );

        let ech_outer = fingerprint
            .opaque_extensions
            .iter()
            .find(|(ext_type, _)| *ext_type == EXT_ECH_OUTER)
            .map(|(_, payload)| payload)
            .expect("ech outer extension");
        let (_client_hello_type, _kdf_id, _aead_id, _config_id, encapsulated_key_len, payload_len) =
            parse_utls_boring_grease_ech_extension(ech_outer)
                .expect("uTLS BoringGREASEECH-like extension");
        assert_eq!(encapsulated_key_len, UTLS_GREASE_ECH_ENCAPSULATED_KEY_LEN);
        assert_eq!(payload_len, chrome_ech_payload_len_from_seed(0x1234));
    }

    #[test]
    fn test_chrome_baseline_randomization_seed_conditions_fe0d_position_family() {
        let cases = [
            (0u16, 144usize, &CHROME_FE0D_POSITIONS_186[..]),
            (1u16, 176usize, &CHROME_FE0D_POSITIONS_218[..]),
            (2u16, 208usize, &CHROME_FE0D_POSITIONS_250[..]),
            (3u16, 240usize, &CHROME_FE0D_POSITIONS_282[..]),
        ];

        for (seed, payload_len, expected_positions) in cases {
            assert_eq!(chrome_ech_payload_len_from_seed(seed), payload_len);
            let fe0d_position = select_fe0d_full_position(seed, payload_len);
            assert!(
                expected_positions.contains(&fe0d_position),
                "seed {seed:#06x} produced fe0d position {fe0d_position}, expected one of {expected_positions:?}"
            );
        }
    }

    #[test]
    fn test_chrome_bucket_targets_bias_key_extensions_by_payload_family() {
        assert!(
            chrome_bucket_target_position(144, EXT_SERVER_NAME)
                < chrome_bucket_target_position(144, EXT_SUPPORTED_VERSIONS)
        );
        assert!(
            chrome_bucket_target_position(176, EXT_COMPRESS_CERTIFICATE)
                < chrome_bucket_target_position(176, EXT_ALPN)
        );
        assert!(
            chrome_bucket_target_position(208, EXT_ALPN)
                < chrome_bucket_target_position(208, EXT_SERVER_NAME)
        );
        assert!(
            chrome_bucket_target_position(240, EXT_RENEGOTIATION_INFO)
                < chrome_bucket_target_position(240, EXT_SIGNATURE_ALGORITHMS)
        );
    }

    #[test]
    fn test_chrome_bucket_signature_modes_capture_go_top_signatures() {
        assert!(
            chrome_bucket_signature_modes(144)
                .iter()
                .any(|mode| *mode == [1, -1, -1, -1, 1])
        );
        assert!(
            chrome_bucket_signature_modes(176)
                .iter()
                .any(|mode| *mode == [1, 1, 1, -1, -1])
        );
        assert!(
            chrome_bucket_signature_modes(176)
                .iter()
                .any(|mode| *mode == [-1, -1, -1, -1, -1])
        );
        assert!(
            chrome_bucket_signature_modes(208)
                .iter()
                .any(|mode| *mode == [-1, -1, -1, -1, 1])
        );
        assert!(
            chrome_bucket_signature_modes(208)
                .iter()
                .any(|mode| *mode == [1, 1, 1, 1, -1])
        );
        assert!(
            chrome_bucket_signature_modes(240)
                .iter()
                .any(|mode| *mode == [-1, 1, 1, 1, -1])
        );
    }

    #[test]
    fn test_chrome_bucket_pairwise_bias_keeps_seed_variability() {
        let bucket_208_values = (0u16..16)
            .map(|seed| {
                (
                    chrome_bucket_pairwise_bias(seed, 208, EXT_SERVER_NAME),
                    chrome_bucket_pairwise_bias(seed, 208, EXT_SUPPORTED_VERSIONS),
                )
            })
            .collect::<std::collections::BTreeSet<_>>();
        let bucket_186_values = (0u16..16)
            .map(|seed| {
                (
                    chrome_bucket_pairwise_bias(seed, 144, EXT_SUPPORTED_VERSIONS),
                    chrome_bucket_pairwise_bias(seed, 144, EXT_ECH_OUTER),
                )
            })
            .collect::<std::collections::BTreeSet<_>>();

        assert!(bucket_208_values.len() > 1);
        assert!(bucket_186_values.len() > 1);
    }

    #[test]
    fn test_chrome_bucket_signature_mode_selection_varies_by_seed() {
        let bucket_186_modes = (0u16..16)
            .map(|seed| chrome_signature_mode_index(seed, 144, 0x2f91))
            .collect::<std::collections::BTreeSet<_>>();
        let bucket_282_modes = (0u16..16)
            .map(|seed| chrome_signature_mode_index(seed, 240, 0x2f91))
            .collect::<std::collections::BTreeSet<_>>();

        assert!(bucket_186_modes.len() > 1);
        assert!(bucket_282_modes.len() > 1);
    }

    #[test]
    fn test_chrome_fe0d_position_band_classification_matches_profiles() {
        assert_eq!(
            chrome_classify_fe0d_position_band(144, 2),
            ChromeFe0dPositionBand::Early
        );
        assert_eq!(
            chrome_classify_fe0d_position_band(144, 8),
            ChromeFe0dPositionBand::Mid
        );
        assert_eq!(
            chrome_classify_fe0d_position_band(144, 15),
            ChromeFe0dPositionBand::Late
        );

        assert_eq!(
            chrome_classify_fe0d_position_band(208, 3),
            ChromeFe0dPositionBand::Early
        );
        assert_eq!(
            chrome_classify_fe0d_position_band(208, 11),
            ChromeFe0dPositionBand::Mid
        );
        assert_eq!(
            chrome_classify_fe0d_position_band(208, 16),
            ChromeFe0dPositionBand::Late
        );
    }

    #[test]
    fn test_chrome_fe0d_band_target_bias_only_adjusts_186_and_250_buckets() {
        assert_eq!(
            chrome_fe0d_band_target_bias(144, ChromeFe0dPositionBand::Early),
            1
        );
        assert_eq!(
            chrome_fe0d_band_target_bias(144, ChromeFe0dPositionBand::Late),
            2
        );
        assert_eq!(
            chrome_fe0d_band_target_bias(208, ChromeFe0dPositionBand::Early),
            -1
        );
        assert_eq!(
            chrome_fe0d_band_target_bias(208, ChromeFe0dPositionBand::Late),
            0
        );
        assert_eq!(
            chrome_fe0d_band_target_bias(176, ChromeFe0dPositionBand::Late),
            0
        );
        assert_eq!(
            chrome_fe0d_band_target_bias(240, ChromeFe0dPositionBand::Early),
            0
        );
    }

    #[test]
    fn test_chrome_fe0d_band_bias_nudges_target_in_expected_direction() {
        let bucket_186_base = blend_fe0d_target_position(15, 144);
        let bucket_250_base = blend_fe0d_target_position(3, 208);

        assert!(
            chrome_adjust_fe0d_target_position(bucket_186_base, 144, ChromeFe0dPositionBand::Late)
                > bucket_186_base
        );
        assert!(
            chrome_adjust_fe0d_target_position(bucket_250_base, 208, ChromeFe0dPositionBand::Early,)
                < bucket_250_base
        );
        assert_eq!(
            chrome_adjust_fe0d_target_position(bucket_186_base, 176, ChromeFe0dPositionBand::Late),
            bucket_186_base
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

            assert_eq!(extension_types.first().copied(), Some(GREASE_EXT_HEAD));
            assert_eq!(extension_types.last().copied(), Some(GREASE_EXT_TAIL));
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
                .all(|len| [496, 528, 560, 592].contains(len)),
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
}
