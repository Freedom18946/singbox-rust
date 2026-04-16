//! REALITY client handshake built on rustls hooks.

use super::auth::{compute_temp_cert_signature, derive_auth_key};
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
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsConnector as RustlsConnector;
use tracing::debug;
use x509_parser::oid_registry::OID_SIG_ED25519;
use x509_parser::prelude::parse_x509_certificate;
use x25519_dalek::{PublicKey, StaticSecret};

const REALITY_SESSION_ID_LEN: usize = 32;
const REALITY_SESSION_PLAINTEXT_LEN: usize = 16;
#[cfg(test)]
const EXT_SERVER_NAME: u16 = 0x0000;
#[cfg(test)]
const EXT_STATUS_REQUEST: u16 = 0x0005;
#[cfg(test)]
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
#[cfg(test)]
const EXT_EC_POINT_FORMATS: u16 = 0x000b;
#[cfg(test)]
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
#[cfg(test)]
const EXT_ALPN: u16 = 0x0010;
const EXT_SCT: u16 = 0x0012;
const EXT_COMPRESS_CERTIFICATE: u16 = 0x001b;
#[cfg(test)]
const EXT_EXTENDED_MASTER_SECRET: u16 = 0x0017;
#[cfg(test)]
const EXT_SESSION_TICKET: u16 = 0x0023;
#[cfg(test)]
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
#[cfg(test)]
const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
#[cfg(test)]
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_APPLICATION_SETTINGS: u16 = 0x44cd;
const EXT_ECH_OUTER: u16 = 0xfe0d;
#[cfg(test)]
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
        Ok(Box::new(tls_stream))
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

    Some(ClientHelloFingerprint {
        opaque_extensions: vec![
            (GREASE_EXT_HEAD, Vec::new()),
            (EXT_SCT, Vec::new()),
            (EXT_COMPRESS_CERTIFICATE, vec![0x02, 0x00, 0x02]),
            (EXT_APPLICATION_SETTINGS, vec![0x00, 0x03, 0x02, b'h', b'2']),
            (EXT_ECH_OUTER, build_utls_boring_grease_ech_extension()),
            (GREASE_EXT_TAIL, vec![0x00]),
        ],
        extension_order: vec![],
        prefix_extension_order: vec![GREASE_EXT_HEAD],
        suffix_extension_order: vec![GREASE_EXT_TAIL],
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
    })
}

fn build_utls_boring_grease_ech_extension() -> Vec<u8> {
    let mut rng = OsRng;
    let mut config_id = [0u8; 1];
    rng.fill_bytes(&mut config_id);

    let payload_len = UTLS_GREASE_ECH_PAYLOAD_LENS
        [(rng.next_u32() as usize) % UTLS_GREASE_ECH_PAYLOAD_LENS.len()];
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
