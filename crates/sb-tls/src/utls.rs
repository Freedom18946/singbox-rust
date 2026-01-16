//! uTLS Client Fingerprinting Implementation
//!
//! Provides TLS client fingerprinting to mimic various browsers and applications.
//! This helps bypass TLS fingerprint-based blocking.
//!
//! ## Supported Fingerprints
//!
//! - **Chrome**: Various Chrome versions
//! - **Firefox**: Firefox browser fingerprints
//! - **Safari**: Safari/iOS fingerprints
//! - **Edge**: Microsoft Edge fingerprints
//! - **Random**: Randomized fingerprint
//! - **Custom**: User-defined parameters
//!
//! ## How It Works
//!
//! TLS fingerprinting detects clients based on:
//! - Cipher suite ordering
//! - Extension ordering and values
//! - Supported TLS versions
//! - Elliptic curve preferences
//! - ALPN protocols
//!
//! This module allows customizing these parameters to match known browsers.

use std::io;

/// TLS fingerprint type
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum UtlsFingerprint {
    // Chrome fingerprints
    /// Chrome 58
    Chrome58,
    /// Chrome 62
    Chrome62,
    /// Chrome 70
    Chrome70,
    /// Chrome 72
    Chrome72,
    /// Chrome 83
    Chrome83,
    /// Chrome 87
    Chrome87,
    /// Chrome 96
    Chrome96,
    /// Chrome 100
    Chrome100,
    /// Chrome 102
    Chrome102,
    /// Chrome 106
    Chrome106,
    /// Chrome 110 (latest pattern)
    #[default]
    Chrome110,

    // Firefox fingerprints
    /// Firefox 55
    Firefox55,
    /// Firefox 56
    Firefox56,
    /// Firefox 63
    Firefox63,
    /// Firefox 65
    Firefox65,
    /// Firefox 99
    Firefox99,
    /// Firefox 105
    Firefox105,

    // Safari fingerprints
    /// Safari - generic
    Safari,
    /// iOS Safari 14
    SafariIos14,
    /// iOS Safari 15
    SafariIos15,
    /// iOS Safari 16
    SafariIos16,

    // Edge fingerprints
    /// Edge 85
    Edge85,
    /// Edge 106
    Edge106,

    // Special fingerprints
    /// Random fingerprint (rotates cipher suites)
    Random,
    /// Randomized with Chrome base
    RandomChrome,
    /// Randomized with Firefox base
    RandomFirefox,

    /// Custom fingerprint
    Custom(CustomFingerprint),

    /// Hello with Chrome PSK extension
    ChromePsk,
    /// Hello with Chrome post-quantum extension
    ChromePq,

    /// 360 browser
    Browser360,
    /// QQ browser
    QQBrowser,
}

impl std::str::FromStr for UtlsFingerprint {
    type Err = io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            // Go sing-box accepts multiple chrome alias names that map to Chrome Auto.
            ""
            | "chrome"
            | "chrome110"
            | "chrome_psk"
            | "chrome_psk_shuffle"
            | "chrome_padding_psk_shuffle"
            | "chrome_pq"
            | "chrome_pq_psk"
            | "android"
            | "android11"
            | "android_11" => Ok(Self::Chrome110),
            "chrome58" => Ok(Self::Chrome58),
            "chrome62" => Ok(Self::Chrome62),
            "chrome70" => Ok(Self::Chrome70),
            "chrome72" => Ok(Self::Chrome72),
            "chrome83" => Ok(Self::Chrome83),
            "chrome87" => Ok(Self::Chrome87),
            "chrome96" => Ok(Self::Chrome96),
            "chrome100" => Ok(Self::Chrome100),
            "chrome102" => Ok(Self::Chrome102),
            "chrome106" => Ok(Self::Chrome106),
            "chromepsk" => Ok(Self::ChromePsk),
            "chromepq" => Ok(Self::ChromePq),

            "firefox" | "firefox105" => Ok(Self::Firefox105),
            "firefox55" => Ok(Self::Firefox55),
            "firefox56" => Ok(Self::Firefox56),
            "firefox63" => Ok(Self::Firefox63),
            "firefox65" => Ok(Self::Firefox65),
            "firefox99" => Ok(Self::Firefox99),

            "safari" => Ok(Self::Safari),
            "ios" | "ios14" | "safari_ios14" => Ok(Self::SafariIos14),
            "ios15" | "safari_ios15" => Ok(Self::SafariIos15),
            "ios16" | "safari_ios16" => Ok(Self::SafariIos16),

            "edge" | "edge106" => Ok(Self::Edge106),
            "edge85" => Ok(Self::Edge85),

            "random" | "randomized" => Ok(Self::Random),

            "randomchrome" | "random_chrome" => Ok(Self::RandomChrome),
            "randomfirefox" | "random_firefox" => Ok(Self::RandomFirefox),

            "360" | "360browser" => Ok(Self::Browser360),
            "qq" | "qqbrowser" => Ok(Self::QQBrowser),

            other => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unknown uTLS fingerprint: {}", other),
            )),
        }
    }
}

impl std::fmt::Display for UtlsFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Chrome58 => write!(f, "chrome58"),
            Self::Chrome62 => write!(f, "chrome62"),
            Self::Chrome70 => write!(f, "chrome70"),
            Self::Chrome72 => write!(f, "chrome72"),
            Self::Chrome83 => write!(f, "chrome83"),
            Self::Chrome87 => write!(f, "chrome87"),
            Self::Chrome96 => write!(f, "chrome96"),
            Self::Chrome100 => write!(f, "chrome100"),
            Self::Chrome102 => write!(f, "chrome102"),
            Self::Chrome106 => write!(f, "chrome106"),
            Self::Chrome110 => write!(f, "chrome110"),
            Self::ChromePsk => write!(f, "chrome_psk"),
            Self::ChromePq => write!(f, "chrome_pq"),

            Self::Firefox55 => write!(f, "firefox55"),
            Self::Firefox56 => write!(f, "firefox56"),
            Self::Firefox63 => write!(f, "firefox63"),
            Self::Firefox65 => write!(f, "firefox65"),
            Self::Firefox99 => write!(f, "firefox99"),
            Self::Firefox105 => write!(f, "firefox105"),

            Self::Safari => write!(f, "safari"),
            Self::SafariIos14 => write!(f, "safari_ios14"),
            Self::SafariIos15 => write!(f, "safari_ios15"),
            Self::SafariIos16 => write!(f, "safari_ios16"),

            Self::Edge85 => write!(f, "edge85"),
            Self::Edge106 => write!(f, "edge106"),

            Self::Random => write!(f, "random"),
            Self::RandomChrome => write!(f, "random_chrome"),
            Self::RandomFirefox => write!(f, "random_firefox"),

            Self::Browser360 => write!(f, "360browser"),
            Self::QQBrowser => write!(f, "qqbrowser"),

            Self::Custom(_) => write!(f, "custom"),
        }
    }
}

/// Custom fingerprint configuration
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomFingerprint {
    /// TLS version (0x0303 for TLS 1.2, 0x0304 for TLS 1.3)
    pub tls_version: u16,
    /// Cipher suites in preferred order
    pub cipher_suites: Vec<u16>,
    /// Extension IDs in order
    pub extensions: Vec<u16>,
    /// Elliptic curves in preferred order
    pub curves: Vec<u16>,
    /// Point formats
    pub point_formats: Vec<u8>,
    /// Signature algorithms
    pub sig_algs: Vec<u16>,
    /// ALPN protocols
    pub alpn: Vec<String>,
}

impl Default for CustomFingerprint {
    fn default() -> Self {
        Self::chrome_110()
    }
}

impl CustomFingerprint {
    /// Chrome 110 fingerprint parameters
    pub fn chrome_110() -> Self {
        Self {
            tls_version: 0x0303,
            cipher_suites: vec![
                0x1301, // TLS_AES_128_GCM_SHA256
                0x1302, // TLS_AES_256_GCM_SHA384
                0x1303, // TLS_CHACHA20_POLY1305_SHA256
                0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
                0xc013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
                0xc014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
                0x009c, // TLS_RSA_WITH_AES_128_GCM_SHA256
                0x009d, // TLS_RSA_WITH_AES_256_GCM_SHA384
                0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
                0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
            ],
            extensions: vec![
                0x0000, // server_name
                0x0017, // extended_master_secret
                0xff01, // renegotiation_info
                0x000a, // supported_groups
                0x000b, // ec_point_formats
                0x0023, // session_ticket
                0x0010, // application_layer_protocol_negotiation
                0x0005, // status_request
                0x000d, // signature_algorithms
                0x0012, // signed_certificate_timestamp
                0x002b, // supported_versions
                0x002d, // psk_key_exchange_modes
                0x0033, // key_share
            ],
            curves: vec![
                0x001d, // x25519
                0x0017, // secp256r1
                0x0018, // secp384r1
            ],
            point_formats: vec![0x00], // uncompressed
            sig_algs: vec![
                0x0403, // ecdsa_secp256r1_sha256
                0x0503, // ecdsa_secp384r1_sha384
                0x0603, // ecdsa_secp521r1_sha512
                0x0804, // rsa_pss_rsae_sha256
                0x0805, // rsa_pss_rsae_sha384
                0x0806, // rsa_pss_rsae_sha512
                0x0401, // rsa_pkcs1_sha256
                0x0501, // rsa_pkcs1_sha384
                0x0601, // rsa_pkcs1_sha512
            ],
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
        }
    }

    /// Firefox 105 fingerprint parameters
    pub fn firefox_105() -> Self {
        Self {
            tls_version: 0x0303,
            cipher_suites: vec![
                0x1301, // TLS_AES_128_GCM_SHA256
                0x1302, // TLS_AES_256_GCM_SHA384
                0x1303, // TLS_CHACHA20_POLY1305_SHA256
                0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
                0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                0xc013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
                0xc014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
            ],
            extensions: vec![
                0x0000, // server_name
                0x0017, // extended_master_secret
                0xff01, // renegotiation_info
                0x000a, // supported_groups
                0x000b, // ec_point_formats
                0x0023, // session_ticket
                0x0010, // application_layer_protocol_negotiation
                0x0005, // status_request
                0x000d, // signature_algorithms
                0x002b, // supported_versions
                0x002d, // psk_key_exchange_modes
                0x0033, // key_share
                0x001c, // record_size_limit
            ],
            curves: vec![
                0x001d, // x25519
                0x0017, // secp256r1
                0x0018, // secp384r1
                0x0019, // secp521r1
                0x0100, // ffdhe2048
                0x0101, // ffdhe3072
            ],
            point_formats: vec![0x00],
            sig_algs: vec![
                0x0403, // ecdsa_secp256r1_sha256
                0x0503, // ecdsa_secp384r1_sha384
                0x0603, // ecdsa_secp521r1_sha512
                0x0804, // rsa_pss_rsae_sha256
                0x0805, // rsa_pss_rsae_sha384
                0x0806, // rsa_pss_rsae_sha512
                0x0401, // rsa_pkcs1_sha256
                0x0501, // rsa_pkcs1_sha384
                0x0601, // rsa_pkcs1_sha512
                0x0201, // rsa_pkcs1_sha1
                0x0203, // ecdsa_sha1
            ],
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
        }
    }

    /// Safari iOS 16 fingerprint parameters
    pub fn safari_ios16() -> Self {
        Self {
            tls_version: 0x0303,
            cipher_suites: vec![
                0x1301, // TLS_AES_128_GCM_SHA256
                0x1302, // TLS_AES_256_GCM_SHA384
                0x1303, // TLS_CHACHA20_POLY1305_SHA256
                0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
                0xc014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
                0xc013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
                0x009d, // TLS_RSA_WITH_AES_256_GCM_SHA384
                0x009c, // TLS_RSA_WITH_AES_128_GCM_SHA256
                0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
                0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
            ],
            extensions: vec![
                0x0000, // server_name
                0x0017, // extended_master_secret
                0x000a, // supported_groups
                0x000b, // ec_point_formats
                0x0010, // application_layer_protocol_negotiation
                0x0005, // status_request
                0x000d, // signature_algorithms
                0x002b, // supported_versions
                0x002d, // psk_key_exchange_modes
                0x0033, // key_share
            ],
            curves: vec![
                0x001d, // x25519
                0x0017, // secp256r1
                0x0018, // secp384r1
                0x0019, // secp521r1
            ],
            point_formats: vec![0x00],
            sig_algs: vec![
                0x0403, // ecdsa_secp256r1_sha256
                0x0503, // ecdsa_secp384r1_sha384
                0x0603, // ecdsa_secp521r1_sha512
                0x0804, // rsa_pss_rsae_sha256
                0x0805, // rsa_pss_rsae_sha384
                0x0806, // rsa_pss_rsae_sha512
                0x0401, // rsa_pkcs1_sha256
                0x0501, // rsa_pkcs1_sha384
                0x0601, // rsa_pkcs1_sha512
            ],
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
        }
    }
}

/// uTLS configuration for TLS connections
#[derive(Debug, Clone)]
pub struct UtlsConfig {
    /// Fingerprint to use
    pub fingerprint: UtlsFingerprint,
    /// Server name for SNI
    pub server_name: String,
    /// Skip certificate verification
    pub insecure_skip_verify: bool,
    /// ALPN protocols (overrides fingerprint default)
    pub alpn: Option<Vec<String>>,
}

impl UtlsConfig {
    /// Create a new uTLS config with Chrome 110 fingerprint
    pub fn new(server_name: impl Into<String>) -> Self {
        Self {
            fingerprint: UtlsFingerprint::default(),
            server_name: server_name.into(),
            insecure_skip_verify: false,
            alpn: None,
        }
    }

    /// Set fingerprint
    #[must_use]
    pub fn with_fingerprint(mut self, fp: UtlsFingerprint) -> Self {
        self.fingerprint = fp;
        self
    }

    /// Set insecure mode
    #[must_use]
    pub fn with_insecure(mut self, insecure: bool) -> Self {
        self.insecure_skip_verify = insecure;
        self
    }

    /// Set ALPN protocols
    #[must_use]
    pub fn with_alpn(mut self, alpn: Vec<String>) -> Self {
        self.alpn = Some(alpn);
        self
    }

    /// Get the custom fingerprint parameters for this config
    pub fn get_fingerprint_params(&self) -> CustomFingerprint {
        match &self.fingerprint {
            UtlsFingerprint::Firefox105
            | UtlsFingerprint::Firefox99
            | UtlsFingerprint::Firefox65
            | UtlsFingerprint::Firefox63 => CustomFingerprint::firefox_105(),
            UtlsFingerprint::SafariIos16
            | UtlsFingerprint::SafariIos15
            | UtlsFingerprint::Safari => CustomFingerprint::safari_ios16(),
            UtlsFingerprint::Custom(custom) => custom.clone(),

            // Mappings for fingerprints ensuring best-effort compatibility:
            // - Android: Mapped to Chrome 110 (closest modern behavior). Go uses specifically utls.HelloAndroid_11_OkHttp.
            // - Random: Mapped to Chrome 110. Go implementation randomizes/rotates; here we use a stable modern baseline.
            // - 360/QQ: Mapped to Chrome 110. Go uses utls.Hello360_Auto/HelloQQ_Auto.
            // - ChromePsk/Pq: Mapped to Chrome 110.
            _ => CustomFingerprint::chrome_110(), // Default to Chrome
        }
    }

    /// Build a rustls ClientConfig with fingerprint-specific cipher suites and ALPN.
    ///
    /// This is the key integration point that wires uTLS fingerprints into actual
    /// TLS handshakes. The resulting ClientConfig can be used with sb-transport's
    /// TlsDialer to perform fingerprinted TLS connections.
    ///
    /// # Returns
    /// A configured `Arc<rustls::ClientConfig>` with:
    /// - Cipher suites ordered according to the fingerprint
    /// - ALPN protocols from fingerprint or config override
    /// - webpki root certificates for production use
    ///
    /// # Example
    /// ```rust,no_run
    /// use sb_tls::utls::{UtlsConfig, UtlsFingerprint};
    ///
    /// let config = UtlsConfig::new("example.com")
    ///     .with_fingerprint(UtlsFingerprint::Firefox105);
    /// let tls_config = config.build_client_config();
    /// // Use tls_config with TlsDialer
    /// ```
    pub fn build_client_config(&self) -> std::sync::Arc<rustls::ClientConfig> {
        use rustls::RootCertStore;

        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        self.build_client_config_with_roots(roots)
    }

    /// Build a rustls ClientConfig using a caller-provided trust store.
    ///
    /// This is used by sb-core/sb-transport to preserve global CA overrides even
    /// when uTLS fingerprinting is enabled.
    pub fn build_client_config_with_roots(
        &self,
        roots: rustls::RootCertStore,
    ) -> std::sync::Arc<rustls::ClientConfig> {
        use rustls::client::danger::{
            HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
        };
        use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
        use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
        use std::sync::Arc;

        let fp = self.get_fingerprint_params();

        // Build CipherSuite list from fingerprint
        let cipher_suites = map_fingerprint_cipher_suites(&fp.cipher_suites);

        // Create a custom CryptoProvider with fingerprint-specific cipher suites
        let provider = rustls::crypto::CryptoProvider {
            cipher_suites,
            ..rustls::crypto::ring::default_provider()
        };

        // Build config with custom cipher suites via CryptoProvider
        #[allow(clippy::expect_used)]
        let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .expect("TLS protocol versions should be valid")
            .with_root_certificates(roots)
            .with_no_client_auth();

        // Apply ALPN from config override or fingerprint default
        let alpn = self.alpn.clone().unwrap_or(fp.alpn);
        config.alpn_protocols = alpn.into_iter().map(String::into_bytes).collect();

        if self.insecure_skip_verify {
            #[derive(Debug)]
            struct NoVerifier;

            impl ServerCertVerifier for NoVerifier {
                fn verify_server_cert(
                    &self,
                    _end_entity: &CertificateDer<'_>,
                    _intermediates: &[CertificateDer<'_>],
                    _server_name: &ServerName<'_>,
                    _ocsp_response: &[u8],
                    _now: UnixTime,
                ) -> Result<ServerCertVerified, rustls::Error> {
                    Ok(ServerCertVerified::assertion())
                }

                fn verify_tls12_signature(
                    &self,
                    _message: &[u8],
                    _cert: &CertificateDer<'_>,
                    _dss: &DigitallySignedStruct,
                ) -> Result<HandshakeSignatureValid, rustls::Error> {
                    Ok(HandshakeSignatureValid::assertion())
                }

                fn verify_tls13_signature(
                    &self,
                    _message: &[u8],
                    _cert: &CertificateDer<'_>,
                    _dss: &DigitallySignedStruct,
                ) -> Result<HandshakeSignatureValid, rustls::Error> {
                    Ok(HandshakeSignatureValid::assertion())
                }

                fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                    vec![
                        SignatureScheme::RSA_PKCS1_SHA256,
                        SignatureScheme::RSA_PKCS1_SHA384,
                        SignatureScheme::RSA_PKCS1_SHA512,
                        SignatureScheme::ECDSA_NISTP256_SHA256,
                        SignatureScheme::ECDSA_NISTP384_SHA384,
                        SignatureScheme::ECDSA_NISTP521_SHA512,
                        SignatureScheme::RSA_PSS_SHA256,
                        SignatureScheme::RSA_PSS_SHA384,
                        SignatureScheme::RSA_PSS_SHA512,
                        SignatureScheme::ED25519,
                    ]
                }
            }

            config
                .dangerous()
                .set_certificate_verifier(Arc::new(NoVerifier));
        }

        Arc::new(config)
    }
}

/// Map fingerprint cipher suite IDs to rustls SupportedCipherSuite
///
/// This maps TLS cipher suite identifiers (as used in uTLS fingerprints)
/// to rustls supported cipher suites. Suites not supported by rustls
/// are silently skipped.
fn map_fingerprint_cipher_suites(ids: &[u16]) -> Vec<rustls::SupportedCipherSuite> {
    use rustls::crypto::ring::cipher_suite;

    let mut suites = Vec::with_capacity(ids.len());

    for id in ids {
        let suite = match id {
            // TLS 1.3 suites
            0x1301 => Some(cipher_suite::TLS13_AES_128_GCM_SHA256),
            0x1302 => Some(cipher_suite::TLS13_AES_256_GCM_SHA384),
            0x1303 => Some(cipher_suite::TLS13_CHACHA20_POLY1305_SHA256),
            // TLS 1.2 ECDHE suites
            0xc02b => Some(cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
            0xc02f => Some(cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
            0xc02c => Some(cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384),
            0xc030 => Some(cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384),
            // Note: CHACHA20 and legacy suites may not be directly available
            // in all rustls configurations
            _ => None,
        };

        if let Some(s) = suite {
            suites.push(s);
        }
    }

    // Ensure we have at least some suites (fallback to defaults if empty)
    if suites.is_empty() {
        vec![
            cipher_suite::TLS13_AES_256_GCM_SHA384,
            cipher_suite::TLS13_AES_128_GCM_SHA256,
            cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        ]
    } else {
        suites
    }
}

/// Get list of all available fingerprints
pub fn available_fingerprints() -> Vec<&'static str> {
    vec![
        "chrome",
        "chrome58",
        "chrome62",
        "chrome70",
        "chrome72",
        "chrome83",
        "chrome87",
        "chrome96",
        "chrome100",
        "chrome102",
        "chrome106",
        "chrome110",
        "chrome_psk",
        "chrome_pq",
        "firefox",
        "firefox55",
        "firefox56",
        "firefox63",
        "firefox65",
        "firefox99",
        "firefox105",
        "safari",
        "safari_ios14",
        "safari_ios15",
        "safari_ios16",
        "edge85",
        "edge106",
        "random",
        "randomized",
        "random_chrome",
        "random_firefox",
        "ios",
        "android",
        "edge",
        "360browser",
        "qqbrowser",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::unwrap_used)]
    #[test]
    fn test_fingerprint_parse() {
        assert_eq!(
            "chrome".parse::<UtlsFingerprint>().unwrap(),
            UtlsFingerprint::Chrome110
        );
        assert_eq!(
            "firefox".parse::<UtlsFingerprint>().unwrap(),
            UtlsFingerprint::Firefox105
        );
        assert_eq!(
            "safari".parse::<UtlsFingerprint>().unwrap(),
            UtlsFingerprint::Safari
        );
        assert_eq!(
            "random".parse::<UtlsFingerprint>().unwrap(),
            UtlsFingerprint::Random
        );
        assert_eq!(
            "chrome_psk".parse::<UtlsFingerprint>().unwrap(),
            UtlsFingerprint::Chrome110
        );
        assert_eq!(
            "randomized".parse::<UtlsFingerprint>().unwrap(),
            UtlsFingerprint::Random
        );
        assert_eq!(
            "android".parse::<UtlsFingerprint>().unwrap(),
            UtlsFingerprint::Chrome110
        );
        assert_eq!(
            "ios".parse::<UtlsFingerprint>().unwrap(),
            UtlsFingerprint::SafariIos14
        );
        assert!("invalid".parse::<UtlsFingerprint>().is_err());
    }

    #[test]
    fn test_fingerprint_display() {
        assert_eq!(UtlsFingerprint::Chrome110.to_string(), "chrome110");
        assert_eq!(UtlsFingerprint::Firefox105.to_string(), "firefox105");
        assert_eq!(UtlsFingerprint::Random.to_string(), "random");
    }

    #[test]
    fn test_custom_fingerprint_chrome() {
        let fp = CustomFingerprint::chrome_110();
        assert!(!fp.cipher_suites.is_empty());
        assert!(fp.cipher_suites.contains(&0x1301)); // TLS_AES_128_GCM_SHA256
        assert!(fp.curves.contains(&0x001d)); // x25519
    }

    #[test]
    fn test_utls_config() {
        let config = UtlsConfig::new("example.com")
            .with_fingerprint(UtlsFingerprint::Firefox105)
            .with_insecure(true);

        assert_eq!(config.server_name, "example.com");
        assert!(matches!(config.fingerprint, UtlsFingerprint::Firefox105));
        assert!(config.insecure_skip_verify);
    }

    #[test]
    fn test_available_fingerprints() {
        let fps = available_fingerprints();
        assert!(fps.contains(&"chrome"));
        assert!(fps.contains(&"firefox"));
        assert!(fps.contains(&"safari"));
    }

    #[test]
    fn test_build_client_config() {
        // Test that build_client_config produces a valid rustls ClientConfig
        let config = UtlsConfig::new("example.com")
            .with_fingerprint(UtlsFingerprint::Chrome110)
            .with_alpn(vec!["h2".to_string(), "http/1.1".to_string()]);

        let tls_config = config.build_client_config();

        // Verify ALPN protocols are set
        assert!(!tls_config.alpn_protocols.is_empty());
        assert_eq!(tls_config.alpn_protocols[0], b"h2");
        assert_eq!(tls_config.alpn_protocols[1], b"http/1.1");
    }

    #[test]
    fn test_build_client_config_firefox() {
        // Test Firefox fingerprint
        let config = UtlsConfig::new("firefox.test").with_fingerprint(UtlsFingerprint::Firefox105);

        let tls_config = config.build_client_config();

        // Firefox default ALPN from fingerprint
        assert!(!tls_config.alpn_protocols.is_empty());
    }
}
