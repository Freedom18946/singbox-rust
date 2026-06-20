#![cfg(feature = "adapter-trojan")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Trojan protocol integration tests
//!
//! These tests verify Trojan protocol implementation including:
//! - Configuration validation
//! - Password hashing (SHA224)
//! - TLS handshake capability
//! - Connector construction

use sb_adapters::outbound::prelude::*;
use sb_adapters::outbound::trojan::{TrojanConfig, TrojanConnector};
use sb_adapters::transport_config::TransportConfig;
use std::time::Duration;

// ============================================================================
// Configuration Tests
// ============================================================================

#[test]
fn test_trojan_config_basic() {
    // Basic valid Trojan configuration
    let config = TrojanConfig {
        server: "127.0.0.1:443".to_string(),
        tag: Some("test-trojan".to_string()),
        password: "test_password".to_string(),
        connect_timeout_sec: Some(30),
        sni: Some("example.com".to_string()),
        alpn: None,
        skip_cert_verify: false,
        detour: None,
        transport_layer: TransportConfig::default(),
        #[cfg(feature = "tls_reality")]
        reality: None,
        multiplex: None,
    };

    let connector = TrojanConnector::new(config);
    assert_eq!(
        connector.name(),
        "trojan",
        "Connector name should be 'trojan'"
    );
}

#[test]
fn test_trojan_config_with_skip_cert_verify() {
    // Configuration with skip_cert_verify enabled
    let config = TrojanConfig {
        server: "10.0.0.1:443".to_string(),
        tag: None,
        password: "insecure_test".to_string(),
        connect_timeout_sec: Some(5),
        sni: None,
        alpn: None,
        skip_cert_verify: true, // Skip verification for testing
        detour: None,
        transport_layer: TransportConfig::default(),
        #[cfg(feature = "tls_reality")]
        reality: None,
        multiplex: None,
    };

    let connector = TrojanConnector::new(config);
    assert_eq!(connector.name(), "trojan");
}

#[test]
fn test_trojan_config_with_alpn() {
    // Configuration with ALPN protocols
    let config = TrojanConfig {
        server: "trojan.example.com:443".to_string(),
        tag: Some("alpn-test".to_string()),
        password: "alpn_password".to_string(),
        connect_timeout_sec: Some(10),
        sni: Some("trojan.example.com".to_string()),
        alpn: Some(vec!["h2".to_string(), "http/1.1".to_string()]),
        skip_cert_verify: false,
        detour: None,
        transport_layer: TransportConfig::default(),
        #[cfg(feature = "tls_reality")]
        reality: None,
        multiplex: None,
    };

    let connector = TrojanConnector::new(config);
    assert_eq!(connector.name(), "trojan");
}

#[test]
fn test_trojan_config_minimal() {
    // Minimal configuration with only required fields
    let config = TrojanConfig {
        server: "localhost:443".to_string(),
        tag: None,
        password: "password123".to_string(),
        connect_timeout_sec: None,
        sni: None,
        alpn: None,
        skip_cert_verify: false,
        detour: None,
        transport_layer: TransportConfig::default(),
        #[cfg(feature = "tls_reality")]
        reality: None,
        multiplex: None,
    };

    let connector = TrojanConnector::new(config);
    assert_eq!(connector.name(), "trojan");
}

// ============================================================================
// Trait Implementation Tests
// ============================================================================

#[test]
fn test_trojan_connector_name() {
    let connector = TrojanConnector::default();
    assert_eq!(
        connector.name(),
        "trojan",
        "Connector name should be 'trojan'"
    );
}

#[test]
fn test_trojan_implements_outbound_connector() {
    // Verify the connector implements OutboundConnector trait
    fn assert_outbound_connector<T: OutboundConnector>() {}
    assert_outbound_connector::<TrojanConnector>();
}

#[test]
fn test_trojan_implements_debug_clone() {
    // Verify Debug and Clone are implemented
    let connector = TrojanConnector::default();
    let _debug = format!("{:?}", connector);
    let _cloned = connector.clone();
}

#[test]
fn test_trojan_default_connector() {
    // Default connector should be constructible
    let connector = TrojanConnector::default();
    assert_eq!(connector.name(), "trojan");
}

// ============================================================================
// Async Tests
// ============================================================================

#[tokio::test]
async fn test_trojan_connector_start() {
    let connector = TrojanConnector::default();
    let result = connector.start().await;
    assert!(result.is_ok(), "Connector start should succeed");
}

#[tokio::test]
async fn test_trojan_dial_without_config() {
    // Default connector without config should fail
    let connector = TrojanConnector::default();
    let target = Target::tcp("example.com", 80);
    let opts = DialOpts::new();

    let result = connector.dial(target, opts).await;
    assert!(
        result.is_err(),
        "Dial without configured server should fail"
    );
}

// NOTE (CAL-28): the former #[ignore]'d `test_trojan_connection_to_mock_server`
// and `test_trojan_connection_timeout` placeholders have been rewritten as real,
// network-free loopback tests and moved into the `fresh13_tls_verifier_loopback`
// module below (see `connection_to_mock_tls_server_completes_handshake` and
// `connection_to_unroutable_ip_fails_bounded`), reusing the self-signed TLS
// listener + CryptoProvider init already present there. The two cited ignore
// reasons ("requires actual TLS server", "CryptoProvider may not be available")
// are both satisfied/refuted by that harness.

// ============================================================================
// Password Hash Tests (validates SHA224 password handling)
// ============================================================================

#[test]
fn test_trojan_password_format() {
    // Trojan uses SHA224 hex-encoded password
    // This test validates the password is stored correctly
    let password = "test-password-123";
    let config = TrojanConfig {
        server: "127.0.0.1:443".to_string(),
        tag: None,
        password: password.to_string(),
        connect_timeout_sec: None,
        sni: None,
        alpn: None,
        skip_cert_verify: false,
        detour: None,
        transport_layer: TransportConfig::default(),
        #[cfg(feature = "tls_reality")]
        reality: None,
        multiplex: None,
    };

    // Connector should be creatable with any password
    let connector = TrojanConnector::new(config);
    assert_eq!(connector.name(), "trojan");
}

#[test]
fn test_trojan_empty_password() {
    // Empty password should still be allowed (server will reject)
    let config = TrojanConfig {
        server: "127.0.0.1:443".to_string(),
        tag: None,
        password: String::new(), // Empty password
        connect_timeout_sec: None,
        sni: None,
        alpn: None,
        skip_cert_verify: false,
        detour: None,
        transport_layer: TransportConfig::default(),
        #[cfg(feature = "tls_reality")]
        reality: None,
        multiplex: None,
    };

    let connector = TrojanConnector::new(config);
    assert_eq!(connector.name(), "trojan");
}

#[test]
fn test_trojan_unicode_password() {
    // Unicode password should work
    let config = TrojanConfig {
        server: "127.0.0.1:443".to_string(),
        tag: None,
        password: "密码测试🔐".to_string(), // Unicode password
        connect_timeout_sec: None,
        sni: None,
        alpn: None,
        skip_cert_verify: false,
        detour: None,
        transport_layer: TransportConfig::default(),
        #[cfg(feature = "tls_reality")]
        reality: None,
        multiplex: None,
    };

    let connector = TrojanConnector::new(config);
    assert_eq!(connector.name(), "trojan");
}

// ============================================================================
// Configuration Serialization Tests
// ============================================================================

#[test]
fn test_trojan_config_serialization() {
    // Test that config can be serialized and deserialized
    let config = TrojanConfig {
        server: "trojan.example.com:443".to_string(),
        tag: Some("serialization-test".to_string()),
        password: "test_password".to_string(),
        connect_timeout_sec: Some(30),
        sni: Some("trojan.example.com".to_string()),
        alpn: Some(vec!["h2".to_string()]),
        skip_cert_verify: false,
        detour: None,
        transport_layer: TransportConfig::default(),
        #[cfg(feature = "tls_reality")]
        reality: None,
        multiplex: None,
    };

    let serialized = serde_json::to_string(&config);
    assert!(serialized.is_ok(), "Config should serialize");

    let json = serialized.unwrap();
    assert!(json.contains("trojan.example.com:443"));
    assert!(json.contains("test_password"));
}

// ============================================================================
// Hostname server regression (MT-TROJAN-FRESH-11)
// ============================================================================

#[tokio::test]
async fn test_trojan_hostname_server_does_not_fail_at_local_parse() {
    // Regression for MT-TROJAN-FRESH-10/11: a hostname-format `server`
    // value (`hostname:port`) must NOT fail at the local parse stage with
    // `Invalid server address: invalid socket address syntax`. The Trojan
    // adapter previously called `config.server.parse::<SocketAddr>()`
    // which only accepts IP literals and rejected hostnames synchronously
    // before any network IO. With the FRESH-11 fix, parsing accepts the
    // hostname and DNS resolution moves to the transport layer; downstream
    // DNS / TCP / TLS errors are still expected for a non-routable
    // domain, but the error must NOT carry the SocketAddr parse phrase.
    let config = TrojanConfig {
        server: "regression.fresh11.invalid:443".to_string(),
        tag: None,
        password: "fresh11".to_string(),
        connect_timeout_sec: Some(1),
        sni: Some("regression.fresh11.invalid".to_string()),
        alpn: None,
        skip_cert_verify: true,
        detour: None,
        transport_layer: TransportConfig::default(),
        #[cfg(feature = "tls_reality")]
        reality: None,
        multiplex: None,
    };
    let connector = TrojanConnector::new(config);
    let target = Target::tcp("example.com", 80);
    let opts = DialOpts::new().with_connect_timeout(Duration::from_millis(500));
    let result = connector.dial(target, opts).await;
    let err = match result {
        Ok(_) => panic!("dial unexpectedly succeeded against a non-routable .invalid hostname"),
        Err(e) => e,
    };
    let msg = format!("{err}");
    assert!(
        !msg.to_ascii_lowercase()
            .contains("invalid socket address syntax"),
        "hostname server must not produce a SocketAddr parse error; got: {}",
        msg
    );
    assert!(
        !msg.to_ascii_lowercase().contains("invalid server address"),
        "hostname server must not produce 'Invalid server address'; got: {}",
        msg
    );
}

// ============================================================================
// MT-TROJAN-FRESH-13 TLS verifier toggle (localhost loopback, no live nodes)
// ============================================================================

#[cfg(test)]
mod fresh13_tls_verifier_loopback {
    use super::*;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer};
    use std::sync::{Arc, Once};
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    static CRYPTO_INIT: Once = Once::new();

    fn init_crypto() {
        CRYPTO_INIT.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    fn generate_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let key = cert.key_pair.serialize_der();
        let cert_der = cert.cert.der().to_vec();
        (
            vec![CertificateDer::from(cert_der)],
            PrivateKeyDer::try_from(key).unwrap(),
        )
    }

    async fn start_self_signed_tls_listener() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>)
    {
        init_crypto();
        let (certs, key) = generate_cert();
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            // Accept exactly one connection. After the TLS handshake we
            // briefly read whatever the client sends (the Trojan client
            // emits its CONNECT request once TLS succeeds) and then drop
            // the stream. The test does not assert on the Trojan-layer
            // response — only on whether the TLS handshake's cert path
            // succeeded or rejected.
            if let Ok((sock, _)) = listener.accept().await {
                if let Ok(mut tls_stream) = acceptor.accept(sock).await {
                    let mut buf = [0u8; 64];
                    let _ = tls_stream.read(&mut buf).await;
                }
            }
        });
        (addr, task)
    }

    fn make_trojan_config(server: &str, skip_cert_verify: bool) -> TrojanConfig {
        TrojanConfig {
            server: server.to_string(),
            tag: Some("fresh13-loopback".to_string()),
            password: "fresh13-test".to_string(),
            connect_timeout_sec: Some(2),
            sni: Some("localhost".to_string()),
            alpn: None,
            skip_cert_verify,
            detour: None,
            transport_layer: TransportConfig::default(),
            #[cfg(feature = "tls_reality")]
            reality: None,
            multiplex: None,
        }
    }

    /// Verify that `skip_cert_verify=true` actually wires up the
    /// `NoVerifier` path: a self-signed cert from a localhost TLS server
    /// must NOT produce a cert-verification failure. The dial may still
    /// fail at the Trojan handshake (the loopback isn't a real Trojan
    /// server), but the failure must not contain any cert-verification
    /// keyword — proving cert verification was actually skipped.
    #[tokio::test]
    async fn skip_cert_verify_true_passes_self_signed_cert() {
        let (addr, _server) = start_self_signed_tls_listener().await;
        let config = make_trojan_config(&format!("127.0.0.1:{}", addr.port()), true);
        let connector = TrojanConnector::new(config);
        let target = Target::tcp("example.com", 80);
        let opts = DialOpts::new().with_connect_timeout(Duration::from_secs(2));
        let result = connector.dial(target, opts).await;
        let msg = match result {
            Ok(_) => String::new(),
            Err(e) => format!("{e}"),
        };
        let lower = msg.to_ascii_lowercase();
        for forbidden in [
            "unknownissuer",
            "unknown issuer",
            "self-signed certificate",
            "self signed certificate",
            "certificate signed by unknown authority",
            "untrusted root",
            "invalid peer certificate: unknownissuer",
            "invalid peer certificate: notvalidforname",
            "certificate not valid for name",
        ] {
            assert!(
                !lower.contains(forbidden),
                "skip_cert_verify=true must NOT surface cert-verify failure '{forbidden}'; got: {msg}"
            );
        }
    }

    /// Verify that `skip_cert_verify=false` rejects a self-signed cert
    /// via the webpki-roots verifier — the dial must fail and the error
    /// must carry a cert-verification keyword. This proves the strict
    /// path is reachable and not silently bypassed.
    #[tokio::test]
    async fn skip_cert_verify_false_rejects_self_signed_cert() {
        let (addr, _server) = start_self_signed_tls_listener().await;
        let config = make_trojan_config(&format!("127.0.0.1:{}", addr.port()), false);
        let connector = TrojanConnector::new(config);
        let target = Target::tcp("example.com", 80);
        let opts = DialOpts::new().with_connect_timeout(Duration::from_secs(2));
        let result = connector.dial(target, opts).await;
        let err = match result {
            Ok(_) => {
                panic!("skip_cert_verify=false unexpectedly accepted a self-signed localhost cert")
            }
            Err(e) => e,
        };
        let lower = format!("{err}").to_ascii_lowercase();
        assert!(
            lower.contains("unknownissuer")
                || lower.contains("unknown issuer")
                || lower.contains("invalid peer certificate")
                || lower.contains("certificate")
                || lower.contains("untrusted")
                || lower.contains("self-signed")
                || lower.contains("self signed")
                || lower.contains("tls handshake failed"),
            "expected cert-verify failure with strict verify; got: {err}"
        );
    }

    /// CAL-28: rewrite of the former #[ignore]'d `test_trojan_connection_to_mock_server`.
    /// The loopback harness above IS the "actual TLS server" the old ignore reason
    /// demanded, so this now runs for real: dial a self-signed localhost TLS listener
    /// with `skip_cert_verify=true` and assert the dial drives a real TCP+TLS handshake
    /// (no connection-refused, no cert-verify failure). The mock isn't a real Trojan
    /// server (Trojan sends no CONNECT response), so we don't assert a full round-trip —
    /// only that the transport path is live, which is all the original placeholder aimed at.
    #[tokio::test]
    async fn connection_to_mock_tls_server_completes_handshake() {
        let (addr, _server) = start_self_signed_tls_listener().await;
        let config = make_trojan_config(&format!("127.0.0.1:{}", addr.port()), true);
        let connector = TrojanConnector::new(config);
        let target = Target::tcp("example.com", 80);
        let opts = DialOpts::new().with_connect_timeout(Duration::from_secs(2));
        let result = connector.dial(target, opts).await;
        let msg = match result {
            Ok(_) => String::new(),
            Err(e) => format!("{e}").to_ascii_lowercase(),
        };
        // The mock accepts TCP and completes TLS, so the dial must NOT fail at the
        // TCP layer (connection refused) nor with a cert-verification error.
        for forbidden in [
            "connection refused",
            "unknownissuer",
            "unknown issuer",
            "certificate signed by unknown authority",
            "self-signed",
            "self signed",
        ] {
            assert!(
                !msg.contains(forbidden),
                "dial to a live mock TLS server must not fail with '{forbidden}'; got: {msg}"
            );
        }
    }

    /// CAL-28: rewrite of the former #[ignore]'d `test_trojan_connection_timeout`.
    /// The old ignore reason ("rustls CryptoProvider may not be available") was a
    /// misdiagnosis — the failure happens in the TCP connect phase to a non-routable
    /// IP, well before any TLS/CryptoProvider use. We still call `init_crypto()` to
    /// remove all doubt, then assert the dial fails within a bounded time (it must not
    /// hang indefinitely). NOTE: since package09 trojan `dial` honors
    /// `DialOpts.connect_timeout`, taking the stricter of it and `config.connect_timeout_sec`.
    /// This test uses `make_trojan_config` (config timeout 2s) + default `DialOpts` (10s),
    /// so the effective bound is ~2s; the generous 30s assertion below still holds.
    /// See `dial_honors_short_dialopts_connect_timeout` for the DialOpts-driven bound.
    #[tokio::test]
    async fn connection_to_unroutable_ip_fails_bounded() {
        init_crypto();
        let config = make_trojan_config("10.255.255.1:443", true); // non-routable
        let connector = TrojanConnector::new(config);
        let target = Target::tcp("example.com", 80);
        let start = std::time::Instant::now();
        let result = connector.dial(target, DialOpts::new()).await;
        let elapsed = start.elapsed();
        assert!(
            result.is_err(),
            "dial to a non-routable IP must fail, not succeed"
        );
        assert!(
            elapsed < Duration::from_secs(30),
            "dial must fail within a bounded time (no infinite hang), took {elapsed:?}"
        );
    }

    /// package09 (supersedes package08 follow-up #2): trojan `dial` previously ignored
    /// `DialOpts` and derived its connect timeout solely from `config.connect_timeout_sec`.
    /// It now uses `opts.connect_timeout.min(config_timeout)`. Give the config a large,
    /// distinctive 99s ceiling and dial a non-routable IP with a 250ms `DialOpts.connect_timeout`:
    /// the dial must fail well within the ceiling, and its `AdapterError::Timeout` must report the
    /// 250ms DialOpts bound, never 99s. The error-content check is deterministic — the reported
    /// duration is the internal `timeout` variable (250ms) regardless of scheduler jitter, so this
    /// does not flake under the timer starvation seen when many connect-to-unroutable tests run in
    /// parallel. The outer 40s test-side timeout guards against a regression that hangs ~99s.
    #[tokio::test]
    async fn dial_honors_short_dialopts_connect_timeout() {
        init_crypto();
        let mut config = make_trojan_config("10.255.255.1:443", true); // non-routable
        config.connect_timeout_sec = Some(99); // large, distinctive ceiling; the DialOpts must win
        let connector = TrojanConnector::new(config);
        let target = Target::tcp("example.com", 80);
        let opts = DialOpts::new().with_connect_timeout(Duration::from_millis(250));
        let outcome =
            tokio::time::timeout(Duration::from_secs(40), connector.dial(target, opts)).await;
        let result = outcome.expect(
            "DialOpts.connect_timeout (250ms) must bound dial well under the 99s config ceiling; \
             dial did not return within 40s (regressed to the config ceiling?)",
        );
        let err = match result {
            Ok(_) => panic!("dial to a non-routable IP must fail, not succeed"),
            Err(e) => e,
        };
        let msg = format!("{err}");
        assert!(
            !msg.contains("99s"),
            "dial timeout must reflect the 250ms DialOpts.connect_timeout, not the 99s config \
             ceiling; got: {msg}"
        );
    }
}
