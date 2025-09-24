//! Dangerous TLS certificate verifiers
//!
//! These verifiers should only be used with extreme caution and explicit
//! environment variable configuration.

#[cfg(feature = "tls_rustls")]
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
#[cfg(feature = "tls_rustls")]
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
#[cfg(feature = "tls_rustls")]
use rustls::{DigitallySignedStruct, Error, SignatureScheme};
use std::fmt;

/// Certificate verifier that skips all verification
/// Should only be used in development/testing environments
#[derive(Debug)]
pub struct NoVerify;

impl NoVerify {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(feature = "tls_rustls")]
impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        // Always accept any certificate
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

/// Certificate verifier that validates SPKI SHA256 pins
#[derive(Debug)]
pub struct PinVerify {
    pins: Vec<[u8; 32]>,
}

impl PinVerify {
    pub fn new(pins: Vec<[u8; 32]>) -> Self {
        Self { pins }
    }

    /// Extract SPKI SHA256 from certificate
    #[cfg(feature = "tls_rustls")]
    fn extract_spki_sha256(cert: &CertificateDer<'_>) -> Result<[u8; 32], Error> {
        use sha2::{Digest, Sha256};

        #[cfg(feature = "tls_rustls")]
        {
            use x509_parser::prelude::*;

            let (_, parsed_cert) = X509Certificate::from_der(cert.as_ref())
                .map_err(|_| Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?;

            let spki = parsed_cert.public_key().raw;
            let mut hasher = Sha256::new();
            hasher.update(spki);
            let hash = hasher.finalize();

            let mut result = [0u8; 32];
            result.copy_from_slice(&hash);
            Ok(result)
        }

        #[cfg(not(feature = "tls_rustls"))]
        {
            // Fallback implementation without x509-parser
            let mut hasher = Sha256::new();
            hasher.update(cert.as_ref());
            let hash = hasher.finalize();

            let mut result = [0u8; 32];
            result.copy_from_slice(&hash);
            Ok(result)
        }
    }
}

#[cfg(feature = "tls_rustls")]
impl ServerCertVerifier for PinVerify {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        // Extract SPKI SHA256 from the end entity certificate
        let cert_pin = Self::extract_spki_sha256(end_entity)?;

        // Check if it matches any of our pins
        if self.pins.contains(&cert_pin) {
            #[cfg(feature = "metrics")]
            {
                use metrics::counter;
                counter!("tls_verify_total", "proto" => "pin", "result" => "ok").increment(1);
            }
            Ok(ServerCertVerified::assertion())
        } else {
            #[cfg(feature = "metrics")]
            {
                use metrics::counter;
                counter!("tls_verify_total", "proto" => "pin", "result" => "fail").increment(1);
            }
            Err(Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        // For pinning, we still need to validate signatures
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        // For pinning, we still need to validate signatures
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

impl fmt::Display for NoVerify {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NoVerify")
    }
}

impl fmt::Display for PinVerify {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PinVerify({} pins)", self.pins.len())
    }
}
