//! Global TLS client configuration
//!
//! Integrates sb-tls global TLS configuration with sb-config's CertificateIR.
//! All TLS types come through sb-tls (which depends on rustls unconditionally),
//! so this module does not directly depend on the rustls crate.

/// Apply TLS client config from IR certificate settings.
///
/// Extracts CA paths and inline PEMs from the IR and passes them to sb-tls.
pub fn apply_from_ir(cert: Option<&sb_config::ir::CertificateIR>) {
    if let Some(c) = cert {
        sb_tls::global::apply_extra_cas(&c.ca_paths, &c.ca_pem);
    } else {
        sb_tls::global::apply_extra_cas(&[], &[]);
    }
}

/// Re-export from sb-tls for backward compatibility.
pub use sb_tls::global::get_effective;

/// Re-export from sb-tls for backward compatibility.
pub use sb_tls::global::base_root_store;

/// Global certificate store implementing CertificateStore trait (Go parity).
#[derive(Debug, Clone, Default)]
pub struct GlobalCertificateStore;

impl crate::context::CertificateStore for GlobalCertificateStore {
    fn root_pool(&self) -> Option<Vec<String>> {
        None
    }
}
