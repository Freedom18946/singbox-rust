pub mod tcp;
#[cfg(feature = "tls_rustls")]
pub mod tls;

// Type alias for TLS stream
#[cfg(feature = "tls_rustls")]
pub type TlsStream<T> = tokio_rustls::TlsStream<T>;

#[cfg(not(feature = "tls_rustls"))]
pub type TlsStream<T> = T; // Fallback when TLS not enabled
