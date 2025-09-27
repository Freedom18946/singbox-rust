//! Static labels for metrics to avoid lifetime issues
//!
//! All metrics labels must be &'static str to satisfy the metrics crate requirements.

#[derive(Debug, Clone, Copy)]
pub enum Proto {
    Trojan,
    ShadowTls,
    NaiveH2,
    Vless,
    Vmess,
    Tuic,
    Hysteria2,
    Shadowsocks,
}

#[derive(Debug, Clone, Copy)]
pub enum ResultTag {
    Ok,
    Timeout,
    TlsFail,
    HttpNon200,
    BadTag,
    ConnectFail,
    AuthFail,
    HandshakeFail,
    ProtocolError,
    Other,
}

#[derive(Debug, Clone, Copy)]
pub enum CipherType {
    Aes128Gcm,
    ChaCha20Poly1305,
    None,
}

impl Proto {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Trojan => "trojan",
            Self::ShadowTls => "shadowtls",
            Self::NaiveH2 => "naive_h2",
            Self::Vless => "vless",
            Self::Vmess => "vmess",
            Self::Tuic => "tuic",
            Self::Hysteria2 => "hysteria2",
            Self::Shadowsocks => "shadowsocks",
        }
    }
}

impl ResultTag {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Timeout => "timeout",
            Self::TlsFail => "tls_fail",
            Self::HttpNon200 => "http_non_200",
            Self::BadTag => "bad_tag",
            Self::ConnectFail => "connect_fail",
            Self::AuthFail => "auth_fail",
            Self::HandshakeFail => "handshake_fail",
            Self::ProtocolError => "protocol_error",
            Self::Other => "other",
        }
    }
}

impl CipherType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Aes128Gcm => "aes-128-gcm",
            Self::ChaCha20Poly1305 => "chacha20-poly1305",
            Self::None => "none",
        }
    }
}

// Convenience functions for common metric patterns
pub fn record_connect_total(proto: Proto, result: ResultTag) {
    #[cfg(feature = "metrics")]
    {
        use metrics::counter;
        counter!("outbound_connect_total", "proto" => proto.as_str(), "result" => result.as_str())
            .increment(1);
    }
}

pub fn record_handshake_duration(proto: Proto, duration_ms: f64) {
    #[cfg(feature = "metrics")]
    {
        use metrics::histogram;
        histogram!("outbound_handshake_duration_ms", "proto" => proto.as_str()).record(duration_ms);
    }
}

pub fn record_tls_verify(proto: Proto, result: &'static str) {
    #[cfg(feature = "metrics")]
    {
        use metrics::counter;
        counter!("tls_verify_total", "proto" => proto.as_str(), "result" => result).increment(1);
    }
}
