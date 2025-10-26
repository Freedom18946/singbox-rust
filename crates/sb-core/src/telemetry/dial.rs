#![allow(dead_code)]
#[cfg(feature = "metrics")]
use metrics::{counter, histogram};
use std::time::Instant;

#[derive(Clone, Copy)]
pub enum Phase {
    TcpConnect,
    ProxyHandshake,
    TlsHandshake,
}

impl Phase {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::TcpConnect => "tcp_connect",
            Self::ProxyHandshake => "proxy_handshake",
            Self::TlsHandshake => "tls_handshake",
        }
    }
}

#[inline]
pub fn start() -> Instant {
    Instant::now()
}

#[inline]
pub fn record_ok(kind: &'static str, phase: Phase, t0: Instant) {
    #[cfg(feature = "metrics")]
    {
        let dt = t0.elapsed().as_secs_f64();
        histogram!("outbound_connect_seconds", "kind"=>kind, "phase"=>phase.as_str()).record(dt);
        counter!("outbound_connect_total", "kind"=>kind, "phase"=>phase.as_str(), "result"=>"ok")
            .increment(1);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = (kind, phase, t0);
    }
}

#[inline]
pub fn record_err(kind: &'static str, phase: Phase, t0: Instant, class: &'static str) {
    #[cfg(feature = "metrics")]
    {
        let dt = t0.elapsed().as_secs_f64();
        histogram!("outbound_connect_seconds", "kind"=>kind, "phase"=>phase.as_str()).record(dt);
        counter!("outbound_connect_total", "kind"=>kind, "phase"=>phase.as_str(), "result"=>"err", "class"=>class).increment(1);
        counter!("outbound_error_total", "kind"=>kind, "phase"=>phase.as_str(), "class"=>class)
            .increment(1);
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = (kind, phase, t0, class);
    }
}
