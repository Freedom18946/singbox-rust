//! Map io/tls errors to `IssueCode` classes for stable surface.
use crate::error_map::IssueCode;

#[derive(Debug, Clone)]
pub struct NetClass {
    pub code: IssueCode,
    pub class: &'static str, // "timeout"|"refused"|"icmp"|"proto"|"cert"|"other"
}

pub fn classify_io(e: &std::io::Error) -> NetClass {
    use std::io::ErrorKind::{ConnectionRefused, TimedOut};
    match e.kind() {
        TimedOut => NetClass {
            code: IssueCode::UpstreamTimeout,
            class: "timeout",
        },
        ConnectionRefused => NetClass {
            code: IssueCode::UpstreamRefused,
            class: "refused",
        },
        // Icmp 在用户态很难精准区分；保留 other
        _ => NetClass {
            code: IssueCode::UpstreamOther,
            class: "other",
        },
    }
}

#[cfg(feature = "tls_rustls")]
pub const fn classify_tls(err: &rustls::Error) -> NetClass {
    use rustls::Error::InvalidCertificate;
    match err {
        InvalidCertificate(_) => NetClass {
            code: IssueCode::TlsCertInvalid,
            class: "cert",
        },
        _ => NetClass {
            code: IssueCode::UpstreamOther,
            class: "other",
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn io_timeout_refused() {
        let t = std::io::Error::from(std::io::ErrorKind::TimedOut);
        assert_eq!(classify_io(&t).class, "timeout");
        let r = std::io::Error::from(std::io::ErrorKind::ConnectionRefused);
        assert_eq!(classify_io(&r).class, "refused");
    }
}
