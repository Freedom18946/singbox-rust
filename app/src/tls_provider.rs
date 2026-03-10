use rustls::crypto::{self, CryptoProvider};
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsProviderKind {
    Ring,
    AwsLc,
}

impl TlsProviderKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ring => "ring",
            Self::AwsLc => "aws-lc",
        }
    }
}

#[derive(Debug, Clone)]
pub struct TlsProviderDecision {
    pub provider: TlsProviderKind,
    pub requested: String,
    pub source: &'static str,
    pub install_result: &'static str,
    pub fallback_reason: Option<String>,
}

pub fn ensure_default_provider() -> TlsProviderDecision {
    static DECISION: OnceLock<TlsProviderDecision> = OnceLock::new();
    DECISION.get_or_init(decide_and_install).clone()
}

#[must_use]
pub const fn aws_lc_compiled() -> bool {
    cfg!(feature = "tls-provider-aws-lc")
}

fn decide_and_install() -> TlsProviderDecision {
    let requested = std::env::var("SB_TLS_PROVIDER").unwrap_or_else(|_| "auto".to_string());
    let requested_norm = requested.trim().to_ascii_lowercase();

    let mut fallback_reason: Option<String> = None;
    let (provider, source) = match requested_norm.as_str() {
        "ring" => (TlsProviderKind::Ring, "env"),
        "aws-lc" | "awslc" | "aws_lc" | "aws_lc_rs" => {
            if aws_lc_compiled() {
                (TlsProviderKind::AwsLc, "env")
            } else {
                fallback_reason = Some(
                    "requested aws-lc but build lacks feature tls-provider-aws-lc".to_string(),
                );
                (TlsProviderKind::Ring, "env-fallback")
            }
        }
        "auto" | "" => (TlsProviderKind::Ring, "default"),
        other => {
            fallback_reason = Some(format!(
                "invalid SB_TLS_PROVIDER='{other}', fallback to ring"
            ));
            (TlsProviderKind::Ring, "env-invalid")
        }
    };

    let already_present = CryptoProvider::get_default().is_some();
    let install_result = if already_present {
        "already_present"
    } else if install_provider(provider).is_ok() {
        "installed"
    } else {
        "already_present"
    };

    TlsProviderDecision {
        provider,
        requested: requested_norm,
        source,
        install_result,
        fallback_reason,
    }
}

fn install_provider(provider: TlsProviderKind) -> Result<(), ArcProvider> {
    match provider {
        TlsProviderKind::Ring => CryptoProvider::install_default(crypto::ring::default_provider()),
        TlsProviderKind::AwsLc => install_aws_lc(),
    }
}

#[cfg(feature = "tls-provider-aws-lc")]
fn install_aws_lc() -> Result<(), ArcProvider> {
    CryptoProvider::install_default(crypto::aws_lc_rs::default_provider())
}

#[cfg(not(feature = "tls-provider-aws-lc"))]
fn install_aws_lc() -> Result<(), ArcProvider> {
    CryptoProvider::install_default(crypto::ring::default_provider())
}

type ArcProvider = std::sync::Arc<CryptoProvider>;

#[cfg(test)]
mod tests {
    use super::aws_lc_compiled;

    #[test]
    fn aws_lc_flag_exposed() {
        let _ = aws_lc_compiled();
    }
}
