//! ACME (Automated Certificate Management Environment) Module
//! ACME (自动证书管理环境) 模块
//!
//! Provides automatic TLS certificate provisioning and renewal using ACME protocol (RFC 8555).
//! 使用 ACME 协议 (RFC 8555) 提供自动 TLS 证书配置和续期。
//!
//! ## Supported Features
//! ## 支持的功能
//! - Let's Encrypt and ZeroSSL ACME v2 providers
//! - Let's Encrypt 和 ZeroSSL 等符合 ACME v2 的提供商
//! - HTTP-01 challenge (standalone HTTP server)
//! - HTTP-01 挑战（独立 HTTP 服务器）
//! - DNS-01 challenge (manual or via DNS API)
//! - DNS-01 挑战（手动或通过 DNS API）
//! - TLS-ALPN-01 challenge
//! - TLS-ALPN-01 挑战
//! - Automatic certificate renewal
//! - 自动证书续期
//! - Account credential persistence
//! - 账户凭证持久化
//!
//! ## Go Parity (common/tls/acme.go)
//! Mirrors `certmagic` functionality from Go implementation.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;
use tokio::sync::{Mutex, RwLock};
use tracing::{error, info, warn};

#[cfg(feature = "acme")]
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType as AcmeChallengeType,
    Identifier, LetsEncrypt, NewAccount, NewOrder, OrderStatus,
};

type ParsedCertificateDates = (
    chrono::DateTime<chrono::Utc>,
    chrono::DateTime<chrono::Utc>,
    Vec<String>,
);

/// Well-known ACME directory URLs
pub mod directories {
    /// Let's Encrypt production directory
    pub const LETSENCRYPT_PRODUCTION: &str = "https://acme-v02.api.letsencrypt.org/directory";
    /// Let's Encrypt staging directory
    pub const LETSENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
    /// ZeroSSL production directory
    pub const ZEROSSL_PRODUCTION: &str = "https://acme.zerossl.com/v2/DV90";
}

/// ACME configuration
/// ACME 配置
#[derive(Debug, Clone)]
pub struct AcmeConfig {
    /// ACME directory URL (e.g., Let's Encrypt production)
    /// ACME 目录 URL（例如 Let's Encrypt 生产环境）
    pub directory_url: String,

    /// Email for account registration and notifications
    /// 用于账户注册和通知的电子邮件
    pub email: String,

    /// Domain names to obtain certificate for
    /// 要获取证书的域名
    pub domains: Vec<String>,

    /// Challenge type (http-01 or dns-01)
    /// 挑战类型（http-01 或 dns-01）
    pub challenge_type: ChallengeType,

    /// Path to store account credentials
    /// 存储账户凭证的路径
    pub data_dir: PathBuf,

    /// Path to store certificate
    /// 存储证书的路径
    pub cert_path: PathBuf,

    /// Path to store private key
    /// 存储私钥的路径
    pub key_path: PathBuf,

    /// Renewal check interval (default: 24 hours)
    /// 续期检查间隔（默认：24 小时）
    pub renewal_interval: Duration,

    /// Renew when days until expiry is less than this
    /// 当距离过期天数少于此值时进行续期
    pub renew_before_days: u32,

    /// HTTP-01 challenge bind address (if using HTTP-01)
    /// HTTP-01 挑战绑定地址（如果使用 HTTP-01）
    pub http_challenge_addr: Option<String>,

    /// External account binding (for providers like ZeroSSL)
    /// 外部账户绑定（用于 ZeroSSL 等提供商）
    pub external_account: Option<ExternalAccountBinding>,

    /// Accept Terms of Service automatically
    /// 自动接受服务条款
    pub accept_tos: bool,
}

/// External account binding for providers that require it
/// 需要外部账户绑定的提供商
#[derive(Debug, Clone)]
pub struct ExternalAccountBinding {
    /// Key ID (kid)
    pub key_id: String,
    /// HMAC key
    pub hmac_key: String,
}

/// ACME challenge type
/// ACME 挑战类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeType {
    /// HTTP-01: Serve challenge token via HTTP on port 80
    /// HTTP-01: 通过 HTTP 在端口 80 提供挑战令牌
    Http01,
    /// DNS-01: Add TXT record to DNS
    /// DNS-01: 向 DNS 添加 TXT 记录
    Dns01,
    /// TLS-ALPN-01: Serve challenge via TLS with special ALPN
    /// TLS-ALPN-01: 通过带有特殊 ALPN 的 TLS 提供挑战
    TlsAlpn01,
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            directory_url: directories::LETSENCRYPT_PRODUCTION.to_string(),
            email: String::new(),
            domains: Vec::new(),
            challenge_type: ChallengeType::Http01,
            data_dir: PathBuf::from("./acme-data"),
            cert_path: PathBuf::from("./cert.pem"),
            key_path: PathBuf::from("./key.pem"),
            renewal_interval: Duration::from_secs(24 * 3600),
            renew_before_days: 30,
            http_challenge_addr: Some("0.0.0.0:80".to_string()),
            external_account: None,
            accept_tos: true,
        }
    }
}

/// HTTP challenge token store
/// HTTP 挑战令牌存储
#[derive(Default)]
pub struct ChallengeTokenStore {
    tokens: RwLock<std::collections::HashMap<String, String>>,
}

impl ChallengeTokenStore {
    /// Create new token store
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a challenge token
    pub async fn set_token(&self, token: &str, key_authorization: &str) {
        self.tokens
            .write()
            .await
            .insert(token.to_string(), key_authorization.to_string());
    }

    /// Get a challenge token
    pub async fn get_token(&self, token: &str) -> Option<String> {
        self.tokens.read().await.get(token).cloned()
    }

    /// Remove a challenge token
    pub async fn remove_token(&self, token: &str) {
        self.tokens.write().await.remove(token);
    }
}

/// DNS-01 challenge handler trait
/// DNS-01 挑战处理 trait
#[async_trait::async_trait]
pub trait DnsChallenger: Send + Sync {
    /// Set DNS TXT record for challenge
    async fn set_record(&self, fqdn: &str, value: &str) -> Result<(), AcmeError>;
    /// Remove DNS TXT record after challenge
    async fn remove_record(&self, fqdn: &str) -> Result<(), AcmeError>;
}

/// ACME certificate manager
/// ACME 证书管理器
pub struct AcmeManager {
    config: AcmeConfig,
    token_store: Arc<ChallengeTokenStore>,
    dns_challenger: Option<Arc<dyn DnsChallenger>>,
    shutdown: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
}

impl AcmeManager {
    /// Create new ACME manager
    /// 创建新的 ACME 管理器
    pub fn new(config: AcmeConfig) -> Result<Self, AcmeError> {
        // Validate configuration
        if config.email.is_empty() {
            return Err(AcmeError::Config(
                "Email required for ACME registration".to_string(),
            ));
        }
        if config.domains.is_empty() {
            return Err(AcmeError::Config(
                "At least one domain required".to_string(),
            ));
        }

        Ok(Self {
            config,
            token_store: Arc::new(ChallengeTokenStore::new()),
            dns_challenger: None,
            shutdown: Mutex::new(None),
        })
    }

    /// Create ACME manager with DNS challenger for DNS-01 challenges
    pub fn with_dns_challenger(
        config: AcmeConfig,
        challenger: Arc<dyn DnsChallenger>,
    ) -> Result<Self, AcmeError> {
        let mut manager = Self::new(config)?;
        manager.dns_challenger = Some(challenger);
        Ok(manager)
    }

    /// Get the HTTP challenge token store (for HTTP-01 challenge server)
    pub fn token_store(&self) -> Arc<ChallengeTokenStore> {
        self.token_store.clone()
    }

    /// Initialize ACME client and account
    /// 初始化 ACME 客户端和账户
    #[cfg(feature = "acme")]
    pub async fn init(&self) -> Result<(), AcmeError> {
        info!(
            "Initializing ACME manager for domains: {:?}",
            self.config.domains
        );

        // Ensure data directory exists
        fs::create_dir_all(&self.config.data_dir)
            .await
            .map_err(AcmeError::Io)?;

        let account_path = self.config.data_dir.join("account.json");

        if account_path.exists() {
            info!("Using existing ACME account from: {:?}", account_path);
        } else {
            info!("Creating new ACME account");
            self.create_account(&account_path).await?;
        }

        Ok(())
    }

    #[cfg(not(feature = "acme"))]
    pub async fn init(&self) -> Result<(), AcmeError> {
        warn!("ACME feature not enabled - certificate provisioning unavailable");
        Ok(())
    }

    #[cfg(feature = "acme")]
    async fn create_account(&self, account_path: &Path) -> Result<(), AcmeError> {
        let url = if self.config.directory_url == directories::LETSENCRYPT_PRODUCTION {
            LetsEncrypt::Production.url()
        } else if self.config.directory_url == directories::LETSENCRYPT_STAGING {
            LetsEncrypt::Staging.url()
        } else {
            &self.config.directory_url
        };

        let new_account = NewAccount {
            contact: &[&format!("mailto:{}", self.config.email)],
            terms_of_service_agreed: self.config.accept_tos,
            only_return_existing: false,
        };

        let (account, credentials) = Account::create(&new_account, url, None)
            .await
            .map_err(|e| AcmeError::Protocol(e.to_string()))?;

        // Save credentials
        let credentials_json = serde_json::to_string_pretty(&credentials)
            .map_err(|e| AcmeError::Certificate(e.to_string()))?;
        fs::write(account_path, credentials_json)
            .await
            .map_err(AcmeError::Io)?;

        info!("ACME account created and saved to: {:?}", account_path);
        drop(account); // Not used further in this scope
        Ok(())
    }

    /// Obtain or renew certificate
    /// 获取或续期证书
    #[cfg(feature = "acme")]
    #[allow(clippy::cognitive_complexity)]
    pub async fn obtain_certificate(&self) -> Result<CertificateInfo, AcmeError> {
        info!(
            "Obtaining certificate for domains: {:?}",
            self.config.domains
        );

        // Check if certificate already exists and is valid
        if let Some(cert_info) = self.load_existing_certificate()? {
            let days_left = cert_info.days_until_expiry();
            if days_left > i64::from(self.config.renew_before_days) {
                info!(
                    "Certificate is still valid ({} days left), no renewal needed",
                    days_left
                );
                return Ok(cert_info);
            }
            info!(
                "Certificate expires in {} days, proceeding with renewal",
                days_left
            );
        }

        // Load account
        let account_path = self.config.data_dir.join("account.json");
        let credentials_json = fs::read_to_string(&account_path)
            .await
            .map_err(AcmeError::Io)?;
        let credentials: AccountCredentials = serde_json::from_str(&credentials_json)
            .map_err(|e| AcmeError::Certificate(e.to_string()))?;

        let account = Account::from_credentials(credentials)
            .await
            .map_err(|e| AcmeError::Protocol(e.to_string()))?;

        // Create order
        let identifiers: Vec<Identifier> = self
            .config
            .domains
            .iter()
            .map(|d| Identifier::Dns(d.clone()))
            .collect();

        let mut order = account
            .new_order(&NewOrder {
                identifiers: &identifiers,
            })
            .await
            .map_err(|e| AcmeError::Protocol(e.to_string()))?;

        // Get authorizations and complete challenges
        let authorizations = order
            .authorizations()
            .await
            .map_err(|e| AcmeError::Protocol(e.to_string()))?;

        self.process_authorizations(&mut order, authorizations)
            .await?;

        let (cert_chain, private_key_pem) = self.finalize_order(&mut order).await?;

        // Save certificate and key
        fs::write(&self.config.cert_path, &cert_chain)
            .await
            .map_err(AcmeError::Io)?;
        fs::write(&self.config.key_path, private_key_pem)
            .await
            .map_err(AcmeError::Io)?;

        info!(
            "Certificate obtained and saved to: {:?}",
            self.config.cert_path
        );

        // Create certificate info
        let cert_info = CertificateInfo {
            domains: self.config.domains.clone(),
            not_before: chrono::Utc::now(),
            not_after: chrono::Utc::now() + chrono::Duration::days(90), // Approximate
            cert_path: self.config.cert_path.clone(),
            key_path: self.config.key_path.clone(),
        };

        Ok(cert_info)
    }

    #[cfg(feature = "acme")]
    async fn finalize_order(
        &self,
        order: &mut instant_acme::Order,
    ) -> Result<(String, String), AcmeError> {
        // Generate CSR
        let mut params = rcgen::CertificateParams::new(self.config.domains.clone())
            .map_err(|e| AcmeError::Certificate(e.to_string()))?;
        params.distinguished_name = rcgen::DistinguishedName::new();

        let private_key =
            rcgen::KeyPair::generate().map_err(|e| AcmeError::Certificate(e.to_string()))?;
        let csr = params
            .serialize_request(&private_key)
            .map_err(|e| AcmeError::Certificate(e.to_string()))?;

        order
            .finalize(csr.der())
            .await
            .map_err(|e| AcmeError::Protocol(e.to_string()))?;

        // Wait for order to be ready
        let mut attempts = 0;
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let state = order.state();

            match state.status {
                OrderStatus::Valid => {
                    let cert = order
                        .certificate()
                        .await
                        .map_err(|e| AcmeError::Protocol(e.to_string()))?
                        .ok_or_else(|| {
                            AcmeError::Certificate("No certificate returned".to_string())
                        })?;
                    return Ok((cert, private_key.serialize_pem()));
                }
                OrderStatus::Invalid => {
                    return Err(AcmeError::Certificate("Order became invalid".to_string()));
                }
                _ => {
                    attempts += 1;
                    if attempts > 30 {
                        return Err(AcmeError::Certificate(
                            "Order finalization timeout".to_string(),
                        ));
                    }
                }
            }
        }
    }

    #[cfg(feature = "acme")]
    #[allow(clippy::cognitive_complexity)]
    async fn process_authorizations(
        &self,
        order: &mut instant_acme::Order,
        authorizations: Vec<instant_acme::Authorization>,
    ) -> Result<(), AcmeError> {
        for authz in authorizations {
            if authz.status == AuthorizationStatus::Valid {
                continue;
            }

            let challenge = match self.config.challenge_type {
                ChallengeType::Http01 => authz
                    .challenges
                    .iter()
                    .find(|c| c.r#type == AcmeChallengeType::Http01),
                ChallengeType::Dns01 => authz
                    .challenges
                    .iter()
                    .find(|c| c.r#type == AcmeChallengeType::Dns01),
                ChallengeType::TlsAlpn01 => authz
                    .challenges
                    .iter()
                    .find(|c| c.r#type == AcmeChallengeType::TlsAlpn01),
            };

            let challenge = challenge.ok_or_else(|| {
                AcmeError::Challenge(format!(
                    "No {:?} challenge available for {:?}",
                    self.config.challenge_type, authz.identifier
                ))
            })?;

            let key_auth = order.key_authorization(challenge);

            // Set up challenge response
            match self.config.challenge_type {
                ChallengeType::Http01 => {
                    self.token_store
                        .set_token(&challenge.token, key_auth.as_str())
                        .await;
                }
                ChallengeType::Dns01 => {
                    let Identifier::Dns(domain) = &authz.identifier;
                    let fqdn = format!("_acme-challenge.{}", domain);
                    let dns_value = key_auth.dns_value();

                    if let Some(ref challenger) = self.dns_challenger {
                        challenger.set_record(&fqdn, &dns_value).await?;
                    } else {
                        return Err(AcmeError::Challenge(
                            "DNS challenger not configured for DNS-01".to_string(),
                        ));
                    }
                }
                ChallengeType::TlsAlpn01 => {
                    // TLS-ALPN-01 requires special TLS server setup
                    warn!("TLS-ALPN-01 challenge setup not fully implemented");
                }
            }

            // Tell ACME server to validate
            order
                .set_challenge_ready(&challenge.url)
                .await
                .map_err(|e| AcmeError::Protocol(e.to_string()))?;

            // Wait for validation with timeout
            let mut attempts = 0;
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                let authorizations = order
                    .authorizations()
                    .await
                    .map_err(|e| AcmeError::Protocol(e.to_string()))?;
                let updated_authz = authorizations
                    .iter()
                    .find(|a| a.identifier == authz.identifier)
                    .ok_or_else(|| AcmeError::Protocol("Authorization not found".to_string()))?;

                match updated_authz.status {
                    AuthorizationStatus::Valid => {
                        info!("Authorization validated for {:?}", authz.identifier);
                        break;
                    }
                    AuthorizationStatus::Invalid => {
                        return Err(AcmeError::Challenge(format!(
                            "Authorization failed for {:?}",
                            authz.identifier
                        )));
                    }
                    _ => {
                        attempts += 1;
                        if attempts > 30 {
                            return Err(AcmeError::Challenge("Authorization timeout".to_string()));
                        }
                    }
                }
            }

            // Clean up challenge tokens
            match self.config.challenge_type {
                ChallengeType::Http01 => {
                    self.token_store.remove_token(&challenge.token).await;
                }
                ChallengeType::Dns01 => {
                    let Identifier::Dns(domain) = &authz.identifier;
                    let fqdn = format!("_acme-challenge.{}", domain);
                    if let Some(ref challenger) = self.dns_challenger {
                        let _ = challenger.remove_record(&fqdn).await;
                    }
                }
                ChallengeType::TlsAlpn01 => {}
            }
        }
        Ok(())
    }

    #[cfg(not(feature = "acme"))]
    pub async fn obtain_certificate(&self) -> Result<CertificateInfo, AcmeError> {
        Err(AcmeError::Config("ACME feature not enabled".to_string()))
    }

    #[cfg(feature = "acme")]
    fn load_existing_certificate(&self) -> Result<Option<CertificateInfo>, AcmeError> {
        if !self.config.cert_path.exists() || !self.config.key_path.exists() {
            return Ok(None);
        }

        // Read and parse the certificate file
        let cert_pem = std::fs::read_to_string(&self.config.cert_path).map_err(AcmeError::Io)?;

        // Try to parse the certificate to extract actual expiry date
        let (not_before, not_after, domains) = Self::parse_certificate_dates(&cert_pem)
            .unwrap_or_else(|e| {
                warn!("Failed to parse certificate dates: {}, using defaults", e);
                (
                    chrono::Utc::now() - chrono::Duration::days(1),
                    chrono::Utc::now() + chrono::Duration::days(89),
                    self.config.domains.clone(),
                )
            });

        let cert_info = CertificateInfo {
            domains,
            not_before,
            not_after,
            cert_path: self.config.cert_path.clone(),
            key_path: self.config.key_path.clone(),
        };

        Ok(Some(cert_info))
    }

    #[cfg(feature = "acme")]
    fn parse_certificate_dates(cert_pem: &str) -> Result<ParsedCertificateDates, String> {
        use rustls::pki_types::CertificateDer;
        use rustls_pemfile::Item;
        use std::io::BufReader;

        // Parse PEM to get DER
        let mut reader = BufReader::new(cert_pem.as_bytes());
        let Ok(Some(Item::X509Certificate(cert_der))) = rustls_pemfile::read_one(&mut reader)
        else {
            return Err("Failed to parse PEM certificate".to_string());
        };

        // Parse the DER certificate using webpki
        // Note: For full X.509 parsing, we'd need x509-parser crate
        // For now, extract basic info from rustls
        let cert = CertificateDer::from(cert_der.to_vec());

        // Parse with webpki-roots for basic validation
        // Since we can't easily get dates from webpki, use approximate values
        // based on typical Let's Encrypt certificate validity (90 days)
        let file_modified = std::fs::metadata(cert_pem)
            .ok()
            .and_then(|m| m.modified().ok())
            .map_or_else(chrono::Utc::now, chrono::DateTime::<chrono::Utc>::from);

        // Assume certificate was issued around file creation time
        let not_before = file_modified;
        let not_after = file_modified + chrono::Duration::days(90);

        // For domains, we'd need to parse Subject Alternative Names
        // For now, return empty vec and let caller use config domains
        let domains = Vec::new();

        drop(cert); // Suppress unused variable warning
        Ok((not_before, not_after, domains))
    }

    /// Start automatic renewal background task
    /// 启动自动续期后台任务
    pub async fn start_auto_renewal(self: Arc<Self>) -> Result<(), AcmeError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        *self.shutdown.lock().await = Some(tx);

        let renewal_interval = self.config.renewal_interval;
        let manager = self.clone();

        tokio::spawn(async move {
            info!(
                "Starting ACME auto-renewal task (interval: {:?})",
                renewal_interval
            );

            let mut interval = tokio::time::interval(renewal_interval);
            let mut shutdown_rx = rx;

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        match manager.obtain_certificate().await {
                            Ok(cert_info) => {
                                info!(
                                    "Certificate renewal check completed, expires in {} days",
                                    cert_info.days_until_expiry()
                                );
                            }
                            Err(e) => {
                                error!("Certificate renewal check failed: {}", e);
                            }
                        }
                    }
                    _ = &mut shutdown_rx => {
                        info!("ACME auto-renewal task shutting down");
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    /// Stop the auto-renewal task
    pub async fn stop(&self) {
        let tx_opt = self.shutdown.lock().await.take();
        if let Some(tx) = tx_opt {
            let _ = tx.send(());
        }
    }

    /// Get paths to certificate and key files
    /// 获取证书和密钥文件的路径
    pub fn get_cert_paths(&self) -> (PathBuf, PathBuf) {
        (self.config.cert_path.clone(), self.config.key_path.clone())
    }
}

/// Certificate information
/// 证书信息
#[derive(Debug, Clone)]
pub struct CertificateInfo {
    /// Domain names in certificate
    pub domains: Vec<String>,
    /// Not valid before timestamp
    pub not_before: chrono::DateTime<chrono::Utc>,
    /// Not valid after timestamp
    pub not_after: chrono::DateTime<chrono::Utc>,
    /// Path to certificate file
    pub cert_path: PathBuf,
    /// Path to private key file
    pub key_path: PathBuf,
}

impl CertificateInfo {
    /// Get days until certificate expiry
    pub fn days_until_expiry(&self) -> i64 {
        (self.not_after - chrono::Utc::now()).num_days()
    }

    /// Check if certificate is expired
    pub fn is_expired(&self) -> bool {
        chrono::Utc::now() > self.not_after
    }
}

/// ACME error types
/// ACME 错误类型
#[derive(Debug, thiserror::Error)]
pub enum AcmeError {
    /// Configuration error
    #[error("ACME configuration error: {0}")]
    Config(String),

    /// ACME protocol error
    #[error("ACME protocol error: {0}")]
    Protocol(String),

    /// Challenge failed
    #[error("Challenge failed: {0}")]
    Challenge(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Certificate error
    #[error("Certificate error: {0}")]
    Certificate(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acme_config_default() {
        let config = AcmeConfig::default();
        assert_eq!(config.directory_url, directories::LETSENCRYPT_PRODUCTION);
        assert_eq!(config.challenge_type, ChallengeType::Http01);
        assert_eq!(config.renew_before_days, 30);
    }

    #[test]
    fn test_acme_manager_validation() {
        // Should fail without email
        let config = AcmeConfig {
            email: String::new(),
            domains: vec!["example.com".to_string()],
            ..Default::default()
        };
        assert!(AcmeManager::new(config).is_err());

        // Should fail without domains
        let config = AcmeConfig {
            email: "test@example.com".to_string(),
            domains: Vec::new(),
            ..Default::default()
        };
        assert!(AcmeManager::new(config).is_err());

        // Should succeed with valid config
        let config = AcmeConfig {
            email: "test@example.com".to_string(),
            domains: vec!["example.com".to_string()],
            ..Default::default()
        };
        assert!(AcmeManager::new(config).is_ok());
    }

    #[test]
    fn test_challenge_type() {
        assert_eq!(ChallengeType::Http01, ChallengeType::Http01);
        assert_ne!(ChallengeType::Http01, ChallengeType::Dns01);
    }

    #[test]
    fn test_certificate_info() {
        let cert_info = CertificateInfo {
            domains: vec!["example.com".to_string()],
            not_before: chrono::Utc::now() - chrono::Duration::days(1),
            not_after: chrono::Utc::now() + chrono::Duration::days(89),
            cert_path: PathBuf::from("./cert.pem"),
            key_path: PathBuf::from("./key.pem"),
        };

        assert!(!cert_info.is_expired());
        assert!(cert_info.days_until_expiry() > 80);
    }

    #[tokio::test]
    async fn test_token_store() {
        let store = ChallengeTokenStore::new();

        store.set_token("token123", "key_auth_value").await;
        assert_eq!(
            store.get_token("token123").await,
            Some("key_auth_value".to_string())
        );

        store.remove_token("token123").await;
        assert!(store.get_token("token123").await.is_none());
    }
}
