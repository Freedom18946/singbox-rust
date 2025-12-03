/// ACME (Automated Certificate Management Environment) configuration
/// ACME (自动证书管理环境) 配置
///
/// Configuration for automatic TLS certificate provisioning and renewal.
/// 用于自动 TLS 证书配置和续期的配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeConfig {
    /// Enable ACME / 启用 ACME
    #[serde(default)]
    pub enabled: bool,
    
    /// ACME provider directory URL (default: Let's Encrypt production)
    /// ACME 提供商目录 URL (默认：Let's Encrypt 生产环境)
    #[serde(default = "default_acme_directory")]
    pub directory: String,
    
    /// Email for account registration and notifications
    /// 用于账户注册和通知的电子邮件
    pub email: String,
    
    /// Domain names to obtain certificate for
    /// 要获取证书的域名
    pub domains: Vec<String>,
    
    /// Challenge type: "http-01" or "dns-01"
    /// 挑战类型："http-01" 或 "dns-01"
    #[serde(default = "default_acme_challenge")]
    pub challenge_type: String,
    
    /// HTTP-01 challenge listen address (default: 0.0.0.0:80)
    /// HTTP-01 挑战监听地址（默认：0.0.0.0:80）
    #[serde(default)]
    pub http_challenge_addr: Option<String>,
    
    /// Path to store account credentials (default: ./acme-account.pem)
    /// 存储账户凭证的路径（默认：./acme-account.pem）
    #[serde(default = "default_acme_account_path")]
    pub account_key_path: String,
    
    /// Path to store certificate (default: ./cert.pem)
    /// 存储证书的路径（默认：./cert.pem）
    #[serde(default = "default_acme_cert_path")]
    pub cert_path: String,
    
    /// Path to store private key (default: ./key.pem)
    /// 存储私钥的路径（默认：./key.pem）
    #[serde(default = "default_acme_key_path")]
    pub key_path: String,
    
    /// Renew when days until expiry is less than this (default: 30)
    /// 当距离过期天数少于此值时进行续期（默认：30）
    #[serde(default = "default_acme_renew_days")]
    pub renew_before_days: u32,
}

fn default_acme_directory() -> String {
    "https://acme-v02.api.letsencrypt.org/directory".to_string()
}

fn default_acme_challenge() -> String {
    "http-01".to_string()
}

fn default_acme_account_path() -> String {
    "./acme-account.pem".to_string()
}

fn default_acme_cert_path() -> String {
    "./cert.pem".to_string()
}

fn default_acme_key_path() -> String {
    "./key.pem".to_string()
}

fn default_acme_renew_days() -> u32 {
    30
}
