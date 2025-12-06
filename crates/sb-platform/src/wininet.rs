//! Windows Internet (WinInet) proxy detection and configuration.
//!
//! Reads system proxy settings from Windows Internet Settings registry
//! and environment variables.
//!
//! # Example
//! ```ignore
//! use sb_platform::wininet::{detect_system_proxy, ProxyConfig};
//!
//! if let Some(config) = detect_system_proxy() {
//!     println!("HTTP proxy: {:?}", config.http_proxy);
//!     println!("HTTPS proxy: {:?}", config.https_proxy);
//! }
//! ```

/// System proxy configuration.
#[derive(Debug, Clone, Default)]
pub struct ProxyConfig {
    /// HTTP proxy address (e.g., "http://proxy:8080").
    pub http_proxy: Option<String>,
    /// HTTPS proxy address.
    pub https_proxy: Option<String>,
    /// SOCKS proxy address.
    pub socks_proxy: Option<String>,
    /// List of hosts to bypass proxy.
    pub no_proxy: Vec<String>,
    /// Whether proxy is enabled.
    pub enabled: bool,
    /// Auto-config URL (PAC).
    pub auto_config_url: Option<String>,
    /// Auto-detect enabled.
    pub auto_detect: bool,
}

impl ProxyConfig {
    /// Check if any proxy is configured.
    pub fn has_proxy(&self) -> bool {
        self.enabled && (self.http_proxy.is_some() || self.https_proxy.is_some() || self.socks_proxy.is_some())
    }

    /// Check if a host should bypass the proxy.
    pub fn should_bypass(&self, host: &str) -> bool {
        let host_lower = host.to_lowercase();
        for pattern in &self.no_proxy {
            let pattern_lower = pattern.to_lowercase();
            if pattern_lower == "*" {
                return true;
            }
            if pattern_lower.starts_with('.') {
                // Suffix match: .example.com matches foo.example.com
                if host_lower.ends_with(&pattern_lower) {
                    return true;
                }
            } else if host_lower == pattern_lower
                || host_lower.ends_with(&format!(".{}", pattern_lower))
            {
                return true;
            }
        }
        // Always bypass localhost
        if host_lower == "localhost" || host_lower == "127.0.0.1" || host_lower == "::1" {
            return true;
        }
        false
    }
}

/// Detect system proxy settings.
///
/// On Windows, reads from registry.
/// On Unix, reads from environment variables.
pub fn detect_system_proxy() -> Option<ProxyConfig> {
    #[cfg(windows)]
    {
        detect_windows_proxy()
    }
    #[cfg(not(windows))]
    {
        detect_env_proxy()
    }
}

/// Detect proxy from environment variables.
pub fn detect_env_proxy() -> Option<ProxyConfig> {
    let http_proxy = std::env::var("HTTP_PROXY")
        .or_else(|_| std::env::var("http_proxy"))
        .ok();
    let https_proxy = std::env::var("HTTPS_PROXY")
        .or_else(|_| std::env::var("https_proxy"))
        .ok();
    let no_proxy = std::env::var("NO_PROXY")
        .or_else(|_| std::env::var("no_proxy"))
        .unwrap_or_default();
    let all_proxy = std::env::var("ALL_PROXY")
        .or_else(|_| std::env::var("all_proxy"))
        .ok();

    let no_proxy_list: Vec<String> = no_proxy
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let http = http_proxy.or_else(|| all_proxy.clone());
    let https = https_proxy.or_else(|| all_proxy.clone());

    if http.is_some() || https.is_some() {
        Some(ProxyConfig {
            http_proxy: http,
            https_proxy: https,
            no_proxy: no_proxy_list,
            enabled: true,
            ..Default::default()
        })
    } else {
        None
    }
}

/// Detect proxy from Windows Internet Settings registry.
#[cfg(windows)]
pub fn detect_windows_proxy() -> Option<ProxyConfig> {
    use winreg::enums::*;
    use winreg::RegKey;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let internet_settings = hkcu
        .open_subkey("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings")
        .ok()?;

    // Check if proxy is enabled
    let proxy_enable: u32 = internet_settings.get_value("ProxyEnable").unwrap_or(0);
    let enabled = proxy_enable != 0;

    // Get proxy server setting
    let proxy_server: String = internet_settings
        .get_value("ProxyServer")
        .unwrap_or_default();

    // Get bypass list
    let proxy_override: String = internet_settings
        .get_value("ProxyOverride")
        .unwrap_or_default();

    // Get auto-config URL
    let auto_config_url: Option<String> = internet_settings
        .get_value("AutoConfigURL")
        .ok();

    // Parse proxy server (can be "host:port" or "http=host:port;https=host:port;...")
    let (http_proxy, https_proxy, socks_proxy) = parse_windows_proxy_server(&proxy_server);

    // Parse bypass list (semicolon-separated)
    let no_proxy: Vec<String> = proxy_override
        .split(';')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s != "<local>")
        .collect();

    Some(ProxyConfig {
        http_proxy,
        https_proxy,
        socks_proxy,
        no_proxy,
        enabled,
        auto_config_url,
        auto_detect: false,
    })
}

/// Parse Windows proxy server string.
#[cfg(windows)]
fn parse_windows_proxy_server(server: &str) -> (Option<String>, Option<String>, Option<String>) {
    if server.is_empty() {
        return (None, None, None);
    }

    // Check if it's protocol-specific format
    if server.contains('=') {
        let mut http = None;
        let mut https = None;
        let mut socks = None;

        for part in server.split(';') {
            let part = part.trim();
            if let Some((proto, addr)) = part.split_once('=') {
                let addr = addr.trim();
                match proto.to_lowercase().as_str() {
                    "http" => http = Some(format!("http://{}", addr)),
                    "https" => https = Some(format!("http://{}", addr)),
                    "socks" => socks = Some(format!("socks5://{}", addr)),
                    _ => {}
                }
            }
        }

        (http, https, socks)
    } else {
        // Single proxy for all protocols
        let proxy = format!("http://{}", server);
        (Some(proxy.clone()), Some(proxy), None)
    }
}

/// Stub for non-Windows platforms.
#[cfg(not(windows))]
pub fn detect_windows_proxy() -> Option<ProxyConfig> {
    None
}

/// Set system proxy (Windows only).
#[cfg(windows)]
pub fn set_system_proxy(config: &ProxyConfig) -> std::io::Result<()> {
    use winreg::enums::*;
    use winreg::RegKey;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (internet_settings, _) = hkcu.create_subkey("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings")?;

    // Set proxy enable
    internet_settings.set_value("ProxyEnable", &(if config.enabled { 1u32 } else { 0u32 }))?;

    // Set proxy server
    if let Some(ref http) = config.http_proxy {
        // Strip protocol prefix
        let server = http.trim_start_matches("http://").trim_start_matches("https://");
        internet_settings.set_value("ProxyServer", &server)?;
    }

    // Set bypass list
    if !config.no_proxy.is_empty() {
        let bypass = config.no_proxy.join(";");
        internet_settings.set_value("ProxyOverride", &bypass)?;
    }

    Ok(())
}

/// Stub for non-Windows platforms.
#[cfg(not(windows))]
pub fn set_system_proxy(_config: &ProxyConfig) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "set_system_proxy is only supported on Windows",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_config_default() {
        let config = ProxyConfig::default();
        assert!(!config.enabled);
        assert!(!config.has_proxy());
    }

    #[test]
    fn test_should_bypass() {
        let config = ProxyConfig {
            no_proxy: vec![
                "example.com".to_string(),
                ".internal.corp".to_string(),
            ],
            ..Default::default()
        };

        assert!(config.should_bypass("example.com"));
        assert!(config.should_bypass("foo.example.com"));
        assert!(config.should_bypass("bar.internal.corp"));
        assert!(config.should_bypass("localhost"));
        assert!(config.should_bypass("127.0.0.1"));
        assert!(!config.should_bypass("other.com"));
    }

    #[test]
    fn test_detect_env_proxy() {
        // This test depends on environment, so just verify it doesn't panic
        let _ = detect_env_proxy();
    }
}
