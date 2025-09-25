use crate::admin_debug::{endpoints, http_util::{respond, respond_json_error, respond_json_ok, is_networking_allowed, supported_patch_kinds}};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use std::sync::OnceLock;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use std::path::PathBuf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use hex;
use httparse;

trait StreamTrait: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> StreamTrait for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
pub struct TlsConf {
    pub enabled: bool,
    pub cert: PathBuf,
    pub key: PathBuf,
    pub ca: Option<PathBuf>,
    pub require_client_cert: bool,
}

impl TlsConf {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            cert: PathBuf::new(),
            key: PathBuf::new(),
            ca: None,
            require_client_cert: false,
        }
    }

    pub fn from_env() -> Self {
        let enabled = std::env::var("SB_ADMIN_TLS_CERT").is_ok() && std::env::var("SB_ADMIN_TLS_KEY").is_ok();

        if !enabled {
            return Self::disabled();
        }

        Self {
            enabled,
            cert: std::env::var("SB_ADMIN_TLS_CERT").unwrap_or_default().into(),
            key: std::env::var("SB_ADMIN_TLS_KEY").unwrap_or_default().into(),
            ca: std::env::var("SB_ADMIN_TLS_CA").ok().map(PathBuf::from),
            require_client_cert: std::env::var("SB_ADMIN_MTLS").ok().as_deref() == Some("1"),
        }
    }
}

#[derive(Debug, Clone)]
pub enum AuthConf {
    Disabled,
    Bearer { token: String },
    Hmac { secret: String },
    BearerAndHmac { token: String, secret: String },
    Mtls { enabled: bool },
}

impl AuthConf {
    pub fn from_env() -> Self {
        if std::env::var("SB_ADMIN_NO_AUTH").ok().as_deref() == Some("1") {
            return Self::Disabled;
        }

        if std::env::var("SB_ADMIN_MTLS").ok().as_deref() == Some("1") {
            return Self::Mtls { enabled: true };
        }

        let token = std::env::var("SB_ADMIN_TOKEN").ok();
        let secret = std::env::var("SB_ADMIN_HMAC_SECRET").ok();

        match (token, secret) {
            (Some(t), Some(s)) => Self::BearerAndHmac { token: t, secret: s },
            (Some(t), None) => Self::Bearer { token: t },
            (None, Some(s)) => Self::Hmac { secret: s },
            (None, None) => Self::Disabled,
        }
    }

    pub fn mode(&self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Bearer { .. } => "bearer",
            Self::Hmac { .. } => "hmac",
            Self::BearerAndHmac { .. } => "bearer+hmac",
            Self::Mtls { .. } => "mtls",
        }
    }
}

pub static START: OnceLock<std::time::Instant> = OnceLock::new();

pub fn check_auth(headers: &HashMap<String, String>, path: &str) -> bool {
    // Check if auth is disabled
    if std::env::var("SB_ADMIN_NO_AUTH").ok().as_deref() == Some("1") {
        return true;
    }

    if let Some(auth_header) = headers.get("authorization") {
        let auth_header = auth_header.trim();

        // Try Bearer token authentication first
        if let Some(token) = auth_header.strip_prefix("Bearer ") {
            if let Some(required_token) = std::env::var("SB_ADMIN_TOKEN").ok() {
                return token.trim() == required_token;
            }
        }

        // Try HMAC authentication
        if let Some(hmac_part) = auth_header.strip_prefix("SB-HMAC ") {
            return check_hmac_auth(hmac_part.trim(), path);
        }
    }

    // If no auth header or no valid auth found, check if Bearer token is configured
    if std::env::var("SB_ADMIN_TOKEN").ok().is_none() {
        return true; // No auth configured, allow access
    }

    false
}

fn check_hmac_auth(hmac_auth: &str, path: &str) -> bool {
    // Parse HMAC auth string: keyId:timestamp:signature
    let parts: Vec<&str> = hmac_auth.split(':').collect();
    if parts.len() != 3 {
        return false;
    }

    let (_key_id, timestamp_str, provided_signature) = (parts[0], parts[1], parts[2]);

    // Parse timestamp
    let timestamp = match timestamp_str.parse::<u64>() {
        Ok(ts) => ts,
        Err(_) => return false,
    };

    // Check time window (5 minutes = 300 seconds)
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if now.abs_diff(timestamp) > 300 {
        return false; // Outside 5-minute window
    }

    // Get HMAC secret from environment
    let secret = match std::env::var("SB_ADMIN_HMAC_SECRET").ok() {
        Some(s) => s,
        None => return false, // No HMAC secret configured
    };

    // Create message to sign: timestamp||path
    let message = format!("{}{}", timestamp, path);

    // Calculate expected signature using real HMAC-SHA256
    let mut mac = match HmacSha256::new_from_slice(secret.as_bytes()) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(message.as_bytes());
    let expected = mac.finalize().into_bytes();
    let expected_hex = hex::encode(expected);

    // Constant-time comparison
    expected_hex.as_bytes().ct_eq(provided_signature.as_bytes()).into()
}

pub fn get_auth_mode() -> &'static str {
    if std::env::var("SB_ADMIN_NO_AUTH").ok().as_deref() == Some("1") {
        "disabled"
    } else if std::env::var("SB_ADMIN_MTLS").ok().as_deref() == Some("1") {
        "mtls"
    } else if std::env::var("SB_ADMIN_HMAC_SECRET").ok().is_some() && std::env::var("SB_ADMIN_TOKEN").ok().is_some() {
        "bearer+hmac"
    } else if std::env::var("SB_ADMIN_HMAC_SECRET").ok().is_some() {
        "hmac"
    } else if std::env::var("SB_ADMIN_TOKEN").ok().is_some() {
        "bearer"
    } else {
        "none"
    }
}

async fn build_tls_acceptor() -> std::io::Result<tokio_rustls::TlsAcceptor> {
    use std::{fs::File, io::BufReader};
    use tokio_rustls::rustls::{ServerConfig, pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer}};

    let cert_path = std::env::var("SB_ADMIN_TLS_CERT").map_err(|_| std::io::Error::new(std::io::ErrorKind::NotFound, "SB_ADMIN_TLS_CERT not set"))?;
    let key_path  = std::env::var("SB_ADMIN_TLS_KEY").map_err(|_| std::io::Error::new(std::io::ErrorKind::NotFound, "SB_ADMIN_TLS_KEY not set"))?;
    let ca_path   = std::env::var("SB_ADMIN_TLS_CA").ok();

    let mut cert_reader = BufReader::new(File::open(cert_path)?);
    let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<_, _>>()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid cert"))?;

    let mut key_reader = BufReader::new(File::open(key_path)?);
    let key = rustls_pemfile::pkcs8_private_keys(&mut key_reader)
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "no private key found"))??;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.secret_pkcs8_der().to_vec()));

    let cfg_builder = ServerConfig::builder()
        .with_no_client_auth(); // Default: no client auth required

    // If mTLS is enabled, require client certificates
    let cfg_builder = if std::env::var("SB_ADMIN_MTLS").ok().as_deref() == Some("1") {
        use tokio_rustls::rustls::{server::WebPkiClientVerifier, RootCertStore};
        let mut roots = RootCertStore::empty();
        if let Some(ca) = ca_path {
            let mut r = BufReader::new(File::open(ca)?);
            for c in rustls_pemfile::certs(&mut r) {
                roots.add(c?).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid CA cert"))?;
            }
        } else {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "SB_ADMIN_TLS_CA required for mTLS"));
        }
        let verifier = WebPkiClientVerifier::builder(roots.into()).build()
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "failed to build client verifier"))?;
        ServerConfig::builder().with_client_cert_verifier(verifier)
    } else {
        cfg_builder
    };

    let mut cfg = cfg_builder
        .with_single_cert(certs, key)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid cert/key"))?;

    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(cfg)))
}

async fn build_tls_acceptor_from_config(tls_conf: &TlsConf) -> std::io::Result<tokio_rustls::TlsAcceptor> {
    use std::{fs::File, io::BufReader};
    use tokio_rustls::rustls::{ServerConfig, pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer}};

    let mut cert_reader = BufReader::new(File::open(&tls_conf.cert)?);
    let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<_, _>>()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid cert"))?;

    let mut key_reader = BufReader::new(File::open(&tls_conf.key)?);
    let key = rustls_pemfile::pkcs8_private_keys(&mut key_reader)
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "no private key found"))??;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.secret_pkcs8_der().to_vec()));

    let cfg_builder = if tls_conf.require_client_cert {
        use tokio_rustls::rustls::{server::WebPkiClientVerifier, RootCertStore};
        let mut roots = RootCertStore::empty();
        if let Some(ca_path) = &tls_conf.ca {
            let mut r = BufReader::new(File::open(ca_path)?);
            for c in rustls_pemfile::certs(&mut r) {
                roots.add(c?).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid CA cert"))?;
            }
        } else {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "CA cert required for mTLS"));
        }
        let verifier = WebPkiClientVerifier::builder(roots.into()).build()
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "failed to build client verifier"))?;
        ServerConfig::builder().with_client_cert_verifier(verifier)
    } else {
        ServerConfig::builder().with_no_client_auth()
    };

    let mut cfg = cfg_builder
        .with_single_cert(certs, key)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid cert/key"))?;

    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(cfg)))
}

fn check_auth_with_config(headers: &HashMap<String, String>, path: &str, auth_conf: &AuthConf) -> bool {
    match auth_conf {
        AuthConf::Disabled => true,
        AuthConf::Mtls { .. } => true, // mTLS auth is handled at TLS layer
        AuthConf::Bearer { token } => {
            if let Some(auth_header) = headers.get("authorization") {
                if let Some(provided_token) = auth_header.trim().strip_prefix("Bearer ") {
                    return provided_token.trim() == token;
                }
            }
            false
        }
        AuthConf::Hmac { secret } => {
            if let Some(auth_header) = headers.get("authorization") {
                if let Some(hmac_part) = auth_header.trim().strip_prefix("SB-HMAC ") {
                    return check_hmac_auth_with_secret(hmac_part.trim(), path, secret);
                }
            }
            false
        }
        AuthConf::BearerAndHmac { token, secret } => {
            if let Some(auth_header) = headers.get("authorization") {
                let auth_header = auth_header.trim();
                // Try Bearer token first
                if let Some(provided_token) = auth_header.strip_prefix("Bearer ") {
                    if provided_token.trim() == token {
                        return true;
                    }
                }
                // Try HMAC authentication
                if let Some(hmac_part) = auth_header.strip_prefix("SB-HMAC ") {
                    return check_hmac_auth_with_secret(hmac_part.trim(), path, secret);
                }
            }
            false
        }
    }
}

fn check_hmac_auth_with_secret(hmac_auth: &str, path: &str, secret: &str) -> bool {
    // Parse HMAC auth string: keyId:timestamp:signature
    let parts: Vec<&str> = hmac_auth.split(':').collect();
    if parts.len() != 3 {
        return false;
    }

    let (_key_id, timestamp_str, provided_signature) = (parts[0], parts[1], parts[2]);

    // Parse timestamp
    let timestamp = match timestamp_str.parse::<u64>() {
        Ok(ts) => ts,
        Err(_) => return false,
    };

    // Check time window (5 minutes = 300 seconds)
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if now.abs_diff(timestamp) > 300 {
        return false; // Outside 5-minute window
    }

    // Create message to sign: timestamp||path
    let message = format!("{}{}", timestamp, path);

    // Calculate expected signature using real HMAC-SHA256
    let mut mac = match HmacSha256::new_from_slice(secret.as_bytes()) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(message.as_bytes());
    let expected = mac.finalize().into_bytes();
    let expected_hex = hex::encode(expected);

    // Constant-time comparison
    expected_hex.as_bytes().ct_eq(provided_signature.as_bytes()).into()
}

async fn read_request_head<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<(String, String, HashMap<String, String>)> {
    let mut buf = Vec::with_capacity(2048);
    let mut tmp = [0u8; 512];
    let mut total = 0usize;

    loop {
        let n = tokio::io::AsyncReadExt::read(r, &mut tmp).await?;
        if n == 0 { break; }
        buf.extend_from_slice(&tmp[..n]);
        total += n;

        if total > 8 * 1024 { // 8KB header limit
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "header too large"));
        }

        if buf.windows(4).any(|w| w == b"\r\n\r\n") { break; }
        if buf.len() > 0 && n < tmp.len() { continue; }
    }

    let mut headers = [httparse::EMPTY_HEADER; 32]; // 32 header limit
    let mut req = httparse::Request::new(&mut headers);
    let _ = req.parse(&buf)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad header"))?;

    let method = req.method.unwrap_or("GET").to_string();
    let path = req.path.unwrap_or("/").to_string();
    let mut map = HashMap::new();

    for h in req.headers.iter() {
        if h.name.len() > 64 || h.value.len() > 4096 { // Per-header size limit
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "header line too large"));
        }
        map.insert(h.name.to_ascii_lowercase(), String::from_utf8_lossy(h.value).trim().to_string());
    }

    Ok((method, path, map))
}

async fn read_request_body<R: AsyncRead + Unpin>(r: &mut R, headers: &HashMap<String, String>) -> std::io::Result<bytes::Bytes> {
    let content_length = headers.get("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);

    if content_length == 0 {
        return Ok(bytes::Bytes::new());
    }

    if content_length > 1024 * 1024 { // 1MB limit
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "request body too large"));
    }

    let mut body = vec![0u8; content_length];
    tokio::io::AsyncReadExt::read_exact(r, &mut body).await?;
    Ok(bytes::Bytes::from(body))
}

pub async fn serve(addr: &str) -> std::io::Result<()> {
    let use_mtls = std::env::var("SB_ADMIN_MTLS").ok().as_deref() == Some("1");
    let listener = TcpListener::bind(addr).await?;
    let actual_addr = listener.local_addr()?;

    tracing::info!(addr = %actual_addr, mtls = use_mtls, "admin debug HTTP server listening");

    // Print and optionally write port for test discovery
    println!("ADMIN_LISTEN={}", actual_addr);
    if let Ok(portfile) = std::env::var("SB_ADMIN_PORTFILE") {
        if let Err(e) = std::fs::write(&portfile, actual_addr.to_string()) {
            tracing::warn!(portfile = %portfile, error = %e, "failed to write admin port file");
        }
    }

    let tls_acceptor = if use_mtls { Some(build_tls_acceptor().await?) } else { None };

    loop {
        let (stream, _) = listener.accept().await?;
        let tls = tls_acceptor.clone();
        tokio::spawn(async move {
            let res = async {
                // Upgrade to TLS if enabled
                let mut s: Box<dyn StreamTrait> = if let Some(a) = tls {
                    Box::new(a.accept(stream).await?)
                } else {
                    Box::new(stream)
                };

                // Bounded parsing
                let (method, path, headers) = read_request_head(&mut s).await?;

                // Unified authentication
                if !check_auth(&headers, &path) {
                    // Provide better feedback for mTLS
                    if std::env::var("SB_ADMIN_MTLS").ok().as_deref() == Some("1") {
                        s.write_all(b"HTTP/1.1 401 Unauthorized\r\n").await?;
                        s.write_all(b"WWW-Authenticate: mtls realm=\"sb-admin\"\r\n").await?;
                        s.write_all(b"Content-Type: text/plain\r\n").await?;
                        let body = "mTLS authentication required: valid client certificate needed";
                        s.write_all(format!("Content-Length: {}\r\n\r\n{}", body.len(), body).as_bytes()).await?;
                    } else {
                        respond(&mut s, 401, "text/plain", "Unauthorized").await?;
                    }
                    return Ok::<(), std::io::Error>(());
                }

                // Route to endpoints
                match (method.as_str(), path.as_str()) {
                    ("GET", "/__health")  => endpoints::handle_health(&mut s).await?,
                    ("GET", "/__metrics") => endpoints::metrics::handle(&mut s).await?,
                    ("GET", "/__config") => endpoints::handle_config_get(&mut s).await?,
                    ("PUT", "/__config") => {
                        let body = read_request_body(&mut s, &headers).await?;
                        endpoints::handle_config_put(&mut s, body, &headers).await?;
                    }
                    (_, p) if p.starts_with("/router/geoip") => endpoints::handle_geoip(p, &mut s).await?,
                    (_, p) if p.starts_with("/router/rules/normalize") => endpoints::handle_normalize(p, &mut s).await?,
                    (_, p) if p.starts_with("/subs/") => {
                        #[cfg(any(feature = "subs_http", feature = "subs_clash", feature = "subs_singbox"))]
                        {
                            endpoints::handle_subs(p, &mut s).await?;
                        }
                        #[cfg(not(any(feature = "subs_http", feature = "subs_clash", feature = "subs_singbox")))]
                        {
                            respond_json_error(&mut s, 501, "subscription features not enabled", Some("enable subs_http, subs_clash, or subs_singbox feature")).await?;
                        }
                    }
                    (_, p) if p.starts_with("/router/analyze") => {
                        #[cfg(feature = "sbcore_rules_tool")]
                        {
                            endpoints::handle_analyze(p, &mut s).await?;
                        }
                        #[cfg(not(feature = "sbcore_rules_tool"))]
                        {
                            respond_json_error(&mut s, 501, "sbcore_rules_tool feature not enabled", Some("enable sbcore_rules_tool feature")).await?;
                        }
                    }
                    (_, p) if p.starts_with("/route/dryrun") => {
                        #[cfg(feature = "route_sandbox")]
                        {
                            endpoints::handle_route_dryrun(p, &mut s).await?;
                        }
                        #[cfg(not(feature = "route_sandbox"))]
                        {
                            respond_json_error(&mut s, 501, "route_sandbox feature not enabled", Some("enable route_sandbox feature")).await?;
                        }
                    }
                    _ => respond_json_error(&mut s, 404, "endpoint not found", None).await?,
                }

                Ok::<_, std::io::Error>(())
            }.await;

            if let Err(e) = res {
                tracing::warn!(%e, "admin http error");
            }
        });
    }
}

/// Spawn admin debug server in background (unified signature for run.rs)
pub fn spawn(
    addr: std::net::SocketAddr,
    tls: Option<TlsConf>,
    auth: AuthConf,
) -> std::io::Result<()> {
    let addr_str = addr.to_string();
    tokio::spawn(async move {
        if let Err(e) = serve_with_config(&addr_str, tls, auth).await {
            tracing::error!(error = %e, "admin debug server failed");
        }
    });
    Ok(())
}

async fn serve_with_config(addr: &str, tls_conf: Option<TlsConf>, auth_conf: AuthConf) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let actual_addr = listener.local_addr()?;

    let use_tls = tls_conf.as_ref().map_or(false, |t| t.enabled);
    tracing::info!(addr = %actual_addr, tls = use_tls, auth = auth_conf.mode(), "admin debug HTTP server listening");

    // Print and optionally write port for test discovery
    println!("ADMIN_LISTEN={}", actual_addr);
    if let Ok(portfile) = std::env::var("SB_ADMIN_PORTFILE") {
        if let Err(e) = std::fs::write(&portfile, actual_addr.to_string()) {
            tracing::warn!(portfile = %portfile, error = %e, "failed to write admin port file");
        }
    }

    let tls_acceptor = if let Some(tls) = tls_conf {
        if tls.enabled {
            Some(build_tls_acceptor_from_config(&tls).await?)
        } else {
            None
        }
    } else {
        None
    };

    loop {
        let (stream, _) = listener.accept().await?;
        let tls = tls_acceptor.clone();
        let auth = auth_conf.clone();
        tokio::spawn(async move {
            let res = async {
                // Upgrade to TLS if enabled
                let mut s: Box<dyn StreamTrait> = if let Some(a) = tls {
                    Box::new(a.accept(stream).await?)
                } else {
                    Box::new(stream)
                };

                // Bounded parsing
                let (method, path, headers) = read_request_head(&mut s).await?;

                // Authentication using explicit config
                if !check_auth_with_config(&headers, &path, &auth) {
                    match auth {
                        AuthConf::Mtls { .. } => {
                            s.write_all(b"HTTP/1.1 401 Unauthorized\r\n").await?;
                            s.write_all(b"WWW-Authenticate: mtls realm=\"sb-admin\"\r\n").await?;
                            s.write_all(b"Content-Type: text/plain\r\n").await?;
                            let body = "mTLS authentication required: valid client certificate needed";
                            s.write_all(format!("Content-Length: {}\r\n\r\n{}", body.len(), body).as_bytes()).await?;
                        }
                        _ => {
                            respond(&mut s, 401, "text/plain", "Unauthorized").await?;
                        }
                    }
                    return Ok::<(), std::io::Error>(());
                }

                // Route to endpoints (same as before)
                match (method.as_str(), path.as_str()) {
                    ("GET", "/__health")  => endpoints::handle_health(&mut s).await?,
                    ("GET", "/__metrics") => endpoints::metrics::handle(&mut s).await?,
                    ("GET", "/__config") => endpoints::handle_config_get(&mut s).await?,
                    ("PUT", "/__config") => {
                        let body = read_request_body(&mut s, &headers).await?;
                        endpoints::handle_config_put(&mut s, body, &headers).await?;
                    }
                    (_, p) if p.starts_with("/router/geoip") => endpoints::handle_geoip(p, &mut s).await?,
                    (_, p) if p.starts_with("/router/rules/normalize") => endpoints::handle_normalize(p, &mut s).await?,
                    (_, p) if p.starts_with("/subs/") => {
                        #[cfg(any(feature = "subs_http", feature = "subs_clash", feature = "subs_singbox"))]
                        {
                            endpoints::handle_subs(p, &mut s).await?;
                        }
                        #[cfg(not(any(feature = "subs_http", feature = "subs_clash", feature = "subs_singbox")))]
                        {
                            respond_json_error(&mut s, 501, "subscription features not enabled", Some("enable subs_http, subs_clash, or subs_singbox feature")).await?;
                        }
                    }
                    (_, p) if p.starts_with("/router/analyze") => {
                        #[cfg(feature = "sbcore_rules_tool")]
                        {
                            endpoints::handle_analyze(p, &mut s).await?;
                        }
                        #[cfg(not(feature = "sbcore_rules_tool"))]
                        {
                            respond_json_error(&mut s, 501, "sbcore_rules_tool feature not enabled", Some("enable sbcore_rules_tool feature")).await?;
                        }
                    }
                    (_, p) if p.starts_with("/route/dryrun") => {
                        #[cfg(feature = "route_sandbox")]
                        {
                            endpoints::handle_route_dryrun(p, &mut s).await?;
                        }
                        #[cfg(not(feature = "route_sandbox"))]
                        {
                            respond_json_error(&mut s, 501, "route_sandbox feature not enabled", Some("enable route_sandbox feature")).await?;
                        }
                    }
                    _ => respond_json_error(&mut s, 404, "endpoint not found", None).await?,
                }

                Ok::<_, std::io::Error>(())
            }.await;

            if let Err(e) = res {
                tracing::warn!(%e, "admin http error");
            }
        });
    }
}

pub async fn serve_plain(addr: &str) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let actual_addr = listener.local_addr()?;
    tracing::info!(addr = %actual_addr, "admin debug HTTP server listening");

    // Print and optionally write port for test discovery
    println!("ADMIN_LISTEN={}", actual_addr);
    if let Ok(portfile) = std::env::var("SB_ADMIN_PORTFILE") {
        if let Err(e) = std::fs::write(&portfile, actual_addr.to_string()) {
            tracing::warn!(portfile = %portfile, error = %e, "failed to write admin port file");
        }
    }

    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream).await {
                tracing::warn!(error = %e, "admin debug connection error");
            }
        });
    }
}

async fn handle_connection(mut stream: TcpStream) -> std::io::Result<()> {
    START.get_or_init(std::time::Instant::now);
    let mut reader = BufReader::new(&mut stream);
    let mut request_line = String::new();

    reader.read_line(&mut request_line).await?;
    let parts: Vec<&str> = request_line.trim().split_whitespace().collect();

    if parts.len() < 2 || parts[0] != "GET" {
        respond_json_error(
            &mut stream,
            400,
            "Only GET requests supported",
            None,
        )
        .await?;
        return Ok(());
    }

    let path_q = parts[1];

    // Parse headers
    let mut headers = HashMap::new();
    let mut line = String::new();
    loop {
        line.clear();
        reader.read_line(&mut line).await?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break; // End of headers
        }

        if let Some((key, value)) = trimmed.split_once(':') {
            headers.insert(key.trim().to_lowercase(), value.trim().to_string());
        }
    }

    tracing::debug!(path = %path_q, "admin debug request");

    // Route to appropriate endpoint
    if path_q == "/__health" {
        if !check_auth(&headers, path_q) {
            return respond(
                &mut stream,
                401,
                "text/plain",
                "Unauthorized"
            ).await;
        }
        endpoints::handle_health(&mut stream).await?;
    } else if path_q == "/__metrics" {
        if !check_auth(&headers, path_q) {
            return respond(
                &mut stream,
                401,
                "text/plain",
                "Unauthorized"
            ).await;
        }
        endpoints::metrics::handle(&mut stream).await?;
    } else if path_q.starts_with("/router/geoip") {
        endpoints::handle_geoip(path_q, &mut stream).await?;
    } else if path_q.starts_with("/router/rules/normalize") {
        endpoints::handle_normalize(path_q, &mut stream).await?;
    } else if path_q.starts_with("/subs/") {
        #[cfg(any(
            feature = "subs_http",
            feature = "subs_clash",
            feature = "subs_singbox"
        ))]
        {
            endpoints::handle_subs(path_q, &mut stream).await?;
        }
        #[cfg(not(any(
            feature = "subs_http",
            feature = "subs_clash",
            feature = "subs_singbox"
        )))]
        {
            respond_json_error(
                &mut stream,
                501,
                "subscription features not enabled",
                Some("enable subs_http, subs_clash, or subs_singbox feature"),
            )
            .await?;
        }
    } else if path_q.starts_with("/router/analyze") {
        #[cfg(feature = "sbcore_rules_tool")]
        {
            endpoints::handle_analyze(path_q, &mut stream).await?;
        }
        #[cfg(not(feature = "sbcore_rules_tool"))]
        {
            respond_json_error(
                &mut stream,
                501,
                "sbcore_rules_tool feature not enabled",
                Some("enable sbcore_rules_tool feature"),
            )
            .await?;
        }
    } else if path_q.starts_with("/route/dryrun") {
        #[cfg(feature = "route_sandbox")]
        {
            endpoints::handle_route_dryrun(path_q, &mut stream).await?;
        }
        #[cfg(not(feature = "route_sandbox"))]
        {
            respond_json_error(
                &mut stream,
                501,
                "route_sandbox feature not enabled",
                Some("enable route_sandbox feature"),
            )
            .await?;
        }
    } else {
        respond_json_error(&mut stream, 404, "endpoint not found", None).await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_auth_disabled() {
        std::env::set_var("SB_ADMIN_NO_AUTH", "1");
        let headers = HashMap::new();
        assert!(check_auth(&headers, "/test"));
        std::env::remove_var("SB_ADMIN_NO_AUTH");
    }

    #[test]
    fn test_bearer_auth_success() {
        std::env::set_var("SB_ADMIN_TOKEN", "secret123");
        let mut headers = HashMap::new();
        headers.insert("authorization".to_string(), "Bearer secret123".to_string());
        assert!(check_auth(&headers, "/test"));
        std::env::remove_var("SB_ADMIN_TOKEN");
    }

    #[test]
    fn test_bearer_auth_failure() {
        std::env::set_var("SB_ADMIN_TOKEN", "secret123");
        let mut headers = HashMap::new();
        headers.insert("authorization".to_string(), "Bearer wrongtoken".to_string());
        assert!(!check_auth(&headers, "/test"));
        std::env::remove_var("SB_ADMIN_TOKEN");
    }

    #[test]
    fn test_bearer_auth_with_whitespace() {
        std::env::set_var("SB_ADMIN_TOKEN", "secret123");
        let mut headers = HashMap::new();
        headers.insert("authorization".to_string(), "  Bearer   secret123  ".to_string());
        assert!(check_auth(&headers, "/test"));
        std::env::remove_var("SB_ADMIN_TOKEN");
    }

    #[test]
    fn test_hmac_auth_format_validation() {
        std::env::set_var("SB_ADMIN_HMAC_SECRET", "testsecret");
        let mut headers = HashMap::new();

        // Invalid format: too few parts
        headers.insert("authorization".to_string(), "SB-HMAC admin:123456".to_string());
        assert!(!check_auth(&headers, "/test"));

        // Invalid format: too many parts
        headers.insert("authorization".to_string(), "SB-HMAC admin:123456:sig:extra".to_string());
        assert!(!check_auth(&headers, "/test"));

        // Invalid timestamp
        headers.insert("authorization".to_string(), "SB-HMAC admin:notanumber:sig".to_string());
        assert!(!check_auth(&headers, "/test"));

        std::env::remove_var("SB_ADMIN_HMAC_SECRET");
    }

    #[test]
    fn test_hmac_auth_time_window() {
        use std::time::{SystemTime, UNIX_EPOCH};

        std::env::set_var("SB_ADMIN_HMAC_SECRET", "testsecret");
        let mut headers = HashMap::new();

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        // Too old (more than 5 minutes)
        let old_timestamp = now - 400; // 400 seconds ago
        headers.insert("authorization".to_string(), format!("SB-HMAC admin:{}:somesig", old_timestamp));
        assert!(!check_auth(&headers, "/test"));

        // Future timestamp (more than 5 minutes ahead)
        let future_timestamp = now + 400; // 400 seconds in future
        headers.insert("authorization".to_string(), format!("SB-HMAC admin:{}:somesig", future_timestamp));
        assert!(!check_auth(&headers, "/test"));

        std::env::remove_var("SB_ADMIN_HMAC_SECRET");
    }

    #[test]
    fn test_hmac_auth_signature_verification() {
        use std::time::{SystemTime, UNIX_EPOCH};

        std::env::set_var("SB_ADMIN_HMAC_SECRET", "testsecret");
        let mut headers = HashMap::new();

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let path = "/test";

        // Generate correct signature using real HMAC-SHA256
        let message = format!("{}{}", now, path);
        let mut mac = HmacSha256::new_from_slice("testsecret".as_bytes()).unwrap();
        mac.update(message.as_bytes());
        let expected = mac.finalize().into_bytes();
        let correct_signature = hex::encode(expected);

        // Valid signature
        headers.insert("authorization".to_string(), format!("SB-HMAC admin:{}:{}", now, correct_signature));
        assert!(check_auth(&headers, path));

        // Invalid signature
        headers.insert("authorization".to_string(), format!("SB-HMAC admin:{}:invalidsig", now));
        assert!(!check_auth(&headers, path));

        std::env::remove_var("SB_ADMIN_HMAC_SECRET");
    }

    #[test]
    fn test_no_auth_configured() {
        // Clear all auth env vars
        std::env::remove_var("SB_ADMIN_TOKEN");
        std::env::remove_var("SB_ADMIN_HMAC_SECRET");
        std::env::remove_var("SB_ADMIN_NO_AUTH");

        let headers = HashMap::new();
        assert!(check_auth(&headers, "/test")); // Should allow access when no auth is configured
    }

    #[test]
    fn test_get_auth_mode() {
        // Test disabled mode
        std::env::set_var("SB_ADMIN_NO_AUTH", "1");
        assert_eq!(get_auth_mode(), "disabled");
        std::env::remove_var("SB_ADMIN_NO_AUTH");

        // Test mTLS mode
        std::env::set_var("SB_ADMIN_MTLS", "1");
        assert_eq!(get_auth_mode(), "mtls");
        std::env::remove_var("SB_ADMIN_MTLS");

        // Test bearer+hmac mode
        std::env::set_var("SB_ADMIN_TOKEN", "token123");
        std::env::set_var("SB_ADMIN_HMAC_SECRET", "secret123");
        assert_eq!(get_auth_mode(), "bearer+hmac");

        // Test hmac only mode
        std::env::remove_var("SB_ADMIN_TOKEN");
        assert_eq!(get_auth_mode(), "hmac");

        // Test bearer only mode
        std::env::remove_var("SB_ADMIN_HMAC_SECRET");
        std::env::set_var("SB_ADMIN_TOKEN", "token123");
        assert_eq!(get_auth_mode(), "bearer");

        // Test no auth mode
        std::env::remove_var("SB_ADMIN_TOKEN");
        assert_eq!(get_auth_mode(), "none");
    }

    #[test]
    fn test_hmac_auth_different_paths() {
        use std::time::{SystemTime, UNIX_EPOCH};

        std::env::set_var("SB_ADMIN_HMAC_SECRET", "testsecret");
        let mut headers = HashMap::new();

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        // Generate signature for path1
        let path1 = "/health";
        let message1 = format!("{}{}", now, path1);
        let mut mac1 = HmacSha256::new_from_slice("testsecret".as_bytes()).unwrap();
        mac1.update(message1.as_bytes());
        let sig1 = hex::encode(mac1.finalize().into_bytes());

        // Generate signature for path2
        let path2 = "/metrics";
        let message2 = format!("{}{}", now, path2);
        let mut mac2 = HmacSha256::new_from_slice("testsecret".as_bytes()).unwrap();
        mac2.update(message2.as_bytes());
        let sig2 = hex::encode(mac2.finalize().into_bytes());

        // Signature for path1 should work only for path1
        headers.insert("authorization".to_string(), format!("SB-HMAC admin:{}:{}", now, sig1));
        assert!(check_auth(&headers, path1));
        assert!(!check_auth(&headers, path2)); // Should fail for different path

        // Signature for path2 should work only for path2
        headers.insert("authorization".to_string(), format!("SB-HMAC admin:{}:{}", now, sig2));
        assert!(check_auth(&headers, path2));
        assert!(!check_auth(&headers, path1)); // Should fail for different path

        std::env::remove_var("SB_ADMIN_HMAC_SECRET");
    }
}
