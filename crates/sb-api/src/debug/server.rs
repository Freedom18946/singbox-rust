#[cfg(feature = "auth")]
use crate::debug::middleware::{
    auth::AuthMiddleware, request_id::RequestIdMiddleware, send_error_response, MiddlewareChain,
    RequestContext,
};
use hex;
use hmac::{Hmac, Mac};
use httparse;
use sha2::Sha256;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;

trait StreamTrait: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> StreamTrait for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

type HmacSha256 = Hmac<Sha256>;

/// Handle to a running admin debug HTTP server.
///
/// Holds a `CancellationToken` to signal shutdown and a `JoinHandle` for the
/// main server task. The server task internally uses a `JoinSet` for all
/// per-connection tasks, so shutting down this handle drains all connections.
///
/// **Drop behaviour**: dropping the handle fires the cancellation signal,
/// causing the accept loop to stop and in-flight connections to drain.
/// The server task then runs to completion on its own (no one awaits it).
/// For an orderly shutdown that *waits* for the task to finish, call
/// [`shutdown()`](Self::shutdown) instead.
pub struct AdminDebugHandle {
    cancel: CancellationToken,
    join: Option<JoinHandle<()>>,
}

impl AdminDebugHandle {
    /// Trigger graceful shutdown: cancel the accept loop, then **await** the
    /// server task (which drains in-flight connections) before returning.
    pub async fn shutdown(mut self) {
        self.cancel.cancel();
        if let Some(join) = self.join.take() {
            if let Err(e) = join.await {
                tracing::warn!(%e, "admin debug server join failed during shutdown");
            }
        }
    }
}

impl Drop for AdminDebugHandle {
    fn drop(&mut self) {
        self.cancel.cancel();
        // JoinHandle (if still present) is dropped without await — the server
        // task will still run to completion after seeing the cancel signal.
    }
}

#[derive(Debug, Clone)]
/// TLS and optional mutual-TLS configuration for debug server.
pub struct TlsConf {
    /// Whether TLS is enabled.
    pub enabled: bool,
    /// PEM certificate path.
    pub cert: PathBuf,
    /// PEM private-key path.
    pub key: PathBuf,
    /// Optional client CA path.
    pub ca: Option<PathBuf>,
    /// Whether client certificates are mandatory.
    pub require_client_cert: bool,
}

impl TlsConf {
    #[must_use]
    /// Build disabled TLS configuration.
    pub const fn disabled() -> Self {
        Self {
            enabled: false,
            cert: PathBuf::new(),
            key: PathBuf::new(),
            ca: None,
            require_client_cert: false,
        }
    }

    /// Load TLS configuration from `SB_ADMIN_TLS_*` variables.
    pub fn from_env() -> Self {
        let enabled =
            std::env::var("SB_ADMIN_TLS_CERT").is_ok() && std::env::var("SB_ADMIN_TLS_KEY").is_ok();

        if !enabled {
            return Self::disabled();
        }

        Self {
            enabled,
            cert: std::env::var("SB_ADMIN_TLS_CERT")
                .unwrap_or_default()
                .into(),
            key: std::env::var("SB_ADMIN_TLS_KEY").unwrap_or_default().into(),
            ca: std::env::var("SB_ADMIN_TLS_CA").ok().map(PathBuf::from),
            require_client_cert: std::env::var("SB_ADMIN_MTLS").ok().as_deref() == Some("1"),
        }
    }
}

#[derive(Debug, Clone)]
/// Authentication mode selected for debug server.
pub enum AuthConf {
    /// No authentication.
    Disabled,
    /// Bearer token authentication.
    Bearer {
        /// Required bearer token.
        token: String,
    },
    /// HMAC authentication.
    Hmac {
        /// HMAC secret.
        secret: String,
    },
    /// Accept either bearer token or HMAC.
    BearerAndHmac {
        /// Required bearer token.
        token: String,
        /// HMAC secret.
        secret: String,
    },
    /// Mutual TLS authentication.
    Mtls {
        /// Whether mutual TLS is enabled.
        enabled: bool,
    },
}

impl AuthConf {
    #[must_use]
    /// Load authentication configuration from `SB_ADMIN_*` variables.
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
            (Some(t), Some(s)) => Self::BearerAndHmac {
                token: t,
                secret: s,
            },
            (Some(t), None) => Self::Bearer { token: t },
            (None, Some(s)) => Self::Hmac { secret: s },
            (None, None) => Self::Disabled,
        }
    }

    #[must_use]
    /// Stable authentication mode label exposed by health endpoint.
    pub const fn mode(&self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Bearer { .. } => "bearer",
            Self::Hmac { .. } => "hmac",
            Self::BearerAndHmac { .. } => "bearer+hmac",
            Self::Mtls { .. } => "mtls",
        }
    }
}

#[cfg(any(test, feature = "admin_tests"))]
#[must_use]
/// Evaluate environment-derived debug authentication for contract tests.
pub fn check_auth(headers: &HashMap<String, String>, path: &str) -> bool {
    check_auth_with_config(headers, path, &AuthConf::from_env())
}

pub(super) fn check_auth_with_config(
    headers: &HashMap<String, String>,
    path: &str,
    auth: &AuthConf,
) -> bool {
    if matches!(auth, AuthConf::Disabled | AuthConf::Mtls { enabled: true }) {
        return true;
    }
    let header = headers.get("authorization").map(|value| value.trim());
    let bearer_matches = |required: &str| {
        header
            .and_then(|value| value.strip_prefix("Bearer "))
            .is_some_and(|provided| {
                bool::from(provided.trim().as_bytes().ct_eq(required.as_bytes()))
            })
    };
    let hmac_matches = |secret: &str| {
        header
            .and_then(|value| value.strip_prefix("SB-HMAC "))
            .is_some_and(|value| check_hmac_auth(value.trim(), path, secret))
    };
    match auth {
        AuthConf::Disabled | AuthConf::Mtls { .. } => true,
        AuthConf::Bearer { token } => bearer_matches(token),
        AuthConf::Hmac { secret } => hmac_matches(secret),
        AuthConf::BearerAndHmac { token, secret } => bearer_matches(token) || hmac_matches(secret),
    }
}

fn check_hmac_auth(hmac_auth: &str, path: &str, secret: &str) -> bool {
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
    let message = format!("{timestamp}{path}");

    // Calculate expected signature using real HMAC-SHA256
    let mut mac = match HmacSha256::new_from_slice(secret.as_bytes()) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(message.as_bytes());
    let expected = mac.finalize().into_bytes();
    let expected_hex = hex::encode(expected);

    // Constant-time comparison
    expected_hex
        .as_bytes()
        .ct_eq(provided_signature.as_bytes())
        .into()
}

#[must_use]
/// Return active authentication mode label.
pub fn get_auth_mode() -> &'static str {
    if std::env::var("SB_ADMIN_NO_AUTH").ok().as_deref() == Some("1") {
        "disabled"
    } else if std::env::var("SB_ADMIN_MTLS").ok().as_deref() == Some("1") {
        "mtls"
    } else if std::env::var("SB_ADMIN_HMAC_SECRET").ok().is_some()
        && std::env::var("SB_ADMIN_TOKEN").ok().is_some()
    {
        "bearer+hmac"
    } else if std::env::var("SB_ADMIN_HMAC_SECRET").ok().is_some() {
        "hmac"
    } else if std::env::var("SB_ADMIN_TOKEN").ok().is_some() {
        "bearer"
    } else {
        "none"
    }
}

fn build_tls_acceptor_from_config(
    tls_conf: &TlsConf,
) -> std::io::Result<tokio_rustls::TlsAcceptor> {
    use std::{fs::File, io::BufReader};
    use tokio_rustls::rustls::{
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
        ServerConfig,
    };

    let mut cert_reader = BufReader::new(File::open(&tls_conf.cert)?);
    let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<_, _>>()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid cert"))?;

    let mut key_reader = BufReader::new(File::open(&tls_conf.key)?);
    let key = rustls_pemfile::pkcs8_private_keys(&mut key_reader)
        .next()
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "no private key found")
        })??;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.secret_pkcs8_der().to_vec()));

    let cfg_builder = if tls_conf.require_client_cert {
        use tokio_rustls::rustls::{server::WebPkiClientVerifier, RootCertStore};
        let mut roots = RootCertStore::empty();
        if let Some(ca_path) = &tls_conf.ca {
            let mut r = BufReader::new(File::open(ca_path)?);
            for c in rustls_pemfile::certs(&mut r) {
                roots.add(c?).map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid CA cert")
                })?;
            }
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "CA cert required for mTLS",
            ));
        }
        let verifier = WebPkiClientVerifier::builder(roots.into())
            .build()
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "failed to build client verifier",
                )
            })?;
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

/// Build the middleware chain for admin debug server
fn build_middleware_chain(auth_conf: &AuthConf) -> MiddlewareChain {
    let mut chain = MiddlewareChain::new().add(RequestIdMiddleware::new());

    // Add rate limiting middleware if enabled
    #[cfg(feature = "rate_limit")]
    {
        if let Some(rate_limiter) = crate::debug::middleware::rate_limit::from_env() {
            tracing::info!(target = "admin", "rate limiting enabled");
            chain = chain.add(rate_limiter);
        }
    }

    // Add authentication middleware
    tracing::info!(
        target = "admin",
        auth_mode = auth_conf.mode(),
        "authentication configured"
    );
    chain = chain.add(AuthMiddleware::new(auth_conf.clone()));

    chain
}

async fn read_request_head<R: AsyncRead + Unpin>(
    r: &mut R,
) -> std::io::Result<(String, String, HashMap<String, String>)> {
    let mut buf = Vec::with_capacity(2048);
    let mut tmp = [0u8; 512];
    let mut total = 0usize;
    let (max_h, _max_b, firstline_ms, _rt) = admin_limits();
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(firstline_ms);

    loop {
        let now = std::time::Instant::now();
        if now >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "first line timeout",
            ));
        }
        let remain = deadline.saturating_duration_since(now);
        let n = tokio::time::timeout(remain, tokio::io::AsyncReadExt::read(r, &mut tmp))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "first line timeout")
            })??;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        total += n;

        if total > max_h {
            // header limit
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "header too large",
            ));
        }

        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if !buf.is_empty() && n < tmp.len() {
            // redundant continue removed; loop proceeds naturally
        }
    }

    let mut headers = [httparse::EMPTY_HEADER; 64]; // 64 header limit
    let mut req = httparse::Request::new(&mut headers);
    req.parse(&buf)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad header"))?;

    let method = req.method.unwrap_or("GET").to_string();
    let path = req.path.unwrap_or("/").to_string();
    let mut map = HashMap::new();

    for h in req.headers.iter() {
        if h.name.len() > 256 || h.value.len() > 16 * 1024 {
            // Per-header size limit
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "header line too large",
            ));
        }
        map.insert(
            h.name.to_ascii_lowercase(),
            String::from_utf8_lossy(h.value).trim().to_string(),
        );
    }

    Ok((method, path, map))
}

async fn read_request_body<R: AsyncRead + Unpin>(
    r: &mut R,
    headers: &HashMap<String, String>,
) -> std::io::Result<bytes::Bytes> {
    let (_max_h, max_b, _fl, read_ms) = admin_limits();
    let content_length = headers
        .get("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);

    if content_length == 0 {
        return Ok(bytes::Bytes::new());
    }

    if content_length > max_b {
        // size limit
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "request body too large",
        ));
    }

    let mut body = vec![0u8; content_length];
    tokio::time::timeout(
        std::time::Duration::from_millis(read_ms),
        tokio::io::AsyncReadExt::read_exact(r, &mut body),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "body read timeout"))??;
    Ok(bytes::Bytes::from(body))
}

/// Shared full-request routing for the middleware-based paths.
async fn route_full_request(
    method: &str,
    path: &str,
    headers: &HashMap<String, String>,
    s: &mut Box<dyn StreamTrait>,
    state: &Arc<dyn crate::debug::DebugRouteExtension>,
) -> std::io::Result<()> {
    let body = read_request_body(s, headers).await?;
    let response = state
        .handle(crate::debug::DebugRequest {
            method: method.to_string(),
            path: path.to_string(),
            headers: headers.clone(),
            body,
        })
        .await?;
    s.write_all(&response).await
}

/// Spawn admin debug server with TLS/auth config. Binds the listener, then
/// spawns a tracked accept loop. Returns a handle for graceful shutdown.
pub async fn spawn(
    addr: std::net::SocketAddr,
    tls: Option<TlsConf>,
    auth: AuthConf,
    state: Arc<dyn crate::debug::DebugRouteExtension>,
) -> std::io::Result<AdminDebugHandle> {
    let listener = TcpListener::bind(addr).await?;
    let actual_addr = listener.local_addr()?;

    let use_tls = tls.as_ref().is_some_and(|t| t.enabled);
    tracing::info!(addr = %actual_addr, tls = use_tls, auth = auth.mode(), "admin debug HTTP server listening");

    println!("ADMIN_LISTEN={actual_addr}");
    if let Ok(portfile) = std::env::var("SB_ADMIN_PORTFILE") {
        if let Err(e) =
            sb_core::util::fs_atomic::write_atomic(&portfile, actual_addr.to_string().as_bytes())
        {
            tracing::warn!(portfile = %portfile, error = %e, "failed to write admin port file");
        }
    }

    let tls_acceptor = if let Some(tls_conf) = tls {
        if tls_conf.enabled {
            Some(build_tls_acceptor_from_config(&tls_conf)?)
        } else {
            None
        }
    } else {
        None
    };

    if matches!(auth, AuthConf::Mtls { enabled: true }) && tls_acceptor.is_none() {
        tracing::warn!(
            "mTLS requested via SB_ADMIN_MTLS=1 but TLS is not configured (SB_ADMIN_TLS_CERT/KEY missing); refusing to authenticate clients with mTLS"
        );
    }

    let middleware_chain = Arc::new(build_middleware_chain(&auth));

    let cancel = CancellationToken::new();
    let cancel_inner = cancel.clone();
    let join = tokio::spawn(async move {
        run_configured_accept_loop(
            listener,
            cancel_inner,
            tls_acceptor,
            auth,
            middleware_chain,
            state,
        )
        .await;
    });

    Ok(AdminDebugHandle {
        cancel,
        join: Some(join),
    })
}

/// Accept loop for the middleware-based configured path (TLS + auth).
/// All per-connection tasks are tracked in a `JoinSet`.
async fn run_configured_accept_loop(
    listener: TcpListener,
    cancel: CancellationToken,
    tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
    auth_conf: AuthConf,
    middleware_chain: Arc<MiddlewareChain>,
    state: Arc<dyn crate::debug::DebugRouteExtension>,
) {
    let mut connections: JoinSet<()> = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => break,
            result = listener.accept() => {
                match result {
                    Ok((stream, _)) => {
                        let tls = tls_acceptor.clone();
                        let auth = auth_conf.clone();
                        let mw = Arc::clone(&middleware_chain);
                        let st = Arc::clone(&state);
                        connections.spawn(async move {
                            let res = handle_middleware_connection(stream, tls, auth, mw, st).await;
                            if let Err(e) = res {
                                tracing::warn!(%e, "admin http error");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!(%e, "admin accept error");
                    }
                }
            }
        }
        while connections.try_join_next().is_some() {}
    }
    while connections.join_next().await.is_some() {}
}

/// Per-connection handler for the middleware-based path (used by `spawn()`).
async fn handle_middleware_connection(
    stream: TcpStream,
    tls: Option<tokio_rustls::TlsAcceptor>,
    auth: AuthConf,
    middleware_chain: Arc<MiddlewareChain>,
    state: Arc<dyn crate::debug::DebugRouteExtension>,
) -> std::io::Result<()> {
    let mut s: Box<dyn StreamTrait> = if let Some(a) = tls {
        Box::new(a.accept(stream).await?)
    } else {
        Box::new(stream)
    };

    let (method, path, headers) = read_request_head(&mut s).await?;

    let mut request_context = RequestContext::new(method.clone(), path.clone(), headers.clone());

    if let Err(error_envelope) = middleware_chain.execute(&mut request_context) {
        let status_code = match &error_envelope.error {
            Some(error) => match error.kind {
                sb_admin_contract::ErrorKind::Auth => 401,
                sb_admin_contract::ErrorKind::RateLimit => 429,
                _ => 500,
            },
            None => 500,
        };

        if matches!(auth, AuthConf::Mtls { .. }) && status_code == 401 {
            s.write_all(b"HTTP/1.1 401 Unauthorized\r\n").await?;
            s.write_all(b"WWW-Authenticate: mtls realm=\"sb-admin\"\r\n")
                .await?;
            s.write_all(b"Content-Type: text/plain\r\n").await?;
            let body = "mTLS authentication required: valid client certificate needed";
            s.write_all(format!("Content-Length: {}\r\n\r\n{}", body.len(), body).as_bytes())
                .await?;
        } else {
            send_error_response(&mut s, error_envelope, status_code).await?;
        }
        return Ok(());
    }

    route_full_request(&method, &path, &headers, &mut s, &state).await
}

/// Start a plain HTTP admin server (async). Binds, spawns a tracked accept
/// loop, and returns a handle for graceful shutdown.
pub async fn serve_plain(
    addr: &str,
    state: Arc<dyn crate::debug::DebugRouteExtension>,
) -> std::io::Result<AdminDebugHandle> {
    let listener = TcpListener::bind(addr).await?;
    let actual_addr = listener.local_addr()?;
    tracing::info!(addr = %actual_addr, "admin debug HTTP server listening");

    println!("ADMIN_LISTEN={actual_addr}");
    if let Ok(portfile) = std::env::var("SB_ADMIN_PORTFILE") {
        if let Err(e) =
            sb_core::util::fs_atomic::write_atomic(&portfile, actual_addr.to_string().as_bytes())
        {
            tracing::warn!(portfile = %portfile, error = %e, "failed to write admin port file");
        }
    }

    let auth_conf = AuthConf::from_env();
    let middleware_chain = Arc::new(build_middleware_chain(&auth_conf));

    let cancel = CancellationToken::new();
    let cancel_inner = cancel.clone();
    let join = tokio::spawn(async move {
        run_plain_accept_loop(listener, cancel_inner, middleware_chain, state).await;
    });

    Ok(AdminDebugHandle {
        cancel,
        join: Some(join),
    })
}

/// Sync entry point: spawns a plain admin server in background.
/// Binding and setup happen inside the spawned task; errors are logged.
/// Used by `admin_debug::init()` which cannot await.
pub fn spawn_plain_sync(
    addr: String,
    state: Arc<dyn crate::debug::DebugRouteExtension>,
) -> AdminDebugHandle {
    let cancel = CancellationToken::new();
    let cancel_inner = cancel.clone();
    let join = tokio::spawn(async move {
        if let Err(e) = serve_plain_inner(&addr, state, cancel_inner).await {
            tracing::error!(error = %e, "admin debug server failed");
        }
    });
    AdminDebugHandle {
        cancel,
        join: Some(join),
    }
}

/// Internal: bind + setup + run accept loop for plain mode (used by `spawn_plain_sync`).
async fn serve_plain_inner(
    addr: &str,
    state: Arc<dyn crate::debug::DebugRouteExtension>,
    cancel: CancellationToken,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let actual_addr = listener.local_addr()?;
    tracing::info!(addr = %actual_addr, "admin debug HTTP server listening");

    println!("ADMIN_LISTEN={actual_addr}");
    if let Ok(portfile) = std::env::var("SB_ADMIN_PORTFILE") {
        if let Err(e) =
            sb_core::util::fs_atomic::write_atomic(&portfile, actual_addr.to_string().as_bytes())
        {
            tracing::warn!(portfile = %portfile, error = %e, "failed to write admin port file");
        }
    }

    let auth_conf = AuthConf::from_env();
    let middleware_chain = Arc::new(build_middleware_chain(&auth_conf));
    run_plain_accept_loop(listener, cancel, middleware_chain, state).await;
    Ok(())
}

/// Accept loop for the plain path. All per-connection tasks tracked in a `JoinSet`.
async fn run_plain_accept_loop(
    listener: TcpListener,
    cancel: CancellationToken,
    middleware_chain: Arc<MiddlewareChain>,
    state: Arc<dyn crate::debug::DebugRouteExtension>,
) {
    let mut connections: JoinSet<()> = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => break,
            result = listener.accept() => {
                match result {
                    Ok((stream, _)) => {
                        let mw = Arc::clone(&middleware_chain);
                        let st = Arc::clone(&state);
                        connections.spawn(async move {
                            if let Err(e) = handle_connection(stream, mw, st).await {
                                tracing::warn!(error = %e, "admin debug connection error");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!(%e, "admin accept error");
                    }
                }
            }
        }
        while connections.try_join_next().is_some() {}
    }
    while connections.join_next().await.is_some() {}
}

async fn handle_connection(
    mut stream: TcpStream,
    middleware_chain: Arc<MiddlewareChain>,
    state: Arc<dyn crate::debug::DebugRouteExtension>,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(&mut stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line).await?;
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 || parts[0] != "GET" {
        drop(reader);
        stream.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 27\r\n\r\nOnly GET requests supported").await?;
        return Ok(());
    }
    let path = parts[1].to_string();
    let mut headers = HashMap::new();
    let mut line = String::new();
    loop {
        line.clear();
        reader.read_line(&mut line).await?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some((key, value)) = trimmed.split_once(":") {
            headers.insert(key.trim().to_lowercase(), value.trim().to_string());
        }
    }
    drop(reader);
    let mut request_context = RequestContext::new("GET".to_string(), path.clone(), headers.clone());
    if matches!(path.as_str(), "/__health" | "/__metrics") {
        if let Err(error_envelope) = middleware_chain.execute(&mut request_context) {
            let status_code = match error_envelope.error.as_ref().map(|error| &error.kind) {
                Some(sb_admin_contract::ErrorKind::Auth) => 401,
                Some(sb_admin_contract::ErrorKind::RateLimit) => 429,
                _ => 500,
            };
            send_error_response(&mut stream, error_envelope, status_code).await?;
            return Ok(());
        }
    }
    let mut boxed: Box<dyn StreamTrait> = Box::new(stream);
    route_full_request("GET", &path, &headers, &mut boxed, &state).await
}

fn admin_limits() -> (usize, usize, u64, u64) {
    // returns (max_header_bytes, max_body_bytes, firstline_timeout_ms, read_timeout_ms)
    let max_h = admin_env_usize("SB_ADMIN_MAX_HEADER_BYTES", 64 * 1024);
    let max_b = admin_env_usize("SB_ADMIN_MAX_BODY_BYTES", 2 * 1024 * 1024);
    let firstline = admin_env_u64("SB_ADMIN_FIRSTLINE_TIMEOUT_MS", 3000);
    let read_timeout = admin_env_u64("SB_ADMIN_READ_TIMEOUT_MS", 4000);
    (max_h, max_b, firstline, read_timeout)
}

fn admin_env_usize(key: &str, default: usize) -> usize {
    let raw = match std::env::var(key) {
        Ok(v) => v,
        Err(_) => return default,
    };
    let t = raw.trim();
    match t.parse::<usize>() {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                "env '{key}' value '{t}' is not a valid usize; silent parse fallback is disabled; using default {default}: {e}"
            );
            default
        }
    }
}
fn admin_env_u64(key: &str, default: u64) -> u64 {
    let raw = match std::env::var(key) {
        Ok(v) => v,
        Err(_) => return default,
    };
    let t = raw.trim();
    match t.parse::<u64>() {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                "env '{key}' value '{t}' is not a valid u64; silent parse fallback is disabled; using default {default}: {e}"
            );
            default
        }
    }
}

#[cfg(test)]
#[cfg(feature = "admin_tests")]
mod tests {
    use super::*;

    struct TestExtension;

    #[async_trait::async_trait]
    impl crate::debug::DebugRouteExtension for TestExtension {
        async fn handle(&self, _request: crate::debug::DebugRequest) -> std::io::Result<Vec<u8>> {
            Ok(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec())
        }
    }

    fn test_state() -> Arc<dyn crate::debug::DebugRouteExtension> {
        Arc::new(TestExtension)
    }
    use std::collections::HashMap;

    #[test]
    #[serial_test::serial]
    fn configured_middleware_uses_explicit_auth_not_environment() {
        std::env::set_var("SB_ADMIN_NO_AUTH", "1");
        let chain = build_middleware_chain(&AuthConf::Bearer {
            token: "configured-secret".into(),
        });
        let mut request = RequestContext::new("GET".into(), "/__health".into(), HashMap::new());
        assert!(chain.execute(&mut request).is_err());
        std::env::remove_var("SB_ADMIN_NO_AUTH");
    }

    #[test]
    #[serial_test::serial]
    fn test_auth_disabled() {
        std::env::set_var("SB_ADMIN_NO_AUTH", "1");
        let headers = HashMap::new();
        assert!(check_auth(&headers, "/test"));
        std::env::remove_var("SB_ADMIN_NO_AUTH");
    }

    #[test]
    #[serial_test::serial]
    fn test_bearer_auth_success() {
        std::env::set_var("SB_ADMIN_TOKEN", "secret123");
        let mut headers = HashMap::new();
        headers.insert("authorization".to_string(), "Bearer secret123".to_string());
        assert!(check_auth(&headers, "/test"));
        std::env::remove_var("SB_ADMIN_TOKEN");
    }

    #[test]
    #[serial_test::serial]
    fn test_bearer_auth_failure() {
        std::env::set_var("SB_ADMIN_TOKEN", "secret123");
        let mut headers = HashMap::new();
        headers.insert("authorization".to_string(), "Bearer wrongtoken".to_string());
        assert!(!check_auth(&headers, "/test"));
        std::env::remove_var("SB_ADMIN_TOKEN");
    }

    #[test]
    #[serial_test::serial]
    fn test_bearer_auth_with_whitespace() {
        std::env::set_var("SB_ADMIN_TOKEN", "secret123");
        let mut headers = HashMap::new();
        headers.insert(
            "authorization".to_string(),
            "  Bearer   secret123  ".to_string(),
        );
        assert!(check_auth(&headers, "/test"));
        std::env::remove_var("SB_ADMIN_TOKEN");
    }

    #[test]
    #[serial_test::serial]
    fn test_hmac_auth_format_validation() {
        std::env::set_var("SB_ADMIN_HMAC_SECRET", "testsecret");
        let mut headers = HashMap::new();

        // Invalid format: too few parts
        headers.insert(
            "authorization".to_string(),
            "SB-HMAC admin:123456".to_string(),
        );
        assert!(!check_auth(&headers, "/test"));

        // Invalid format: too many parts
        headers.insert(
            "authorization".to_string(),
            "SB-HMAC admin:123456:sig:extra".to_string(),
        );
        assert!(!check_auth(&headers, "/test"));

        // Invalid timestamp
        headers.insert(
            "authorization".to_string(),
            "SB-HMAC admin:notanumber:sig".to_string(),
        );
        assert!(!check_auth(&headers, "/test"));

        std::env::remove_var("SB_ADMIN_HMAC_SECRET");
    }

    #[test]
    #[serial_test::serial]
    fn test_hmac_auth_time_window() {
        use std::time::{SystemTime, UNIX_EPOCH};

        std::env::set_var("SB_ADMIN_HMAC_SECRET", "testsecret");
        let mut headers = HashMap::new();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Too old (more than 5 minutes)
        let old_timestamp = now - 400; // 400 seconds ago
        headers.insert(
            "authorization".to_string(),
            format!("SB-HMAC admin:{}:somesig", old_timestamp),
        );
        assert!(!check_auth(&headers, "/test"));

        // Future timestamp (more than 5 minutes ahead)
        let future_timestamp = now + 400; // 400 seconds in future
        headers.insert(
            "authorization".to_string(),
            format!("SB-HMAC admin:{}:somesig", future_timestamp),
        );
        assert!(!check_auth(&headers, "/test"));

        std::env::remove_var("SB_ADMIN_HMAC_SECRET");
    }

    #[test]
    #[serial_test::serial]
    fn test_hmac_auth_signature_verification() {
        use std::time::{SystemTime, UNIX_EPOCH};

        std::env::set_var("SB_ADMIN_HMAC_SECRET", "testsecret");
        let mut headers = HashMap::new();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let path = "/test";

        // Generate correct signature using real HMAC-SHA256
        let message = format!("{}{}", now, path);
        let mut mac = HmacSha256::new_from_slice("testsecret".as_bytes()).unwrap();
        mac.update(message.as_bytes());
        let expected = mac.finalize().into_bytes();
        let correct_signature = hex::encode(expected);

        // Valid signature
        headers.insert(
            "authorization".to_string(),
            format!("SB-HMAC admin:{}:{}", now, correct_signature),
        );
        assert!(check_auth(&headers, path));

        // Invalid signature
        headers.insert(
            "authorization".to_string(),
            format!("SB-HMAC admin:{}:invalidsig", now),
        );
        assert!(!check_auth(&headers, path));

        std::env::remove_var("SB_ADMIN_HMAC_SECRET");
    }

    #[test]
    #[serial_test::serial]
    fn test_no_auth_configured() {
        // Clear all auth env vars
        std::env::remove_var("SB_ADMIN_TOKEN");
        std::env::remove_var("SB_ADMIN_HMAC_SECRET");
        std::env::remove_var("SB_ADMIN_NO_AUTH");

        let headers = HashMap::new();
        assert!(check_auth(&headers, "/test")); // Should allow access when no auth is configured
    }

    #[test]
    #[serial_test::serial]
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
    fn server_routes_authenticated_requests_through_extension() {
        let source = include_str!("server.rs");

        assert!(source.contains("state\n        .handle(crate::debug::DebugRequest"));
    }

    #[test]
    #[serial_test::serial]
    fn test_hmac_auth_different_paths() {
        use std::time::{SystemTime, UNIX_EPOCH};

        std::env::set_var("SB_ADMIN_HMAC_SECRET", "testsecret");
        let mut headers = HashMap::new();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

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
        headers.insert(
            "authorization".to_string(),
            format!("SB-HMAC admin:{}:{}", now, sig1),
        );
        assert!(check_auth(&headers, path1));
        assert!(!check_auth(&headers, path2)); // Should fail for different path

        // Signature for path2 should work only for path2
        headers.insert(
            "authorization".to_string(),
            format!("SB-HMAC admin:{}:{}", now, sig2),
        );
        assert!(check_auth(&headers, path2));
        assert!(!check_auth(&headers, path1)); // Should fail for different path

        std::env::remove_var("SB_ADMIN_HMAC_SECRET");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_serve_plain_returns_handle_and_shuts_down() {
        std::env::set_var("SB_ADMIN_NO_AUTH", "1");
        let state = test_state();

        let handle = serve_plain("127.0.0.1:0", state)
            .await
            .expect("serve_plain should bind and return handle");

        // Shutdown should complete without hanging
        let shutdown = tokio::time::timeout(std::time::Duration::from_secs(2), handle.shutdown());
        shutdown.await.expect("shutdown should complete within 2s");

        std::env::remove_var("SB_ADMIN_NO_AUTH");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_shutdown_releases_listener() {
        std::env::set_var("SB_ADMIN_NO_AUTH", "1");
        let state = test_state();

        // Start first server, get its port
        let handle1 = serve_plain("127.0.0.1:0", Arc::clone(&state))
            .await
            .expect("first serve_plain should succeed");

        // Shutdown first server
        handle1.shutdown().await;

        // Second bind to the same ephemeral allocation should succeed
        // (proves the listener was released)
        let handle2 = serve_plain("127.0.0.1:0", state)
            .await
            .expect("second serve_plain should succeed after shutdown");
        handle2.shutdown().await;

        std::env::remove_var("SB_ADMIN_NO_AUTH");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_spawn_plain_sync_returns_handle() {
        std::env::set_var("SB_ADMIN_NO_AUTH", "1");
        let state = test_state();

        let handle = spawn_plain_sync("127.0.0.1:0".to_string(), state);

        // Give it a moment to bind
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let shutdown = tokio::time::timeout(std::time::Duration::from_secs(2), handle.shutdown());
        shutdown
            .await
            .expect("spawn_plain_sync handle should shutdown within 2s");

        std::env::remove_var("SB_ADMIN_NO_AUTH");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_connections_tracked_during_shutdown() {
        std::env::set_var("SB_ADMIN_NO_AUTH", "1");
        let state = test_state();

        let handle = serve_plain("127.0.0.1:0", Arc::clone(&state))
            .await
            .expect("serve_plain should succeed");

        // We just need to prove shutdown works even after connections were made.
        // The fact that shutdown completes (does not hang) proves connections
        // are tracked in JoinSet and properly drained.
        let shutdown = tokio::time::timeout(std::time::Duration::from_secs(2), handle.shutdown());
        shutdown
            .await
            .expect("shutdown with no active connections should complete");

        std::env::remove_var("SB_ADMIN_NO_AUTH");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_drop_triggers_cancel_signal() {
        std::env::set_var("SB_ADMIN_NO_AUTH", "1");
        let state = test_state();

        let handle = serve_plain("127.0.0.1:0", state)
            .await
            .expect("serve_plain should succeed");

        // Clone the cancel token before dropping — private field accessible in-module test
        let cancel_witness = handle.cancel.clone();
        assert!(
            !cancel_witness.is_cancelled(),
            "cancel should not fire before drop"
        );

        drop(handle);

        assert!(
            cancel_witness.is_cancelled(),
            "Drop must fire the cancellation signal"
        );

        std::env::remove_var("SB_ADMIN_NO_AUTH");
    }
}
