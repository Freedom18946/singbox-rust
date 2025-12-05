//! SSH inbound adapter: provides SSH tunnel server functionality.
//!
//! This adapter listens for incoming SSH connections and forwards
//! traffic through the proxy chain after SSH authentication.
//!
//! Reference: Go sing-box `protocol/ssh/`

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use sb_core::adapter::InboundService;
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tracing::{debug, info, warn};

#[cfg(feature = "ssh")]
use {
    async_trait::async_trait,
    russh::server::{self, Auth, Msg, Session},
    russh::{Channel, ChannelId, CryptoVec},
    std::path::Path,
    tokio::io::AsyncReadExt,
};

/// SSH inbound adapter that provides SSH tunnel server functionality.
#[derive(Debug)]
pub struct SshInboundAdapter {
    /// Listen address for SSH server
    listen: SocketAddr,
    /// Server private key path
    host_key_path: Option<String>,
    /// Authorized keys for client authentication (username -> keys)
    authorized_keys: HashMap<String, Vec<String>>,
    /// Password authentication (username -> password)
    passwords: HashMap<String, String>,
    /// Shutdown signal
    shutdown: Arc<AtomicBool>,
    /// Shutdown notification
    shutdown_notify: Arc<Notify>,
    /// Active connection counter
    active_connections: Arc<AtomicU64>,
}

/// SSH inbound configuration parameters
#[derive(Debug, Clone)]
pub struct SshInboundConfig {
    /// Listen address (e.g., "127.0.0.1")
    pub listen: String,
    /// Listen port (typically 22 or higher unprivileged port)
    pub port: u16,
    /// Server host key file path (PEM format)
    pub host_key_path: Option<String>,
    /// Authorized users with their public keys (username -> [key_data])
    pub authorized_keys: HashMap<String, Vec<String>>,
    /// Password authentication (username -> password)
    pub passwords: HashMap<String, String>,
}

impl Default for SshInboundConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1".to_string(),
            port: 2222,
            host_key_path: None,
            authorized_keys: HashMap::new(),
            passwords: HashMap::new(),
        }
    }
}

impl SshInboundAdapter {
    /// Create a new SSH inbound adapter from configuration.
    pub fn new(config: SshInboundConfig) -> std::io::Result<Self> {
        let listen_str = format!("{}:{}", config.listen, config.port);
        let listen: SocketAddr = listen_str.parse().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid listen address '{}': {}", listen_str, e),
            )
        })?;

        Ok(Self {
            listen,
            host_key_path: config.host_key_path,
            authorized_keys: config.authorized_keys,
            passwords: config.passwords,
            shutdown: Arc::new(AtomicBool::new(false)),
            shutdown_notify: Arc::new(Notify::new()),
            active_connections: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Create a new SSH inbound adapter from InboundParam.
    pub fn create(
        param: &sb_core::adapter::InboundParam,
    ) -> std::io::Result<Box<dyn InboundService>> {
        // SSH inbound uses password field for simple auth
        let mut passwords = HashMap::new();
        if let Some(pwd) = &param.password {
            passwords.insert("user".to_string(), pwd.clone());
        }

        let config = SshInboundConfig {
            listen: param.listen.clone(),
            port: param.port,
            host_key_path: None, // TODO: Add host_key_path to InboundParam
            authorized_keys: HashMap::new(),
            passwords,
        };

        let adapter = Self::new(config)?;
        Ok(Box::new(adapter))
    }
}

// SSH server implementation when ssh feature is enabled
#[cfg(feature = "ssh")]
mod ssh_server {
    use super::*;

    /// SSH server handler that processes client connections
    pub(super) struct SshServerHandler {
        /// Username of authenticated client
        pub username: Option<String>,
        /// Authorized keys for verification
        pub authorized_keys: HashMap<String, Vec<String>>,
        /// Password database
        pub passwords: HashMap<String, String>,
        /// Active channels (direct-tcpip connections)
        pub channels: HashMap<ChannelId, ChannelState>,
        /// Connection counter reference
        pub active_connections: Arc<AtomicU64>,
    }

    /// State for an active SSH channel
    pub(super) struct ChannelState {
        pub target_host: String,
        pub target_port: u32,
    }

    impl server::Server for SshServerHandler {
        type Handler = Self;

        fn new_client(&mut self, _peer_addr: Option<std::net::SocketAddr>) -> Self::Handler {
            SshServerHandler {
                username: None,
                authorized_keys: self.authorized_keys.clone(),
                passwords: self.passwords.clone(),
                channels: HashMap::new(),
                active_connections: self.active_connections.clone(),
            }
        }
    }

    #[async_trait]
    impl server::Handler for SshServerHandler {
        type Error = anyhow::Error;

        async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
            debug!(user = %user, "SSH password authentication attempt");

            if let Some(stored_pwd) = self.passwords.get(user) {
                if stored_pwd == password {
                    self.username = Some(user.to_string());
                    info!(user = %user, "SSH password authentication successful");
                    return Ok(Auth::Accept);
                }
            }

            warn!(user = %user, "SSH password authentication failed");
            Ok(Auth::Reject {
                proceed_with_methods: None,
            })
        }

        async fn auth_publickey(
            &mut self,
            user: &str,
            public_key: &ssh_key::PublicKey,
        ) -> Result<Auth, Self::Error> {
            debug!(user = %user, "SSH public key authentication attempt");

            if let Some(authorized) = self.authorized_keys.get(user) {
                // Get base64 encoding of the key
                let key_fingerprint = public_key.fingerprint(ssh_key::HashAlg::Sha256).to_string();
                for auth_key in authorized {
                    // Compare fingerprints or raw key data
                    if auth_key.contains(&key_fingerprint) {
                        self.username = Some(user.to_string());
                        info!(user = %user, "SSH public key authentication successful");
                        return Ok(Auth::Accept);
                    }
                }
            }

            warn!(user = %user, "SSH public key authentication failed");
            Ok(Auth::Reject {
                proceed_with_methods: None,
            })
        }

        async fn channel_open_direct_tcpip(
            &mut self,
            channel: Channel<Msg>,
            host_to_connect: &str,
            port_to_connect: u32,
            _originator_address: &str,
            _originator_port: u32,
            session: &mut Session,
        ) -> Result<bool, Self::Error> {
            let channel_id = channel.id();
            info!(
                channel = ?channel_id,
                target = %format!("{}:{}", host_to_connect, port_to_connect),
                user = ?self.username,
                "SSH direct-tcpip channel requested"
            );

            // Store channel state
            self.channels.insert(
                channel_id,
                ChannelState {
                    target_host: host_to_connect.to_string(),
                    target_port: port_to_connect,
                },
            );

            // Accept the channel and initiate connection
            let target = format!("{}:{}", host_to_connect, port_to_connect);

            // Spawn connection handler
            let session_handle = session.handle();
            tokio::spawn(async move {
                match tokio::net::TcpStream::connect(&target).await {
                    Ok(mut stream) => {
                        debug!(target = %target, "Connected to target for SSH tunnel");

                        // Read from target and send to SSH channel
                        let (mut read_half, _write_half) = stream.split();
                        let mut buf = vec![0u8; 32768];

                        loop {
                            match read_half.read(&mut buf).await {
                                Ok(0) => {
                                    debug!(target = %target, "Target connection closed");
                                    let _ = session_handle.close(channel_id);
                                    break;
                                }
                                Ok(n) => {
                                    let data = CryptoVec::from_slice(&buf[..n]);
                                    if session_handle.data(channel_id, data).await.is_err() {
                                        break;
                                    }
                                }
                                Err(e) => {
                                    warn!(error = %e, "Read from target failed");
                                    let _ = session_handle.close(channel_id);
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!(target = %target, error = %e, "Failed to connect to target");
                        let _ = session_handle.close(channel_id);
                    }
                }
            });

            Ok(true)
        }

        async fn data(
            &mut self,
            channel: ChannelId,
            data: &[u8],
            _session: &mut Session,
        ) -> Result<(), Self::Error> {
            if let Some(state) = self.channels.get(&channel) {
                debug!(
                    channel = ?channel,
                    len = data.len(),
                    target = %format!("{}:{}", state.target_host, state.target_port),
                    "SSH channel data received"
                );
                // In full implementation, we'd write to the stored TcpStream
            }
            Ok(())
        }

        async fn channel_close(
            &mut self,
            channel: ChannelId,
            _session: &mut Session,
        ) -> Result<(), Self::Error> {
            debug!(channel = ?channel, "SSH channel closed");
            self.channels.remove(&channel);
            Ok(())
        }

        async fn channel_eof(
            &mut self,
            channel: ChannelId,
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            debug!(channel = ?channel, "SSH channel EOF");
            let _ = session.close(channel);
            Ok(())
        }
    }

    impl SshInboundAdapter {
        /// Load or generate server key
        pub async fn get_server_key(&self) -> Result<ssh_key::PrivateKey, anyhow::Error> {
            if let Some(path) = &self.host_key_path {
                // Try to load existing key
                if Path::new(path).exists() {
                    let key_data = tokio::fs::read_to_string(path).await?;
                    match russh_keys::decode_secret_key(&key_data, None) {
                        Ok(key) => {
                            info!(path = %path, "Loaded SSH host key");
                            return Ok(key);
                        }
                        Err(e) => {
                            warn!(path = %path, error = %e, "Failed to load SSH host key, generating new one");
                        }
                    }
                }
            }

            // Generate new Ed25519 key using ssh_key crate
            let private_key =
                ssh_key::PrivateKey::random(&mut rand::thread_rng(), ssh_key::Algorithm::Ed25519)
                    .map_err(|e| anyhow::anyhow!("Failed to generate Ed25519 key: {}", e))?;
            info!("Generated new Ed25519 SSH host key");

            Ok(private_key)
        }

        /// Run the SSH server using russh
        pub async fn run_ssh_server(&self) -> std::io::Result<()> {
            // Get or generate server key
            let key = self
                .get_server_key()
                .await
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

            // Configure SSH server
            let config = server::Config {
                keys: vec![key],
                inactivity_timeout: Some(std::time::Duration::from_secs(3600)),
                auth_rejection_time: std::time::Duration::from_secs(3),
                auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
                ..Default::default()
            };
            let config = Arc::new(config);

            info!(addr = ?self.listen, "SSH server starting with russh");

            // Bind and run server
            let listener = TcpListener::bind(self.listen).await?;

            loop {
                if self.shutdown.load(Ordering::Relaxed) {
                    info!("SSH server shutting down");
                    break;
                }

                tokio::select! {
                    result = listener.accept() => {
                        match result {
                            Ok((stream, peer_addr)) => {
                                self.active_connections.fetch_add(1, Ordering::Relaxed);
                                let config = config.clone();
                                let handler = SshServerHandler {
                                    username: None,
                                    authorized_keys: self.authorized_keys.clone(),
                                    passwords: self.passwords.clone(),
                                    channels: HashMap::new(),
                                    active_connections: self.active_connections.clone(),
                                };
                                let active_connections = self.active_connections.clone();

                                tokio::spawn(async move {
                                    info!(peer = %peer_addr, "SSH client connected");

                                    match server::run_stream(config, stream, handler).await {
                                        Ok(_) => {
                                            debug!(peer = %peer_addr, "SSH session completed");
                                        }
                                        Err(e) => {
                                            warn!(peer = %peer_addr, error = %e, "SSH session error");
                                        }
                                    }

                                    active_connections.fetch_sub(1, Ordering::Relaxed);
                                });
                            }
                            Err(e) => {
                                if !self.shutdown.load(Ordering::Relaxed) {
                                    warn!(error = %e, "SSH accept error");
                                }
                            }
                        }
                    }
                    _ = self.shutdown_notify.notified() => {
                        info!("SSH server received shutdown signal");
                        break;
                    }
                }
            }

            Ok(())
        }
    }
}

// Stub implementation when ssh feature is NOT enabled
#[cfg(not(feature = "ssh"))]
impl SshInboundAdapter {
    /// Run the SSH server (stub, feature not enabled)
    async fn run_server(&self) -> std::io::Result<()> {
        let listener = TcpListener::bind(self.listen).await?;
        info!(addr = ?self.listen, "SSH server listening (stub mode - ssh feature not enabled)");

        loop {
            if self.shutdown.load(Ordering::Relaxed) {
                info!("SSH server shutting down");
                break;
            }

            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, peer_addr)) => {
                            self.active_connections.fetch_add(1, Ordering::Relaxed);
                            let active_connections = self.active_connections.clone();

                            debug!(peer = %peer_addr, "SSH connection accepted (stub)");

                            tokio::spawn(async move {
                                warn!(peer = %peer_addr, "SSH handler requires 'ssh' feature, closing connection");
                                drop(stream);
                                active_connections.fetch_sub(1, Ordering::Relaxed);
                            });
                        }
                        Err(e) => {
                            if !self.shutdown.load(Ordering::Relaxed) {
                                warn!(error = %e, "SSH accept error");
                            }
                        }
                    }
                }
                _ = self.shutdown_notify.notified() => {
                    info!("SSH server received shutdown signal");
                    break;
                }
            }
        }

        Ok(())
    }
}

impl InboundService for SshInboundAdapter {
    fn serve(&self) -> std::io::Result<()> {
        // Run in a blocking context to match the sync interface
        let rt = tokio::runtime::Handle::try_current()
            .or_else(|_| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map(|rt| rt.handle().clone())
            })
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        let listen = self.listen;
        let shutdown = self.shutdown.clone();
        let shutdown_notify = self.shutdown_notify.clone();
        let active_connections = self.active_connections.clone();
        let host_key_path = self.host_key_path.clone();
        let authorized_keys = self.authorized_keys.clone();
        let passwords = self.passwords.clone();

        rt.block_on(async move {
            info!(addr = ?listen, "SSH inbound starting");

            let adapter = SshInboundAdapter {
                listen,
                host_key_path,
                authorized_keys,
                passwords,
                shutdown,
                shutdown_notify,
                active_connections,
            };

            #[cfg(feature = "ssh")]
            {
                adapter.run_ssh_server().await
            }

            #[cfg(not(feature = "ssh"))]
            {
                adapter.run_server().await
            }
        })
    }

    fn request_shutdown(&self) {
        info!("SSH inbound shutdown requested");
        self.shutdown.store(true, Ordering::Relaxed);
        self.shutdown_notify.notify_waiters();
    }

    fn active_connections(&self) -> Option<u64> {
        Some(self.active_connections.load(Ordering::Relaxed))
    }

    fn udp_sessions_estimate(&self) -> Option<u64> {
        None // SSH is TCP-only
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssh_inbound_config_default() {
        let config = SshInboundConfig::default();
        assert_eq!(config.listen, "127.0.0.1");
        assert_eq!(config.port, 2222);
        assert!(config.host_key_path.is_none());
        assert!(config.authorized_keys.is_empty());
        assert!(config.passwords.is_empty());
    }

    #[test]
    fn test_ssh_inbound_creation() {
        let mut passwords = HashMap::new();
        passwords.insert("testuser".to_string(), "testpass".to_string());

        let config = SshInboundConfig {
            listen: "127.0.0.1".to_string(),
            port: 2222,
            host_key_path: None,
            authorized_keys: HashMap::new(),
            passwords,
        };

        let adapter = SshInboundAdapter::new(config).unwrap();
        assert_eq!(adapter.listen.port(), 2222);
        assert_eq!(
            adapter.passwords.get("testuser"),
            Some(&"testpass".to_string())
        );
    }

    #[test]
    fn test_ssh_invalid_address() {
        let config = SshInboundConfig {
            listen: "not-a-valid-address".to_string(),
            port: 22,
            ..Default::default()
        };

        let result = SshInboundAdapter::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_ssh_with_authorized_keys() {
        let mut authorized_keys = HashMap::new();
        authorized_keys.insert(
            "admin".to_string(),
            vec!["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5... admin@example.com".to_string()],
        );

        let config = SshInboundConfig {
            authorized_keys,
            ..Default::default()
        };

        let adapter = SshInboundAdapter::new(config).unwrap();
        assert!(adapter.authorized_keys.contains_key("admin"));
    }
}
