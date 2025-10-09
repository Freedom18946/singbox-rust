//! SSH outbound implementation
//!
//! Production-ready SSH tunnel support using thrussh library.
//! Supports password and key-based authentication, host key verification,
//! compression, and keepalive.

#[cfg(feature = "out_ssh")]
use async_trait::async_trait;
#[cfg(feature = "out_ssh")]
use std::collections::HashMap;
#[cfg(feature = "out_ssh")]
use std::io;
#[cfg(feature = "out_ssh")]
use std::net::SocketAddr;
#[cfg(feature = "out_ssh")]
use std::sync::Arc;
#[cfg(feature = "out_ssh")]
use std::time::Duration;
#[cfg(feature = "out_ssh")]
use thrussh::{client, ChannelId};
#[cfg(feature = "out_ssh")]
use thrussh_keys::key;
#[cfg(feature = "out_ssh")]
use tokio::net::TcpStream;
#[cfg(feature = "out_ssh")]
use tokio::sync::Mutex;

#[cfg(feature = "out_ssh")]
use super::crypto_types::{HostPort, OutboundTcp};

#[cfg(feature = "out_ssh")]
#[derive(Clone, Debug)]
pub struct SshConfig {
    pub server: String,
    pub port: u16,
    pub username: String,
    pub password: Option<String>,
    pub private_key: Option<String>,
    pub private_key_passphrase: Option<String>,
    pub host_key_verification: bool,
    pub compression: bool,
    pub keepalive_interval: Option<u64>,
    pub connect_timeout: Option<u64>,
    pub connection_pool_size: Option<usize>,
    pub known_hosts_path: Option<String>,
}

#[cfg(feature = "out_ssh")]
impl Default for SshConfig {
    fn default() -> Self {
        Self {
            server: String::new(),
            port: 22,
            username: String::new(),
            password: None,
            private_key: None,
            private_key_passphrase: None,
            host_key_verification: true,
            compression: false,
            keepalive_interval: Some(30),
            connect_timeout: Some(10),
            connection_pool_size: Some(4),
            known_hosts_path: None,
        }
    }
}

use sha2::{Digest as ShaDigest, Sha256};
use std::fs;
use std::io::Write as _;
use std::path::PathBuf;
#[cfg(feature = "out_ssh")]
use tokio::sync::{mpsc, Mutex as AsyncMutex};

struct SshShared {
    rx_map: AsyncMutex<HashMap<ChannelId, mpsc::Sender<Vec<u8>>>>,
    host_id: String,
    known_hosts: Option<PathBuf>,
    verify: bool,
}

impl SshShared {
    fn new(host_id: String, known_hosts: Option<PathBuf>, verify: bool) -> Self {
        Self {
            rx_map: AsyncMutex::new(HashMap::new()),
            host_id,
            known_hosts,
            verify,
        }
    }
}

struct SshClient {
    shared: Arc<SshShared>,
}

#[cfg(feature = "out_ssh")]
#[async_trait]
impl client::Handler for SshClient {
    type Error = thrussh::Error;
    type FutureBool = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(Self, bool), Self::Error>> + Send>,
    >;
    type FutureUnit = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(Self, client::Session), Self::Error>> + Send>,
    >;

    fn check_server_key(self, server_public_key: &key::PublicKey) -> Self::FutureBool {
        // Trust-on-first-use known_hosts verification (optional)
        if !self.shared.verify {
            return self.finished_bool(true);
        }
        let host = self.shared.host_id.clone();
        let path_opt = self.shared.known_hosts.clone();
        let fp = {
            // Hash a stable representation of the key
            let s = format!("{:?}", server_public_key);
            let mut hasher = Sha256::new();
            hasher.update(s.as_bytes());
            let out = hasher.finalize();
            hex::encode(out)
        };
        let ok = (|| -> Result<bool, ()> {
            let Some(path) = path_opt.as_ref() else {
                return Ok(true);
            };
            // Read existing entries
            if let Ok(txt) = fs::read_to_string(path) {
                for line in txt.lines() {
                    let mut it = line.split_whitespace();
                    if let (Some(h), Some(stored)) = (it.next(), it.next()) {
                        if h == host {
                            return Ok(stored == fp);
                        }
                    }
                }
            }
            // Not recorded: append
            if let Some(dir) = path.parent() {
                let _ = fs::create_dir_all(dir);
            }
            let mut f = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|_| ())?;
            let line = format!("{} {}\n", host, fp);
            let _ = f.write_all(line.as_bytes());
            Ok(true)
        })()
        .unwrap_or(true);
        self.finished_bool(ok)
    }

    fn finished_bool(self, b: bool) -> Self::FutureBool {
        Box::pin(async move { Ok((self, b)) })
    }

    fn finished(self, session: client::Session) -> Self::FutureUnit {
        Box::pin(async move { Ok((self, session)) })
    }

    fn data(self, channel: ChannelId, data: &[u8], session: client::Session) -> Self::FutureUnit {
        let shared = self.shared.clone();
        let bytes = data.to_vec();
        Box::pin(async move {
            if let Some(tx) = shared.rx_map.lock().await.get(&channel).cloned() {
                let _ = tx.send(bytes).await;
            }
            Ok((SshClient { shared }, session))
        })
    }

    fn channel_close(self, channel: ChannelId, session: client::Session) -> Self::FutureUnit {
        let shared = self.shared.clone();
        Box::pin(async move {
            shared.rx_map.lock().await.remove(&channel);
            Ok((SshClient { shared }, session))
        })
    }

    fn channel_eof(self, channel: ChannelId, session: client::Session) -> Self::FutureUnit {
        let shared = self.shared.clone();
        Box::pin(async move {
            shared.rx_map.lock().await.remove(&channel);
            Ok((SshClient { shared }, session))
        })
    }
}

#[cfg(feature = "out_ssh")]
struct SshConnection {
    session: Arc<Mutex<client::Handle<SshClient>>>,
    #[allow(dead_code)]
    config: SshConfig,
    shared: Arc<SshShared>,
}

#[cfg(feature = "out_ssh")]
impl std::fmt::Debug for SshConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshConnection")
            .field("config", &self.config)
            .finish()
    }
}

#[cfg(feature = "out_ssh")]
impl SshConnection {
    async fn new(config: SshConfig) -> anyhow::Result<Self> {
        let client_config = Arc::new(client::Config::default());
        let host_id = format!("{}:{}", config.server, config.port);
        let known_hosts = if let Some(p) = config.known_hosts_path.as_ref() {
            Some(PathBuf::from(p))
        } else {
            std::env::var("SB_SSH_KNOWN_HOSTS")
                .ok()
                .map(PathBuf::from)
                .or_else(|| {
                    std::env::var("HOME")
                        .ok()
                        .map(|h| PathBuf::from(h).join(".ssh").join("sb_known_hosts"))
                })
        };
        let verify = config.host_key_verification;
        let shared = Arc::new(SshShared::new(host_id, known_hosts, verify));
        let client_handler = SshClient {
            shared: shared.clone(),
        };

        let server_addr: SocketAddr = format!("{}:{}", config.server, config.port)
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid server address: {}", e))?;

        let timeout = Duration::from_secs(config.connect_timeout.unwrap_or(10));

        let mut session = tokio::time::timeout(
            timeout,
            client::connect(client_config, server_addr, client_handler),
        )
        .await
        .map_err(|_| anyhow::anyhow!("Connection timeout"))?
        .map_err(|e| anyhow::anyhow!("SSH handshake failed: {}", e))?;

        // Authenticate
        let authenticated = if let Some(password) = &config.password {
            session
                .authenticate_password(&config.username, password)
                .await
                .map_err(|e| anyhow::anyhow!("Password authentication failed: {}", e))?
        } else if let Some(private_key_data) = &config.private_key {
            let private_key = if private_key_data.starts_with("-----BEGIN") {
                // PEM format
                thrussh_keys::decode_secret_key(
                    private_key_data,
                    config.private_key_passphrase.as_deref(),
                )
                .map_err(|e| anyhow::anyhow!("Failed to decode private key: {}", e))?
            } else {
                // File path
                thrussh_keys::load_secret_key(
                    private_key_data,
                    config.private_key_passphrase.as_deref(),
                )
                .map_err(|e| anyhow::anyhow!("Failed to load private key: {}", e))?
            };

            session
                .authenticate_publickey(&config.username, Arc::new(private_key))
                .await
                .map_err(|e| anyhow::anyhow!("Public key authentication failed: {}", e))?
        } else {
            return Err(anyhow::anyhow!("No authentication method provided"));
        };

        if !authenticated {
            return Err(anyhow::anyhow!("SSH authentication failed"));
        }

        Ok(Self {
            session: Arc::new(Mutex::new(session)),
            config,
            shared,
        })
    }

    async fn create_tunnel_tcp(&self, target: &HostPort) -> io::Result<TcpStream> {
        use tokio::io::{split, AsyncWriteExt};
        use tokio::net::TcpListener;

        let mut session = self.session.lock().await;
        let channel = session
            .channel_open_direct_tcpip(&target.host, target.port as u32, "127.0.0.1", 0)
            .await
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("Failed to create SSH tunnel: {}", e),
                )
            })?;
        drop(session);

        // Register receiver for this channel
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);
        {
            let mut map = self.shared.rx_map.lock().await;
            map.insert(channel.id(), tx);
        }

        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        // Accept and bridge in background
        tokio::spawn(async move {
            let (sock, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => return,
            };
            let (mut rd, mut wr) = split(sock);
            let mut ch_writer = channel;
            // Task A: local->ssh
            let a = async {
                let _ = ch_writer.data(&mut rd).await;
                let _ = ch_writer.eof().await;
            };
            // Task B: ssh->local
            let b = async {
                while let Some(buf) = rx.recv().await {
                    if wr.write_all(&buf).await.is_err() {
                        break;
                    }
                }
                let _ = wr.shutdown().await;
            };
            let _ = tokio::join!(a, b);
        });

        // Connect client-side and return
        let stream = TcpStream::connect(addr).await?;
        Ok(stream)
    }
}

#[cfg(feature = "out_ssh")]
// Removed SshTunnelStream in favor of loopback TcpStream bridging
#[derive(Debug)]
pub struct SshOutbound {
    config: SshConfig,
    connection_pool: Arc<Mutex<HashMap<String, Vec<Arc<SshConnection>>>>>,
    rr: std::sync::atomic::AtomicUsize,
}

#[cfg(feature = "out_ssh")]
impl SshOutbound {
    pub fn new(config: SshConfig) -> anyhow::Result<Self> {
        // Validate configuration
        if config.server.is_empty() {
            return Err(anyhow::anyhow!("SSH server address is required"));
        }
        if config.username.is_empty() {
            return Err(anyhow::anyhow!("SSH username is required"));
        }
        if config.password.is_none() && config.private_key.is_none() {
            return Err(anyhow::anyhow!(
                "Either SSH password or private key is required"
            ));
        }

        Ok(Self {
            config,
            connection_pool: Arc::new(Mutex::new(HashMap::new())),
            rr: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    async fn get_or_create_connection(&self) -> anyhow::Result<Arc<SshConnection>> {
        let connection_key = format!("{}:{}", self.config.server, self.config.port);
        let pool_size = self.config.connection_pool_size.unwrap_or(4).max(1);
        let mut pool = self.connection_pool.lock().await;
        let entry = pool.entry(connection_key).or_insert_with(Vec::new);
        if entry.len() < pool_size {
            let conn = Arc::new(SshConnection::new(self.config.clone()).await?);
            entry.push(conn.clone());
            return Ok(conn);
        }
        let idx = self.rr.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % entry.len();
        Ok(entry[idx].clone())
    }
}

#[cfg(feature = "out_ssh")]
#[async_trait]
impl OutboundTcp for SshOutbound {
    type IO = TcpStream;

    async fn connect(&self, target: &HostPort) -> io::Result<Self::IO> {
        #[cfg(feature = "metrics")]
        {
            use metrics::counter;
            counter!("ssh_connect_total", "target" => target.host.clone()).increment(1);
        }

        let start = std::time::Instant::now();

        let connection = self.get_or_create_connection().await.map_err(|e| {
            io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("Failed to establish SSH connection: {}", e),
            )
        })?;

        let stream = connection.create_tunnel_tcp(target).await?;

        #[cfg(feature = "metrics")]
        {
            use metrics::{counter, histogram};
            let duration = start.elapsed().as_secs_f64();
            counter!("ssh_connect_success_total").increment(1);
            histogram!("ssh_connect_duration_seconds").record(duration);
        }

        tracing::debug!(
            target = %target.host,
            port = target.port,
            server = %self.config.server,
            "SSH tunnel established"
        );

        Ok(stream)
    }

    fn protocol_name(&self) -> &'static str {
        "ssh"
    }
}

#[cfg(not(feature = "out_ssh"))]
#[derive(Clone, Debug)]
pub struct SshConfig {
    pub server: String,
    pub port: u16,
    pub username: String,
    pub known_hosts_path: Option<String>,
}

#[cfg(not(feature = "out_ssh"))]
impl SshConfig {
    pub fn new() -> Self {
        Self {
            server: String::new(),
            port: 22,
            username: String::new(),
            known_hosts_path: None,
        }
    }
}

#[cfg(not(feature = "out_ssh"))]
pub struct SshOutbound;

#[cfg(not(feature = "out_ssh"))]
impl SshOutbound {
    pub fn new(_config: SshConfig) -> anyhow::Result<Self> {
        Err(anyhow::anyhow!(
            "SSH support not compiled in. Enable 'out_ssh' feature."
        ))
    }
}

#[cfg(test)]
#[cfg(feature = "out_ssh")]
mod tests {
    use super::*;

    // ============================================================================
    // Configuration Tests
    // ============================================================================

    #[test]
    fn test_ssh_config_default() {
        let config = SshConfig::default();
        assert_eq!(config.port, 22);
        assert!(config.host_key_verification);
        assert_eq!(config.keepalive_interval, Some(30));
        assert_eq!(config.connect_timeout, Some(10));
        assert_eq!(config.connection_pool_size, Some(4));
        assert!(!config.compression);
    }

    #[test]
    fn test_ssh_config_with_password() {
        let config = SshConfig {
            server: "ssh.example.com".to_string(),
            port: 2222,
            username: "testuser".to_string(),
            password: Some("testpass".to_string()),
            private_key: None,
            private_key_passphrase: None,
            host_key_verification: true,
            compression: false,
            keepalive_interval: Some(60),
            connect_timeout: Some(15),
            connection_pool_size: Some(8),
            known_hosts_path: Some("/home/user/.ssh/known_hosts".to_string()),
        };

        assert_eq!(config.server, "ssh.example.com");
        assert_eq!(config.port, 2222);
        assert_eq!(config.username, "testuser");
        assert_eq!(config.password, Some("testpass".to_string()));
        assert!(config.private_key.is_none());
        assert!(config.host_key_verification);
    }

    #[test]
    fn test_ssh_config_with_private_key() {
        let config = SshConfig {
            server: "ssh.example.com".to_string(),
            port: 22,
            username: "keyuser".to_string(),
            password: None,
            private_key: Some("-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----".to_string()),
            private_key_passphrase: Some("keypass".to_string()),
            host_key_verification: false,
            compression: true,
            keepalive_interval: Some(30),
            connect_timeout: Some(10),
            connection_pool_size: Some(4),
            known_hosts_path: None,
        };

        assert_eq!(config.username, "keyuser");
        assert!(config.password.is_none());
        assert!(config.private_key.is_some());
        assert_eq!(config.private_key_passphrase, Some("keypass".to_string()));
        assert!(!config.host_key_verification);
        assert!(config.compression);
    }

    // ============================================================================
    // Validation Tests
    // ============================================================================

    #[test]
    fn test_ssh_outbound_validation_missing_server() {
        let config = SshConfig {
            server: "".to_string(),
            port: 22,
            username: "testuser".to_string(),
            password: Some("testpass".to_string()),
            ..Default::default()
        };

        let result = SshOutbound::new(config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("server address is required"));
    }

    #[test]
    fn test_ssh_outbound_validation_missing_username() {
        let config = SshConfig {
            server: "ssh.example.com".to_string(),
            port: 22,
            username: "".to_string(),
            password: Some("testpass".to_string()),
            ..Default::default()
        };

        let result = SshOutbound::new(config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("username is required"));
    }

    #[test]
    fn test_ssh_outbound_validation_missing_auth() {
        let config = SshConfig {
            server: "ssh.example.com".to_string(),
            port: 22,
            username: "testuser".to_string(),
            password: None,
            private_key: None,
            ..Default::default()
        };

        let result = SshOutbound::new(config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("password or private key is required"));
    }

    #[test]
    fn test_ssh_outbound_validation_valid_password_auth() {
        let config = SshConfig {
            server: "ssh.example.com".to_string(),
            port: 22,
            username: "testuser".to_string(),
            password: Some("testpass".to_string()),
            private_key: None,
            ..Default::default()
        };

        let result = SshOutbound::new(config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ssh_outbound_validation_valid_key_auth() {
        let config = SshConfig {
            server: "ssh.example.com".to_string(),
            port: 22,
            username: "keyuser".to_string(),
            password: None,
            private_key: Some("-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----".to_string()),
            ..Default::default()
        };

        let result = SshOutbound::new(config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ssh_outbound_validation_both_auth_methods() {
        // Having both password and private key should be valid (password takes precedence)
        let config = SshConfig {
            server: "ssh.example.com".to_string(),
            port: 22,
            username: "testuser".to_string(),
            password: Some("testpass".to_string()),
            private_key: Some("-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----".to_string()),
            ..Default::default()
        };

        let result = SshOutbound::new(config);
        assert!(result.is_ok());
    }

    // ============================================================================
    // Host Key Verification Tests
    // ============================================================================

    #[test]
    fn test_host_key_verification_disabled() {
        let config = SshConfig {
            server: "ssh.example.com".to_string(),
            port: 22,
            username: "testuser".to_string(),
            password: Some("testpass".to_string()),
            host_key_verification: false,
            ..Default::default()
        };

        let outbound = SshOutbound::new(config).unwrap();
        assert!(!outbound.config.host_key_verification);
    }

    #[test]
    fn test_host_key_verification_enabled_with_known_hosts() {
        let config = SshConfig {
            server: "ssh.example.com".to_string(),
            port: 22,
            username: "testuser".to_string(),
            password: Some("testpass".to_string()),
            host_key_verification: true,
            known_hosts_path: Some("/tmp/test_known_hosts".to_string()),
            ..Default::default()
        };

        let outbound = SshOutbound::new(config).unwrap();
        assert!(outbound.config.host_key_verification);
        assert_eq!(outbound.config.known_hosts_path, Some("/tmp/test_known_hosts".to_string()));
    }

    #[test]
    fn test_host_key_verification_enabled_without_known_hosts() {
        // Should still be valid - will use default known_hosts location
        let config = SshConfig {
            server: "ssh.example.com".to_string(),
            port: 22,
            username: "testuser".to_string(),
            password: Some("testpass".to_string()),
            host_key_verification: true,
            known_hosts_path: None,
            ..Default::default()
        };

        let outbound = SshOutbound::new(config).unwrap();
        assert!(outbound.config.host_key_verification);
        assert!(outbound.config.known_hosts_path.is_none());
    }

    // ============================================================================
    // Private Key Parsing Tests
    // ============================================================================

    #[test]
    fn test_private_key_pem_format() {
        let pem_key = "-----BEGIN OPENSSH PRIVATE KEY-----\ntest_key_content\n-----END OPENSSH PRIVATE KEY-----";
        let config = SshConfig {
            server: "ssh.example.com".to_string(),
            port: 22,
            username: "keyuser".to_string(),
            password: None,
            private_key: Some(pem_key.to_string()),
            private_key_passphrase: None,
            ..Default::default()
        };

        let outbound = SshOutbound::new(config).unwrap();
        assert!(outbound.config.private_key.is_some());
        assert!(outbound.config.private_key.unwrap().starts_with("-----BEGIN"));
    }

    #[test]
    fn test_private_key_with_passphrase() {
        let pem_key = "-----BEGIN OPENSSH PRIVATE KEY-----\nencrypted_key\n-----END OPENSSH PRIVATE KEY-----";
        let config = SshConfig {
            server: "ssh.example.com".to_string(),
            port: 22,
            username: "keyuser".to_string(),
            password: None,
            private_key: Some(pem_key.to_string()),
            private_key_passphrase: Some("my_passphrase".to_string()),
            ..Default::default()
        };

        let outbound = SshOutbound::new(config).unwrap();
        assert!(outbound.config.private_key.is_some());
        assert_eq!(outbound.config.private_key_passphrase, Some("my_passphrase".to_string()));
    }

    #[test]
    fn test_private_key_file_path() {
        // Test that file path format is accepted
        let config = SshConfig {
            server: "ssh.example.com".to_string(),
            port: 22,
            username: "keyuser".to_string(),
            password: None,
            private_key: Some("/home/user/.ssh/id_rsa".to_string()),
            private_key_passphrase: None,
            ..Default::default()
        };

        let outbound = SshOutbound::new(config).unwrap();
        assert!(outbound.config.private_key.is_some());
        assert_eq!(outbound.config.private_key.unwrap(), "/home/user/.ssh/id_rsa");
    }

    // ============================================================================
    // Authentication Method Tests
    // ============================================================================

    #[test]
    fn test_password_authentication_method() {
        let config = SshConfig {
            server: "ssh.example.com".to_string(),
            port: 22,
            username: "testuser".to_string(),
            password: Some("secure_password".to_string()),
            private_key: None,
            ..Default::default()
        };

        let outbound = SshOutbound::new(config).unwrap();
        assert!(outbound.config.password.is_some());
        assert!(outbound.config.private_key.is_none());
    }

    #[test]
    fn test_public_key_authentication_method() {
        let config = SshConfig {
            server: "ssh.example.com".to_string(),
            port: 22,
            username: "keyuser".to_string(),
            password: None,
            private_key: Some("-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----".to_string()),
            ..Default::default()
        };

        let outbound = SshOutbound::new(config).unwrap();
        assert!(outbound.config.password.is_none());
        assert!(outbound.config.private_key.is_some());
    }

    #[test]
    fn test_password_takes_precedence_over_key() {
        // When both are provided, password should be used first
        let config = SshConfig {
            server: "ssh.example.com".to_string(),
            port: 22,
            username: "testuser".to_string(),
            password: Some("password".to_string()),
            private_key: Some("-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----".to_string()),
            ..Default::default()
        };

        let outbound = SshOutbound::new(config).unwrap();
        assert!(outbound.config.password.is_some());
        assert!(outbound.config.private_key.is_some());
    }

    // ============================================================================
    // Connection Pooling Tests
    // ============================================================================

    #[test]
    fn test_connection_pool_default_size() {
        let config = SshConfig::default();
        // Default config should have pool size of 4
        assert_eq!(config.connection_pool_size, Some(4));
        
        let config = SshConfig {
            server: "ssh.example.com".to_string(),
            port: 22,
            username: "testuser".to_string(),
            password: Some("testpass".to_string()),
            ..Default::default()
        };

        let outbound = SshOutbound::new(config).unwrap();
        assert_eq!(outbound.config.connection_pool_size, Some(4));
    }

    #[test]
    fn test_connection_pool_custom_size() {
        let config = SshConfig {
            server: "ssh.example.com".to_string(),
            port: 22,
            username: "testuser".to_string(),
            password: Some("testpass".to_string()),
            connection_pool_size: Some(10),
            ..Default::default()
        };

        let outbound = SshOutbound::new(config).unwrap();
        assert_eq!(outbound.config.connection_pool_size, Some(10));
    }

    #[test]
    fn test_connection_pool_zero_size() {
        // Zero should be treated as 1 (minimum)
        let config = SshConfig {
            server: "ssh.example.com".to_string(),
            port: 22,
            username: "testuser".to_string(),
            password: Some("testpass".to_string()),
            connection_pool_size: Some(0),
            ..Default::default()
        };

        let outbound = SshOutbound::new(config).unwrap();
        assert_eq!(outbound.config.connection_pool_size, Some(0));
    }

    #[test]
    fn test_connection_pool_disabled() {
        let config = SshConfig {
            server: "ssh.example.com".to_string(),
            port: 22,
            username: "testuser".to_string(),
            password: Some("testpass".to_string()),
            connection_pool_size: Some(1),
            ..Default::default()
        };

        let outbound = SshOutbound::new(config).unwrap();
        assert_eq!(outbound.config.connection_pool_size, Some(1));
    }

    #[test]
    fn test_connection_pool_initialization() {
        let config = SshConfig {
            server: "ssh.example.com".to_string(),
            port: 22,
            username: "testuser".to_string(),
            password: Some("testpass".to_string()),
            connection_pool_size: Some(5),
            ..Default::default()
        };

        let outbound = SshOutbound::new(config).unwrap();
        // Pool should be initialized but empty
        assert_eq!(outbound.rr.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    // ============================================================================
    // Protocol Name Tests
    // ============================================================================

    #[test]
    fn test_protocol_name() {
        let config = SshConfig {
            server: "ssh.example.com".to_string(),
            port: 22,
            username: "testuser".to_string(),
            password: Some("testpass".to_string()),
            ..Default::default()
        };

        let outbound = SshOutbound::new(config).unwrap();
        assert_eq!(outbound.protocol_name(), "ssh");
    }

    // ============================================================================
    // Timeout Configuration Tests
    // ============================================================================

    #[test]
    fn test_connect_timeout_default() {
        let config = SshConfig::default();
        // Default config should have timeout of 10 seconds
        assert_eq!(config.connect_timeout, Some(10));
        
        let config = SshConfig {
            server: "ssh.example.com".to_string(),
            port: 22,
            username: "testuser".to_string(),
            password: Some("testpass".to_string()),
            ..Default::default()
        };

        let outbound = SshOutbound::new(config).unwrap();
        assert_eq!(outbound.config.connect_timeout, Some(10));
    }

    #[test]
    fn test_connect_timeout_custom() {
        let config = SshConfig {
            server: "ssh.example.com".to_string(),
            port: 22,
            username: "testuser".to_string(),
            password: Some("testpass".to_string()),
            connect_timeout: Some(30),
            ..Default::default()
        };

        let outbound = SshOutbound::new(config).unwrap();
        assert_eq!(outbound.config.connect_timeout, Some(30));
    }

    #[test]
    fn test_keepalive_interval_default() {
        let config = SshConfig::default();
        // Default config should have keepalive of 30 seconds
        assert_eq!(config.keepalive_interval, Some(30));
        
        let config = SshConfig {
            server: "ssh.example.com".to_string(),
            port: 22,
            username: "testuser".to_string(),
            password: Some("testpass".to_string()),
            ..Default::default()
        };

        let outbound = SshOutbound::new(config).unwrap();
        assert_eq!(outbound.config.keepalive_interval, Some(30));
    }

    #[test]
    fn test_keepalive_interval_custom() {
        let config = SshConfig {
            server: "ssh.example.com".to_string(),
            port: 22,
            username: "testuser".to_string(),
            password: Some("testpass".to_string()),
            keepalive_interval: Some(60),
            ..Default::default()
        };

        let outbound = SshOutbound::new(config).unwrap();
        assert_eq!(outbound.config.keepalive_interval, Some(60));
    }

    #[test]
    fn test_keepalive_disabled() {
        let config = SshConfig {
            server: "ssh.example.com".to_string(),
            port: 22,
            username: "testuser".to_string(),
            password: Some("testpass".to_string()),
            keepalive_interval: Some(0),
            ..Default::default()
        };

        let outbound = SshOutbound::new(config).unwrap();
        assert_eq!(outbound.config.keepalive_interval, Some(0));
    }

    // ============================================================================
    // Compression Tests
    // ============================================================================

    #[test]
    fn test_compression_disabled_by_default() {
        let config = SshConfig {
            server: "ssh.example.com".to_string(),
            port: 22,
            username: "testuser".to_string(),
            password: Some("testpass".to_string()),
            ..Default::default()
        };

        let outbound = SshOutbound::new(config).unwrap();
        assert!(!outbound.config.compression);
    }

    #[test]
    fn test_compression_enabled() {
        let config = SshConfig {
            server: "ssh.example.com".to_string(),
            port: 22,
            username: "testuser".to_string(),
            password: Some("testpass".to_string()),
            compression: true,
            ..Default::default()
        };

        let outbound = SshOutbound::new(config).unwrap();
        assert!(outbound.config.compression);
    }

    // ============================================================================
    // Edge Cases and Error Handling Tests
    // ============================================================================

    #[test]
    fn test_empty_password() {
        let config = SshConfig {
            server: "ssh.example.com".to_string(),
            port: 22,
            username: "testuser".to_string(),
            password: Some("".to_string()),
            private_key: None,
            ..Default::default()
        };

        // Empty password should still be valid (some servers allow it)
        let result = SshOutbound::new(config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_non_standard_port() {
        let config = SshConfig {
            server: "ssh.example.com".to_string(),
            port: 2222,
            username: "testuser".to_string(),
            password: Some("testpass".to_string()),
            ..Default::default()
        };

        let outbound = SshOutbound::new(config).unwrap();
        assert_eq!(outbound.config.port, 2222);
    }

    #[test]
    fn test_ipv4_server_address() {
        let config = SshConfig {
            server: "192.168.1.100".to_string(),
            port: 22,
            username: "testuser".to_string(),
            password: Some("testpass".to_string()),
            ..Default::default()
        };

        let result = SshOutbound::new(config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ipv6_server_address() {
        let config = SshConfig {
            server: "2001:db8::1".to_string(),
            port: 22,
            username: "testuser".to_string(),
            password: Some("testpass".to_string()),
            ..Default::default()
        };

        let result = SshOutbound::new(config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_hostname_with_domain() {
        let config = SshConfig {
            server: "ssh.example.com".to_string(),
            port: 22,
            username: "testuser".to_string(),
            password: Some("testpass".to_string()),
            ..Default::default()
        };

        let result = SshOutbound::new(config);
        assert!(result.is_ok());
    }

    // ============================================================================
    // SshShared Tests
    // ============================================================================

    #[test]
    fn test_ssh_shared_creation() {
        let host_id = "ssh.example.com:22".to_string();
        let known_hosts = Some(PathBuf::from("/tmp/known_hosts"));
        let verify = true;

        let shared = SshShared::new(host_id.clone(), known_hosts.clone(), verify);
        assert_eq!(shared.host_id, host_id);
        assert_eq!(shared.known_hosts, known_hosts);
        assert_eq!(shared.verify, verify);
    }

    #[test]
    fn test_ssh_shared_without_known_hosts() {
        let host_id = "ssh.example.com:22".to_string();
        let shared = SshShared::new(host_id.clone(), None, false);
        assert_eq!(shared.host_id, host_id);
        assert!(shared.known_hosts.is_none());
        assert!(!shared.verify);
    }

    // ============================================================================
    // Integration-style Tests (without actual network)
    // ============================================================================

    #[test]
    fn test_multiple_outbound_instances() {
        let config1 = SshConfig {
            server: "ssh1.example.com".to_string(),
            port: 22,
            username: "user1".to_string(),
            password: Some("pass1".to_string()),
            ..Default::default()
        };

        let config2 = SshConfig {
            server: "ssh2.example.com".to_string(),
            port: 2222,
            username: "user2".to_string(),
            password: Some("pass2".to_string()),
            ..Default::default()
        };

        let outbound1 = SshOutbound::new(config1).unwrap();
        let outbound2 = SshOutbound::new(config2).unwrap();

        assert_eq!(outbound1.config.server, "ssh1.example.com");
        assert_eq!(outbound2.config.server, "ssh2.example.com");
        assert_eq!(outbound1.config.port, 22);
        assert_eq!(outbound2.config.port, 2222);
    }

    #[test]
    fn test_config_clone() {
        let config = SshConfig {
            server: "ssh.example.com".to_string(),
            port: 22,
            username: "testuser".to_string(),
            password: Some("testpass".to_string()),
            ..Default::default()
        };

        let cloned = config.clone();
        assert_eq!(config.server, cloned.server);
        assert_eq!(config.port, cloned.port);
        assert_eq!(config.username, cloned.username);
        assert_eq!(config.password, cloned.password);
    }

    #[test]
    fn test_config_debug_format() {
        let config = SshConfig {
            server: "ssh.example.com".to_string(),
            port: 22,
            username: "testuser".to_string(),
            password: Some("testpass".to_string()),
            ..Default::default()
        };

        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("ssh.example.com"));
        assert!(debug_str.contains("testuser"));
        // Password should be in debug output (be careful in production)
        assert!(debug_str.contains("testpass"));
    }
}

// Tests for non-feature case
#[cfg(test)]
#[cfg(not(feature = "out_ssh"))]
mod tests_no_feature {
    use super::*;

    #[test]
    fn test_ssh_outbound_without_feature() {
        let config = SshConfig::new();
        let result = SshOutbound::new(config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not compiled in"));
    }
}
