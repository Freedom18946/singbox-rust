//! SSH outbound adapter implementation
//!
//! Fully self-contained SSH tunnel support using the `russh` library.
//! Supports password and key-based authentication, host key verification,
//! connection pooling, and TCP forwarding via `direct-tcpip` channels.

use crate::outbound::prelude::*;

/// SSH adapter configuration
#[derive(Debug, Clone)]
pub struct SshAdapterConfig {
    pub server: String,
    pub port: u16,
    pub username: String,
    pub password: Option<String>,
    pub private_key: Option<String>,
    pub private_key_passphrase: Option<String>,
    pub host_key_verification: bool,
    pub known_hosts_path: Option<String>,
    pub connection_pool_size: Option<usize>,
    pub compression: bool,
    pub keepalive_interval: Option<u64>,
    pub connect_timeout: Option<u64>,
}

impl Default for SshAdapterConfig {
    fn default() -> Self {
        Self {
            server: String::new(),
            port: 22,
            username: String::new(),
            password: None,
            private_key: None,
            private_key_passphrase: None,
            host_key_verification: true,
            known_hosts_path: None,
            connection_pool_size: Some(4),
            compression: false,
            keepalive_interval: Some(30),
            connect_timeout: Some(10),
        }
    }
}

/// SSH outbound connector — fully self-contained, no sb-core dependency.
#[derive(Clone)]
pub struct SshConnector {
    config: SshAdapterConfig,
    #[cfg(feature = "adapter-ssh")]
    pool: std::sync::Arc<tokio::sync::Mutex<SshPool>>,
}

#[cfg(feature = "adapter-ssh")]
struct SshPool {
    connections: Vec<std::sync::Arc<inner::SshConnection>>,
    rr: usize,
}

impl std::fmt::Debug for SshConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshConnector")
            .field("config", &self.config)
            .finish()
    }
}

impl SshConnector {
    pub fn new(config: SshAdapterConfig) -> Self {
        #[cfg(feature = "adapter-ssh")]
        {
            Self {
                config,
                pool: std::sync::Arc::new(tokio::sync::Mutex::new(SshPool {
                    connections: Vec::new(),
                    rr: 0,
                })),
            }
        }

        #[cfg(not(feature = "adapter-ssh"))]
        Self { config }
    }
}

impl Default for SshConnector {
    fn default() -> Self {
        Self::new(SshAdapterConfig::default())
    }
}

// ── Internals (behind feature gate) ──────────────────────────────────

#[cfg(feature = "adapter-ssh")]
mod inner {
    use super::*;
    use sha2::{Digest as ShaDigest, Sha256};
    use std::collections::HashMap;
    use std::io;
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{split, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::{mpsc, Mutex as AsyncMutex};

    // ── Known hosts verification ─────────────────────────────────────

    struct SshShared {
        rx_map: AsyncMutex<HashMap<russh::ChannelId, mpsc::Sender<Vec<u8>>>>,
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

    // ── SSH client handler ───────────────────────────────────────────

    struct SshClient {
        shared: Arc<SshShared>,
    }

    #[async_trait::async_trait]
    impl russh::client::Handler for SshClient {
        type Error = russh::Error;

        async fn check_server_key(
            &mut self,
            server_public_key: &ssh_key::PublicKey,
        ) -> Result<bool, Self::Error> {
            if !self.shared.verify {
                return Ok(true);
            }
            let host = &self.shared.host_id;
            let path_opt = &self.shared.known_hosts;
            let fp = {
                let s = format!("{:?}", server_public_key);
                let mut hasher = Sha256::new();
                hasher.update(s.as_bytes());
                hex::encode(hasher.finalize())
            };
            let ok = (|| -> Result<bool, ()> {
                let Some(path) = path_opt.as_ref() else {
                    return Ok(true);
                };
                if let Ok(txt) = std::fs::read_to_string(path) {
                    for line in txt.lines() {
                        let mut it = line.split_whitespace();
                        if let (Some(h), Some(stored)) = (it.next(), it.next()) {
                            if h == host {
                                return Ok(stored == fp);
                            }
                        }
                    }
                }
                // Not recorded: append (TOFU)
                if let Some(dir) = path.parent() {
                    let _ = std::fs::create_dir_all(dir);
                }
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                {
                    use std::io::Write;
                    let _ = f.write_all(format!("{} {}\n", host, fp).as_bytes());
                }
                Ok(true)
            })()
            .unwrap_or(true);
            Ok(ok)
        }

        async fn data(
            &mut self,
            channel: russh::ChannelId,
            data: &[u8],
            _session: &mut russh::client::Session,
        ) -> Result<(), Self::Error> {
            if let Some(tx) = self.shared.rx_map.lock().await.get(&channel).cloned() {
                let _ = tx.send(data.to_vec()).await;
            }
            Ok(())
        }

        async fn channel_close(
            &mut self,
            channel: russh::ChannelId,
            _session: &mut russh::client::Session,
        ) -> Result<(), Self::Error> {
            self.shared.rx_map.lock().await.remove(&channel);
            Ok(())
        }

        async fn channel_eof(
            &mut self,
            channel: russh::ChannelId,
            _session: &mut russh::client::Session,
        ) -> Result<(), Self::Error> {
            self.shared.rx_map.lock().await.remove(&channel);
            Ok(())
        }
    }

    // ── Connection wrapper ───────────────────────────────────────────

    pub(super) struct SshConnection {
        session: tokio::sync::Mutex<russh::client::Handle<SshClient>>,
        shared: Arc<SshShared>,
    }

    impl SshConnection {
        pub(super) async fn new(config: &SshAdapterConfig) -> anyhow::Result<Self> {
            let client_config = Arc::new(russh::client::Config::default());
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
                .map_err(|e| anyhow::anyhow!("Invalid SSH server address: {}", e))?;

            let timeout = Duration::from_secs(config.connect_timeout.unwrap_or(10));

            let mut session = tokio::time::timeout(
                timeout,
                russh::client::connect(client_config, server_addr, client_handler),
            )
            .await
            .map_err(|_| anyhow::anyhow!("SSH connection timeout"))?
            .map_err(|e| anyhow::anyhow!("SSH handshake failed: {}", e))?;

            // Authenticate
            let authenticated = if let Some(password) = &config.password {
                session
                    .authenticate_password(&config.username, password)
                    .await
                    .map_err(|e| anyhow::anyhow!("SSH password auth failed: {}", e))?
            } else if let Some(private_key_data) = &config.private_key {
                let private_key = if private_key_data.starts_with("-----BEGIN") {
                    russh_keys::decode_secret_key(
                        private_key_data,
                        config.private_key_passphrase.as_deref(),
                    )
                    .map_err(|e| anyhow::anyhow!("Failed to decode private key: {}", e))?
                } else {
                    russh_keys::load_secret_key(
                        private_key_data,
                        config.private_key_passphrase.as_deref(),
                    )
                    .map_err(|e| anyhow::anyhow!("Failed to load private key: {}", e))?
                };
                let key_with_hash = russh_keys::key::PrivateKeyWithHashAlg::new(
                    Arc::new(private_key),
                    None,
                ).map_err(|e| anyhow::anyhow!("Failed to create key hash alg: {}", e))?;
                session
                    .authenticate_publickey(&config.username, key_with_hash)
                    .await
                    .map_err(|e| anyhow::anyhow!("SSH pubkey auth failed: {}", e))?
            } else {
                return Err(anyhow::anyhow!("No SSH authentication method provided"));
            };

            if !authenticated {
                return Err(anyhow::anyhow!("SSH authentication failed"));
            }

            Ok(Self {
                session: tokio::sync::Mutex::new(session),
                shared,
            })
        }

        pub(super) async fn create_tunnel_tcp(
            &self,
            host: &str,
            port: u16,
        ) -> io::Result<TcpStream> {
            let session = self.session.lock().await;
            let channel = session
                .channel_open_direct_tcpip(host, port as u32, "127.0.0.1", 0)
                .await
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        format!("Failed to create SSH tunnel: {}", e),
                    )
                })?;
            drop(session);

            // Register data receiver for this channel
            let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);
            {
                let mut map = self.shared.rx_map.lock().await;
                map.insert(channel.id(), tx);
            }

            // Bridge via local loopback
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;

            tokio::spawn(async move {
                let (sock, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => return,
                };
                let (mut rd, mut wr) = split(sock);
                let ch_writer = channel;
                // local → SSH channel
                let a = async {
                    let _ = ch_writer.data(&mut rd).await;
                    let _ = ch_writer.eof().await;
                };
                // SSH channel → local
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

            TcpStream::connect(addr).await
        }
    }

    impl SshConnector {
        pub(super) async fn get_or_create_connection(
            &self,
        ) -> anyhow::Result<Arc<SshConnection>> {
            let pool_size = self.config.connection_pool_size.unwrap_or(4).max(1);
            let mut pool = self.pool.lock().await;
            if pool.connections.len() < pool_size {
                let conn = Arc::new(SshConnection::new(&self.config).await?);
                pool.connections.push(conn.clone());
                return Ok(conn);
            }
            let idx = pool.rr % pool.connections.len();
            pool.rr = pool.rr.wrapping_add(1);
            Ok(pool.connections[idx].clone())
        }
    }
}

// ── OutboundConnector impl ───────────────────────────────────────────

#[async_trait]
impl OutboundConnector for SshConnector {
    fn name(&self) -> &'static str {
        "ssh"
    }

    async fn start(&self) -> Result<()> {
        #[cfg(not(feature = "adapter-ssh"))]
        return Err(AdapterError::NotImplemented {
            what: "adapter-ssh",
        });

        #[cfg(feature = "adapter-ssh")]
        {
            if self.config.server.is_empty() {
                return Err(AdapterError::InvalidConfig(
                    "SSH server address is required",
                ));
            }
            if self.config.username.is_empty() {
                return Err(AdapterError::InvalidConfig("SSH username is required"));
            }
            if self.config.password.is_none() && self.config.private_key.is_none() {
                return Err(AdapterError::InvalidConfig(
                    "Either SSH password or private key is required",
                ));
            }

            tracing::info!(
                server = %self.config.server,
                port = self.config.port,
                username = %self.config.username,
                has_password = self.config.password.is_some(),
                has_private_key = self.config.private_key.is_some(),
                host_key_verification = self.config.host_key_verification,
                pool_size = ?self.config.connection_pool_size,
                "SSH outbound connector initialized"
            );

            Ok(())
        }
    }

    async fn dial(&self, target: Target, _opts: DialOpts) -> Result<BoxedStream> {
        #[cfg(not(feature = "adapter-ssh"))]
        return Err(AdapterError::NotImplemented {
            what: "adapter-ssh",
        });

        #[cfg(feature = "adapter-ssh")]
        {
            let _span = crate::outbound::span_dial("ssh", &target);

            #[cfg(feature = "metrics")]
            let start_time = sb_metrics::start_adapter_timer();

            if target.kind != TransportKind::Tcp {
                return Err(AdapterError::Protocol(
                    "SSH only supports TCP connections".to_string(),
                ));
            }

            let dial_result = async {
                let conn = self
                    .get_or_create_connection()
                    .await
                    .map_err(|e| AdapterError::Network(format!("SSH connection failed: {}", e)))?;

                let stream = conn
                    .create_tunnel_tcp(&target.host, target.port)
                    .await
                    .map_err(|e| AdapterError::Network(format!("SSH tunnel failed: {}", e)))?;

                Ok(stream)
            }
            .await;

            #[cfg(feature = "metrics")]
            {
                let result = match &dial_result {
                    Ok(_) => Ok(()),
                    Err(e) => Err(e as &dyn core::fmt::Display),
                };
                sb_metrics::record_adapter_dial("ssh", start_time, result);
            }

            match dial_result {
                Ok(stream) => {
                    tracing::debug!(
                        server = %self.config.server,
                        target = %format!("{}:{}", target.host, target.port),
                        "SSH tunnel established"
                    );
                    Ok(Box::new(stream) as BoxedStream)
                }
                Err(e) => {
                    tracing::debug!(
                        server = %self.config.server,
                        target = %format!("{}:{}", target.host, target.port),
                        error = %e,
                        "SSH tunnel failed"
                    );
                    Err(e)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssh_config_default() {
        let config = SshAdapterConfig::default();
        assert_eq!(config.port, 22);
        assert!(config.host_key_verification);
        assert_eq!(config.connection_pool_size, Some(4));
    }

    #[test]
    fn test_ssh_connector_creation() {
        let config = SshAdapterConfig {
            server: "ssh.example.com".to_string(),
            port: 22,
            username: "testuser".to_string(),
            password: Some("testpass".to_string()),
            ..Default::default()
        };

        let connector = SshConnector::new(config);
        assert_eq!(connector.name(), "ssh");
    }

    #[cfg(feature = "adapter-ssh")]
    #[tokio::test]
    async fn test_ssh_start_validation() {
        // Test missing server
        let config = SshAdapterConfig {
            server: String::new(),
            username: "user".to_string(),
            password: Some("pass".to_string()),
            ..Default::default()
        };
        let connector = SshConnector::new(config);
        assert!(connector.start().await.is_err());

        // Test missing username
        let config = SshAdapterConfig {
            server: "ssh.example.com".to_string(),
            username: String::new(),
            password: Some("pass".to_string()),
            ..Default::default()
        };
        let connector = SshConnector::new(config);
        assert!(connector.start().await.is_err());

        // Test missing auth
        let config = SshAdapterConfig {
            server: "ssh.example.com".to_string(),
            username: "user".to_string(),
            password: None,
            private_key: None,
            ..Default::default()
        };
        let connector = SshConnector::new(config);
        assert!(connector.start().await.is_err());
    }
}
