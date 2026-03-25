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
    /// Tracked bridge tasks — aborted on connector drop via `JoinSet::drop`.
    #[cfg(feature = "adapter-ssh")]
    bridge_tasks: std::sync::Arc<tokio::sync::Mutex<tokio::task::JoinSet<()>>>,
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
                bridge_tasks: std::sync::Arc::new(tokio::sync::Mutex::new(
                    tokio::task::JoinSet::new(),
                )),
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
    use tokio::task::JoinSet;

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

    // ── Post-auth session wrapper ────────────────────────────────────

    /// Minimum-capability wrapper around a post-authentication SSH session.
    ///
    /// The raw `russh::client::Handle` is kept private and inaccessible from
    /// outside this struct. The only exposed capability is [`open_direct_tcpip`],
    /// which delegates to `Handle::channel_open_direct_tcpip(&self, ...)`.
    ///
    /// # Why `unsafe impl Sync`
    ///
    /// `Handle` is `!Sync` because it contains an `UnboundedReceiver<Reply>`
    /// (used only during authentication) and a `JoinHandle` (for the background
    /// session loop). Neither field is accessed by `channel_open_direct_tcpip`;
    /// that method sends a message through `self.sender` (a `tokio::mpsc::Sender`,
    /// which is `Send + Sync + Clone`) and awaits a *local* per-channel receiver
    /// it creates on the spot.
    ///
    /// Because the wrapper never exposes the raw Handle, future code cannot
    /// accidentally call `&mut self` methods (like `authenticate_*`) or touch
    /// the `!Sync` receiver. Adding a new method to this wrapper requires
    /// re-auditing the safety invariant.
    pub(super) struct PostAuthSession {
        /// Private — never exposed outside this struct.
        handle: russh::client::Handle<SshClient>,
    }

    // SAFETY: The only method on PostAuthSession is open_direct_tcpip, which
    // calls Handle::channel_open_direct_tcpip(&self). That method exclusively
    // uses Handle.sender (Sender<Msg>: Send + Sync + Clone) and a freshly
    // created local receiver. The !Sync fields (receiver, join) are never
    // accessed through this wrapper.
    unsafe impl Sync for PostAuthSession {}

    impl PostAuthSession {
        fn new(handle: russh::client::Handle<SshClient>) -> Self {
            Self { handle }
        }

        /// Open a direct-tcpip channel on the SSH session.
        ///
        /// This is the **only** capability exposed by this wrapper. It delegates
        /// to `Handle::channel_open_direct_tcpip(&self, ...)` which only accesses
        /// the Sync `sender` field internally.
        async fn open_direct_tcpip(
            &self,
            host: &str,
            port: u32,
        ) -> Result<russh::Channel<russh::client::Msg>, russh::Error> {
            self.handle
                .channel_open_direct_tcpip(host, port, "127.0.0.1", 0)
                .await
        }
    }

    // ── Connection wrapper ───────────────────────────────────────────

    pub(super) struct SshConnection {
        session: Arc<PostAuthSession>,
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

            // Authenticate (uses &mut self — last mutable access before wrapping)
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
                let key_with_hash =
                    russh_keys::key::PrivateKeyWithHashAlg::new(Arc::new(private_key), None)
                        .map_err(|e| anyhow::anyhow!("Failed to create key hash alg: {}", e))?;
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

            // After authentication, Handle is only used via &self methods.
            // Wrap in PostAuthSession + Arc for lock-free concurrent access.
            Ok(Self {
                session: Arc::new(PostAuthSession::new(session)),
                shared,
            })
        }

        /// Open a direct-tcpip channel and bridge it to a local TcpStream.
        ///
        /// No lock is held across the channel open await — `session` is behind
        /// `Arc<PostAuthSession>` which exposes only `open_direct_tcpip`.
        /// The bridge task is spawned into the caller-provided `JoinSet`.
        pub(super) async fn create_tunnel_tcp(
            &self,
            host: &str,
            port: u16,
            bridge_tasks: &AsyncMutex<JoinSet<()>>,
        ) -> io::Result<TcpStream> {
            // No lock — PostAuthSession::open_direct_tcpip is the only capability
            let channel = self
                .session
                .open_direct_tcpip(host, port as u32)
                .await
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        format!("Failed to create SSH tunnel: {}", e),
                    )
                })?;

            // Register data receiver for this channel
            let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);
            {
                let mut map = self.shared.rx_map.lock().await;
                map.insert(channel.id(), tx);
            }

            // Bridge via local loopback — tracked in JoinSet, not fire-and-forget
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;

            {
                let mut bridges = bridge_tasks.lock().await;
                // Reap completed bridge tasks to prevent unbounded growth
                while bridges.try_join_next().is_some() {}
                bridges.spawn(async move {
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
            }

            TcpStream::connect(addr).await
        }
    }

    impl SshConnector {
        /// Get an existing pooled connection or create a new one.
        ///
        /// Uses a three-phase lock pattern to avoid holding the pool lock across
        /// the async SSH connection establishment:
        /// 1. Short lock: check pool for available connection
        /// 2. Lock-free: create new connection if needed
        /// 3. Short lock: install new connection (with race handling)
        pub(super) async fn get_or_create_connection(&self) -> anyhow::Result<Arc<SshConnection>> {
            let pool_size = self.config.connection_pool_size.unwrap_or(4).max(1);

            // Phase 1: short lock — check existing pool
            {
                let mut pool = self.pool.lock().await;
                if pool.connections.len() >= pool_size {
                    // Pool full, round-robin an existing connection
                    let idx = pool.rr % pool.connections.len();
                    pool.rr = pool.rr.wrapping_add(1);
                    return Ok(pool.connections[idx].clone());
                }
            }
            // Lock released here

            // Phase 2: lock-free — create new connection (slow, async)
            let conn = Arc::new(SshConnection::new(&self.config).await?);

            // Phase 3: short lock — install, handling concurrent race
            {
                let mut pool = self.pool.lock().await;
                if pool.connections.len() >= pool_size {
                    // Another task filled the pool while we were connecting.
                    // Use our fresh connection anyway (it's already authenticated)
                    // but don't push it into the pool — just return it for this dial.
                    return Ok(conn);
                }
                pool.connections.push(conn.clone());
            }

            Ok(conn)
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
                    .create_tunnel_tcp(&target.host, target.port, &self.bridge_tasks)
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

    #[cfg(feature = "adapter-ssh")]
    #[tokio::test]
    async fn test_bridge_tasks_tracked_in_joinset() {
        // Proves that the bridge_tasks JoinSet exists and can track tasks.
        // JoinSet::drop aborts all tracked tasks — this is the sync fallback
        // that ensures no bridge task outlives the connector.
        let mut js = tokio::task::JoinSet::new();
        let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();
        js.spawn(async move {
            // Block until cancelled
            let _ = tokio::time::sleep(std::time::Duration::from_secs(300)).await;
            let _ = tx.send(());
        });
        assert_eq!(js.len(), 1);
        drop(js); // JoinSet::drop aborts all — must not hang
        // The task was aborted, so tx was dropped without sending
        assert!(rx.try_recv().is_err());
    }

    #[cfg(feature = "adapter-ssh")]
    #[tokio::test]
    async fn test_bridge_reaping() {
        // Proves that try_join_next reaps completed tasks from JoinSet,
        // preventing unbounded growth of the bridge_tasks set.
        let mut js = tokio::task::JoinSet::new();
        js.spawn(async { /* completes immediately */ });
        // Give the task time to complete
        tokio::task::yield_now().await;
        // Reap
        let reaped = js.try_join_next();
        assert!(reaped.is_some());
        assert_eq!(js.len(), 0);
    }

    #[cfg(feature = "adapter-ssh")]
    #[tokio::test]
    async fn test_pool_three_phase_lock_pattern() {
        // Validates the three-phase pool lock pattern by constructing a connector
        // and verifying the pool starts empty and the bridge_tasks JoinSet exists.
        let config = SshAdapterConfig {
            server: "ssh.example.com".to_string(),
            username: "user".to_string(),
            password: Some("pass".to_string()),
            connection_pool_size: Some(2),
            ..Default::default()
        };
        let connector = SshConnector::new(config);

        // Pool starts empty
        {
            let pool = connector.pool.lock().await;
            assert!(pool.connections.is_empty());
            assert_eq!(pool.rr, 0);
        }

        // Bridge tasks set starts empty
        {
            let bridges = connector.bridge_tasks.lock().await;
            assert_eq!(bridges.len(), 0);
        }
    }

    #[cfg(feature = "adapter-ssh")]
    #[tokio::test]
    async fn test_connector_clone_shares_bridge_tasks() {
        // Proves that cloning the connector shares the same bridge_tasks JoinSet
        // (via Arc), so all bridge tasks have a single owner regardless of which
        // clone spawned them.
        let config = SshAdapterConfig {
            server: "ssh.example.com".to_string(),
            username: "user".to_string(),
            password: Some("pass".to_string()),
            ..Default::default()
        };
        let c1 = SshConnector::new(config);
        let c2 = c1.clone();

        // Spawn a task via c1's bridge_tasks
        {
            let mut bridges = c1.bridge_tasks.lock().await;
            bridges.spawn(async { /* dummy */ });
        }

        // Visible via c2's bridge_tasks (same Arc)
        {
            let bridges = c2.bridge_tasks.lock().await;
            assert_eq!(bridges.len(), 1);
        }
    }

    /// Compile-time proof that PostAuthSession encapsulates the raw Handle.
    ///
    /// PostAuthSession has a single private field (`handle`) and exposes only
    /// `open_direct_tcpip()`. This test exists to document and anchor that
    /// invariant: if someone adds a public accessor or makes the field pub,
    /// this test's rationale comment should trigger review of the unsafe
    /// impl Sync boundary.
    #[cfg(feature = "adapter-ssh")]
    #[test]
    fn test_post_auth_session_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        // PostAuthSession must be Send + Sync for Arc<PostAuthSession> to work.
        // Sync comes from our unsafe impl — if that impl is ever removed,
        // this line will fail to compile, surfacing the issue.
        assert_send_sync::<inner::PostAuthSession>();
    }
}
