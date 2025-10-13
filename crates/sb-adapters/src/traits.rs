//! Unified traits and interfaces for all adapters

use crate::error::Result;
use async_trait::async_trait;
use rand::Rng;
use std::{fmt::Debug, fmt::Display, str::FromStr, time::Duration};

/// Retry policy for connection attempts
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Maximum number of retry attempts (0 = no retries)
    pub max_retries: u32,
    /// Base delay in milliseconds for exponential backoff
    pub base_delay_ms: u64,
    /// Jitter factor (0.0 - 1.0) to add randomness to delays
    pub jitter: f32,
    /// Maximum delay cap in milliseconds
    pub max_delay_ms: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 2,
            base_delay_ms: 100,
            jitter: 0.1,
            max_delay_ms: 5000,
        }
    }
}

impl RetryPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    pub fn with_base_delay(mut self, delay_ms: u64) -> Self {
        self.base_delay_ms = delay_ms;
        self
    }

    pub fn with_jitter(mut self, jitter: f32) -> Self {
        self.jitter = jitter.clamp(0.0, 1.0);
        self
    }

    pub fn with_max_delay(mut self, max_delay_ms: u64) -> Self {
        self.max_delay_ms = max_delay_ms;
        self
    }

    /// Calculate delay for a given attempt (0-indexed)
    pub fn calculate_delay(&self, attempt: u32) -> Duration {
        if attempt == 0 {
            return Duration::from_millis(0);
        }

        // Exponential backoff: base_delay * 2^(attempt-1)
        let base_delay = self.base_delay_ms as f64;
        let exponential_delay = base_delay * 2.0_f64.powi((attempt - 1) as i32);

        // Apply jitter
        let mut rng = rand::thread_rng();
        let jitter_factor = 1.0 + (rng.gen::<f32>() - 0.5) * 2.0 * self.jitter;
        let delay_with_jitter = exponential_delay * jitter_factor as f64;

        // Cap at max delay
        let final_delay = delay_with_jitter.min(self.max_delay_ms as f64) as u64;
        Duration::from_millis(final_delay)
    }
}

/// DNS resolution mode
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveMode {
    /// Resolve locally and send IP to proxy
    Local,
    /// Send domain name to proxy for remote resolution
    Remote,
}

impl Default for ResolveMode {
    fn default() -> Self {
        Self::Remote
    }
}

impl Display for ResolveMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Local => write!(f, "local"),
            Self::Remote => write!(f, "remote"),
        }
    }
}

impl FromStr for ResolveMode {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "local" => Ok(Self::Local),
            "remote" => Ok(Self::Remote),
            _ => Err(format!(
                "Invalid resolve mode: {}. Valid options: local, remote",
                s
            )),
        }
    }
}

#[cfg(feature = "clap")]
impl clap::ValueEnum for ResolveMode {
    fn value_variants<'a>() -> &'a [Self] {
        &[Self::Local, Self::Remote]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(match self {
            Self::Local => clap::builder::PossibleValue::new("local"),
            Self::Remote => clap::builder::PossibleValue::new("remote"),
        })
    }
}

/// Dial options for connection requests
#[derive(Debug, Clone)]
pub struct DialOpts {
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub retry_policy: RetryPolicy,
    pub resolve_mode: ResolveMode,
}

impl Default for DialOpts {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(30),
            retry_policy: RetryPolicy::default(),
            resolve_mode: ResolveMode::default(),
        }
    }
}

impl DialOpts {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    pub fn with_read_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = timeout;
        self
    }

    pub fn with_retry_policy(mut self, retry_policy: RetryPolicy) -> Self {
        self.retry_policy = retry_policy;
        self
    }

    pub fn with_resolve_mode(mut self, resolve_mode: ResolveMode) -> Self {
        self.resolve_mode = resolve_mode;
        self
    }
}

/// Transport type for connection requests
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportKind {
    Tcp,
    Udp,
}

/// Connection target specification
#[derive(Debug, Clone)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub kind: TransportKind,
}

impl Target {
    pub fn new(host: impl Into<String>, port: u16, kind: TransportKind) -> Self {
        Self {
            host: host.into(),
            port,
            kind,
        }
    }

    pub fn tcp(host: impl Into<String>, port: u16) -> Self {
        Self::new(host, port, TransportKind::Tcp)
    }

    pub fn udp(host: impl Into<String>, port: u16) -> Self {
        Self::new(host, port, TransportKind::Udp)
    }
}

/// Boxed async stream for connections (temporary abstraction)
pub type BoxedStream = Box<dyn AsyncStream>;

/// Combined trait for async read + write + unpin + send + sync
pub trait AsyncStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync {}

/// Blanket implementation for any type that implements the required traits
impl<T> AsyncStream for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync
{}

/// Lightweight UDP abstraction for outbound datagram connections
/// Provides optional packet-level interface without breaking existing dial() API
#[async_trait]
pub trait OutboundDatagram: Send + Sync + Debug {
    /// Send data to the remote target
    async fn send_to(&self, payload: &[u8]) -> Result<usize>;

    /// Receive data from the remote target
    async fn recv_from(&self, buf: &mut [u8]) -> Result<usize>;

    /// Close the datagram connection
    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

/// Unified outbound connector trait for all adapters
#[async_trait]
pub trait OutboundConnector: Send + Sync + Debug {
    /// Initialize the connector (load certificates, resolve DNS, etc.)
    async fn start(&self) -> Result<()> {
        Ok(())
    }

    /// Establish connection to target
    async fn dial(&self, target: Target, opts: DialOpts) -> Result<BoxedStream>;

    /// Get connector type/name for logging
    fn name(&self) -> &'static str {
        "unknown"
    }
}

/// Check if an error is retryable
pub fn is_retryable_error(error: &crate::error::AdapterError) -> bool {
    use crate::error::AdapterError;

    match error {
        // Network/IO errors are generally retryable
        AdapterError::Io(io_err) => {
            use std::io::ErrorKind;
            matches!(
                io_err.kind(),
                ErrorKind::TimedOut
                    | ErrorKind::ConnectionRefused
                    | ErrorKind::ConnectionReset
                    | ErrorKind::ConnectionAborted
                    | ErrorKind::NotConnected
                    | ErrorKind::AddrInUse
                    | ErrorKind::AddrNotAvailable
                    | ErrorKind::Interrupted
                    | ErrorKind::WouldBlock
            )
        }
        // Timeout errors are retryable
        AdapterError::Timeout(_) => true,

        // Network errors might be retryable depending on context
        AdapterError::Network(_) => true,

        // Protocol errors usually aren't retryable (authentication, handshake failures)
        AdapterError::InvalidConfig(_)
        | AdapterError::UnsupportedProtocol(_)
        | AdapterError::AuthenticationFailed
        | AdapterError::Protocol(_) => false,

        // Other errors might be retryable depending on context
        AdapterError::Other(_) => false,
        AdapterError::NotImplemented { .. } => false,
    }
}

/// Retry a future with exponential backoff and jitter
pub async fn with_retry<F, Fut, T>(retry_policy: &RetryPolicy, mut operation: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let mut last_error = None;

    for attempt in 0..=(retry_policy.max_retries) {
        // Add delay before retry (but not before first attempt)
        if attempt > 0 {
            let delay = retry_policy.calculate_delay(attempt);
            if delay > Duration::from_millis(0) {
                tokio::time::sleep(delay).await;
            }
        }

        match operation().await {
            Ok(result) => return Ok(result),
            Err(error) => {
                last_error = Some(error.clone());

                // Don't retry if this is the last attempt or error is not retryable
                if attempt >= retry_policy.max_retries || !is_retryable_error(&error) {
                    break;
                }

                // Log retry attempt
                #[cfg(feature = "metrics")]
                {
                    // Note: adapter name will be provided by the caller through context if needed
                    // For now, we'll use a generic label - specific adapters should call their own metrics
                }

                tracing::debug!(
                    "Retry attempt {} after error: {} (will retry in {:?})",
                    attempt + 1,
                    error,
                    retry_policy.calculate_delay(attempt + 1)
                );
            }
        }
    }

    Err(last_error.unwrap_or_else(|| crate::error::AdapterError::Other("retry failed".into())))
}

/// Retry a future with exponential backoff and jitter, with adapter metrics
#[cfg(feature = "metrics")]
pub async fn with_adapter_retry<F, Fut, T>(
    retry_policy: &RetryPolicy,
    adapter_name: &'static str,
    mut operation: F,
) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let mut last_error = None;

    for attempt in 0..=(retry_policy.max_retries) {
        // Add delay before retry (but not before first attempt)
        if attempt > 0 {
            let delay = retry_policy.calculate_delay(attempt);
            if delay > Duration::from_millis(0) {
                tokio::time::sleep(delay).await;
            }

            // Record retry attempt
            sb_metrics::inc_adapter_retries_total(adapter_name);
        }

        match operation().await {
            Ok(result) => return Ok(result),
            Err(error) => {
                last_error = Some(error.clone());

                // Don't retry if this is the last attempt or error is not retryable
                if attempt >= retry_policy.max_retries || !is_retryable_error(&error) {
                    break;
                }

                tracing::debug!(
                    adapter = adapter_name,
                    "Retry attempt {} after error: {} (will retry in {:?})",
                    attempt + 1,
                    error,
                    retry_policy.calculate_delay(attempt + 1)
                );
            }
        }
    }

    Err(last_error.unwrap_or_else(|| crate::error::AdapterError::Other("retry failed".into())))
}
