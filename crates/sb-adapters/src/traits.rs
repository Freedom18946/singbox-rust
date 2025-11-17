//! Unified traits and interfaces for all adapters.
//!
//! This module defines the core abstractions used throughout the adapter layer:
//!
//! - [`OutboundConnector`]: Trait for outbound proxy adapters
//! - [`OutboundDatagram`]: Trait for UDP-based connections
//! - [`Target`]: Specification of connection destination
//! - [`RetryPolicy`]: Configurable retry with exponential backoff
//! - [`DialOpts`]: Connection options (timeouts, retry, DNS mode)
//! - [`ResolveMode`]: DNS resolution strategy (local vs remote)

use crate::error::Result;
use async_trait::async_trait;
use rand::Rng;
use std::any::Any;
use std::{fmt::Debug, fmt::Display, str::FromStr, time::Duration};

/// Retry policy for connection attempts with exponential backoff and jitter.
///
/// # Examples
///
/// ```rust,ignore
/// use sb_adapters::traits::RetryPolicy;
/// use std::time::Duration;
///
/// let policy = RetryPolicy::new()
///     .with_max_retries(3)
///     .with_base_delay(200)
///     .with_jitter(0.2);
///
/// assert_eq!(policy.calculate_delay(0), Duration::from_millis(0));
/// ```
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Maximum number of retry attempts (0 = no retries).
    pub max_retries: u32,

    /// Base delay in milliseconds for exponential backoff.
    pub base_delay_ms: u64,

    /// Jitter factor (0.0 - 1.0) to add randomness to delays.
    pub jitter: f32,

    /// Maximum delay cap in milliseconds.
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
    /// Creates a new retry policy with default values.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use sb_adapters::traits::RetryPolicy;
    ///
    /// let policy = RetryPolicy::new();
    /// assert_eq!(policy.max_retries, 2);
    /// assert_eq!(policy.base_delay_ms, 100);
    /// ```
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the maximum number of retry attempts.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use sb_adapters::traits::RetryPolicy;
    ///
    /// let policy = RetryPolicy::new().with_max_retries(5);
    /// assert_eq!(policy.max_retries, 5);
    /// ```
    #[inline]
    #[must_use]
    pub fn with_max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    /// Sets the base delay for exponential backoff.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use sb_adapters::traits::RetryPolicy;
    ///
    /// let policy = RetryPolicy::new().with_base_delay(200);
    /// assert_eq!(policy.base_delay_ms, 200);
    /// ```
    #[inline]
    #[must_use]
    pub fn with_base_delay(mut self, delay_ms: u64) -> Self {
        self.base_delay_ms = delay_ms;
        self
    }

    /// Sets the jitter factor (clamped to 0.0 - 1.0).
    ///
    /// Jitter adds randomness to retry delays to avoid thundering herd problems.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use sb_adapters::traits::RetryPolicy;
    ///
    /// let policy = RetryPolicy::new().with_jitter(0.3);
    /// assert_eq!(policy.jitter, 0.3);
    /// ```
    #[inline]
    #[must_use]
    pub fn with_jitter(mut self, jitter: f32) -> Self {
        self.jitter = jitter.clamp(0.0, 1.0);
        self
    }

    /// Sets the maximum delay cap.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use sb_adapters::traits::RetryPolicy;
    ///
    /// let policy = RetryPolicy::new().with_max_delay(10_000);
    /// assert_eq!(policy.max_delay_ms, 10_000);
    /// ```
    #[inline]
    #[must_use]
    pub fn with_max_delay(mut self, max_delay_ms: u64) -> Self {
        self.max_delay_ms = max_delay_ms;
        self
    }

    /// Calculates delay for a given attempt (0-indexed).
    ///
    /// Uses exponential backoff formula: `base_delay * 2^(attempt-1)` with jitter.
    ///
    /// # Algorithm
    ///
    /// 1. For attempt 0, return 0ms (no delay before first try)
    /// 2. Calculate base delay: `base_delay_ms * 2^(attempt-1)`
    /// 3. Apply jitter: multiply by random factor in `[1-jitter, 1+jitter]`
    /// 4. Cap at `max_delay_ms`
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use sb_adapters::traits::RetryPolicy;
    /// use std::time::Duration;
    ///
    /// let policy = RetryPolicy::new().with_base_delay(100).with_jitter(0.0);
    /// assert_eq!(policy.calculate_delay(0), Duration::from_millis(0));
    /// assert_eq!(policy.calculate_delay(1), Duration::from_millis(100));
    /// assert_eq!(policy.calculate_delay(2), Duration::from_millis(200));
    /// assert_eq!(policy.calculate_delay(3), Duration::from_millis(400));
    /// ```
    #[must_use]
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
        let delay_with_jitter = exponential_delay * f64::from(jitter_factor);

        // Cap at max delay
        let final_delay = delay_with_jitter.min(self.max_delay_ms as f64) as u64;
        Duration::from_millis(final_delay)
    }
}

/// DNS resolution mode for proxy connections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveMode {
    /// Resolve domain names locally and send IP addresses to the proxy.
    Local,

    /// Send domain names to the proxy for remote resolution.
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
                "Invalid resolve mode: {s}. Valid options: local, remote"
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

/// Dial options for connection requests.
///
/// Configures timeouts, retry behavior, and DNS resolution mode for outbound connections.
#[derive(Debug, Clone)]
pub struct DialOpts {
    /// Connection establishment timeout.
    pub connect_timeout: Duration,

    /// Read operation timeout.
    pub read_timeout: Duration,

    /// Retry policy for failed connection attempts.
    pub retry_policy: RetryPolicy,

    /// DNS resolution mode (local or remote).
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
    /// Creates new dial options with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the connection timeout.
    #[must_use]
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Sets the read timeout.
    #[must_use]
    pub fn with_read_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = timeout;
        self
    }

    /// Sets the retry policy.
    #[must_use]
    pub fn with_retry_policy(mut self, retry_policy: RetryPolicy) -> Self {
        self.retry_policy = retry_policy;
        self
    }

    /// Sets the DNS resolution mode.
    #[must_use]
    pub fn with_resolve_mode(mut self, resolve_mode: ResolveMode) -> Self {
        self.resolve_mode = resolve_mode;
        self
    }
}

/// Transport type for connection requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportKind {
    /// TCP connection.
    Tcp,

    /// UDP connection.
    Udp,
}

/// Connection target specification.
///
/// Specifies the destination host, port, and transport protocol for a connection.
#[derive(Debug, Clone)]
pub struct Target {
    /// Target hostname or IP address.
    pub host: String,

    /// Target port number.
    pub port: u16,

    /// Transport protocol (TCP or UDP).
    pub kind: TransportKind,
}

impl Target {
    /// Creates a new connection target.
    #[must_use]
    pub fn new(host: impl Into<String>, port: u16, kind: TransportKind) -> Self {
        Self {
            host: host.into(),
            port,
            kind,
        }
    }

    /// Creates a TCP connection target.
    #[must_use]
    pub fn tcp(host: impl Into<String>, port: u16) -> Self {
        Self::new(host, port, TransportKind::Tcp)
    }

    /// Creates a UDP connection target.
    #[must_use]
    pub fn udp(host: impl Into<String>, port: u16) -> Self {
        Self::new(host, port, TransportKind::Udp)
    }
}

/// Boxed async stream for connections.
///
/// Temporary abstraction over `AsyncRead + AsyncWrite` traits.
pub type BoxedStream = Box<dyn AsyncStream>;

/// Combined trait for async read + write + unpin + send + sync.
pub trait AsyncStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

/// Blanket implementation for any type that implements the required traits.
impl<T> AsyncStream for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

/// Converts a transport `IoStream` to `BoxedStream`.
///
/// This function bridges `sb-transport` (which uses `AsyncReadWrite` trait)
/// and `sb-adapters` (which uses `AsyncStream` trait). Both traits have identical
/// bounds, so this is a safe zero-cost conversion via a wrapper struct.
#[cfg(feature = "sb-transport")]
#[must_use]
pub fn from_transport_stream(stream: sb_transport::dialer::IoStream) -> BoxedStream {
    Box::new(TransportStreamAdapter { inner: stream })
}

/// Adapter to convert `sb-transport` streams to `AsyncStream`.
#[cfg(feature = "sb-transport")]
struct TransportStreamAdapter {
    inner: sb_transport::dialer::IoStream,
}

#[cfg(feature = "sb-transport")]
impl tokio::io::AsyncRead for TransportStreamAdapter {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

#[cfg(feature = "sb-transport")]
impl tokio::io::AsyncWrite for TransportStreamAdapter {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Helper trait to enable downcasting from trait objects.
pub trait DynDowncast: Any {
    /// Returns `self` as `&dyn Any` for downcasting.
    fn as_any(&self) -> &dyn Any;
}

impl<T: Any> DynDowncast for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Lightweight UDP abstraction for outbound datagram connections.
///
/// Provides a packet-level interface for UDP-based proxy protocols
/// without breaking the existing `dial()` API.
#[async_trait]
pub trait OutboundDatagram: DynDowncast + Send + Sync + Debug {
    /// Sends data to the remote target.
    ///
    /// # Errors
    ///
    /// Returns an error if the send operation fails.
    async fn send_to(&self, payload: &[u8]) -> Result<usize>;

    /// Receives data from the remote target.
    ///
    /// # Errors
    ///
    /// Returns an error if the receive operation fails.
    async fn recv_from(&self, buf: &mut [u8]) -> Result<usize>;

    /// Closes the datagram connection.
    ///
    /// Default implementation does nothing (stateless UDP).
    ///
    /// # Errors
    ///
    /// Returns an error if the close operation fails.
    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

/// Unified outbound connector trait for all adapters.
///
/// This trait defines the interface for client-side proxy adapters
/// that establish outbound connections to remote servers.
#[async_trait]
pub trait OutboundConnector: Send + Sync + Debug {
    /// Initializes the connector (loads certificates, resolves DNS, etc.).
    ///
    /// Called once before the connector is used. Default implementation does nothing.
    ///
    /// # Errors
    ///
    /// Returns an error if initialization fails.
    async fn start(&self) -> Result<()> {
        Ok(())
    }

    /// Establishes a connection to the target.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection fails or times out.
    async fn dial(&self, target: Target, opts: DialOpts) -> Result<BoxedStream>;

    /// Returns the connector type/name for logging and metrics.
    fn name(&self) -> &'static str {
        "unknown"
    }
}

/// Checks if an error is retryable.
///
/// Network and I/O errors are generally retryable, while protocol and
/// authentication errors are not.
///
/// # Examples
///
/// ```rust,ignore
/// use sb_adapters::error::AdapterError;
/// use sb_adapters::traits::is_retryable_error;
/// use std::time::Duration;
///
/// let timeout_err = AdapterError::Timeout(Duration::from_secs(5));
/// assert!(is_retryable_error(&timeout_err));
///
/// let auth_err = AdapterError::AuthenticationFailed;
/// assert!(!is_retryable_error(&auth_err));
/// ```
#[inline]
#[must_use]
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
        | AdapterError::Protocol(_)
        | AdapterError::Other(_)
        | AdapterError::NotImplemented { .. } => false,
    }
}

/// Retries a future with exponential backoff and jitter.
///
/// # Errors
///
/// Returns the last error encountered if all retry attempts fail.
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

                tracing::debug!(
                    "Retry attempt {} after error: {} (will retry in {:?})",
                    attempt + 1,
                    error,
                    retry_policy.calculate_delay(attempt + 1)
                );
            }
        }
    }

    // Return last error (should always be Some after loop executes at least once)
    Err(last_error.unwrap_or_else(|| {
        crate::error::AdapterError::other("retry loop completed without executing operation")
    }))
}

/// Retries a future with exponential backoff, jitter, and adapter metrics.
///
/// # Errors
///
/// Returns the last error encountered if all retry attempts fail.
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

    // Return last error (should always be Some after loop executes at least once)
    Err(last_error.unwrap_or_else(|| {
        crate::error::AdapterError::other("retry loop completed without executing operation")
    }))
}
