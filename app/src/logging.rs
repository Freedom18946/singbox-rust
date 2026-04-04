//! Configurable logging pipeline with JSON/compact formats, sampling, and exit flush
//! 可配置的日志管道，支持 JSON/紧凑格式、采样和退出刷新
//!
//! # Global Strategic Logic / 全局战略逻辑
//! This module implements the **Observability Pipeline** for logs.
//! 本模块实现了日志的 **可观测性管道**。
//!
//! ## Pipeline Architecture / 管道架构
//! `Log Event` -> `Filter (Level)` -> `Sampler (Rate Limit)` -> `Formatter (JSON/Compact)` -> `Redactor (Privacy)` -> `Output (Stderr)`
//! `日志事件` -> `过滤器 (级别)` -> `采样器 (速率限制)` -> `格式化器 (JSON/紧凑)` -> `脱敏器 (隐私)` -> `输出 (Stderr)`
//!
//! ## Strategic Features / 战略特性
//! 1. **Sampling / 采样**: Prevents log flooding (e.g., during network storms) from degrading performance.
//!    防止日志泛滥（例如在网络风暴期间）降低性能。
//! 2. **Redaction / 脱敏**: Automatically masks sensitive data (like private keys or tokens) before output.
//!    在输出前自动掩盖敏感数据（如私钥或令牌）。
//! 3. **Graceful Flush / 优雅刷新**: Ensures logs are persisted even during crashes or forced exits.
//!    确保即使在崩溃或强制退出期间也能持久化日志。

use anyhow::{self, Result};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::io::{self, Write};
use std::sync::{Arc, LazyLock, Weak};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

static ACTIVE_RUNTIME: LazyLock<Mutex<Weak<LoggingRuntime>>> =
    LazyLock::new(|| Mutex::new(Weak::new()));

pub struct LoggingOwner {
    runtime: Arc<LoggingRuntime>,
    signal_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl LoggingOwner {
    #[cfg(test)]
    fn new(runtime: Arc<LoggingRuntime>) -> Self {
        Self::with_signal_task(runtime, None)
    }

    fn with_signal_task(
        runtime: Arc<LoggingRuntime>,
        signal_task: Option<tokio::task::JoinHandle<()>>,
    ) -> Self {
        Self {
            runtime,
            signal_task: Mutex::new(signal_task),
        }
    }

    fn runtime(&self) -> &Arc<LoggingRuntime> {
        &self.runtime
    }

    /// Install this owner into the legacy compat runtime slot.
    ///
    /// New runtime paths should keep using the explicit owner directly; this is
    /// only for callers that still need [`flush_logs()`] and similar compat
    /// helpers.
    ///
    /// # Errors
    ///
    /// Returns an error if another compat runtime has already been installed.
    pub fn install_compat(&self) -> Result<()> {
        install_active_runtime_compat(self.runtime())
    }

    pub async fn flush(&self) {
        let task = { self.signal_task.lock().take() };
        if let Some(task) = task {
            task.abort();
            if let Err(error) = task.await {
                if !error.is_cancelled() {
                    tracing::warn!(%error, "logging signal task join failed during flush");
                }
            }
        }
        flush_logs_with(Arc::clone(&self.runtime)).await;
    }
}

/// Logging configuration from environment
#[derive(Debug, Clone)]
pub struct LoggingConfig {
    /// Output format: "json" or "compact"
    pub format: LogFormat,
    /// Log level filter
    pub level: String,
    /// Sampling configuration for high-frequency logs
    pub sampling: Option<SamplingConfig>,
    /// Enable sensitive data redaction in log output (`SB_LOG_REDACT`, default: on)
    pub redact: bool,
    /// Include timestamp in logs (`SB_LOG_TIMESTAMP`, default: on)
    pub timestamp: bool,
    /// Enable ANSI color output (`SB_LOG_COLOR=0` disables)
    pub color: bool,
}

/// Supported log output formats
#[derive(Debug, Clone, PartialEq)]
pub enum LogFormat {
    /// Human-readable compact format
    Compact,
    /// Machine-readable JSON format
    Json,
}

/// Log sampling configuration
#[derive(Debug, Clone)]
pub struct SamplingConfig {
    /// Maximum samples per second for info/debug logs
    pub rate_per_second: u32,
    /// Sampling window duration
    pub window: Duration,
}

/// Sampler state for rate limiting
#[derive(Debug)]
struct SamplerState {
    /// Sample counts per target within current window
    samples: HashMap<String, u32>,
    /// Window start time
    window_start: Instant,
}

#[derive(Debug)]
struct LoggingRuntime {
    config: LoggingConfig,
    shutdown_sender: broadcast::Sender<()>,
    sampler: Mutex<SamplerState>,
}

impl LoggingRuntime {
    fn new(config: LoggingConfig) -> Self {
        let (shutdown_sender, _rx) = broadcast::channel(1);
        Self {
            config,
            shutdown_sender,
            sampler: Mutex::new(SamplerState {
                samples: HashMap::new(),
                window_start: Instant::now(),
            }),
        }
    }
}

fn write_internal_stderr(message: &str) {
    let mut stderr = io::stderr().lock();
    if let Err(_write_err) = stderr.write_all(message.as_bytes()) {
        // Ignoring write failure: initialization/panic paths have no safer fallback sink.
        return;
    }
    if let Err(_write_err) = stderr.write_all(b"\n") {
        // Ignoring write failure: initialization/panic paths have no safer fallback sink.
        return;
    }
    if let Err(_flush_err) = stderr.flush() {
        // Ignoring flush failure: initialization/panic paths have no safer fallback sink.
    }
}

impl LoggingConfig {
    /// Create logging configuration from environment variables
    pub fn from_env() -> Self {
        let format = match std::env::var("SB_LOG_FORMAT")
            .as_deref()
            .unwrap_or("compact")
        {
            "json" => LogFormat::Json,
            _ => LogFormat::Compact,
        };

        let level = std::env::var("SB_LOG_LEVEL").unwrap_or_else(|_| "info".to_string());

        let sampling = match std::env::var("SB_LOG_SAMPLE") {
            Ok(raw) => {
                let trimmed = raw.trim();
                match trimmed.parse::<u32>() {
                    Ok(rate) => Some(SamplingConfig {
                        rate_per_second: rate,
                        window: Duration::from_secs(1),
                    }),
                    Err(err) => {
                        write_internal_stderr(&format!(
                            "env 'SB_LOG_SAMPLE' value '{trimmed}' is not a valid u32; silent parse fallback is disabled; ignoring: {err}"
                        ));
                        None
                    }
                }
            }
            Err(_) => None,
        };

        let mut color = std::env::var("SB_LOG_COLOR")
            .ok()
            .map(|v| v != "0")
            .unwrap_or(true);
        if std::env::var("NO_COLOR").is_ok() {
            color = false;
        }

        Self {
            format,
            level,
            sampling,
            redact: std::env::var("SB_LOG_REDACT")
                .ok()
                .map(|v| v != "0")
                .unwrap_or(true),
            timestamp: std::env::var("SB_LOG_TIMESTAMP")
                .ok()
                .map(|v| v != "0")
                .unwrap_or(true),
            color,
        }
    }
}

/// Initialize the logging system with compatibility wrappers for callers
/// that still use the legacy public API.
#[allow(dead_code)]
pub fn init_logging(redactor: Arc<app::redact::Redactor>) -> Result<()> {
    let owner = init_logging_with_owner(redactor)?;
    owner.install_compat()?;
    Ok(())
}

/// Initialize logging and return the explicit runtime owner for production
/// paths that do not need the global compat registry.
pub fn init_logging_with_owner(redactor: Arc<app::redact::Redactor>) -> Result<LoggingOwner> {
    let config = LoggingConfig::from_env();
    let runtime = Arc::new(LoggingRuntime::new(config.clone()));

    // Build the subscriber based on configuration
    let env_filter = EnvFilter::new(&config.level);

    match config.format {
        LogFormat::Json => {
            let sampling_layer = config
                .sampling
                .as_ref()
                .map(|_| SamplingLayer::new(Arc::clone(&runtime)));
            if config.timestamp {
                let fmt_layer = fmt::layer()
                    .json()
                    .with_target(true)
                    .with_ansi(config.color)
                    .with_writer(make_writer(config.redact, Arc::clone(&redactor)))
                    .with_filter(env_filter.clone());
                if let Some(sampling_layer) = sampling_layer {
                    tracing_subscriber::registry()
                        .with(fmt_layer)
                        .with(sampling_layer)
                        .try_init()
                        .map_err(|error| {
                            anyhow::anyhow!("failed to initialize JSON logging subscriber: {error}")
                        })?;
                } else {
                    tracing_subscriber::registry()
                        .with(fmt_layer)
                        .try_init()
                        .map_err(|error| {
                            anyhow::anyhow!("failed to initialize JSON logging subscriber: {error}")
                        })?;
                }
            } else {
                let fmt_layer = fmt::layer()
                    .json()
                    .without_time()
                    .with_target(true)
                    .with_ansi(config.color)
                    .with_writer(make_writer(config.redact, Arc::clone(&redactor)))
                    .with_filter(env_filter.clone());
                if let Some(sampling_layer) = sampling_layer {
                    tracing_subscriber::registry()
                        .with(fmt_layer)
                        .with(sampling_layer)
                        .try_init()
                        .map_err(|error| {
                            anyhow::anyhow!("failed to initialize JSON logging subscriber: {error}")
                        })?;
                } else {
                    tracing_subscriber::registry()
                        .with(fmt_layer)
                        .try_init()
                        .map_err(|error| {
                            anyhow::anyhow!("failed to initialize JSON logging subscriber: {error}")
                        })?;
                }
            }
        }
        LogFormat::Compact => {
            let sampling_layer = config
                .sampling
                .as_ref()
                .map(|_| SamplingLayer::new(Arc::clone(&runtime)));
            if config.timestamp {
                let fmt_layer = fmt::layer()
                    .compact()
                    .with_target(true)
                    .with_ansi(config.color)
                    .with_writer(make_writer(config.redact, Arc::clone(&redactor)))
                    .with_filter(env_filter.clone());
                if let Some(sampling_layer) = sampling_layer {
                    tracing_subscriber::registry()
                        .with(fmt_layer)
                        .with(sampling_layer)
                        .try_init()
                        .map_err(|error| {
                            anyhow::anyhow!(
                                "failed to initialize compact logging subscriber: {error}"
                            )
                        })?;
                } else {
                    tracing_subscriber::registry()
                        .with(fmt_layer)
                        .try_init()
                        .map_err(|error| {
                            anyhow::anyhow!(
                                "failed to initialize compact logging subscriber: {error}"
                            )
                        })?;
                }
            } else {
                let fmt_layer = fmt::layer()
                    .compact()
                    .without_time()
                    .with_target(true)
                    .with_ansi(config.color)
                    .with_writer(make_writer(config.redact, Arc::clone(&redactor)))
                    .with_filter(env_filter.clone());
                if let Some(sampling_layer) = sampling_layer {
                    tracing_subscriber::registry()
                        .with(fmt_layer)
                        .with(sampling_layer)
                        .try_init()
                        .map_err(|error| {
                            anyhow::anyhow!(
                                "failed to initialize compact logging subscriber: {error}"
                            )
                        })?;
                } else {
                    tracing_subscriber::registry()
                        .with(fmt_layer)
                        .try_init()
                        .map_err(|error| {
                            anyhow::anyhow!(
                                "failed to initialize compact logging subscriber: {error}"
                            )
                        })?;
                }
            }
        }
    }

    // Install exit hook for log flushing
    let signal_task = install_exit_hook(Arc::clone(&runtime));

    tracing::info!(
        format = ?config.format,
        level = %config.level,
        sampling = ?config.sampling,
        redact = %config.redact,
        "Logging system initialized"
    );

    Ok(LoggingOwner::with_signal_task(runtime, signal_task))
}

/// Create a writer (possibly redacting) for tracing-subscriber fmt layer
fn make_writer(redact: bool, redactor: Arc<app::redact::Redactor>) -> fmt::writer::BoxMakeWriter {
    fmt::writer::BoxMakeWriter::new(move || {
        if redact {
            Box::new(RedactingWriter {
                buf: Vec::with_capacity(256),
                inner: io::stderr(),
                redactor: Arc::clone(&redactor),
            }) as Box<dyn Write + Send>
        } else {
            Box::new(io::stderr()) as Box<dyn Write + Send>
        }
    })
}

/// Writer that buffers a single event line, applies redaction, then flushes
struct RedactingWriter {
    buf: Vec<u8>,
    inner: io::Stderr,
    redactor: Arc<app::redact::Redactor>,
}

impl Write for RedactingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for RedactingWriter {
    fn drop(&mut self) {
        if self.buf.is_empty() {
            return;
        }
        let s = String::from_utf8_lossy(&self.buf);
        let redacted = self.redactor.redact_str(&s);
        if let Err(err) = self.inner.write_all(redacted.as_bytes()) {
            write_internal_stderr(&format!("logging redaction write failed: {err}"));
        }
        if let Err(err) = self.inner.flush() {
            write_internal_stderr(&format!("logging redaction flush failed: {err}"));
        }
    }
}

/// Sampling layer for rate limiting high-frequency logs
struct SamplingLayer {
    runtime: Arc<LoggingRuntime>,
}

impl SamplingLayer {
    fn new(runtime: Arc<LoggingRuntime>) -> Self {
        Self { runtime }
    }
}

impl<S> Layer<S> for SamplingLayer
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let metadata = event.metadata();

        // Only sample info and debug levels
        if !matches!(
            *metadata.level(),
            tracing::Level::INFO | tracing::Level::DEBUG
        ) {
            return;
        }

        if let Some(sampling) = &self.runtime.config.sampling {
            if !should_sample(&self.runtime, metadata.target(), sampling) {
                // Rate limit exceeded; skip event
            }
        }
    }
}

/// Check if a log event should be sampled based on rate limiting
fn should_sample(runtime: &LoggingRuntime, target: &str, config: &SamplingConfig) -> bool {
    let mut sampler = runtime.sampler.lock();
    let now = Instant::now();

    // Reset window if expired
    if now.duration_since(sampler.window_start) >= config.window {
        sampler.samples.clear();
        sampler.window_start = now;
    }

    // Check current sample count for this target
    let count = sampler.samples.entry(target.to_string()).or_insert(0);
    if *count >= config.rate_per_second {
        return false; // Rate limit exceeded
    }

    *count += 1;
    true
}

/// Install exit hook to flush logs before shutdown
fn install_exit_hook(runtime: Arc<LoggingRuntime>) -> Option<tokio::task::JoinHandle<()>> {
    // Register signal handlers for graceful shutdown
    let signal_runtime = Arc::clone(&runtime);
    let signal_task = tokio::spawn(async move {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => Some(s),
            Err(e) => {
                tracing::warn!(error = %e, "install signal handler failed: SIGTERM");
                None
            }
        };
        let mut sigint = match signal(SignalKind::interrupt()) {
            Ok(s) => Some(s),
            Err(e) => {
                tracing::warn!(error = %e, "install signal handler failed: SIGINT");
                None
            }
        };

        match (sigterm.as_mut(), sigint.as_mut()) {
            (Some(s1), Some(s2)) => {
                tokio::select! {
                    _ = s1.recv() => {
                        tracing::info!("Received SIGTERM, flushing logs...");
                        flush_logs_with(Arc::clone(&signal_runtime)).await;
                    }
                    _ = s2.recv() => {
                        tracing::info!("Received SIGINT, flushing logs...");
                        flush_logs_with(Arc::clone(&signal_runtime)).await;
                    }
                }
            }
            (Some(s1), None) => {
                if s1.recv().await.is_none() {
                    tracing::debug!("SIGTERM stream ended before shutdown");
                }
                tracing::info!("Received SIGTERM, flushing logs...");
                flush_logs_with(Arc::clone(&signal_runtime)).await;
            }
            (None, Some(s2)) => {
                if s2.recv().await.is_none() {
                    tracing::debug!("SIGINT stream ended before shutdown");
                }
                tracing::info!("Received SIGINT, flushing logs...");
                flush_logs_with(Arc::clone(&signal_runtime)).await;
            }
            (None, None) => {
                // No handlers installed; nothing to do.
            }
        }
    });

    // Also register a panic hook for emergency flush
    let original_hook = std::panic::take_hook();
    let panic_runtime = Arc::clone(&runtime);
    std::panic::set_hook(Box::new(move |panic_info| {
        write_internal_stderr("Panic occurred, attempting to flush logs...");
        if let Err(error) = std::thread::spawn({
            let panic_runtime = Arc::clone(&panic_runtime);
            move || {
                if let Ok(handle) = tokio::runtime::Handle::try_current() {
                    handle.spawn(flush_logs_with(panic_runtime));
                } else {
                    // If no async runtime, wait briefly to allow buffers to flush
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        })
        .join()
        {
            write_internal_stderr(&format!("panic-time logging flush join failed: {error:?}"));
        }

        original_hook(panic_info);
    }));

    Some(signal_task)
}

/// Flush all pending logs and wait for completion
#[allow(dead_code)]
pub async fn flush_logs() {
    let runtime = current_compat_runtime();
    let Some(runtime) = runtime else {
        tracing::debug!("flush_logs called before logging runtime initialization");
        return;
    };
    flush_logs_with(runtime).await;
}

fn current_compat_runtime() -> Option<Arc<LoggingRuntime>> {
    ACTIVE_RUNTIME.lock().upgrade()
}

fn install_active_runtime_compat(runtime: &Arc<LoggingRuntime>) -> Result<()> {
    let mut runtime_slot = ACTIVE_RUNTIME.lock();
    if runtime_slot.upgrade().is_some() {
        return Err(anyhow::anyhow!("logging already initialized"));
    }

    *runtime_slot = Arc::downgrade(runtime);
    Ok(())
}

async fn flush_logs_with(runtime: Arc<LoggingRuntime>) {
    tracing::info!("Flushing logs before shutdown...");

    // Send shutdown signal
    if let Err(error) = runtime.shutdown_sender.send(()) {
        tracing::debug!(%error, "logging shutdown signal had no active receivers");
    }

    // Give time for logs to flush
    tokio::time::sleep(Duration::from_millis(200)).await;

    tracing::info!("Log flush completed");
}

/// Force immediate flush of logs (for testing)
#[cfg(any(test, feature = "dev-cli"))]
#[allow(dead_code)]
pub fn flush_logs_sync() {
    // For synchronous environments, just add a small delay
    std::thread::sleep(Duration::from_millis(100));
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn clear_active_runtime_for_test() {
        let mut runtime_slot = ACTIVE_RUNTIME.lock();
        *runtime_slot = Weak::new();
    }

    #[test]
    #[serial]
    fn test_logging_config_from_env() {
        // Test JSON format
        std::env::set_var("SB_LOG_FORMAT", "json");
        std::env::set_var("SB_LOG_LEVEL", "debug");
        std::env::set_var("SB_LOG_SAMPLE", "100");

        let config = LoggingConfig::from_env();
        assert_eq!(config.format, LogFormat::Json);
        assert_eq!(config.level, "debug");
        assert!(config.sampling.is_some());
        assert_eq!(config.sampling.as_ref().unwrap().rate_per_second, 100);

        // Cleanup
        std::env::remove_var("SB_LOG_FORMAT");
        std::env::remove_var("SB_LOG_LEVEL");
        std::env::remove_var("SB_LOG_SAMPLE");
    }

    #[test]
    #[serial]
    fn test_logging_config_defaults() {
        // Ensure no environment variables are set
        std::env::remove_var("SB_LOG_FORMAT");
        std::env::remove_var("SB_LOG_LEVEL");
        std::env::remove_var("SB_LOG_SAMPLE");

        let config = LoggingConfig::from_env();
        assert_eq!(config.format, LogFormat::Compact);
        assert_eq!(config.level, "info");
        assert!(config.sampling.is_none());
    }

    #[test]
    fn test_sampling_rate_limit() {
        let runtime = LoggingRuntime::new(LoggingConfig {
            format: LogFormat::Compact,
            level: "info".to_string(),
            sampling: Some(SamplingConfig {
                rate_per_second: 2,
                window: Duration::from_secs(1),
            }),
            redact: true,
            timestamp: true,
            color: false,
        });
        let config = SamplingConfig {
            rate_per_second: 2,
            window: Duration::from_secs(1),
        };

        // Reset sampler state
        {
            let mut sampler = runtime.sampler.lock();
            sampler.samples.clear();
            sampler.window_start = Instant::now();
        }

        // First two should pass
        assert!(should_sample(&runtime, "test_target", &config));
        assert!(should_sample(&runtime, "test_target", &config));

        // Third should be rate limited
        assert!(!should_sample(&runtime, "test_target", &config));
    }

    #[test]
    #[serial]
    fn explicit_owner_does_not_install_compat_registry() {
        clear_active_runtime_for_test();

        let owner = LoggingOwner::new(Arc::new(LoggingRuntime::new(LoggingConfig {
            format: LogFormat::Compact,
            level: "info".to_string(),
            sampling: None,
            redact: true,
            timestamp: true,
            color: false,
        })));

        assert!(
            current_compat_runtime().is_none(),
            "explicit owner path should not auto-install compat runtime"
        );

        owner
            .install_compat()
            .expect("compat registration should succeed");
        assert!(current_compat_runtime().is_some());

        clear_active_runtime_for_test();
    }

    #[tokio::test]
    #[serial]
    async fn test_flush_logs_async() {
        clear_active_runtime_for_test();
        flush_logs().await;
        clear_active_runtime_for_test();
    }

    #[tokio::test]
    async fn explicit_owner_flush_completes() {
        let owner = LoggingOwner::new(Arc::new(LoggingRuntime::new(LoggingConfig {
            format: LogFormat::Compact,
            level: "info".to_string(),
            sampling: None,
            redact: true,
            timestamp: true,
            color: false,
        })));

        owner.flush().await;
    }

    #[tokio::test]
    async fn explicit_owner_flush_cancels_owned_signal_task() {
        let join = tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let owner = LoggingOwner::with_signal_task(
            Arc::new(LoggingRuntime::new(LoggingConfig {
                format: LogFormat::Compact,
                level: "info".to_string(),
                sampling: None,
                redact: true,
                timestamp: true,
                color: false,
            })),
            Some(join),
        );

        owner.flush().await;
        assert!(owner.signal_task.lock().is_none());
    }
}
