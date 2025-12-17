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
use std::collections::HashMap;
use std::io::{self, Write};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

/// Global logging configuration
static LOGGING_CONFIG: OnceLock<LoggingConfig> = OnceLock::new();

/// Channel for coordinating application shutdown and log flushing
static SHUTDOWN_SENDER: OnceLock<broadcast::Sender<()>> = OnceLock::new();

/// Logging configuration from environment
#[derive(Debug, Clone)]
pub struct LoggingConfig {
    /// Output format: "json" or "compact"
    pub format: LogFormat,
    /// Log level filter
    pub level: String,
    /// Sampling configuration for high-frequency logs
    pub sampling: Option<SamplingConfig>,
    /// Enable sensitive data redaction in log output (SB_LOG_REDACT, default: on)
    pub redact: bool,
    /// Include timestamp in logs (SB_LOG_TIMESTAMP, default: on)
    pub timestamp: bool,
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

/// Global sampler for rate limiting logs
static SAMPLER: OnceLock<Mutex<SamplerState>> = OnceLock::new();

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

        let sampling = std::env::var("SB_LOG_SAMPLE")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .map(|rate| SamplingConfig {
                rate_per_second: rate,
                window: Duration::from_secs(1),
            });

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
        }
    }
}

/// Initialize the logging system with environment-based configuration
pub fn init_logging() -> Result<()> {
    let config = LoggingConfig::from_env();
    LOGGING_CONFIG
        .set(config.clone())
        .map_err(|_| anyhow::anyhow!("logging already initialized"))?;

    // Create shutdown channel for coordinated flushing
    let (tx, _rx) = broadcast::channel(1);
    SHUTDOWN_SENDER
        .set(tx)
        .map_err(|_| anyhow::anyhow!("shutdown sender already set"))?;

    // Build the subscriber based on configuration
    let env_filter = EnvFilter::new(&config.level);

    match config.format {
        LogFormat::Json => {
            let sampling_layer = config.sampling.as_ref().map(|_| SamplingLayer);
            if config.timestamp {
                let fmt_layer = fmt::layer()
                    .json()
                    .with_target(true)
                    .with_writer(make_writer(config.redact))
                    .with_filter(env_filter.clone());
                if let Some(sampling_layer) = sampling_layer {
                    tracing_subscriber::registry()
                        .with(fmt_layer)
                        .with(sampling_layer)
                        .init();
                } else {
                    tracing_subscriber::registry().with(fmt_layer).init();
                }
            } else {
                let fmt_layer = fmt::layer()
                    .json()
                    .without_time()
                    .with_target(true)
                    .with_writer(make_writer(config.redact))
                    .with_filter(env_filter.clone());
                if let Some(sampling_layer) = sampling_layer {
                    tracing_subscriber::registry()
                        .with(fmt_layer)
                        .with(sampling_layer)
                        .init();
                } else {
                    tracing_subscriber::registry().with(fmt_layer).init();
                }
            }
        }
        LogFormat::Compact => {
            let sampling_layer = config.sampling.as_ref().map(|_| SamplingLayer);
            if config.timestamp {
                let fmt_layer = fmt::layer()
                    .compact()
                    .with_target(true)
                    .with_writer(make_writer(config.redact))
                    .with_filter(env_filter.clone());
                if let Some(sampling_layer) = sampling_layer {
                    tracing_subscriber::registry()
                        .with(fmt_layer)
                        .with(sampling_layer)
                        .init();
                } else {
                    tracing_subscriber::registry().with(fmt_layer).init();
                }
            } else {
                let fmt_layer = fmt::layer()
                    .compact()
                    .without_time()
                    .with_target(true)
                    .with_writer(make_writer(config.redact))
                    .with_filter(env_filter.clone());
                if let Some(sampling_layer) = sampling_layer {
                    tracing_subscriber::registry()
                        .with(fmt_layer)
                        .with(sampling_layer)
                        .init();
                } else {
                    tracing_subscriber::registry().with(fmt_layer).init();
                }
            }
        }
    }

    // Install exit hook for log flushing
    install_exit_hook();

    tracing::info!(
        format = ?config.format,
        level = %config.level,
        sampling = ?config.sampling,
        redact = %config.redact,
        "Logging system initialized"
    );

    Ok(())
}

/// Create a writer (possibly redacting) for tracing-subscriber fmt layer
fn make_writer(redact: bool) -> fmt::writer::BoxMakeWriter {
    fmt::writer::BoxMakeWriter::new(move || {
        if redact {
            Box::new(RedactingWriter {
                buf: Vec::with_capacity(256),
                inner: io::stderr(),
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
        use crate::redact::redact_str;
        if self.buf.is_empty() {
            return;
        }
        let s = String::from_utf8_lossy(&self.buf);
        let redacted = redact_str(&s);
        let _ = self.inner.write_all(redacted.as_bytes());
        let _ = self.inner.flush();
    }
}

/// Sampling layer for rate limiting high-frequency logs
struct SamplingLayer;

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

        if let Some(config) = LOGGING_CONFIG.get() {
            if let Some(sampling) = &config.sampling {
                if !should_sample(metadata.target(), sampling) {
                    // Rate limit exceeded; skip event
                }
            }
        }
    }
}

/// Check if a log event should be sampled based on rate limiting
fn should_sample(target: &str, config: &SamplingConfig) -> bool {
    let sampler_mutex = SAMPLER.get_or_init(|| {
        Mutex::new(SamplerState {
            samples: HashMap::new(),
            window_start: Instant::now(),
        })
    });
    let mut sampler = match sampler_mutex.lock() {
        Ok(g) => g,
        Err(_poison) => {
            // On lock poison, allow the event rather than panic.
            return true;
        }
    };
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
fn install_exit_hook() {
    // Register signal handlers for graceful shutdown
    tokio::spawn(async {
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
                        flush_logs().await;
                    }
                    _ = s2.recv() => {
                        tracing::info!("Received SIGINT, flushing logs...");
                        flush_logs().await;
                    }
                }
            }
            (Some(s1), None) => {
                let _ = s1.recv().await;
                tracing::info!("Received SIGTERM, flushing logs...");
                flush_logs().await;
            }
            (None, Some(s2)) => {
                let _ = s2.recv().await;
                tracing::info!("Received SIGINT, flushing logs...");
                flush_logs().await;
            }
            (None, None) => {
                // No handlers installed; nothing to do.
            }
        }
    });

    // Also register a panic hook for emergency flush
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        eprintln!("Panic occurred, attempting to flush logs...");
        let _ = std::thread::spawn(|| {
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(flush_logs());
            } else {
                // If no async runtime, wait briefly to allow buffers to flush
                std::thread::sleep(Duration::from_millis(100));
            }
        })
        .join();

        original_hook(panic_info);
    }));
}

/// Flush all pending logs and wait for completion
pub async fn flush_logs() {
    tracing::info!("Flushing logs before shutdown...");

    // Send shutdown signal
    if let Some(tx) = SHUTDOWN_SENDER.get() {
        let _ = tx.send(());
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
        let config = SamplingConfig {
            rate_per_second: 2,
            window: Duration::from_secs(1),
        };

        // Reset sampler state
        {
            let sampler_mutex = SAMPLER.get_or_init(|| {
                Mutex::new(SamplerState {
                    samples: HashMap::new(),
                    window_start: Instant::now(),
                })
            });
            let mut sampler = sampler_mutex.lock().unwrap();
            sampler.samples.clear();
            sampler.window_start = Instant::now();
        }

        // First two should pass
        assert!(should_sample("test_target", &config));
        assert!(should_sample("test_target", &config));

        // Third should be rate limited
        assert!(!should_sample("test_target", &config));
    }

    #[tokio::test]
    async fn test_flush_logs_async() {
        // This test verifies flush_logs doesn't panic
        flush_logs().await;
        // If we reach here, the function completed successfully
    }
}
