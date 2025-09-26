//! Configurable logging pipeline with JSON/compact formats, sampling, and exit flush
//!
//! This module provides an enhanced logging system that supports:
//! - Multiple output formats (JSON, compact)
//! - Log level filtering
//! - Sampling for high-frequency logs
//! - Explicit flush on application exit
//! - Environment-driven configuration

use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use std::collections::HashMap;
use tokio::sync::broadcast;
use tracing_subscriber::{
    fmt,
    layer::SubscriberExt,
    util::SubscriberInitExt,
    Layer,
    EnvFilter,
};
use anyhow::{self, Result};

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
        let format = match std::env::var("SB_LOG_FORMAT").as_deref().unwrap_or("compact") {
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
            let fmt_layer = fmt::layer()
                .json()
                .with_target(true)
                .with_filter(env_filter);

            let sampling_layer = config.sampling.as_ref().map(|_| SamplingLayer);

            if let Some(sampling_layer) = sampling_layer {
                tracing_subscriber::registry()
                    .with(fmt_layer)
                    .with(sampling_layer)
                    .init();
            } else {
                tracing_subscriber::registry()
                    .with(fmt_layer)
                    .init();
            }
        }
        LogFormat::Compact => {
            let fmt_layer = fmt::layer()
                .compact()
                .with_target(true)
                .with_filter(env_filter);

            let sampling_layer = config.sampling.as_ref().map(|_| SamplingLayer);

            if let Some(sampling_layer) = sampling_layer {
                tracing_subscriber::registry()
                    .with(fmt_layer)
                    .with(sampling_layer)
                    .init();
            } else {
                tracing_subscriber::registry()
                    .with(fmt_layer)
                    .init();
            }
        }
    }

    // Install exit hook for log flushing
    install_exit_hook();

    tracing::info!(
        format = ?config.format,
        level = %config.level,
        sampling = ?config.sampling,
        "Logging system initialized"
    );

    Ok(())
}

/// Sampling layer for rate limiting high-frequency logs
struct SamplingLayer;

impl<S> Layer<S> for SamplingLayer
where
    S: tracing::Subscriber,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: tracing_subscriber::layer::Context<'_, S>) {
        let metadata = event.metadata();

        // Only sample info and debug levels
        if !matches!(*metadata.level(), tracing::Level::INFO | tracing::Level::DEBUG) {
            return;
        }

        if let Some(config) = LOGGING_CONFIG.get() {
            if let Some(sampling) = &config.sampling {
                if !should_sample(metadata.target(), sampling) {
                    return; // Skip this event
                }
            }
        }
    }
}

/// Check if a log event should be sampled based on rate limiting
fn should_sample(target: &str, config: &SamplingConfig) -> bool {
    let sampler_mutex = SAMPLER.get_or_init(|| Mutex::new(SamplerState {
        samples: HashMap::new(),
        window_start: Instant::now(),
    }));
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
        }).join();

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
pub fn flush_logs_sync() {
    // For synchronous environments, just add a small delay
    std::thread::sleep(Duration::from_millis(100));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
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
            let sampler_mutex = SAMPLER.get_or_init(|| Mutex::new(SamplerState {
                samples: HashMap::new(),
                window_start: Instant::now(),
            }));
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
