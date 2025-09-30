//! Rate limiting middleware for admin debug HTTP server
//!
//! This middleware implements a token bucket rate limiter with configurable
//! limits per endpoint or path. Rate limit violations return 429 status
//! with contract-compliant `ResponseEnvelope` errors.
//!
//! This module is only available when the "`rate_limit`" feature is enabled.

use super::{Middleware, MiddlewareResult, RequestContext};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Token bucket for rate limiting
#[derive(Debug, Clone)]
struct TokenBucket {
    /// Maximum number of tokens
    capacity: u32,
    /// Current number of tokens
    tokens: u32,
    /// Rate at which tokens are added (tokens per second)
    refill_rate: u32,
    /// Last time the bucket was refilled
    last_refill: Instant,
}

impl TokenBucket {
    fn new(capacity: u32, refill_rate: u32) -> Self {
        Self {
            capacity,
            tokens: capacity,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    /// Try to consume a token from the bucket
    fn consume(&mut self) -> bool {
        self.refill();
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }

    /// Refill tokens based on elapsed time
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);
        let tokens_to_add = (elapsed.as_secs_f64() * f64::from(self.refill_rate)) as u32;

        if tokens_to_add > 0 {
            self.tokens = (self.tokens + tokens_to_add).min(self.capacity);
            self.last_refill = now;
        }
    }
}

/// Rate limiting strategy
#[derive(Debug, Clone)]
pub enum RateLimitStrategy {
    /// Rate limit by exact path
    ByPath,
    /// Rate limit by endpoint pattern (normalized path)
    ByEndpoint,
    /// Rate limit globally (all requests)
    Global,
}

/// Rate limit configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum requests per time window
    pub max_requests: u32,
    /// Time window duration
    pub window_duration: Duration,
    /// Rate limiting strategy
    pub strategy: RateLimitStrategy,
    /// Burst capacity (defaults to `max_requests`)
    pub burst_capacity: Option<u32>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 60,
            window_duration: Duration::from_secs(60),
            strategy: RateLimitStrategy::ByPath,
            burst_capacity: None,
        }
    }
}

impl RateLimitConfig {
    #[must_use] 
    pub const fn new(max_requests: u32, window_secs: u64) -> Self {
        Self {
            max_requests,
            window_duration: Duration::from_secs(window_secs),
            strategy: RateLimitStrategy::ByPath,
            burst_capacity: None,
        }
    }

    #[must_use] 
    pub const fn with_strategy(mut self, strategy: RateLimitStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    #[must_use] 
    pub const fn with_burst(mut self, burst_capacity: u32) -> Self {
        self.burst_capacity = Some(burst_capacity);
        self
    }

    fn get_capacity(&self) -> u32 {
        self.burst_capacity.unwrap_or(self.max_requests)
    }

    fn get_refill_rate(&self) -> u32 {
        // Refill rate in tokens per second
        (f64::from(self.max_requests) / self.window_duration.as_secs_f64()) as u32
    }
}

/// Rate limiting middleware implementation
pub struct RateLimitMiddleware {
    config: RateLimitConfig,
    buckets: Arc<Mutex<HashMap<String, TokenBucket>>>,
}

impl RateLimitMiddleware {
    #[must_use] 
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            buckets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Get the rate limit key for a request based on strategy
    fn get_rate_limit_key(&self, ctx: &RequestContext) -> String {
        match self.config.strategy {
            RateLimitStrategy::ByPath => ctx.path.clone(),
            RateLimitStrategy::ByEndpoint => normalize_endpoint(&ctx.path),
            RateLimitStrategy::Global => "global".to_string(),
        }
    }

    /// Create rate limit error response
    fn create_rate_limit_error(&self, request_id: &str) -> sb_admin_contract::ResponseEnvelope<()> {
        sb_admin_contract::ResponseEnvelope::err(
            sb_admin_contract::ErrorKind::RateLimit,
            "Rate limit exceeded",
        )
        .with_request_id(request_id)
    }
}

impl Middleware for RateLimitMiddleware {
    fn process(&self, ctx: &mut RequestContext) -> MiddlewareResult<()> {
        let key = self.get_rate_limit_key(ctx);
        let mut buckets = self.buckets.lock().map_err(|_| {
            sb_admin_contract::ResponseEnvelope::err(
                sb_admin_contract::ErrorKind::Internal,
                "Rate limiter lock error",
            )
            .with_request_id(&ctx.request_id)
        })?;

        // Get or create bucket for this key
        let bucket = buckets.entry(key.clone()).or_insert_with(|| {
            TokenBucket::new(self.config.get_capacity(), self.config.get_refill_rate())
        });

        // Try to consume a token
        if bucket.consume() {
            tracing::debug!(
                request_id = %ctx.request_id,
                key = %key,
                tokens_remaining = bucket.tokens,
                target = "admin",
                "rate limit check passed"
            );
            Ok(())
        } else {
            tracing::warn!(
                request_id = %ctx.request_id,
                key = %key,
                target = "admin",
                "rate limit exceeded"
            );
            Err(self.create_rate_limit_error(&ctx.request_id))
        }
    }
}

/// Normalize endpoint path for endpoint-based rate limiting
fn normalize_endpoint(path: &str) -> String {
    // Remove query parameters
    let path = path.split('?').next().unwrap_or(path);

    // Normalize common admin endpoints
    match path {
        p if p.starts_with("/router/geoip") => "/router/geoip".to_string(),
        p if p.starts_with("/router/rules/normalize") => "/router/rules/normalize".to_string(),
        p if p.starts_with("/router/analyze") => "/router/analyze".to_string(),
        p if p.starts_with("/route/dryrun") => "/route/dryrun".to_string(),
        p if p.starts_with("/subs/") => "/subs".to_string(),
        other => other.to_string(),
    }
}

/// Create rate limiter from environment configuration
#[must_use] 
pub fn from_env() -> Option<RateLimitMiddleware> {
    // Check if rate limiting is enabled
    let enabled = std::env::var("SB_ADMIN_RATE_LIMIT_ENABLED").ok().as_deref() == Some("1");

    if !enabled {
        return None;
    }

    let max_requests = std::env::var("SB_ADMIN_RATE_LIMIT_MAX")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60);

    let window_secs = std::env::var("SB_ADMIN_RATE_LIMIT_WINDOW_SEC")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60);

    let strategy = match std::env::var("SB_ADMIN_RATE_LIMIT_STRATEGY")
        .ok()
        .as_deref()
    {
        Some("endpoint") => RateLimitStrategy::ByEndpoint,
        Some("global") => RateLimitStrategy::Global,
        _ => RateLimitStrategy::ByPath,
    };

    let burst = std::env::var("SB_ADMIN_RATE_LIMIT_BURST")
        .ok()
        .and_then(|v| v.parse().ok());

    let mut config = RateLimitConfig::new(max_requests, window_secs).with_strategy(strategy);

    if let Some(burst_capacity) = burst {
        config = config.with_burst(burst_capacity);
    }

    Some(RateLimitMiddleware::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_token_bucket_consume() {
        let mut bucket = TokenBucket::new(3, 1);

        // Should be able to consume initial tokens
        assert!(bucket.consume());
        assert!(bucket.consume());
        assert!(bucket.consume());

        // Should be empty now
        assert!(!bucket.consume());
    }

    #[test]
    fn test_token_bucket_refill() {
        let mut bucket = TokenBucket::new(2, 2); // 2 tokens per second

        // Consume all tokens
        assert!(bucket.consume());
        assert!(bucket.consume());
        assert!(!bucket.consume());

        // Wait for refill
        thread::sleep(Duration::from_millis(600)); // > 0.5 seconds

        // Should have at least 1 token now
        assert!(bucket.consume());
    }

    #[test]
    fn test_normalize_endpoint() {
        assert_eq!(normalize_endpoint("/router/geoip/test"), "/router/geoip");
        assert_eq!(
            normalize_endpoint("/router/rules/normalize?param=1"),
            "/router/rules/normalize"
        );
        assert_eq!(normalize_endpoint("/subs/clash/config"), "/subs");
        assert_eq!(normalize_endpoint("/__health"), "/__health");
    }

    #[test]
    fn test_rate_limit_config() {
        let config = RateLimitConfig::new(10, 30)
            .with_strategy(RateLimitStrategy::ByEndpoint)
            .with_burst(15);

        assert_eq!(config.max_requests, 10);
        assert_eq!(config.window_duration, Duration::from_secs(30));
        assert_eq!(config.get_capacity(), 15);
        assert!(matches!(config.strategy, RateLimitStrategy::ByEndpoint));
    }

    #[test]
    fn test_middleware_rate_limit_key() {
        let config = RateLimitConfig::new(10, 60).with_strategy(RateLimitStrategy::ByPath);
        let middleware = RateLimitMiddleware::new(config);

        let ctx = RequestContext::new("GET".to_string(), "/test/path".to_string(), HashMap::new());

        assert_eq!(middleware.get_rate_limit_key(&ctx), "/test/path");
    }

    #[test]
    fn test_middleware_rate_limit_enforcement() {
        let config = RateLimitConfig::new(2, 60); // Very low limit for testing
        let middleware = RateLimitMiddleware::new(config);

        let mut ctx = RequestContext::new("GET".to_string(), "/test".to_string(), HashMap::new());

        // First two requests should pass
        assert!(middleware.process(&mut ctx).is_ok());
        assert!(middleware.process(&mut ctx).is_ok());

        // Third request should be rate limited
        let result = middleware.process(&mut ctx);
        assert!(result.is_err());

        if let Err(envelope) = result {
            assert!(!envelope.ok);
            if let Some(error) = envelope.error {
                assert!(matches!(
                    error.kind,
                    sb_admin_contract::ErrorKind::RateLimit
                ));
            }
        }
    }
}
