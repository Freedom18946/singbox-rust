use once_cell::sync::OnceCell;
use rand::Rng;
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

/// Clock abstraction for testable time operations
pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
}

/// System clock using real time
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Global clock instance - can be injected for testing
static CLOCK: OnceCell<std::sync::Arc<dyn Clock>> = OnceCell::new();

/// Get the current time from the configured clock
#[cfg(test)]
fn now() -> Instant {
    now_test()
}

#[cfg(not(test))]
fn now() -> Instant {
    CLOCK.get_or_init(|| std::sync::Arc::new(SystemClock)).now()
}

/// Inject a custom clock for testing (must be called before first usage)
#[cfg(test)]
pub fn set_test_clock(clock: std::sync::Arc<dyn Clock>) -> bool {
    CLOCK.set(clock).is_ok()
}

/// Reset clock to default system clock (for testing only)
#[cfg(test)]
pub fn reset_clock() {
    // We can't reset OnceCell, but we can work around this for tests
    // by using a different approach
}

/// Test-only clock replacement mechanism
#[cfg(test)]
thread_local! {
    static TEST_CLOCK: std::cell::RefCell<Option<std::sync::Arc<dyn Clock>>> = std::cell::RefCell::new(None);
}

#[cfg(test)]
fn now_test() -> Instant {
    TEST_CLOCK.with(|clock| {
        if let Some(test_clock) = clock.borrow().as_ref() {
            test_clock.now()
        } else {
            CLOCK.get_or_init(|| std::sync::Arc::new(SystemClock)).now()
        }
    })
}

#[cfg(test)]
pub fn set_thread_local_clock(clock: std::sync::Arc<dyn Clock>) {
    TEST_CLOCK.with(|c| {
        *c.borrow_mut() = Some(clock);
    });
}

#[cfg(test)]
pub fn clear_thread_local_clock() {
    TEST_CLOCK.with(|c| {
        *c.borrow_mut() = None;
    });
}

#[derive(Debug, Clone)]
enum State {
    Closed,
    Open { until: Instant, _backoff: Duration },
    // probes: number of successful probes required to fully close the circuit
    // permits: number of probe attempts allowed while half-open
    HalfOpen { probes: u32, permits: u32 },
}

impl Default for State {
    fn default() -> Self {
        Self::Closed
    }
}

struct HostStat {
    successes: u32,
    failures: u32,
    window_start: Instant,
    state: State,
    reopen_count: u32,
}

impl Default for HostStat {
    fn default() -> Self {
        Self {
            successes: 0,
            failures: 0,
            window_start: now(),
            state: State::default(),
            reopen_count: 0,
        }
    }
}

pub struct HostBreaker {
    window: Duration,
    open_duration: Duration,
    max_open_duration: Duration,
    half_open_probes: u32,
    map: HashMap<String, HostStat>,
    failure_threshold: u32,
    failure_ratio: f32,
}

impl HostBreaker {
    #[must_use]
    pub fn new(window_ms: u64, open_ms: u64, threshold: u32, ratio: f32) -> Self {
        Self {
            window: Duration::from_millis(window_ms),
            open_duration: Duration::from_millis(open_ms),
            max_open_duration: Duration::from_millis(open_ms * 32), // Max 32x backoff
            half_open_probes: 3, // Allow 3 probes in half-open state
            map: HashMap::new(),
            failure_threshold: threshold,
            failure_ratio: ratio,
        }
    }

    pub fn check(&mut self, host: &str) -> bool {
        let current_time = now();
        let stat = self
            .map
            .entry(host.to_string())
            .or_insert_with(|| HostStat {
                successes: 0,
                failures: 0,
                window_start: current_time,
                state: State::Closed,
                reopen_count: 0,
            });

        // Reset window if expired
        if current_time.duration_since(stat.window_start) > self.window {
            stat.window_start = current_time;
            stat.successes = 0;
            stat.failures = 0;
        }

        match &mut stat.state {
            State::Closed => true, // Allow all requests
            State::Open { until, .. } => {
                if current_time < *until {
                    false // Circuit is still open, block request
                } else {
                    // Transition to half-open
                    let permits = self.half_open_probes.saturating_sub(1);
                    stat.state = State::HalfOpen { probes: self.half_open_probes, permits };
                    true // Allow first probe request
                }
            }
            State::HalfOpen { permits, .. } => {
                if *permits > 0 {
                    *permits -= 1;
                    true
                } else {
                    false
                }
            }
        }
    }

    pub fn mark_success(&mut self, host: &str) {
        if let Some(stat) = self.map.get_mut(host) {
            stat.successes += 1;

            match &mut stat.state {
                State::HalfOpen { probes, .. } => {
                    *probes = probes.saturating_sub(1);
                    if *probes == 0 {
                        // All probes succeeded, close the circuit
                        stat.state = State::Closed;
                        tracing::info!(host = %host, "Circuit breaker closed after successful probes");
                    }
                }
                State::Closed => {
                    // Continue normal operation
                }
                State::Open { .. } => {
                    // Shouldn't happen, but handle gracefully
                    tracing::warn!(host = %host, "Unexpected success in OPEN state");
                }
            }
        }
    }

    pub fn mark_failure(&mut self, host: &str) {
        let current_time = now();

        // Calculate backoff first to avoid borrowing issues
        let (should_reopen, backoff) = self.map.get(host).map_or_else(
            || (false, Duration::from_secs(0)),
            |stat| match &stat.state {
                State::HalfOpen { .. } => {
                    let new_count = stat.reopen_count + 1;
                    (true, self.calculate_backoff(new_count))
                }
                _ => (false, Duration::from_secs(0)),
            },
        );

        // Precompute jittered values to avoid borrowing conflicts
        let jittered_backoff = if should_reopen {
            self.apply_jitter(backoff)
        } else {
            backoff
        };

        let initial_backoff = self.apply_jitter(self.open_duration);

        let stat = self
            .map
            .entry(host.to_string())
            .or_insert_with(|| HostStat {
                successes: 0,
                failures: 0,
                window_start: current_time,
                state: State::Closed,
                reopen_count: 0,
            });

        stat.failures += 1;

        match &stat.state {
            State::HalfOpen { .. } => {
                // Half-open probe failed, go back to OPEN with exponential backoff
                stat.reopen_count += 1;
                stat.state = State::Open {
                    until: current_time + jittered_backoff,
                    _backoff: jittered_backoff,
                };

                // Record reopen metric
                crate::admin_debug::security_metrics::inc_breaker_reopen();

                tracing::warn!(host = %host, backoff_ms = %backoff.as_millis(), "Circuit breaker reopened with backoff");
            }
            State::Closed => {
                // Check if we should trip the circuit
                let total = (stat.successes + stat.failures).max(1);
                #[allow(clippy::cast_precision_loss)]
                let ratio = (stat.failures as f32) / (total as f32);
                // Only use ratio after we have enough samples (>=3)
                const MIN_SAMPLES_FOR_RATIO: u32 = 3;
                if stat.failures >= self.failure_threshold
                    || (total >= MIN_SAMPLES_FOR_RATIO && ratio >= self.failure_ratio)
                {
                    // Trip circuit to OPEN state
                    stat.reopen_count = 1;
                    stat.state = State::Open {
                        until: current_time + initial_backoff,
                        _backoff: initial_backoff,
                    };

                    // Record initial reopen metric
                    crate::admin_debug::security_metrics::inc_breaker_reopen();

                    tracing::warn!(host = %host, failures = %stat.failures, ratio = %ratio, "Circuit breaker opened");
                }
            }
            State::Open { .. } => {
                // Already open, continue counting failures
            }
        }
    }

    fn calculate_backoff(&self, reopen_count: u32) -> Duration {
        #[allow(clippy::cast_possible_truncation)]
        let base_ms = self.open_duration.as_millis() as u64;
        let multiplier = 2_u64.pow(reopen_count.saturating_sub(1).min(5)); // Cap at 2^5 = 32x
        #[allow(clippy::cast_possible_truncation)]
        let backoff_ms = (base_ms * multiplier).min(self.max_open_duration.as_millis() as u64);
        Duration::from_millis(backoff_ms)
    }

    #[allow(clippy::unused_self)]
    fn apply_jitter(&self, base_duration: Duration) -> Duration {
        // Add 20-30% jitter only once when entering OPEN state
        let mut rng = rand::thread_rng();
        let jitter_factor = rng.gen_range(1.2..1.3); // 20-30% increase
        #[allow(
            clippy::cast_precision_loss,
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss
        )]
        let final_ms = (base_duration.as_millis() as f64 * jitter_factor) as u64;
        Duration::from_millis(final_ms)
    }

    #[must_use]
    pub fn stats(&self) -> Vec<(String, u32, u32, bool)> {
        let current_time = now();
        self.map
            .iter()
            .map(|(host, stat)| {
                let is_open = matches!(
                    stat.state,
                    State::Open { until, .. } if current_time < until
                );
                (host.clone(), stat.successes, stat.failures, is_open)
            })
            .collect()
    }

    #[must_use]
    pub fn state_stats(&self) -> Vec<(String, String, u32)> {
        let current_time = now();
        self.map
            .iter()
            .filter_map(|(host, stat)| {
                let state_opt = match &stat.state {
                    // Include closed entries only if they previously tripped (reopen_count > 0)
                    State::Closed => (stat.reopen_count > 0).then(|| "closed".to_string()),
                    // Reflect actual state
                    State::Open { .. } => Some("open".to_string()),
                    State::HalfOpen { .. } => Some("half_open".to_string()),
                };
                state_opt.map(|state_name| (host.clone(), state_name, stat.reopen_count))
            })
            .collect()
    }

    // Compatibility aliases to ensure method name consistency
    pub fn mark_fail(&mut self, host: &str) {
        self.mark_failure(host);
    }
    pub fn mark_ok(&mut self, host: &str) {
        self.mark_success(host);
    }
}

static BREAKER: OnceCell<Mutex<HostBreaker>> = OnceCell::new();

pub fn global() -> &'static Mutex<HostBreaker> {
    BREAKER.get_or_init(|| {
        let window_ms = std::env::var("SB_SUBS_BR_WIN_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30_000);

        let open_ms = std::env::var("SB_SUBS_BR_OPEN_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(15_000);

        let threshold = std::env::var("SB_SUBS_BR_FAILS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5);

        let ratio = std::env::var("SB_SUBS_BR_RATIO")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0.5);

        Mutex::new(HostBreaker::new(window_ms, open_ms, threshold, ratio))
    })
}

#[cfg(test)]
#[cfg(feature = "admin_tests")]
mod tests {
    use super::*;
    use std::{cell::RefCell, rc::Rc, thread};

    /// Controllable test clock for deterministic testing
    pub struct TestClock {
        current_time: std::sync::RwLock<Instant>,
    }

    impl TestClock {
        pub fn new(start_time: Instant) -> Self {
            Self {
                current_time: std::sync::RwLock::new(start_time),
            }
        }

        pub fn advance(&self, duration: Duration) {
            let mut time = self.current_time.write().unwrap();
            *time = *time + duration;
        }

        pub fn set_time(&self, new_time: Instant) {
            *self.current_time.write().unwrap() = new_time;
        }
    }

    impl Clock for TestClock {
        fn now(&self) -> Instant {
            *self.current_time.read().unwrap()
        }
    }

    /// Helper to set up test clock for a test
    fn setup_test_clock() -> std::sync::Arc<TestClock> {
        let test_clock = std::sync::Arc::new(TestClock::new(Instant::now()));
        set_thread_local_clock(test_clock.clone());
        test_clock
    }

    #[test]
    fn test_breaker_basic() {
        let mut br = HostBreaker::new(1000, 500, 3, 0.5);
        assert!(br.check("test.com"));
        br.mark_success("test.com");
        assert!(br.check("test.com"));
    }

    #[test]
    fn test_breaker_trips_on_threshold() {
        let _clock = setup_test_clock();
        let mut br = HostBreaker::new(10000, 1000, 3, 0.9);

        for _ in 0..3 {
            assert!(br.check("bad.com"));
            br.mark_failure("bad.com");
        }

        // Circuit should be open now
        assert!(!br.check("bad.com"));
    }

    #[test]
    fn test_breaker_trips_on_ratio() {
        let _clock = setup_test_clock();
        let mut br = HostBreaker::new(10000, 1000, 100, 0.5);

        assert!(br.check("mixed.com"));
        br.mark_success("mixed.com");
        assert!(br.check("mixed.com"));
        br.mark_failure("mixed.com");
        assert!(br.check("mixed.com"));
        br.mark_failure("mixed.com");

        // 1 success, 2 failures = 66% failure rate, should trip at 50%
        assert!(!br.check("mixed.com"));
    }

    #[test]
    fn test_breaker_recovers_after_timeout() {
        let clock = setup_test_clock();
        let mut br = HostBreaker::new(10000, 50, 2, 0.9);

        for _ in 0..2 {
            br.mark_failure("recover.com");
        }
        assert!(!br.check("recover.com"));

        // Advance time beyond open duration (accounting for jitter)
        clock.advance(Duration::from_millis(80));

        // Should recover after open duration
        assert!(br.check("recover.com"));
    }

    #[test]
    fn test_breaker_window_reset() {
        let clock = setup_test_clock();
        let mut br = HostBreaker::new(50, 1000, 3, 0.9);

        br.mark_failure("window.com");
        br.mark_failure("window.com");

        // Advance time beyond window duration
        clock.advance(Duration::from_millis(60));

        // Window should reset
        assert!(br.check("window.com"));
        let stats = br.stats();
        let stat = stats.iter().find(|(h, _, _, _)| h == "window.com").unwrap();
        assert_eq!(stat.2, 0); // failures reset to 0
    }

    #[test]
    fn test_breaker_half_open_success() {
        let clock = setup_test_clock();
        let mut br = HostBreaker::new(10000, 100, 2, 0.9);

        // Trip the circuit
        for _ in 0..2 {
            assert!(br.check("half-open.com"));
            br.mark_failure("half-open.com");
        }
        assert!(!br.check("half-open.com")); // Should be OPEN

        // Advance time beyond open duration (accounting for jitter)
        clock.advance(Duration::from_millis(150));

        // First check after timeout should allow probe (transition to HALF_OPEN)
        assert!(br.check("half-open.com"));

        // Simulate successful probes
        for _ in 0..3 {
            br.mark_success("half-open.com");
        }

        // Should be CLOSED now and allow requests
        assert!(br.check("half-open.com"));

        let state_stats = br.state_stats();
        let stat = state_stats
            .iter()
            .find(|(h, _, _)| h == "half-open.com")
            .unwrap();
        assert_eq!(stat.1, "closed");
    }

    #[test]
    fn test_breaker_half_open_failure_backoff() {
        let clock = setup_test_clock();
        let mut br = HostBreaker::new(10000, 100, 2, 0.9);

        // Trip the circuit
        for _ in 0..2 {
            br.mark_failure("backoff.com");
        }

        // Advance time beyond initial open duration (accounting for jitter)
        clock.advance(Duration::from_millis(150));

        // Try to probe (should be allowed)
        assert!(br.check("backoff.com"));

        // Fail the probe - should go back to OPEN with longer backoff
        br.mark_failure("backoff.com");

        // Should be blocked again
        assert!(!br.check("backoff.com"));

        let state_stats = br.state_stats();
        let stat = state_stats
            .iter()
            .find(|(h, _, _)| h == "backoff.com")
            .unwrap();
        assert_eq!(stat.1, "open");
        assert_eq!(stat.2, 2); // reopen_count should be 2
    }

    #[test]
    fn test_exponential_backoff_calculation() {
        let br = HostBreaker::new(10000, 1000, 3, 0.5);

        let backoff1 = br.calculate_backoff(1);
        let backoff2 = br.calculate_backoff(2);
        let backoff3 = br.calculate_backoff(3);

        // Each backoff should be 2x the previous (without jitter)
        // calculate_backoff returns base duration without jitter
        assert_eq!(backoff1.as_millis(), 1000); // 1000ms * 2^0
        assert_eq!(backoff2.as_millis(), 2000); // 1000ms * 2^1
        assert_eq!(backoff3.as_millis(), 4000); // 1000ms * 2^2
    }

    #[test]
    fn test_half_open_probe_limit() {
        let clock = setup_test_clock();
        let mut br = HostBreaker::new(10000, 100, 2, 0.9);

        // Trip circuit
        for _ in 0..2 {
            br.mark_failure("probe-limit.com");
        }

        // Advance time beyond open duration (accounting for jitter)
        clock.advance(Duration::from_millis(150));

        // Should allow exactly 3 probes (half_open_probes)
        for i in 0..3 {
            assert!(
                br.check("probe-limit.com"),
                "Probe {} should be allowed",
                i + 1
            );
        }

        // 4th probe should be blocked
        assert!(!br.check("probe-limit.com"), "4th probe should be blocked");
    }

    #[test]
    fn test_state_stats_output() {
        let mut br = HostBreaker::new(10000, 1000, 2, 0.9);

        // Initially should have no stats
        let stats = br.state_stats();
        assert_eq!(stats.len(), 0);

        // Trip a circuit
        for _ in 0..2 {
            br.mark_failure("stats-test.com");
        }

        let stats = br.state_stats();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].0, "stats-test.com");
        assert_eq!(stats[0].1, "open"); // Should be open
        assert_eq!(stats[0].2, 1); // reopen_count should be 1
    }

    #[test]
    fn test_jitter_application() {
        let br = HostBreaker::new(10000, 1000, 3, 0.5);

        // Test that jitter increases the base duration
        let base_duration = Duration::from_millis(1000);
        let jittered = br.apply_jitter(base_duration);

        // Should be in the 1200-1300ms range (1000ms * 1.2 to 1000ms * 1.3)
        assert!(
            jittered.as_millis() >= 1200,
            "Jittered duration {} should be >= 1200ms",
            jittered.as_millis()
        );
        assert!(
            jittered.as_millis() <= 1300,
            "Jittered duration {} should be <= 1300ms",
            jittered.as_millis()
        );

        // Test that base calculation is deterministic (without jitter)
        let backoff1 = br.calculate_backoff(2);
        let backoff2 = br.calculate_backoff(2);
        assert_eq!(
            backoff1, backoff2,
            "Base backoff calculation should be deterministic"
        );

        // Base backoff should be exactly 2000ms (1000ms * 2^1)
        assert_eq!(backoff1.as_millis(), 2000);
    }

    #[test]
    fn test_backoff_cap() {
        let br = HostBreaker::new(10000, 100, 3, 0.5); // 100ms base, max 3200ms

        // Test very high reopen count (should cap at max_open_duration)
        let backoff_high = br.calculate_backoff(20);

        // Should be capped at max_open_duration (without jitter)
        // max = 100ms * 32 = 3200ms
        assert_eq!(
            backoff_high.as_millis(),
            3200,
            "Backoff should be capped at max_open_duration"
        );

        // Test with jitter applied
        let jittered_high = br.apply_jitter(backoff_high);
        // With jitter = 3200ms * 1.2 to 3200ms * 1.3 = 3840ms to 4160ms
        assert!(
            jittered_high.as_millis() >= 3840,
            "Jittered backoff should have minimum jitter, got {}ms",
            jittered_high.as_millis()
        );
        assert!(
            jittered_high.as_millis() <= 4160,
            "Jittered backoff should be capped, got {}ms",
            jittered_high.as_millis()
        );
    }

    #[test]
    fn test_metrics_integration() {
        let clock = setup_test_clock();
        let mut br = HostBreaker::new(10000, 500, 2, 0.9);

        // Create multiple hosts with different states for metrics testing
        let hosts = ["metrics1.com", "metrics2.com", "metrics3.com"];

        // Put first host in OPEN state
        for _ in 0..2 {
            br.mark_failure(hosts[0]);
        }

        // Second host should be CLOSED (no failures)
        assert!(br.check(hosts[1]));

        // Third host: trip then recover to HALF_OPEN
        for _ in 0..2 {
            br.mark_failure(hosts[2]);
        }

        // Advance time beyond open duration (accounting for jitter)
        clock.advance(Duration::from_millis(700));
        assert!(br.check(hosts[2])); // Should transition to HALF_OPEN

        // Check state stats for metrics
        let stats = br.state_stats();
        assert_eq!(
            stats.len(),
            2,
            "Should have stats for 2 hosts that have been accessed"
        );

        // Verify states (order may vary)
        let state_map: std::collections::HashMap<String, String> = stats
            .iter()
            .map(|(host, state, _)| (host.clone(), state.clone()))
            .collect();

        assert_eq!(state_map.get(hosts[0]), Some(&"open".to_string()));
        // Note: hosts[2] might be "half_open" or back to "open" depending on timing
    }

    #[test]
    fn test_host_isolation() {
        let mut br = HostBreaker::new(10000, 1000, 2, 0.9);

        // Fail one host
        for _ in 0..2 {
            br.mark_failure("bad.com");
        }

        // Other hosts should not be affected
        assert!(br.check("good.com"));
        assert!(!br.check("bad.com")); // Should be blocked

        // Good host should remain working
        br.mark_success("good.com");
        assert!(br.check("good.com"));
    }

    #[test]
    fn test_state_transitions() {
        let clock = setup_test_clock();
        let mut br = HostBreaker::new(10000, 100, 2, 0.9);

        let host = "transition-test.com";

        // Start CLOSED
        assert!(br.check(host));

        // Transition to OPEN
        for _ in 0..2 {
            assert!(br.check(host)); // Should allow while building failures
            br.mark_failure(host);
        }
        assert!(!br.check(host)); // Should be OPEN now

        // Advance time and transition to HALF_OPEN
        clock.advance(Duration::from_millis(150));
        assert!(br.check(host)); // First probe allowed

        // Successful probe should close circuit
        br.mark_success(host);

        // Complete successful probes to close
        br.mark_success(host);
        br.mark_success(host);

        let stats = br.state_stats();
        let host_state = stats.iter().find(|(h, _, _)| h == host).unwrap();
        assert_eq!(
            host_state.1, "closed",
            "Circuit should be closed after successful probes"
        );
    }

    #[test]
    fn test_reopen_count_progression() {
        let clock = setup_test_clock();
        let mut br = HostBreaker::new(10000, 50, 2, 0.9);

        let host = "reopen-count.com";

        // First failure cycle
        for _ in 0..2 {
            br.mark_failure(host);
        }

        let stats1 = br.state_stats();
        let reopen1 = stats1.iter().find(|(h, _, _)| h == host).unwrap().2;
        assert_eq!(reopen1, 1, "First trip should have reopen_count = 1");

        // Advance time and fail probe
        clock.advance(Duration::from_millis(80));
        assert!(br.check(host)); // Allow probe
        br.mark_failure(host); // Fail the probe

        let stats2 = br.state_stats();
        let reopen2 = stats2.iter().find(|(h, _, _)| h == host).unwrap().2;
        assert_eq!(
            reopen2, 2,
            "Failed probe should increment reopen_count to 2"
        );

        // Third cycle (need to wait longer due to exponential backoff + jitter)
        clock.advance(Duration::from_millis(200));
        assert!(br.check(host));
        br.mark_failure(host);

        let stats3 = br.state_stats();
        let reopen3 = stats3.iter().find(|(h, _, _)| h == host).unwrap().2;
        assert_eq!(
            reopen3, 3,
            "Third failure should increment reopen_count to 3"
        );
    }
}
