//! Stress Testing Suite for P0 Protocols
//!
//! This test suite provides comprehensive stress testing for all P0 protocols.
//!
//! ## Test Categories
//!
//! 1. **Baseline Tests**: Direct TCP without protocol overhead
//! 2. **Protocol-Specific Tests**: Each P0 protocol under stress
//! 3. **Resource Monitoring**: Memory and FD leak detection
//! 4. **Endurance Tests**: 24-hour long-running tests
//!
//! ## Running Tests
//!
//! Run all stress tests (short duration):
//! ```bash
//! cargo test --test stress_tests --release -- --ignored --test-threads=1
//! ```
//!
//! Run specific test:
//! ```bash
//! cargo test --test stress_tests --release -- baseline_short --ignored
//! ```
//!
//! Run 24-hour endurance test:
//! ```bash
//! cargo test --test stress_tests --release -- 24_hour --ignored --test-threads=1
//! ```
//!
//! ## Monitoring
//!
//! Use the monitoring script in parallel:
//! ```bash
//! ./scripts/monitor_stress_test.sh
//! ```

#[path = "../../tests/stress/mod.rs"]
mod stress;

#[path = "../../tests/stress/baseline_stress.rs"]
mod baseline_stress;

#[path = "../../tests/stress/p0_protocols_stress.rs"]
mod p0_protocols_stress;
