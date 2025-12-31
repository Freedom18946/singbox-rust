//! Time service implementation (Go parity).

use crate::context::TimeService;
// use std::sync::Arc;
use std::time::{SystemTime, Instant};

/// Default time service using system clock.
#[derive(Debug, Clone, Default)]
pub struct SystemTimeService;

impl SystemTimeService {
    pub fn new() -> Self {
        Self
    }
}

impl TimeService for SystemTimeService {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
    
    fn monotonic(&self) -> Instant {
        Instant::now()
    }
}
