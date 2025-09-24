#![cfg(feature = "selector_p3")]
#![cfg_attr(
    any(test),
    allow(dead_code, unused_imports, unused_variables, unused_must_use)
)]
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Instant;

pub trait SelectorFeedback {
    fn record_success(&mut self, id: &str, rtt_ms: u64);
    fn record_error(&mut self, id: &str);
    fn record_open_fail(&mut self, id: &str);
}

#[derive(Clone)]
pub struct FeedbackHandle {
    inner: Arc<Mutex<dyn SelectorFeedback + Send + Sync>>,
}

impl FeedbackHandle {
    pub fn new(inner: Arc<Mutex<dyn SelectorFeedback + Send + Sync>>) -> Self {
        Self { inner }
    }
    pub fn success(&self, id: &str, started: Instant) {
        let ms = started.elapsed().as_millis() as u64;
        self.inner.lock().record_success(id, ms);
    }
    pub fn error(&self, id: &str) {
        self.inner.lock().record_error(id);
    }
    pub fn open_fail(&self, id: &str) {
        self.inner.lock().record_open_fail(id);
    }
}

/// Bridge wrapper so `FeedbackHandle` can drive a concrete `ScoreSelector`
/// while keeping a single callsite in selection/observation.
#[derive(Clone)]
pub struct P3FeedbackWrapper {
    inner: Arc<Mutex<crate::outbound::selector_p3::ScoreSelector>>, // concrete selector
}

impl P3FeedbackWrapper {
    pub fn new(inner: Arc<Mutex<crate::outbound::selector_p3::ScoreSelector>>) -> Self {
        Self { inner }
    }
}

impl SelectorFeedback for P3FeedbackWrapper {
    fn record_success(&mut self, id: &str, rtt_ms: u64) {
        self.inner.lock().record_success(id, rtt_ms);
    }
    fn record_error(&mut self, id: &str) {
        self.inner.lock().record_error(id);
    }
    fn record_open_fail(&mut self, id: &str) {
        self.inner.lock().record_open_fail(id);
    }
}
