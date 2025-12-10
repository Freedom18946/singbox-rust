//! Common interrupt handling and graceful shutdown coordination.
//!
//! Provides utilities for coordinating graceful shutdown across multiple
//! services and tasks.
//!
//! # Example
//! ```ignore
//! use sb_common::interrupt::{InterruptHandler, ShutdownSignal};
//!
//! let handler = InterruptHandler::new();
//! let signal = handler.subscribe();
//!
//! // In a task:
//! tokio::select! {
//!     _ = signal.wait() => {
//!         // Graceful shutdown
//!     }
//!     _ = do_work() => {}
//! }
//! ```

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::broadcast;

/// Shutdown signal that can be awaited.
pub struct ShutdownSignal {
    /// Receiver for shutdown broadcast.
    rx: broadcast::Receiver<()>,
    /// Flag for immediate check.
    flag: Arc<AtomicBool>,
}

impl ShutdownSignal {
    /// Wait for shutdown signal.
    pub async fn wait(&mut self) {
        if self.flag.load(Ordering::Relaxed) {
            return;
        }
        let _ = self.rx.recv().await;
    }

    /// Check if shutdown has been requested (non-blocking).
    pub fn is_shutdown(&self) -> bool {
        self.flag.load(Ordering::Relaxed)
    }
}

/// Interrupt handler for coordinating graceful shutdown.
#[derive(Clone)]
pub struct InterruptHandler {
    /// Sender for shutdown broadcast.
    tx: broadcast::Sender<()>,
    /// Flag for immediate check.
    flag: Arc<AtomicBool>,
}

impl Default for InterruptHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl InterruptHandler {
    /// Create a new interrupt handler.
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(1);
        Self {
            tx,
            flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Subscribe to shutdown signal.
    pub fn subscribe(&self) -> ShutdownSignal {
        ShutdownSignal {
            rx: self.tx.subscribe(),
            flag: self.flag.clone(),
        }
    }

    /// Trigger shutdown.
    pub fn shutdown(&self) {
        self.flag.store(true, Ordering::SeqCst);
        let _ = self.tx.send(());
    }

    /// Check if shutdown has been triggered.
    pub fn is_shutdown(&self) -> bool {
        self.flag.load(Ordering::Relaxed)
    }
}

/// Task monitor for tracking service lifecycle.
#[derive(Default)]
pub struct TaskMonitor {
    /// Active task count.
    active: std::sync::atomic::AtomicUsize,
    /// Completed task count.
    completed: std::sync::atomic::AtomicUsize,
    /// Failed task count.
    failed: std::sync::atomic::AtomicUsize,
}

impl TaskMonitor {
    /// Create a new task monitor.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record task start.
    pub fn task_started(&self) {
        self.active.fetch_add(1, Ordering::Relaxed);
    }

    /// Record task completion.
    pub fn task_completed(&self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
        self.completed.fetch_add(1, Ordering::Relaxed);
    }

    /// Record task failure.
    pub fn task_failed(&self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
        self.failed.fetch_add(1, Ordering::Relaxed);
    }

    /// Get active task count.
    pub fn active_count(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }

    /// Get completed task count.
    pub fn completed_count(&self) -> usize {
        self.completed.load(Ordering::Relaxed)
    }

    /// Get failed task count.
    pub fn failed_count(&self) -> usize {
        self.failed.load(Ordering::Relaxed)
    }

    /// Wait until all tasks complete.
    pub async fn wait_all(&self) {
        while self.active_count() > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    /// Wait with timeout.
    pub async fn wait_timeout(&self, timeout: std::time::Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        while self.active_count() > 0 {
            if std::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        true
    }
}

/// Guard that tracks task lifecycle.
pub struct TaskGuard<'a> {
    monitor: &'a TaskMonitor,
    failed: bool,
}

impl<'a> TaskGuard<'a> {
    /// Create a new task guard.
    pub fn new(monitor: &'a TaskMonitor) -> Self {
        monitor.task_started();
        Self {
            monitor,
            failed: false,
        }
    }

    /// Mark task as failed.
    pub fn fail(&mut self) {
        self.failed = true;
    }
}

impl Drop for TaskGuard<'_> {
    fn drop(&mut self) {
        if self.failed {
            self.monitor.task_failed();
        } else {
            self.monitor.task_completed();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_interrupt_handler() {
        let handler = InterruptHandler::new();
        let mut signal = handler.subscribe();

        assert!(!handler.is_shutdown());

        handler.shutdown();

        assert!(handler.is_shutdown());
        signal.wait().await;
    }

    #[tokio::test]
    async fn test_task_monitor() {
        let monitor = TaskMonitor::new();

        {
            let _guard = TaskGuard::new(&monitor);
            assert_eq!(monitor.active_count(), 1);
        }

        assert_eq!(monitor.active_count(), 0);
        assert_eq!(monitor.completed_count(), 1);
    }

    #[tokio::test]
    async fn test_task_failure() {
        let monitor = TaskMonitor::new();

        {
            let mut guard = TaskGuard::new(&monitor);
            guard.fail();
        }

        assert_eq!(monitor.failed_count(), 1);
        assert_eq!(monitor.completed_count(), 0);
    }
}
