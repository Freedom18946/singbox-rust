use std::sync::{Arc, OnceLock, RwLock};

#[cfg(test)]
use tokio::sync::{Mutex, MutexGuard};

use super::Resolver;

static GLOBAL: OnceLock<RwLock<Option<Arc<dyn Resolver>>>> = OnceLock::new();

fn cell() -> &'static RwLock<Option<Arc<dyn Resolver>>> {
    GLOBAL.get_or_init(|| RwLock::new(None))
}

/// Set global DNS resolver (replaces existing).
pub fn set(resolver: Arc<dyn Resolver>) {
    let lock = cell();
    let mut g = lock.write().unwrap();
    *g = Some(resolver);
}

/// Clear global DNS resolver.
#[allow(dead_code)]
pub fn clear() {
    let lock = cell();
    let mut g = lock.write().unwrap();
    *g = None;
}

/// Get global DNS resolver if exists.
pub fn get() -> Option<Arc<dyn Resolver>> {
    let lock = cell();
    lock.read().unwrap().as_ref().cloned()
}

#[cfg(test)]
pub(crate) struct TestGuard {
    _lock: MutexGuard<'static, ()>,
    previous: Option<Arc<dyn Resolver>>,
}

#[cfg(test)]
impl Drop for TestGuard {
    fn drop(&mut self) {
        if let Some(resolver) = self.previous.take() {
            set(resolver);
        } else {
            clear();
        }
    }
}

/// Serialize tests that replace the process-global DNS resolver and restore
/// the previous resolver when the guard is dropped.
#[cfg(test)]
pub(crate) async fn test_guard() -> TestGuard {
    static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let lock = TEST_LOCK.get_or_init(|| Mutex::new(())).lock().await;
    let previous = get();
    TestGuard {
        _lock: lock,
        previous,
    }
}
