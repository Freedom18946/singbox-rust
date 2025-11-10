use std::sync::{Arc, OnceLock, RwLock};

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

