use std::sync::OnceLock;

use parking_lot::{ReentrantMutex, ReentrantMutexGuard};

fn env_lock() -> ReentrantMutexGuard<'static, ()> {
    static LOCK: OnceLock<ReentrantMutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| ReentrantMutex::new(())).lock()
}

pub(crate) struct EnvVarGuard {
    _lock: ReentrantMutexGuard<'static, ()>,
    key: &'static str,
    prev: Option<String>,
}

impl EnvVarGuard {
    pub(crate) fn set(key: &'static str, value: &str) -> Self {
        let lock = env_lock();
        let prev = std::env::var(key).ok();
        std::env::set_var(key, value);
        Self {
            _lock: lock,
            key,
            prev,
        }
    }

    pub(crate) fn remove(key: &'static str) -> Self {
        let lock = env_lock();
        let prev = std::env::var(key).ok();
        std::env::remove_var(key);
        Self {
            _lock: lock,
            key,
            prev,
        }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        if let Some(prev) = &self.prev {
            std::env::set_var(self.key, prev);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

