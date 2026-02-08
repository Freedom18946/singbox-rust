use crate::context::{URLTestHistory, URLTestHistoryStorage};
use dashmap::DashMap;

#[derive(Debug)]
pub struct URLTestHistoryService {
    entries: DashMap<String, URLTestHistory>,
}

impl URLTestHistoryService {
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }
}

impl Default for URLTestHistoryService {
    fn default() -> Self {
        Self::new()
    }
}

impl URLTestHistoryStorage for URLTestHistoryService {
    fn load(&self, tag: &str) -> Option<URLTestHistory> {
        self.entries.get(tag).map(|e| e.value().clone())
    }

    fn store(&self, tag: &str, history: URLTestHistory) {
        self.entries.insert(tag.to_string(), history);
    }

    fn delete(&self, tag: &str) {
        self.entries.remove(tag);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    #[test]
    fn test_store_and_load() {
        let svc = URLTestHistoryService::new();
        assert!(svc.load("proxy-a").is_none());

        svc.store(
            "proxy-a",
            URLTestHistory {
                time: SystemTime::now(),
                delay: 42,
            },
        );
        let h = svc.load("proxy-a").unwrap();
        assert_eq!(h.delay, 42);
    }

    #[test]
    fn test_delete() {
        let svc = URLTestHistoryService::new();
        svc.store(
            "proxy-b",
            URLTestHistory {
                time: SystemTime::now(),
                delay: 100,
            },
        );
        assert!(svc.load("proxy-b").is_some());
        svc.delete("proxy-b");
        assert!(svc.load("proxy-b").is_none());
    }

    #[test]
    fn test_overwrite() {
        let svc = URLTestHistoryService::new();
        svc.store(
            "proxy-c",
            URLTestHistory {
                time: SystemTime::now(),
                delay: 50,
            },
        );
        svc.store(
            "proxy-c",
            URLTestHistory {
                time: SystemTime::now(),
                delay: 80,
            },
        );
        assert_eq!(svc.load("proxy-c").unwrap().delay, 80);
    }
}
