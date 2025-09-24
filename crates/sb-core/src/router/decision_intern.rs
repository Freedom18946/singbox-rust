use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// A tiny interning pool for routing decisions to avoid scattered leaks.
/// Typical decisions are few (e.g., direct/reject/proxy names), so a global
/// map guarded by a Mutex is sufficient and simple.
struct Pool {
    map: HashMap<String, &'static str>,
}

impl Pool {
    fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }
    fn intern(&mut self, s: &str) -> &'static str {
        if let Some(&p) = self.map.get(s) {
            return p;
        }
        let boxed: Box<str> = s.to_owned().into_boxed_str();
        let leaked: &'static str = Box::leak(boxed);
        // Use the leaked string as key to avoid a second allocation on hit path.
        self.map.insert(leaked.to_string(), leaked);
        leaked
    }
    fn len(&self) -> usize {
        self.map.len()
    }
}

fn pool() -> &'static Mutex<Pool> {
    static G: OnceLock<Mutex<Pool>> = OnceLock::new();
    G.get_or_init(|| Mutex::new(Pool::new()))
}

/// Intern a decision string and return &'static str for legacy APIs.
pub fn intern_decision(s: &str) -> &'static str {
    let mut g = pool().lock().unwrap();
    g.intern(s)
}

/// 统一入口：把拥有权的 String 驻留并返回 &'static
pub fn intern_decision_owned(s: String) -> &'static str {
    intern_decision(&s)
}

/// Visible for tests.
#[allow(dead_code)]
pub fn intern_size() -> usize {
    let g = pool().lock().unwrap();
    g.len()
}
