use once_cell::sync::OnceCell;
use std::sync::Mutex;
use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_AUDIT_ENTRIES: usize = 100;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditEntry {
    pub ts: u64,
    pub actor: String,
    pub action: String,
    pub delta: serde_json::Value,
    pub ok: bool,
    pub msg: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changed: Option<bool>,
}

static AUDIT_LOG: OnceCell<Mutex<VecDeque<AuditEntry>>> = OnceCell::new();

fn get_log() -> &'static Mutex<VecDeque<AuditEntry>> {
    AUDIT_LOG.get_or_init(|| Mutex::new(VecDeque::with_capacity(MAX_AUDIT_ENTRIES)))
}

pub fn log(entry: AuditEntry) {
    let log = get_log();
    if let Ok(mut queue) = log.lock() {
        queue.push_back(entry.clone());
        while queue.len() > MAX_AUDIT_ENTRIES {
            queue.pop_front();
        }
        tracing::info!(
            actor = %entry.actor,
            action = %entry.action,
            ok = entry.ok,
            msg = %entry.msg,
            "Audit log entry"
        );
    }
}

pub fn recent(n: usize) -> Vec<AuditEntry> {
    let log = get_log();
    if let Ok(queue) = log.lock() {
        queue.iter()
            .rev()
            .take(n)
            .cloned()
            .collect()
    } else {
        Vec::new()
    }
}

pub fn latest_ts() -> Option<u64> {
    let log = get_log();
    if let Ok(queue) = log.lock() {
        queue.back().map(|entry| entry.ts)
    } else {
        None
    }
}

pub fn create_entry(
    actor: impl Into<String>,
    action: impl Into<String>,
    delta: serde_json::Value,
    ok: bool,
    msg: impl Into<String>,
) -> AuditEntry {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    AuditEntry {
        ts,
        actor: actor.into(),
        action: action.into(),
        delta,
        ok,
        msg: msg.into(),
        changed: None,
    }
}

impl AuditEntry {
    pub fn with_changed(mut self, changed: bool) -> Self {
        self.changed = Some(changed);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_log_basic() {
        let entry = create_entry(
            "admin",
            "config.update",
            serde_json::json!({"timeout_ms": 5000}),
            true,
            "Updated timeout",
        );

        log(entry.clone());

        let entries = recent(10);
        assert!(!entries.is_empty());
        assert_eq!(entries[0].actor, "admin");
        assert_eq!(entries[0].action, "config.update");
        assert!(entries[0].ok);
    }

    #[test]
    fn test_audit_log_capacity() {
        for i in 0..150 {
            let entry = create_entry(
                "user",
                format!("test.action.{}", i),
                serde_json::json!({}),
                true,
                format!("Test entry {}", i),
            );
            log(entry);
        }

        let entries = recent(200);
        assert!(entries.len() <= MAX_AUDIT_ENTRIES);
    }

    #[test]
    fn test_recent_limit() {
        for i in 0..20 {
            let entry = create_entry(
                "user",
                "test.action",
                serde_json::json!({"index": i}),
                true,
                format!("Entry {}", i),
            );
            log(entry);
        }

        let entries = recent(5);
        assert_eq!(entries.len(), 5);
    }
}