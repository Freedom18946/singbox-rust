use std::error::Error;
use std::fmt::Display;
use std::io;

fn require_net() -> bool {
    std::env::var("SB_TEST_REQUIRE_NET")
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            matches!(v.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(false)
}

/// Print a standardized skip message and return true (unless SB_TEST_REQUIRE_NET=1).
pub fn skip_with_reason(context: &str, reason: impl Display) -> bool {
    if require_net() {
        return false;
    }
    eprintln!("skipping {}: {}", context, reason);
    true
}

/// Skip when an error message contains the provided needle.
pub fn skip_if_msg_contains(err: &dyn Error, needle: &str, context: &str) -> bool {
    let msg = err.to_string();
    if msg.contains(needle) {
        return skip_with_reason(context, msg);
    }
    false
}

/// Skip when an IO error indicates permission denied.
pub fn skip_if_io_permission_denied(err: &io::Error, context: &str) -> bool {
    if err.kind() == io::ErrorKind::PermissionDenied {
        return skip_with_reason(context, err);
    }
    false
}
