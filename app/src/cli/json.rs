//! Simple JSON helpers for CLI tools (unified ok/error shape)
use serde::Serialize;
use serde_json::json;

/// Print a success JSON with optional payload
pub fn ok<T: Serialize>(payload: &T) {
    let obj = json!({
        "ok": true,
        "data": payload
    });
    println!("{}", serde_json::to_string(&obj).unwrap());
}

/// Print an error JSON and exit with non-zero status
pub fn err(code: u16, error: &str, hint: &str) -> ! {
    let obj = json!({
        "ok": false,
        "error": error,
        "hint": hint,
        "code": code
    });
    eprintln!("{}", serde_json::to_string(&obj).unwrap());
    std::process::exit(1);
}