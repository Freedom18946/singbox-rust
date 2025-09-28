//! Simple JSON helpers for CLI tools (unified ok/error shape)
use serde::Serialize;
#[cfg(feature = "dev-cli")]
use serde_json::json;

/// Print a success JSON with optional payload
#[cfg(feature = "dev-cli")]
pub fn ok<T: Serialize>(payload: &T) {
    let obj = json!({
        "ok": true,
        "data": payload
    });
    println!("{}", serde_json::to_string(&obj).unwrap());
}

/// Print an error JSON and exit with non-zero status
#[cfg(feature = "dev-cli")]
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

// Fallback minimal helpers when dev-cli is not enabled
#[cfg(not(feature = "dev-cli"))]
#[allow(dead_code)] // Scaffolding helpers for when dev-cli is disabled
pub fn ok<T: Serialize>(payload: &T) {
    match serde_json::to_string(payload) {
        Ok(s) => println!("{}", s),
        Err(_) => println!("{{}}"),
    }
}

#[cfg(not(feature = "dev-cli"))]
#[allow(dead_code)] // Scaffolding helper for when dev-cli is disabled
pub fn err(_code: u16, error: &str, hint: &str) -> ! {
    eprintln!("error: {} hint: {}", error, hint);
    std::process::exit(1);
}
