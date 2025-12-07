#![cfg(feature = "router")]
use sb_core::router::minijson::{self, Val};

#[test]
fn json_basic() {
    let s = minijson::obj([
        ("a", Val::NumU(1)),
        ("b", Val::Bool(true)),
        ("c", Val::Str("x\"y\\z")),
    ]);
    assert!(s.contains("\"a\":1"));
    assert!(s.contains("\"b\":true"));
    assert!(s.contains("\"c\":\"x\\\"y\\\\z\""));
}
