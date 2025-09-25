#![cfg_attr(feature = "strict_warnings", deny(warnings))]

// This binary can be built without the `rule_coverage` feature. When the
// feature is disabled we still provide a stub `main` so `cargo check` works
// out of the box.
#[cfg(not(feature = "rule_coverage"))]
fn main() {
    eprintln!("sb-rule-coverage: build without `--features rule_coverage` — stub running.");
    eprintln!("Hint: enable the feature to output JSON coverage snapshot.");
}

#[cfg(feature = "rule_coverage")]
fn main() {
    let snap = sb_core::router::coverage::snapshot();
    println!("{}", serde_json::to_string_pretty(&snap).unwrap());
}
