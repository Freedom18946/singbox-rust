#![cfg(feature = "rule_coverage")]
#![cfg_attr(feature = "strict_warnings", deny(warnings))]
fn main() {
    let snap = sb_core::router::coverage::snapshot();
    println!("{}", serde_json::to_string_pretty(&snap).unwrap());
}
