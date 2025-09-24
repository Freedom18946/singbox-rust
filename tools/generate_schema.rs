//! Placeholder tool: could export v2_schema.json from Rust types in future.
//! 当前仅打印内置 schema 的摘要，供人工核对。
use std::io::{Read};
fn main() {
    let schema = include_str!("../crates/sb-config/src/validator/v2_schema.json");
    let bytes = schema.as_bytes().len();
    let lines = schema.lines().count();
    println!(r#"{{"schema_bytes":{},"schema_lines":{}}}"#, bytes, lines);
}