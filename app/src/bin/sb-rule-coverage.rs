#![cfg_attr(feature = "strict_warnings", deny(warnings))]

fn main() -> anyhow::Result<()> {
    let snap = sb_core::router::coverage::snapshot();
    println!("{}", serde_json::to_string_pretty(&snap)?);
    Ok(())
}
