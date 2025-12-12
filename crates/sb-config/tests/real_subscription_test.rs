//! Test subscription parsing on real data.
//!
//! This test is intended for manual QA with a local subscription sample.
//! By default it is skipped unless a fixture path is provided.

use sb_config::subscribe::from_subscription;

#[test]
fn test_real_subscription() -> anyhow::Result<()> {
    let path = std::env::var("SB_SUBSCRIPTION_TEST_PATH").unwrap_or_else(|_| {
        format!(
            "{}/tests/fixtures/subscription_test.txt",
            env!("CARGO_MANIFEST_DIR")
        )
    });

    let Ok(content) = std::fs::read_to_string(&path) else {
        eprintln!(
            "skipping real subscription test; fixture not found at {}",
            path
        );
        return Ok(());
    };

    println!("Content size: {} bytes", content.len());
    println!("First 300 chars:\n{}", &content[..content.len().min(300)]);

    let config = from_subscription(&content)?;
    println!("\n✅ Parsing SUCCESS!");
    println!("Outbounds: {}", config.outbounds.len());
    println!("Rules: {}", config.rules.len());

    for (i, ob) in config.outbounds.iter().take(10).enumerate() {
        println!("  [{}] {:?}", i + 1, ob);
    }
    Ok(())
}
