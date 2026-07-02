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
        return Ok(());
    };

    let config = from_subscription(&content)?;
    assert_eq!(config.schema_version, 2);
    Ok(())
}
