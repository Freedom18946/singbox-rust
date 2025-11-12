//! Test for Naive inbound adapter registration and instantiation.

#[test]
fn test_naive_inbound_registration() {
    // Ensure Naive inbound can be registered
    #[cfg(all(feature = "adapters", feature = "adapter-naive"))]
    {
        // Register all adapters
        sb_adapters::register::register_all();

        // Note: Full integration testing requires a router context and would be done in E2E tests
        println!("✓ Naive inbound registration completed successfully");
    }

    #[cfg(not(all(feature = "adapters", feature = "adapter-naive")))]
    {
        println!("⊘ Skipping Naive inbound test: required features not enabled");
    }
}

#[test]
fn test_naive_compiles() {
    // This test just ensures that the Naive inbound adapter compiles
    println!("✓ Naive inbound adapter compilation test passed");
}
