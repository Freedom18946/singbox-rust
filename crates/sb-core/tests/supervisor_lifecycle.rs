use sb_config::ir::{ConfigIR, OutboundIR, OutboundType};
use sb_core::runtime::supervisor::Supervisor;
use std::time::Duration;
use tokio::time::sleep;

#[tokio::test]
async fn test_supervisor_lifecycle() {
    std::env::set_var("SB_INBOUND_RELOAD_GRACE_MS", "0");
    // 1. Setup initial config
    let initial_ir = ConfigIR {
        inbounds: vec![],
        outbounds: vec![OutboundIR {
            ty: OutboundType::Direct,
            ..Default::default()
        }],
        ..Default::default()
    };

    // 2. Start Supervisor
    // We use the start method. Depending on features, it might be different, but the signature is the same.
    let supervisor = Supervisor::start(initial_ir.clone())
        .await
        .expect("failed to start supervisor");
    let handle = supervisor.handle();

    // 3. Verify initial state
    {
        let state = handle.state().await;
        let guard = state.read().await;
        assert_eq!(guard.current_ir, initial_ir);
    }

    // 4. Reload with new config
    let new_ir = ConfigIR {
        inbounds: vec![],
        outbounds: vec![OutboundIR {
            ty: OutboundType::Direct,
            name: Some("direct-2".to_string()), // Change something
            ..Default::default()
        }],
        ..Default::default()
    };

    let _diff = supervisor
        .reload(new_ir.clone())
        .await
        .expect("reload");
    // Diff might be empty if SB_RUNTIME_DIFF is not set, but reload should succeed.

    // 5. Verify new state
    // Give it a moment to process the reload message
    sleep(Duration::from_millis(500)).await;

    // if handle.is_finished() {
    //     panic!("Supervisor task finished unexpectedly");
    // }

    {
        let state = handle.state().await;
        let guard = state.read().await;
        assert_eq!(guard.current_ir, new_ir);
    }

    // 6. Shutdown
    supervisor
        .shutdown_graceful(Duration::from_secs(1))
        .await
        .expect("failed to shutdown");
}
