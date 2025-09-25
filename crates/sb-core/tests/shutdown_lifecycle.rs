use sb_core::runtime::supervisor::Supervisor;

#[tokio::test]
async fn shutdown_converges_quickly() {
    let ir = sb_config::ir::ConfigIR::default();
    let sup = Supervisor::start(ir).await.expect("start supervisor");
    let handle = sup.handle();
    handle
        .shutdown_graceful(std::time::Duration::from_millis(100))
        .await
        .expect("shutdown");
}

#[tokio::test]
async fn repeated_init_and_shutdown_no_leak() {
    let ir = sb_config::ir::ConfigIR::default();
    let sup1 = Supervisor::start(ir.clone())
        .await
        .expect("start supervisor #1");
    let h1 = sup1.handle();
    h1
        .shutdown_graceful(std::time::Duration::from_millis(100))
        .await
        .expect("shutdown #1");

    let sup2 = Supervisor::start(ir)
        .await
        .expect("start supervisor #2");
    let h2 = sup2.handle();
    h2
        .shutdown_graceful(std::time::Duration::from_millis(100))
        .await
        .expect("shutdown #2");
}

