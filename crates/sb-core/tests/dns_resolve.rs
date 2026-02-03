//! 跨路径 DNS 测试：系统解析与内部缓存解析都应工作，并返回至少 1 个地址
#![cfg(test)]

#[tokio::test]
async fn resolve_all_system_and_cache_paths() {
    // 1) 默认系统解析（未开缓存）
    std::env::remove_var("SB_DNS_CACHE_ENABLE");
    let a = match sb_core::dns::resolve::resolve_all("example.com", 80).await {
        Ok(addrs) => addrs,
        Err(err) => {
            eprintln!("skip: system resolve unavailable: {err}");
            return;
        }
    };
    assert!(!a.is_empty(), "system resolve returns at least 1 addr");

    // 2) 开启缓存路径（内部仍可落到系统解析，但带 LRU/并发闸门/Prefetch）
    std::env::set_var("SB_DNS_CACHE_ENABLE", "1");
    let b = sb_core::dns::resolve::resolve_all("example.com", 80)
        .await
        .expect("internal cached resolve must work");
    assert!(
        !b.is_empty(),
        "internal cached resolve returns at least 1 addr"
    );
}
