#[cfg(feature = "proto_trojan_min")]
#[tokio::test]
async fn harness_tcp_timeout_is_bounded() {
    // 连接到保留地址，期望超时而不是卡死
    let r = sb_proto::trojan_harness::connect_env(
        "203.0.113.1",
        9,
        "pass",
        sb_proto::trojan_harness::ConnectOpts {
            tls: false,
            timeout_ms: 50,
        },
    );
    let _ = r.await; // 不断言网络结果，只验证函数可返回
    // Test passes if we reach here without hanging
}
