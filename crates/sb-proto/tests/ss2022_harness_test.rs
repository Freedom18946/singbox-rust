#[cfg(feature = "proto_ss2022_min")]
#[tokio::test]
async fn harness_shape_only() {
    // 只校验返回结构，不做真实网络（可用 SB_ADMIN_ALLOW_NET 控制上层端点）
    let r = sb_proto::ss2022_harness::ConnectReport {
        ok: true,
        path: "tcp",
        elapsed_ms: 1,
    };
    assert!(r.ok && (r.path == "tcp" || r.path == "tls"));
}
