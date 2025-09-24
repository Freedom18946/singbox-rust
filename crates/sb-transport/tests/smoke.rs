//! # sb-transport 冒烟测试
//!
//! 该文件包含 sb-transport crate 的冒烟测试（smoke tests）。
//! 冒烟测试的目的是验证代码能够正常编译和运行，
//! 而不是测试具体的功能正确性。
//!
//! ## 测试策略
//! - **编译测试**: 验证代码结构和类型系统的正确性
//! - **实例化测试**: 验证对象可以正常创建
//! - **安全测试**: 使用不安全的配置，不进行实际网络操作
//!
//! ## 注意事项
//! 这里的测试使用了不安全的 TLS 配置（空根证书存储），
//! 绝对不能在生产环境中使用！

/// TLS 拨号器编译测试
///
/// 该测试验证 TLS 拨号器能够正常编译和实例化。
/// 这是一个冒烟测试，只检查编译能力，不测试实际功能。
///
/// ## 测试覆盖范围
/// - TLS 相关类型的正确导入
/// - TlsDialer 结构体的创建
/// - TcpDialer 作为底层传输的集成
/// - smoke_empty_roots_config 的正常调用
///
/// ## 安全性警告
/// ⚠️ 该测试使用了不安全的 TLS 配置：
/// - 空的根证书存储
/// - 不验证服务器证书
/// - 容易受到中间人攻击
///
/// 这种配置**绝对不能**在生产环境中使用！
///
/// ## 测试逻辑
/// 1. 创建 TcpDialer 作为底层传输
/// 2. 使用测试用的空 TLS 配置
/// 3. 组装 TlsDialer 实例
/// 4. 验证实例可以正常创建和引用
///
/// # 前置条件
/// 该测试仅在启用 `transport_tls` feature 时才会编译和运行。
///
/// # 预期结果
/// 测试应该成功通过，表示 TLS 相关代码能够正常编译。
#[cfg(feature = "transport_tls")]
#[tokio::test]
async fn tls_dialer_compiles() {
    // 导入必要的类型和 trait
    use sb_transport::dialer::{Dialer, TcpDialer};
    use sb_transport::tls::{smoke_empty_roots_config, TlsDialer};

    // 创建 TLS 拨号器实例
    // 这里使用了各种有代表性的配置组合
    let d = TlsDialer {
        // 使用基础的 TCP 拨号器作为底层传输
        inner: TcpDialer,

        // 使用测试用的空 TLS 配置
        // 注意：这是不安全的，只用于测试！
        config: smoke_empty_roots_config(),

        // 不设置 SNI 重写，使用默认行为
        sni_override: None,

        // 不设置 ALPN 协商，使用默认行为
        alpn: None,
    };

    // 仅进行编译检查，验证实例可以正常创建和引用
    // 这里不进行实际的网络连接测试
    let _ = &d;

    // 断言测试通过
    // 如果能执行到这里，说明编译和实例化都成功了
    assert!(true);
}
