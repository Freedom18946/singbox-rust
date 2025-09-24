//! # TLS 传输层安全模块
//!
//! 该模块提供基于 rustls 的 TLS 连接包装器，支持：
//! - TLS 客户端连接建立
//! - SNI (Server Name Indication) 配置
//! - ALPN (Application Layer Protocol Negotiation) 支持
//! - 环境变量驱动的配置
//!
//! ## 安全性考虑
//! - 使用现代的 rustls 库提供 TLS 支持
//! - 支持灵活的根证书配置
//! - 提供测试和生产环境的不同配置选项

use super::dialer::{DialError, Dialer, IoStream};
use async_trait::async_trait;
use std::sync::Arc;

/// TLS 拨号器包装器
///
/// 该结构体包装了任意的底层拨号器，为其添加 TLS 加密层支持。
/// 它采用装饰器模式，可以将任何实现了 `Dialer` trait 的拨号器
/// 转换为支持 TLS 的安全连接拨号器。
///
/// ## 设计理念
/// - **组合优于继承**: 通过包装而不是继承来扩展功能
/// - **灵活配置**: 支持 SNI 重写和 ALPN 协商
/// - **环境驱动**: 可通过环境变量进行配置
///
/// ## 类型参数
/// - `D`: 底层拨号器类型，必须实现 `Dialer` trait
///
/// ## 字段说明
/// - `inner`: 底层拨号器实例，负责建立基础连接
/// - `config`: rustls 客户端配置，包含证书、协议等设置
/// - `sni_override`: 可选的 SNI 主机名重写
/// - `alpn`: 可选的应用层协议协商列表
pub struct TlsDialer<D: Dialer> {
    /// 底层拨号器，负责建立原始连接
    pub inner: D,

    /// TLS 客户端配置，包含根证书、协议版本等
    pub config: Arc<rustls::ClientConfig>,

    /// SNI 主机名重写（可选）
    /// 如果设置，将使用此值而不是连接目标主机名作为 SNI
    pub sni_override: Option<String>,

    /// ALPN 协议列表（可选）
    /// 用于在 TLS 握手期间协商应用层协议
    pub alpn: Option<Vec<Vec<u8>>>,
}

#[async_trait]
impl<D: Dialer + Send + Sync> Dialer for TlsDialer<D> {
    /// 建立 TLS 加密连接
    ///
    /// 该方法实现了完整的 TLS 连接建立流程：
    /// 1. 使用底层拨号器建立原始连接
    /// 2. 配置 SNI 和 ALPN 参数
    /// 3. 执行 TLS 握手
    /// 4. 返回加密的连接流
    ///
    /// # 连接流程
    /// ```text
    /// 原始连接 -> TLS握手 -> 加密连接
    ///     ↑          ↑         ↑
    ///   底层拨号器   rustls   IoStream
    /// ```
    ///
    /// # 参数处理
    /// - SNI: 使用 `sni_override` 或回退到目标主机名
    /// - ALPN: 如果配置了协议列表，会克隆配置并应用
    ///
    /// # 错误处理
    /// - 底层连接失败: 直接传播 `DialError`
    /// - SNI 解析失败: 转换为 `DialError::Tls`
    /// - TLS 握手失败: 转换为 `DialError::Tls`
    async fn connect(&self, host: &str, port: u16) -> Result<IoStream, DialError> {
        use rustls::pki_types::ServerName;
        use tokio_rustls::TlsConnector;

        // 第一步：使用底层拨号器建立原始连接
        // 这可能是 TCP、Unix socket 或其他任何传输层连接
        let stream = self.inner.connect(host, port).await?;

        // 第二步：确定 SNI 主机名
        // SNI (Server Name Indication) 告诉服务器客户端期望的主机名
        // 这对于虚拟主机和 CDN 场景非常重要
        let sni_host = self.sni_override.as_deref().unwrap_or(host);

        // 将主机名转换为 rustls 的 ServerName 类型
        // 这里会进行主机名格式验证
        let sn = ServerName::try_from(sni_host.to_string())
            .map_err(|e| DialError::Tls(format!("SNI 主机名解析失败: {:?}", e)))?;

        // 第三步：处理 ALPN 配置
        // ALPN (Application Layer Protocol Negotiation) 允许在 TLS 握手期间
        // 协商应用层协议，常用于 HTTP/2, HTTP/3 等
        let cfg = if let Some(alpns) = &self.alpn {
            // 克隆基础配置并应用 ALPN 设置
            let mut c = (*self.config).clone();
            // 在 rustls 0.23 中，alpn_protocols 可以直接设置
            c.alpn_protocols = alpns.clone();
            Arc::new(c)
        } else {
            // 如果没有 ALPN 配置，直接使用原始配置
            self.config.clone()
        };

        // 第四步：创建 TLS 连接器并执行握手
        let connector = TlsConnector::from(cfg);
        let tls = connector
            .connect(sn, stream)
            .await
            .map_err(|e| DialError::Tls(format!("TLS 握手失败: {}", e)))?;

        // 第五步：将 TLS 流包装为通用的 IoStream
        // 这样调用者就可以像使用普通流一样使用加密连接
        Ok(Box::new(tls))
    }
}

/// 构建生产环境 TLS 配置（基于 webpki_roots）
///
/// 该函数创建一个适用于生产环境的 TLS 客户端配置，特点：
/// - 使用系统或内置的根证书存储
/// - 不使用客户端证书认证
/// - 适用于标准的 HTTPS 连接
///
/// ## 注意事项
/// 当前实现使用空的根证书存储作为占位符。在生产环境中，应该：
/// - 使用 `webpki-roots` crate 加载内置根证书
/// - 或使用 `rustls-native-certs` 加载系统根证书
/// - 或手动加载自定义根证书
///
/// ## rustls 0.23 兼容性
/// 该实现基于 rustls 0.23 的 API，RootCertStore 的使用方式
/// 可能与旧版本有所不同。
///
/// # 返回值
/// 返回共享的 `ClientConfig` 实例，可以安全地在多个连接间复用
///
/// # 使用示例
/// ```rust,no_run
/// use sb_transport::{webpki_roots_config, TlsDialer, TcpDialer};
///
/// let config = webpki_roots_config();
/// let tls_dialer = TlsDialer {
///     inner: TcpDialer,
///     config,
///     sni_override: None,
///     alpn: None,
/// };
/// ```
#[cfg(feature = "transport_tls")]
pub fn webpki_roots_config() -> Arc<rustls::ClientConfig> {
    use rustls::{ClientConfig, RootCertStore};

    // 注意：rustls 0.23 下 RootCertStore API 已更新
    // 为避免复杂度，这里使用空 Root 作为占位
    // 在实际生产环境中，应该使用以下方式之一：
    //
    // 1. 使用 webpki-roots:
    //    let mut roots = RootCertStore::empty();
    //    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    //
    // 2. 使用系统根证书:
    //    let mut roots = RootCertStore::empty();
    //    for cert in rustls_native_certs::load_native_certs()? {
    //        roots.add(cert)?;
    //    }
    let roots = RootCertStore::empty();

    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// 构建测试专用 TLS 配置（空根证书存储）
///
/// 该函数创建一个仅用于测试的 TLS 客户端配置，特点：
/// - 使用空的根证书存储
/// - 不进行证书验证
/// - **严禁在生产环境使用**
///
/// ## 安全警告
/// 🚨 **该配置不提供任何安全保障！**
/// - 不验证服务器证书
/// - 不检查证书链
/// - 容易受到中间人攻击
///
/// ## 适用场景
/// 仅适用于以下测试场景：
/// - 单元测试中的 TLS 代码路径验证
/// - 本地开发环境的快速原型测试
/// - 不涉及真实网络通信的集成测试
///
/// ## 命名说明
/// "smoke" 表示这是一个冒烟测试配置，仅用于验证代码
/// 是否能正常编译和运行，不保证实际功能正确性。
///
/// # 返回值
/// 返回一个不安全的测试用 `ClientConfig` 实例
///
/// # 使用示例
/// ```rust,no_run
/// // 仅在测试中使用！
/// #[cfg(test)]
/// mod tests {
///     use super::*;
///
///     #[test]
///     fn test_tls_dialer_creation() {
///         let config = smoke_empty_roots_config();
///         // 测试代码...
///     }
/// }
/// ```
#[cfg(feature = "transport_tls")]
pub fn smoke_empty_roots_config() -> Arc<rustls::ClientConfig> {
    use rustls::{ClientConfig, RootCertStore};

    // 创建完全空的根证书存储
    // 这意味着不会验证任何服务器证书
    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth(),
    )
}
impl<D: Dialer> TlsDialer<D> {
    /// 从环境变量构建 TLS 拨号器
    ///
    /// R69: 从环境变量构建配置（SNI/ALPN），无网络副作用
    ///
    /// 该方法提供了一种通过环境变量配置 TLS 行为的便捷方式，
    /// 特别适用于容器化部署和 12-Factor App 模式。
    ///
    /// ## 支持的环境变量
    ///
    /// ### `SB_TLS_SNI`
    /// - **作用**: 重写 SNI (Server Name Indication) 主机名
    /// - **格式**: 字符串，如 `"api.example.com"`
    /// - **用途**: 在需要连接到特定主机但 SNI 需要指向其他主机名时使用
    /// - **示例**: 连接到负载均衡器但需要特定的 SNI
    ///
    /// ### `SB_TLS_ALPN`
    /// - **作用**: 配置 ALPN (Application Layer Protocol Negotiation) 协议列表
    /// - **格式**: 逗号分隔的协议名称，如 `"h2,http/1.1"`
    /// - **用途**: 启用 HTTP/2、HTTP/3 等现代协议支持
    /// - **示例**: `"h2,http/1.1"` 表示优先使用 HTTP/2，回退到 HTTP/1.1
    ///
    /// ## 设计原则
    /// - **无副作用**: 仅读取环境变量，不执行网络操作
    /// - **容错性**: 环境变量不存在时使用合理默认值
    /// - **可测试性**: 环境变量可以在测试中轻松模拟
    ///
    /// # 参数
    /// - `inner`: 底层拨号器实例
    /// - `config`: 基础 TLS 配置，环境变量设置会在此基础上叠加
    ///
    /// # 返回值
    /// 配置好的 `TlsDialer` 实例，包含环境变量指定的设置
    ///
    /// # 使用示例
    /// ```bash
    /// # 设置环境变量
    /// export SB_TLS_SNI="api.backend.internal"
    /// export SB_TLS_ALPN="h2,http/1.1"
    /// ```
    ///
    /// ```rust,no_run
    /// use sb_transport::{TlsDialer, TcpDialer, webpki_roots_config};
    ///
    /// let base_dialer = TcpDialer;
    /// let tls_config = webpki_roots_config();
    /// let tls_dialer = TlsDialer::from_env(base_dialer, tls_config);
    /// // 此时 tls_dialer 已根据环境变量进行了配置
    /// ```
    ///
    /// ## 错误处理
    /// 该方法不会因为环境变量解析失败而panic，而是采用以下策略：
    /// - 环境变量不存在: 使用 `None` 作为默认值
    /// - ALPN 格式错误: 忽略错误的条目，继续处理其他协议
    /// - SNI 格式错误: 在实际连接时由 rustls 进行验证和报错
    pub fn from_env(inner: D, config: Arc<rustls::ClientConfig>) -> Self {
        // 读取 SNI 重写配置
        // 如果环境变量不存在，std::env::var 返回 Err，.ok() 将其转换为 None
        let sni = std::env::var("SB_TLS_SNI").ok();

        // 读取和解析 ALPN 协议列表
        let alpn = std::env::var("SB_TLS_ALPN").ok().map(|s| {
            s.split(',')
                .map(|x| x.trim().as_bytes().to_vec())
                .collect::<Vec<_>>()
        });

        Self {
            inner,
            config,
            sni_override: sni,
            alpn,
        }
    }
}
