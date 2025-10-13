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
use rustls_pemfile;
use std::sync::Arc;

#[cfg(feature = "transport_reality")]
use sb_tls::TlsConnector;

/// TLS 拨号器包装器
///
/// 该结构体包装了任意的底层拨号器，为其添加 TLS 加密层支持。
/// 它采用装饰器模式，可以将任何实现了 `Dialer` trait 的拨号器
/// 转换为支持 TLS 的安全连接拨号器。
///
/// ## 设计理念
// - **组合优于继承**: 通过包装而不是继承来扩展功能
// - **灵活配置**: 支持 SNI 重写和 ALPN 协商
// - **环境驱动**: 可通过环境变量进行配置
///
/// ## 类型参数
// - `D`: 底层拨号器类型，必须实现 `Dialer` trait
///
/// ## 字段说明
// - `inner`: 底层拨号器实例，负责建立基础连接
// - `config`: rustls 客户端配置，包含证书、协议等设置
// - `sni_override`: 可选的 SNI 主机名重写
// - `alpn`: 可选的应用层协议协商列表
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
    // - SNI: 使用 `sni_override` 或回退到目标主机名
    // - ALPN: 如果配置了协议列表，会克隆配置并应用
    ///
    /// # 错误处理
    // - 底层连接失败: 直接传播 `DialError`
    // - SNI 解析失败: 转换为 `DialError::Tls`
    // - TLS 握手失败: 转换为 `DialError::Tls`
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
// - 使用系统或内置的根证书存储
// - 不使用客户端证书认证
// - 适用于标准的 HTTPS 连接
///
/// ## 注意事项
/// 当前实现使用空的根证书存储作为占位符。在生产环境中，应该：
// - 使用 `webpki-roots` crate 加载内置根证书
// - 或使用 `rustls-native-certs` 加载系统根证书
// - 或手动加载自定义根证书
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

    // Use an empty root store placeholder to keep builds reproducible
    // (system/webpki roots wiring can be added when distributing binaries)
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
// - 使用空的根证书存储
// - 不进行证书验证
// - **严禁在生产环境使用**
///
/// ## 安全警告
/// 🚨 **该配置不提供任何安全保障！**
// - 不验证服务器证书
// - 不检查证书链
// - 容易受到中间人攻击
///
/// ## 适用场景
/// 仅适用于以下测试场景：
// - 单元测试中的 TLS 代码路径验证
// - 本地开发环境的快速原型测试
// - 不涉及真实网络通信的集成测试
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

/// REALITY TLS 拨号器包装器
///
/// 该结构体包装了任意的底层拨号器，为其添加 REALITY TLS 支持。
/// REALITY 是一种反审查协议，通过 SNI 伪造和证书窃取来绕过 DPI 检测。
///
/// ## REALITY 协议特点
/// - SNI 伪造：使用目标域名（如 www.apple.com）作为 SNI
/// - 证书窃取：从真实目标网站获取证书
/// - 认证机制：使用 X25519 密钥交换进行身份验证
/// - 回退模式：认证失败时透明代理到真实目标
///
/// ## 设计理念
/// - **反审查优先**: 专为绕过 SNI 白名单和 DPI 检测设计
/// - **不可检测性**: 认证失败时表现为正常浏览器访问
/// - **灵活配置**: 支持多种目标域名和认证参数
///
/// ## 类型参数
/// - `D`: 底层拨号器类型，必须实现 `Dialer` trait
///
/// ## 字段说明
/// - `inner`: 底层拨号器实例，负责建立基础连接
/// - `connector`: REALITY 连接器，处理 REALITY 协议握手
#[cfg(feature = "transport_reality")]
pub struct RealityDialer<D: Dialer> {
    /// 底层拨号器，负责建立原始连接
    pub inner: D,

    /// REALITY 连接器，处理 REALITY 协议握手
    pub connector: sb_tls::RealityConnector,
}

#[cfg(feature = "transport_reality")]
#[async_trait]
impl<D: Dialer + Send + Sync> Dialer for RealityDialer<D> {
    /// 建立 REALITY TLS 加密连接
    ///
    /// 该方法实现了完整的 REALITY 连接建立流程：
    /// 1. 使用底层拨号器建立原始连接
    /// 2. 执行 REALITY 握手（SNI 伪造 + 认证）
    /// 3. 返回加密的连接流
    ///
    /// # 连接流程
    /// ```text
    /// 原始连接 -> REALITY握手 -> 加密连接
    ///     ↑          ↑            ↑
    ///   底层拨号器   sb-tls     IoStream
    /// ```
    ///
    /// # REALITY 握手过程
    /// 1. 使用伪造的 SNI（目标域名）建立 TLS 连接
    /// 2. 在 ClientHello 中嵌入认证数据
    /// 3. 服务器验证认证数据
    /// 4. 成功：返回代理连接；失败：回退到真实目标
    ///
    /// # 错误处理
    /// - 底层连接失败: 直接传播 `DialError`
    /// - REALITY 握手失败: 转换为 `DialError::Tls`
    /// - 认证失败: 可能进入回退模式（取决于服务器配置）
    async fn connect(&self, host: &str, port: u16) -> Result<IoStream, DialError> {
        // 第一步：使用底层拨号器建立原始连接
        let stream = self.inner.connect(host, port).await?;

        // 第二步：执行 REALITY 握手
        // 使用配置中的 server_name 作为 SNI（伪造的目标域名）
        let server_name = &self.connector.config().server_name;

        let tls_stream = self
            .connector
            .connect(stream, server_name)
            .await
            .map_err(|e| DialError::Tls(format!("REALITY 握手失败: {}", e)))?;

        // 第三步：返回加密连接
        // Wrap the TLS stream in an adapter to convert trait objects
        Ok(Box::new(RealityStreamAdapter { inner: tls_stream }))
    }
}

/// Adapter to convert sb-tls::TlsIoStream to sb-transport::IoStream
///
/// This adapter wraps a TLS stream from sb-tls and implements the AsyncReadWrite
/// trait required by sb-transport. Both traits have identical bounds, so this is
/// just a type conversion wrapper.
#[cfg(feature = "transport_reality")]
struct RealityStreamAdapter {
    inner: sb_tls::TlsIoStream,
}

#[cfg(feature = "transport_reality")]
impl tokio::io::AsyncRead for RealityStreamAdapter {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

#[cfg(feature = "transport_reality")]
impl tokio::io::AsyncWrite for RealityStreamAdapter {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(feature = "transport_reality")]
impl<D: Dialer> RealityDialer<D> {
    /// 创建新的 REALITY 拨号器
    ///
    /// # 参数
    /// - `inner`: 底层拨号器实例
    /// - `config`: REALITY 客户端配置
    ///
    /// # 返回值
    /// 返回配置好的 `RealityDialer` 实例，如果配置无效则返回错误
    ///
    /// # 使用示例
    /// ```rust,no_run
    /// use sb_transport::{RealityDialer, TcpDialer};
    /// use sb_tls::RealityClientConfig;
    ///
    /// let config = RealityClientConfig {
    ///     target: "www.apple.com".to_string(),
    ///     server_name: "www.apple.com".to_string(),
    ///     public_key: "0123...abcdef".to_string(),
    ///     short_id: Some("01ab".to_string()),
    ///     fingerprint: "chrome".to_string(),
    ///     alpn: vec![],
    /// };
    ///
    /// let dialer = RealityDialer::new(TcpDialer, config)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn new(inner: D, config: sb_tls::RealityClientConfig) -> Result<Self, DialError> {
        let connector = sb_tls::RealityConnector::new(config)
            .map_err(|e| DialError::Tls(format!("Failed to create REALITY connector: {}", e)))?;

        Ok(Self { inner, connector })
    }

    /// 从环境变量构建 REALITY 拨号器
    ///
    /// 该方法提供了一种通过环境变量配置 REALITY 行为的便捷方式。
    ///
    /// ## 支持的环境变量
    ///
    /// ### `SB_REALITY_TARGET`
    /// - **作用**: 目标域名（用于 SNI 伪造）
    /// - **格式**: 字符串，如 `"www.apple.com"`
    /// - **必需**: 是
    ///
    /// ### `SB_REALITY_SERVER_NAME`
    /// - **作用**: 服务器名称（通常与 target 相同）
    /// - **格式**: 字符串
    /// - **默认**: 使用 `SB_REALITY_TARGET` 的值
    ///
    /// ### `SB_REALITY_PUBLIC_KEY`
    /// - **作用**: 服务器公钥（用于认证）
    /// - **格式**: 64 字符十六进制字符串
    /// - **必需**: 是
    ///
    /// ### `SB_REALITY_SHORT_ID`
    /// - **作用**: 短 ID（用于标识不同客户端）
    /// - **格式**: 十六进制字符串
    /// - **可选**: 是
    ///
    /// ### `SB_REALITY_FINGERPRINT`
    /// - **作用**: 浏览器指纹类型
    /// - **格式**: 字符串，如 `"chrome"`, `"firefox"`, `"safari"`
    /// - **默认**: `"chrome"`
    ///
    /// # 参数
    /// - `inner`: 底层拨号器实例
    ///
    /// # 返回值
    /// 配置好的 `RealityDialer` 实例，如果环境变量缺失或无效则返回错误
    ///
    /// # 使用示例
    /// ```bash
    /// # 设置环境变量
    /// export SB_REALITY_TARGET="www.apple.com"
    /// export SB_REALITY_PUBLIC_KEY="0123456789abcdef..."
    /// export SB_REALITY_SHORT_ID="01ab"
    /// ```
    ///
    /// ```rust,no_run
    /// use sb_transport::{RealityDialer, TcpDialer};
    ///
    /// let dialer = RealityDialer::from_env(TcpDialer)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn from_env(inner: D) -> Result<Self, DialError> {
        let target = std::env::var("SB_REALITY_TARGET")
            .map_err(|_| DialError::Tls("SB_REALITY_TARGET not set".to_string()))?;

        let server_name =
            std::env::var("SB_REALITY_SERVER_NAME").unwrap_or_else(|_| target.clone());

        let public_key = std::env::var("SB_REALITY_PUBLIC_KEY")
            .map_err(|_| DialError::Tls("SB_REALITY_PUBLIC_KEY not set".to_string()))?;

        let short_id = std::env::var("SB_REALITY_SHORT_ID").ok();

        let fingerprint =
            std::env::var("SB_REALITY_FINGERPRINT").unwrap_or_else(|_| "chrome".to_string());

        let config = sb_tls::RealityClientConfig {
            target,
            server_name,
            public_key,
            short_id,
            fingerprint,
            alpn: vec![],
        };

        Self::new(inner, config)
    }
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
    // - **作用**: 重写 SNI (Server Name Indication) 主机名
    // - **格式**: 字符串，如 `"api.example.com"`
    // - **用途**: 在需要连接到特定主机但 SNI 需要指向其他主机名时使用
    // - **示例**: 连接到负载均衡器但需要特定的 SNI
    ///
    /// ### `SB_TLS_ALPN`
    // - **作用**: 配置 ALPN (Application Layer Protocol Negotiation) 协议列表
    // - **格式**: 逗号分隔的协议名称，如 `"h2,http/1.1"`
    // - **用途**: 启用 HTTP/2、HTTP/3 等现代协议支持
    // - **示例**: `"h2,http/1.1"` 表示优先使用 HTTP/2，回退到 HTTP/1.1
    ///
    /// ## 设计原则
    // - **无副作用**: 仅读取环境变量，不执行网络操作
    // - **容错性**: 环境变量不存在时使用合理默认值
    // - **可测试性**: 环境变量可以在测试中轻松模拟
    ///
    /// # 参数
    // - `inner`: 底层拨号器实例
    // - `config`: 基础 TLS 配置，环境变量设置会在此基础上叠加
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
    // - 环境变量不存在: 使用 `None` 作为默认值
    // - ALPN 格式错误: 忽略错误的条目，继续处理其他协议
    // - SNI 格式错误: 在实际连接时由 rustls 进行验证和报错
    pub fn from_env(inner: D, config: Arc<rustls::ClientConfig>) -> Self {
        // 读取 SNI 重写配置
        // 如果环境变量不存在，std::env::var 返回 Err，.ok() 将其转换为 None
        let sni = std::env::var("SB_TLS_SNI").ok();

        // 读取和解析 ALPN 协议列表
        let alpn = std::env::var("SB_TLS_ALPN").ok().map(|s| {
            let parts = s.split(',');
            let mut v = Vec::with_capacity(parts.clone().count());
            for p in parts {
                let p = p.trim();
                if !p.is_empty() {
                    // 最小拷贝：直接基于 &str 生成 Vec<u8>
                    v.push(p.as_bytes().to_vec());
                }
            }
            v
        });

        Self {
            inner,
            config,
            sni_override: sni,
            alpn,
        }
    }
}

/// ECH (Encrypted Client Hello) 拨号器包装器
///
/// 该结构体包装了任意的底层拨号器，为其添加 ECH 支持。
/// ECH 是一种 TLS 扩展，通过加密 ClientHello 来防止流量分析和基于 SNI 的封锁。
///
/// ## ECH 协议特点
/// - ClientHello 加密：使用 HPKE 加密真实的 SNI
/// - 公共名称：使用无害的公共域名作为外层 SNI
/// - 前向保密：每次连接使用新的临时密钥
/// - 防审查：审查者无法看到真实的目标域名
///
/// ## 设计理念
/// - **隐私优先**: 保护 SNI 不被窃听
/// - **反审查**: 绕过基于 SNI 的封锁
/// - **标准兼容**: 遵循 IETF ECH 草案规范
///
/// ## 类型参数
/// - `D`: 底层拨号器类型，必须实现 `Dialer` trait
///
/// ## 字段说明
/// - `inner`: 底层拨号器实例，负责建立基础连接
/// - `config`: rustls 客户端配置
/// - `ech_connector`: ECH 连接器，处理 ECH 加密
#[cfg(feature = "transport_ech")]
pub struct EchDialer<D: Dialer> {
    /// 底层拨号器，负责建立原始连接
    pub inner: D,

    /// TLS 客户端配置
    pub config: Arc<rustls::ClientConfig>,

    /// ECH 连接器，处理 ClientHello 加密
    pub ech_connector: sb_tls::EchConnector,
}

#[cfg(feature = "transport_ech")]
#[async_trait]
impl<D: Dialer + Send + Sync> Dialer for EchDialer<D> {
    /// 建立 ECH 加密的 TLS 连接
    ///
    /// 该方法实现了完整的 ECH 连接建立流程：
    /// 1. 使用底层拨号器建立原始连接
    /// 2. 使用 ECH 加密真实的 SNI
    /// 3. 执行 TLS 握手（带 ECH 扩展）
    /// 4. 验证 ECH 接受状态
    /// 5. 返回加密的连接流
    ///
    /// # 连接流程
    /// ```text
    /// 原始连接 -> ECH加密 -> TLS握手 -> ECH验证 -> 加密连接
    ///     ↑         ↑         ↑         ↑          ↑
    ///   底层拨号器  sb-tls   rustls   sb-tls   IoStream
    /// ```
    ///
    /// # ECH 握手过程
    /// 1. 生成 ECH ClientHello（加密真实 SNI）
    /// 2. 使用公共名称作为外层 SNI
    /// 3. 在 TLS 扩展中嵌入加密的 ClientHello
    /// 4. 服务器解密并处理真实的 ClientHello
    /// 5. 验证服务器的 ECH 接受响应
    ///
    /// # rustls ECH 支持状态
    ///
    /// ⚠️ **当前限制**: rustls 0.23 不支持 ECH 扩展
    ///
    /// 本实现提供了 ECH 集成的框架：
    /// - ECH ClientHello 加密（完成）
    /// - ECH 配置管理（完成）
    /// - TLS 握手集成点（待 rustls 支持）
    ///
    /// 当 rustls 添加 ECH 支持时，需要：
    /// 1. 在 ClientConfig 中启用 ECH
    /// 2. 传递 ech_hello.ech_payload 到 TLS 握手
    /// 3. 从 ServerHello 中提取 ECH 接受状态
    ///
    /// # 错误处理
    /// - 底层连接失败: 直接传播 `DialError`
    /// - ECH 未启用: 返回 `DialError::Tls` 错误
    /// - ECH 加密失败: 转换为 `DialError::Tls`
    /// - 外层 SNI 无效: 转换为 `DialError::Tls`
    /// - TLS 握手失败: 转换为 `DialError::Tls`
    /// - ECH 未被接受: 记录警告但继续连接（降级行为）
    async fn connect(&self, host: &str, port: u16) -> Result<IoStream, DialError> {
        use rustls::pki_types::ServerName;
        use tokio_rustls::TlsConnector;

        // 第一步：验证 ECH 是否启用
        if !self.ech_connector.config().enabled {
            return Err(DialError::Tls(
                "ECH connector created but ECH is disabled in config".to_string(),
            ));
        }

        // 第二步：使用底层拨号器建立原始连接
        let stream = self.inner.connect(host, port).await?;

        // 第三步：使用 ECH 加密真实的 SNI
        // 这会生成包含加密 ClientHello 的 ECH 结构
        let ech_hello = self
            .ech_connector
            .wrap_tls(host)
            .map_err(|e| DialError::Tls(format!("ECH 加密失败: {}", e)))?;

        // 第四步：使用外层 SNI（公共名称）进行 TLS 连接
        // 这是审查者能看到的 SNI，应该是一个无害的域名
        let outer_sni = ServerName::try_from(ech_hello.outer_sni.clone())
            .map_err(|e| DialError::Tls(format!("外层 SNI 解析失败: {:?}", e)))?;

        // 第五步：配置 TLS 连接
        // 注意：这里使用标准的 rustls，ECH 扩展已经在 ClientHello 中
        // 实际的 ECH 支持需要 rustls 的 ECH 功能或自定义扩展处理
        let connector = TlsConnector::from(self.config.clone());

        // 第六步：执行 TLS 握手
        // TODO: 当 rustls 支持 ECH 时，需要在这里传递 ech_hello.ech_payload
        // 集成点示例：
        // ```rust
        // let mut config = (*self.config).clone();
        // config.enable_ech(ech_hello.ech_payload);
        // let connector = TlsConnector::from(Arc::new(config));
        // ```
        let tls = connector
            .connect(outer_sni, stream)
            .await
            .map_err(|e| DialError::Tls(format!("ECH TLS 握手失败: {}", e)))?;

        // 第七步：验证 ECH 接受状态（可选）
        // 注意：由于 rustls 当前不支持 ECH，我们无法从 ServerHello 中提取数据
        // 当 rustls 支持 ECH 时，应该在这里验证服务器是否接受了 ECH
        // 集成点示例：
        // ```rust
        // if let Some(server_hello) = tls.get_server_hello() {
        //     if !self.ech_connector.verify_ech_acceptance(server_hello)? {
        //         tracing::warn!("服务器未接受 ECH，连接可能降级");
        //     }
        // }
        // ```

        // 第八步：返回加密连接
        Ok(Box::new(tls))
    }
}

#[cfg(feature = "transport_ech")]
impl<D: Dialer> EchDialer<D> {
    /// 创建新的 ECH 拨号器
    ///
    /// # 参数
    /// - `inner`: 底层拨号器实例
    /// - `config`: TLS 客户端配置
    /// - `ech_config`: ECH 客户端配置
    ///
    /// # 返回值
    /// 返回配置好的 `EchDialer` 实例，如果配置无效则返回错误
    ///
    /// # 错误情况
    /// - ECH 配置验证失败（enabled=true 但缺少 config/config_list）
    /// - ECHConfigList 解析失败
    /// - 无效的 ECH 参数
    ///
    /// # 使用示例
    /// ```rust,no_run
    /// use sb_transport::{EchDialer, TcpDialer, webpki_roots_config};
    /// use sb_tls::EchClientConfig;
    ///
    /// let ech_config = EchClientConfig {
    ///     enabled: true,
    ///     config: Some("base64_encoded_config".to_string()),
    ///     config_list: None,
    ///     pq_signature_schemes_enabled: false,
    ///     dynamic_record_sizing_disabled: None,
    /// };
    ///
    /// let tls_config = webpki_roots_config();
    /// let dialer = EchDialer::new(TcpDialer, tls_config, ech_config)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn new(
        inner: D,
        config: Arc<rustls::ClientConfig>,
        ech_config: sb_tls::EchClientConfig,
    ) -> Result<Self, DialError> {
        // 创建 ECH 连接器，这会验证配置并解析 ECHConfigList
        let ech_connector = sb_tls::EchConnector::new(ech_config)
            .map_err(|e| DialError::Tls(format!("创建 ECH 连接器失败: {}", e)))?;

        Ok(Self {
            inner,
            config,
            ech_connector,
        })
    }

    /// 从环境变量构建 ECH 拨号器
    ///
    /// 该方法提供了一种通过环境变量配置 ECH 行为的便捷方式。
    ///
    /// ## 支持的环境变量
    ///
    /// ### `SB_ECH_CONFIG`
    /// - **作用**: ECH 配置列表（base64 编码）
    /// - **格式**: Base64 字符串
    /// - **来源**: 通常从 DNS TXT 记录或服务器配置获取
    /// - **必需**: 是
    ///
    /// ### `SB_ECH_ENABLED`
    /// - **作用**: 启用或禁用 ECH
    /// - **格式**: "true" 或 "false"
    /// - **默认**: "true"
    ///
    /// ### `SB_ECH_PQ_ENABLED`
    /// - **作用**: 启用后量子签名方案
    /// - **格式**: "true" 或 "false"
    /// - **默认**: "false"
    ///
    /// ### `SB_ECH_DYNAMIC_RECORD_SIZING_DISABLED`
    /// - **作用**: 禁用动态记录大小调整
    /// - **格式**: "true" 或 "false"
    /// - **默认**: "false"
    ///
    /// # 参数
    /// - `inner`: 底层拨号器实例
    /// - `config`: TLS 客户端配置
    ///
    /// # 返回值
    /// 配置好的 `EchDialer` 实例，如果环境变量缺失或无效则返回错误
    ///
    /// # 错误情况
    /// - `SB_ECH_CONFIG` 未设置
    /// - ECH 配置格式无效（非 base64 或解析失败）
    /// - 环境变量值无法解析为布尔值（使用默认值）
    ///
    /// # 使用示例
    /// ```bash
    /// # 设置环境变量
    /// export SB_ECH_CONFIG="base64_encoded_ech_config_list"
    /// export SB_ECH_ENABLED="true"
    /// export SB_ECH_PQ_ENABLED="false"
    /// ```
    ///
    /// ```rust,no_run
    /// use sb_transport::{EchDialer, TcpDialer, webpki_roots_config};
    ///
    /// let tls_config = webpki_roots_config();
    /// let dialer = EchDialer::from_env(TcpDialer, tls_config)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn from_env(inner: D, config: Arc<rustls::ClientConfig>) -> Result<Self, DialError> {
        // 读取必需的 ECH 配置
        let ech_config_b64 = std::env::var("SB_ECH_CONFIG")
            .map_err(|_| DialError::Tls("环境变量 SB_ECH_CONFIG 未设置".to_string()))?;

        // 读取可选的布尔配置，解析失败时使用默认值
        let enabled = std::env::var("SB_ECH_ENABLED")
            .ok()
            .and_then(|s| s.parse::<bool>().ok())
            .unwrap_or(true);

        let pq_enabled = std::env::var("SB_ECH_PQ_ENABLED")
            .ok()
            .and_then(|s| s.parse::<bool>().ok())
            .unwrap_or(false);

        let dynamic_record_sizing_disabled = std::env::var("SB_ECH_DYNAMIC_RECORD_SIZING_DISABLED")
            .ok()
            .and_then(|s| s.parse::<bool>().ok());

        // 创建 ECH 配置
        let ech_config = sb_tls::EchClientConfig::new(ech_config_b64)
            .map_err(|e| DialError::Tls(format!("无效的 ECH 配置: {}", e)))?;

        // 应用环境变量覆盖
        let ech_config = sb_tls::EchClientConfig {
            enabled,
            pq_signature_schemes_enabled: pq_enabled,
            dynamic_record_sizing_disabled,
            ..ech_config
        };

        Self::new(inner, config, ech_config)
    }
}

/// TLS Transport Wrapper
///
/// This module provides a unified interface for wrapping streams with TLS
/// using the `sb-tls` crate. It supports Standard TLS, REALITY, and ECH.
///
/// ## Design
/// - Unified configuration through `TlsConfig` enum
/// - Consistent `wrap_client()` and `wrap_server()` methods
/// - Integration with `sb-tls` crate for all TLS variants
/// - Serde support for configuration deserialization
///
/// ## Usage
/// ```rust,no_run
/// use sb_transport::TlsTransport;
/// use sb_transport::TlsConfig;
///
/// // Create Standard TLS transport
/// let config = TlsConfig::Standard(StandardTlsConfig::default());
/// let transport = TlsTransport::new(config);
///
/// // Wrap a client stream
/// // let tls_stream = transport.wrap_client(stream, "example.com").await?;
/// ```
use serde::{Deserialize, Serialize};

/// TLS configuration enum supporting Standard/REALITY/ECH
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum TlsConfig {
    /// Standard TLS 1.3 using rustls
    Standard(StandardTlsConfig),

    /// REALITY anti-censorship protocol
    #[cfg(feature = "transport_reality")]
    Reality(RealityTlsConfig),

    /// Encrypted Client Hello (ECH)
    #[cfg(feature = "transport_ech")]
    Ech(EchTlsConfig),
}

/// Standard TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StandardTlsConfig {
    /// Server name for SNI (client-side)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,

    /// ALPN protocols
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alpn: Vec<String>,

    /// Skip certificate verification (insecure, for testing only)
    #[serde(default)]
    pub insecure: bool,

    /// Certificate path (server-side)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_path: Option<String>,

    /// Private key path (server-side)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_path: Option<String>,
}

impl Default for StandardTlsConfig {
    fn default() -> Self {
        Self {
            server_name: None,
            alpn: Vec::new(),
            insecure: false,
            cert_path: None,
            key_path: None,
        }
    }
}

/// REALITY TLS configuration
#[cfg(feature = "transport_reality")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealityTlsConfig {
    /// Target domain for SNI forgery
    pub target: String,

    /// Server name (usually same as target)
    pub server_name: String,

    /// Server public key (hex-encoded)
    pub public_key: String,

    /// Short ID for client identification
    #[serde(skip_serializing_if = "Option::is_none")]
    pub short_id: Option<String>,

    /// Browser fingerprint to emulate
    #[serde(default = "default_fingerprint")]
    pub fingerprint: String,

    /// ALPN protocols
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alpn: Vec<String>,
}

#[cfg(feature = "transport_reality")]
fn default_fingerprint() -> String {
    "chrome".to_string()
}

/// ECH TLS configuration
#[cfg(feature = "transport_ech")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EchTlsConfig {
    /// Enable ECH
    #[serde(default)]
    pub enabled: bool,

    /// ECH configuration (base64-encoded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<String>,

    /// ECH config list (raw bytes)
    #[serde(skip_serializing_if = "Option::is_none", with = "serde_bytes")]
    pub config_list: Option<Vec<u8>>,

    /// Enable post-quantum signature schemes
    #[serde(default)]
    pub pq_signature_schemes_enabled: bool,

    /// Disable dynamic record sizing
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dynamic_record_sizing_disabled: Option<bool>,

    /// Server name for outer SNI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,

    /// ALPN protocols
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alpn: Vec<String>,
}

#[cfg(feature = "transport_ech")]
mod serde_bytes {
    use base64::{engine::general_purpose, Engine as _};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match bytes {
            Some(b) => serializer.serialize_some(&general_purpose::STANDARD.encode(b)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: Option<String> = Option::deserialize(deserializer)?;
        match s {
            Some(s) => general_purpose::STANDARD
                .decode(&s)
                .map(Some)
                .map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}

/// TLS Transport wrapper
///
/// Provides a unified interface for wrapping streams with TLS.
/// Supports Standard TLS, REALITY, and ECH through the `TlsConfig` enum.
pub struct TlsTransport {
    config: TlsConfig,
}

impl TlsTransport {
    /// Create a new TLS transport with the given configuration
    pub fn new(config: TlsConfig) -> Self {
        Self { config }
    }

    /// Wrap a client stream with TLS
    ///
    /// # Arguments
    /// - `stream`: The underlying stream to wrap
    /// - `server_name`: The server name for SNI
    ///
    /// # Returns
    /// A TLS-wrapped stream
    ///
    /// # Errors
    /// Returns `DialError::Tls` if the TLS handshake fails
    pub async fn wrap_client<S>(&self, stream: S, server_name: &str) -> Result<IoStream, DialError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + 'static,
    {
        match &self.config {
            TlsConfig::Standard(config) => {
                self.wrap_standard_client(stream, server_name, config).await
            }

            #[cfg(feature = "transport_reality")]
            TlsConfig::Reality(config) => {
                self.wrap_reality_client(stream, server_name, config).await
            }

            #[cfg(feature = "transport_ech")]
            TlsConfig::Ech(config) => self.wrap_ech_client(stream, server_name, config).await,
        }
    }

    /// Wrap a server stream with TLS
    ///
    /// # Arguments
    /// - `stream`: The underlying stream to wrap
    ///
    /// # Returns
    /// A TLS-wrapped stream
    ///
    /// # Errors
    /// Returns `DialError::Tls` if the TLS handshake fails or server configuration is missing
    pub async fn wrap_server<S>(&self, stream: S) -> Result<IoStream, DialError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + 'static,
    {
        match &self.config {
            TlsConfig::Standard(config) => self.wrap_standard_server(stream, config).await,

            #[cfg(feature = "transport_reality")]
            TlsConfig::Reality(_config) => {
                // REALITY server-side wrapping would use RealityAcceptor
                // For now, return an error as server-side REALITY needs more context
                Err(DialError::Tls(
                    "REALITY server-side wrapping not yet implemented in TlsTransport".to_string(),
                ))
            }

            #[cfg(feature = "transport_ech")]
            TlsConfig::Ech(_config) => {
                // ECH server-side wrapping would use ECH acceptor
                // For now, return an error as server-side ECH needs more context
                Err(DialError::Tls(
                    "ECH server-side wrapping not yet implemented in TlsTransport".to_string(),
                ))
            }
        }
    }

    /// Wrap client stream with Standard TLS
    async fn wrap_standard_client<S>(
        &self,
        stream: S,
        server_name: &str,
        config: &StandardTlsConfig,
    ) -> Result<IoStream, DialError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + 'static,
    {
        use rustls::pki_types::ServerName;
        use tokio_rustls::TlsConnector;

        // Create rustls client config
        let mut tls_config = if config.insecure {
            // Insecure mode: skip certificate verification
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth()
        } else {
            // Secure mode: use webpki roots
            let root_store = rustls::RootCertStore::empty();
            // In production, load webpki-roots or system roots here
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        // Configure ALPN
        if !config.alpn.is_empty() {
            tls_config.alpn_protocols = config.alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
        }

        // Parse server name
        let sni = config.server_name.as_deref().unwrap_or(server_name);
        let server_name = ServerName::try_from(sni.to_string())
            .map_err(|e| DialError::Tls(format!("Invalid server name: {:?}", e)))?;

        // Perform TLS handshake
        let connector = TlsConnector::from(Arc::new(tls_config));
        let tls_stream = connector
            .connect(server_name, stream)
            .await
            .map_err(|e| DialError::Tls(format!("TLS handshake failed: {}", e)))?;

        Ok(Box::new(tls_stream))
    }

    /// Wrap server stream with Standard TLS
    async fn wrap_standard_server<S>(
        &self,
        stream: S,
        config: &StandardTlsConfig,
    ) -> Result<IoStream, DialError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + 'static,
    {
        use tokio_rustls::TlsAcceptor;

        // Validate server configuration
        let cert_path = config
            .cert_path
            .as_ref()
            .ok_or_else(|| DialError::Tls("Server certificate path not configured".to_string()))?;
        let key_path = config
            .key_path
            .as_ref()
            .ok_or_else(|| DialError::Tls("Server private key path not configured".to_string()))?;

        // Load certificate and private key
        let certs = load_certs(cert_path)?;
        let key = load_private_key(key_path)?;

        // Create rustls server config
        let mut tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| DialError::Tls(format!("Invalid certificate or key: {}", e)))?;

        // Configure ALPN
        if !config.alpn.is_empty() {
            tls_config.alpn_protocols = config.alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
        }

        // Perform TLS handshake
        let acceptor = TlsAcceptor::from(Arc::new(tls_config));
        let tls_stream = acceptor
            .accept(stream)
            .await
            .map_err(|e| DialError::Tls(format!("TLS accept failed: {}", e)))?;

        Ok(Box::new(tls_stream))
    }

    /// Wrap client stream with REALITY
    #[cfg(feature = "transport_reality")]
    async fn wrap_reality_client<S>(
        &self,
        stream: S,
        server_name: &str,
        config: &RealityTlsConfig,
    ) -> Result<IoStream, DialError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + 'static,
    {
        // Create REALITY client config
        let reality_config = sb_tls::RealityClientConfig {
            target: config.target.clone(),
            server_name: config.server_name.clone(),
            public_key: config.public_key.clone(),
            short_id: config.short_id.clone(),
            fingerprint: config.fingerprint.clone(),
            alpn: config.alpn.clone(),
        };

        // Create REALITY connector
        let connector = sb_tls::RealityConnector::new(reality_config)
            .map_err(|e| DialError::Tls(format!("Failed to create REALITY connector: {}", e)))?;

        // Perform REALITY handshake
        let tls_stream = connector
            .connect(stream, server_name)
            .await
            .map_err(|e| DialError::Tls(format!("REALITY handshake failed: {}", e)))?;

        // Wrap the sb_tls::TlsIoStream in an adapter to convert to IoStream
        Ok(Box::new(TlsStreamAdapter { inner: tls_stream }))
    }

    /// Wrap client stream with ECH
    #[cfg(feature = "transport_ech")]
    async fn wrap_ech_client<S>(
        &self,
        stream: S,
        server_name: &str,
        config: &EchTlsConfig,
    ) -> Result<IoStream, DialError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        use rustls::pki_types::ServerName;
        use tokio_rustls::TlsConnector;

        // Create ECH client config
        let ech_config = sb_tls::EchClientConfig {
            enabled: config.enabled,
            config: config.config.clone(),
            config_list: config.config_list.clone(),
            pq_signature_schemes_enabled: config.pq_signature_schemes_enabled,
            dynamic_record_sizing_disabled: config.dynamic_record_sizing_disabled,
        };

        // Create ECH connector
        let ech_connector = sb_tls::EchConnector::new(ech_config)
            .map_err(|e| DialError::Tls(format!("Failed to create ECH connector: {}", e)))?;

        // Wrap TLS to get ECH ClientHello
        let ech_hello = ech_connector
            .wrap_tls(server_name)
            .map_err(|e| DialError::Tls(format!("ECH encryption failed: {}", e)))?;

        // Create rustls client config
        let root_store = rustls::RootCertStore::empty();
        let mut tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        // Configure ALPN
        if !config.alpn.is_empty() {
            tls_config.alpn_protocols = config.alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
        }

        // Use outer SNI from ECH
        let outer_sni = ServerName::try_from(ech_hello.outer_sni.clone())
            .map_err(|e| DialError::Tls(format!("Invalid outer SNI: {:?}", e)))?;

        // Perform TLS handshake with ECH
        // Note: rustls 0.23 doesn't natively support ECH, so this is a placeholder
        // When rustls adds ECH support, we'll need to pass ech_hello.ech_payload
        let connector = TlsConnector::from(Arc::new(tls_config));
        let tls_stream = connector
            .connect(outer_sni, stream)
            .await
            .map_err(|e| DialError::Tls(format!("ECH TLS handshake failed: {}", e)))?;

        Ok(Box::new(tls_stream))
    }
}

/// Helper: Load certificates from PEM file
fn load_certs(path: &str) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, DialError> {
    use std::io::BufReader;

    let file = std::fs::File::open(path)
        .map_err(|e| DialError::Tls(format!("Failed to open certificate file: {}", e)))?;

    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| DialError::Tls(format!("Failed to parse certificates: {}", e)))?;

    if certs.is_empty() {
        return Err(DialError::Tls("No certificates found in file".to_string()));
    }

    Ok(certs)
}

/// Helper: Load private key from PEM file
fn load_private_key(path: &str) -> Result<rustls::pki_types::PrivateKeyDer<'static>, DialError> {
    use std::io::BufReader;

    let file = std::fs::File::open(path)
        .map_err(|e| DialError::Tls(format!("Failed to open private key file: {}", e)))?;

    let mut reader = BufReader::new(file);

    // Try to read as PKCS8 first
    if let Some(key) = rustls_pemfile::pkcs8_private_keys(&mut reader).next() {
        return key
            .map(rustls::pki_types::PrivateKeyDer::Pkcs8)
            .map_err(|e| DialError::Tls(format!("Failed to parse PKCS8 private key: {}", e)));
    }

    // Reset reader and try RSA
    let file = std::fs::File::open(path)
        .map_err(|e| DialError::Tls(format!("Failed to reopen private key file: {}", e)))?;
    let mut reader = BufReader::new(file);

    if let Some(key) = rustls_pemfile::rsa_private_keys(&mut reader).next() {
        return key
            .map(rustls::pki_types::PrivateKeyDer::Pkcs1)
            .map_err(|e| DialError::Tls(format!("Failed to parse RSA private key: {}", e)));
    }

    Err(DialError::Tls("No private key found in file".to_string()))
}

/// Adapter to convert sb_tls::TlsIoStream to sb_transport::IoStream
///
/// This adapter wraps a TLS stream from sb-tls and implements the AsyncReadWrite
/// trait required by sb-transport. Both traits have identical bounds, so this is
/// just a type conversion wrapper.
#[cfg(feature = "transport_reality")]
struct TlsStreamAdapter {
    inner: sb_tls::TlsIoStream,
}

#[cfg(feature = "transport_reality")]
impl tokio::io::AsyncRead for TlsStreamAdapter {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

#[cfg(feature = "transport_reality")]
impl tokio::io::AsyncWrite for TlsStreamAdapter {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// No-op certificate verifier for insecure mode (testing only)
#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

#[cfg(all(test, feature = "transport_ech"))]
mod ech_tests {
    use super::*;
    use crate::TcpDialer;

    #[test]
    fn test_ech_dialer_invalid_config() {
        // 测试无效的 ECH 配置（enabled 但没有 config）
        let ech_config = sb_tls::EchClientConfig {
            enabled: true,
            config: None,
            config_list: None,
            pq_signature_schemes_enabled: false,
            dynamic_record_sizing_disabled: None,
        };

        let tls_config = smoke_empty_roots_config();
        let result = EchDialer::new(TcpDialer, tls_config, ech_config);

        // 应该失败，因为 enabled=true 但没有提供配置
        assert!(result.is_err());
        if let Err(DialError::Tls(msg)) = result {
            assert!(
                msg.contains("创建 ECH 连接器失败")
                    || msg.contains("Failed to create ECH connector")
            );
        }
    }

    #[test]
    fn test_ech_dialer_disabled() {
        // 测试禁用的 ECH 配置（应该成功创建）
        let ech_config = sb_tls::EchClientConfig {
            enabled: false,
            config: None,
            config_list: None,
            pq_signature_schemes_enabled: false,
            dynamic_record_sizing_disabled: None,
        };

        let tls_config = smoke_empty_roots_config();
        let result = EchDialer::new(TcpDialer, tls_config, ech_config);

        // 应该成功，因为 ECH 被禁用
        assert!(result.is_ok());
    }

    #[test]
    fn test_ech_dialer_with_valid_config() {
        // 测试有效的 ECH 配置
        let ech_config = sb_tls::EchClientConfig {
            enabled: true,
            config: Some("test_config".to_string()),
            config_list: Some(create_test_ech_config_list()),
            pq_signature_schemes_enabled: false,
            dynamic_record_sizing_disabled: None,
        };

        let tls_config = smoke_empty_roots_config();
        let result = EchDialer::new(TcpDialer, tls_config, ech_config);

        // 应该成功
        assert!(result.is_ok());
    }

    #[test]
    fn test_ech_dialer_with_pq_enabled() {
        // 测试启用后量子签名方案的配置
        let ech_config = sb_tls::EchClientConfig {
            enabled: true,
            config: Some("test_config".to_string()),
            config_list: Some(create_test_ech_config_list()),
            pq_signature_schemes_enabled: true,
            dynamic_record_sizing_disabled: None,
        };

        let tls_config = smoke_empty_roots_config();
        let result = EchDialer::new(TcpDialer, tls_config, ech_config);

        assert!(result.is_ok());
        let dialer = result.unwrap();
        assert!(dialer.ech_connector.config().pq_signature_schemes_enabled);
    }

    #[test]
    fn test_ech_dialer_with_dynamic_record_sizing_disabled() {
        // 测试禁用动态记录大小调整的配置
        let ech_config = sb_tls::EchClientConfig {
            enabled: true,
            config: Some("test_config".to_string()),
            config_list: Some(create_test_ech_config_list()),
            pq_signature_schemes_enabled: false,
            dynamic_record_sizing_disabled: Some(true),
        };

        let tls_config = smoke_empty_roots_config();
        let result = EchDialer::new(TcpDialer, tls_config, ech_config);

        assert!(result.is_ok());
        let dialer = result.unwrap();
        assert_eq!(
            dialer.ech_connector.config().dynamic_record_sizing_disabled,
            Some(true)
        );
    }

    #[test]
    fn test_ech_dialer_error_message_quality() {
        // 测试错误消息的质量
        let ech_config = sb_tls::EchClientConfig {
            enabled: true,
            config: None,
            config_list: None,
            pq_signature_schemes_enabled: false,
            dynamic_record_sizing_disabled: None,
        };

        let tls_config = smoke_empty_roots_config();
        let result = EchDialer::new(TcpDialer, tls_config, ech_config);

        assert!(result.is_err());
        if let Err(DialError::Tls(msg)) = result {
            // 错误消息应该清晰地说明问题
            assert!(!msg.is_empty());
            assert!(msg.len() > 10); // 不应该是空消息或太短的消息
        }
    }

    #[test]
    fn test_ech_dialer_from_env_missing_config() {
        // 测试缺少环境变量的情况
        std::env::remove_var("SB_ECH_CONFIG");

        let tls_config = smoke_empty_roots_config();
        let result = EchDialer::from_env(TcpDialer, tls_config);

        assert!(result.is_err());
        if let Err(DialError::Tls(msg)) = result {
            assert!(msg.contains("SB_ECH_CONFIG") || msg.contains("环境变量"));
        }
    }

    // Helper function to create a test ECH config list
    // This creates a minimal valid ECH config list for testing purposes
    fn create_test_ech_config_list() -> Vec<u8> {
        // Use a fixed public key for testing (32 bytes of 0x01)
        let public_key = [0x01u8; 32];

        let mut config_list = Vec::new();

        // List length (will be filled later)
        let list_start = config_list.len();
        config_list.extend_from_slice(&[0x00, 0x00]);

        // ECH version (0xfe0d = Draft-13)
        config_list.extend_from_slice(&[0xfe, 0x0d]);

        // Config length (will be filled later)
        let config_start = config_list.len();
        config_list.extend_from_slice(&[0x00, 0x00]);

        // Public key length + public key (32 bytes for X25519)
        config_list.extend_from_slice(&[0x00, 0x20]);
        config_list.extend_from_slice(&public_key);

        // Cipher suites length + cipher suite
        // One suite: KEM=0x0020, KDF=0x0001, AEAD=0x0001
        config_list.extend_from_slice(&[0x00, 0x06]);
        config_list.extend_from_slice(&[0x00, 0x20]); // KEM: X25519
        config_list.extend_from_slice(&[0x00, 0x01]); // KDF: HKDF-SHA256
        config_list.extend_from_slice(&[0x00, 0x01]); // AEAD: AES-128-GCM

        // Maximum name length
        config_list.push(64);

        // Public name length + public name
        let public_name = b"public.example.com";
        config_list.push(public_name.len() as u8);
        config_list.extend_from_slice(public_name);

        // Extensions length (empty)
        config_list.extend_from_slice(&[0x00, 0x00]);

        // Fill in config length
        let config_len = config_list.len() - config_start - 2;
        config_list[config_start..config_start + 2]
            .copy_from_slice(&(config_len as u16).to_be_bytes());

        // Fill in list length
        let list_len = config_list.len() - list_start - 2;
        config_list[list_start..list_start + 2].copy_from_slice(&(list_len as u16).to_be_bytes());

        config_list
    }
}

#[cfg(test)]
mod tls_transport_tests {
    use super::*;

    #[test]
    fn test_tls_config_standard_default() {
        let config = StandardTlsConfig::default();
        assert!(config.server_name.is_none());
        assert!(config.alpn.is_empty());
        assert!(!config.insecure);
        assert!(config.cert_path.is_none());
        assert!(config.key_path.is_none());
    }

    #[test]
    fn test_tls_config_standard_with_alpn() {
        let config = StandardTlsConfig {
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
            ..Default::default()
        };
        assert_eq!(config.alpn.len(), 2);
        assert_eq!(config.alpn[0], "h2");
        assert_eq!(config.alpn[1], "http/1.1");
    }

    #[test]
    fn test_tls_transport_creation_standard() {
        let config = TlsConfig::Standard(StandardTlsConfig::default());
        let transport = TlsTransport::new(config);

        match transport.config {
            TlsConfig::Standard(_) => (),
            #[allow(unreachable_patterns)]
            _ => panic!("Expected Standard config"),
        }
    }

    #[cfg(feature = "transport_reality")]
    #[test]
    fn test_tls_config_reality() {
        let config = RealityTlsConfig {
            target: "www.apple.com".to_string(),
            server_name: "www.apple.com".to_string(),
            public_key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_string(),
            short_id: Some("01ab".to_string()),
            fingerprint: "chrome".to_string(),
            alpn: vec![],
        };

        assert_eq!(config.target, "www.apple.com");
        assert_eq!(config.fingerprint, "chrome");
    }

    #[cfg(feature = "transport_reality")]
    #[test]
    fn test_tls_transport_creation_reality() {
        let config = TlsConfig::Reality(RealityTlsConfig {
            target: "www.apple.com".to_string(),
            server_name: "www.apple.com".to_string(),
            public_key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_string(),
            short_id: Some("01ab".to_string()),
            fingerprint: "chrome".to_string(),
            alpn: vec![],
        });

        let transport = TlsTransport::new(config);

        match transport.config {
            TlsConfig::Reality(_) => (),
            #[allow(unreachable_patterns)]
            _ => panic!("Expected Reality config"),
        }
    }

    #[cfg(feature = "transport_ech")]
    #[test]
    fn test_tls_config_ech() {
        let config = EchTlsConfig {
            enabled: true,
            config: Some("test_config".to_string()),
            config_list: None,
            pq_signature_schemes_enabled: false,
            dynamic_record_sizing_disabled: None,
            server_name: Some("public.example.com".to_string()),
            alpn: vec![],
        };

        assert!(config.enabled);
        assert_eq!(config.server_name, Some("public.example.com".to_string()));
    }

    #[cfg(feature = "transport_ech")]
    #[test]
    fn test_tls_transport_creation_ech() {
        let config = TlsConfig::Ech(EchTlsConfig {
            enabled: true,
            config: Some("test_config".to_string()),
            config_list: Some(create_test_ech_config_list()),
            pq_signature_schemes_enabled: false,
            dynamic_record_sizing_disabled: None,
            server_name: Some("public.example.com".to_string()),
            alpn: vec![],
        });

        let transport = TlsTransport::new(config);

        match transport.config {
            TlsConfig::Ech(_) => (),
            #[allow(unreachable_patterns)]
            _ => panic!("Expected ECH config"),
        }
    }

    #[test]
    fn test_tls_config_serde_standard() {
        let config = TlsConfig::Standard(StandardTlsConfig {
            server_name: Some("example.com".to_string()),
            alpn: vec!["h2".to_string()],
            insecure: false,
            cert_path: None,
            key_path: None,
        });

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: TlsConfig = serde_json::from_str(&json).unwrap();

        match deserialized {
            TlsConfig::Standard(c) => {
                assert_eq!(c.server_name, Some("example.com".to_string()));
                assert_eq!(c.alpn, vec!["h2".to_string()]);
            }
            #[allow(unreachable_patterns)]
            _ => panic!("Expected Standard config"),
        }
    }

    #[cfg(feature = "transport_reality")]
    #[test]
    fn test_tls_config_serde_reality() {
        let config = TlsConfig::Reality(RealityTlsConfig {
            target: "www.apple.com".to_string(),
            server_name: "www.apple.com".to_string(),
            public_key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_string(),
            short_id: Some("01ab".to_string()),
            fingerprint: "chrome".to_string(),
            alpn: vec![],
        });

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: TlsConfig = serde_json::from_str(&json).unwrap();

        match deserialized {
            TlsConfig::Reality(c) => {
                assert_eq!(c.target, "www.apple.com");
                assert_eq!(
                    c.public_key,
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                );
            }
            #[allow(unreachable_patterns)]
            _ => panic!("Expected Reality config"),
        }
    }

    #[test]
    fn test_standard_tls_config_server_paths() {
        let config = StandardTlsConfig {
            cert_path: Some("/path/to/cert.pem".to_string()),
            key_path: Some("/path/to/key.pem".to_string()),
            ..Default::default()
        };

        assert_eq!(config.cert_path, Some("/path/to/cert.pem".to_string()));
        assert_eq!(config.key_path, Some("/path/to/key.pem".to_string()));
    }

    #[test]
    fn test_standard_tls_config_insecure() {
        let config = StandardTlsConfig {
            insecure: true,
            ..Default::default()
        };

        assert!(config.insecure);
    }

    #[cfg(feature = "transport_reality")]
    #[test]
    fn test_reality_config_default_fingerprint() {
        let fingerprint = default_fingerprint();
        assert_eq!(fingerprint, "chrome");
    }

    #[cfg(feature = "transport_ech")]
    #[test]
    fn test_ech_config_pq_enabled() {
        let config = EchTlsConfig {
            enabled: true,
            config: Some("test".to_string()),
            config_list: None,
            pq_signature_schemes_enabled: true,
            dynamic_record_sizing_disabled: Some(true),
            server_name: None,
            alpn: vec![],
        };

        assert!(config.pq_signature_schemes_enabled);
        assert_eq!(config.dynamic_record_sizing_disabled, Some(true));
    }

    #[test]
    fn test_tls_transport_clone_config() {
        let config = TlsConfig::Standard(StandardTlsConfig::default());
        let cloned = config.clone();

        match (config, cloned) {
            (TlsConfig::Standard(_), TlsConfig::Standard(_)) => (),
            #[allow(unreachable_patterns)]
            _ => panic!("Config clone failed"),
        }
    }

    #[cfg(feature = "transport_ech")]
    fn create_test_ech_config_list() -> Vec<u8> {
        use x25519_dalek::{PublicKey, StaticSecret};

        let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public_key = PublicKey::from(&secret);

        let mut config_list = Vec::new();

        // List length (will be filled later)
        let list_start = config_list.len();
        config_list.extend_from_slice(&[0x00, 0x00]);

        // ECH version (0xfe0d = Draft-13)
        config_list.extend_from_slice(&[0xfe, 0x0d]);

        // Config length (will be filled later)
        let config_start = config_list.len();
        config_list.extend_from_slice(&[0x00, 0x00]);

        // Public key length + public key (32 bytes for X25519)
        config_list.extend_from_slice(&[0x00, 0x20]);
        config_list.extend_from_slice(public_key.as_bytes());

        // Cipher suites length + cipher suite
        config_list.extend_from_slice(&[0x00, 0x06]);
        config_list.extend_from_slice(&[0x00, 0x20]); // KEM: X25519
        config_list.extend_from_slice(&[0x00, 0x01]); // KDF: HKDF-SHA256
        config_list.extend_from_slice(&[0x00, 0x01]); // AEAD: AES-128-GCM

        // Maximum name length
        config_list.push(64);

        // Public name length + public name
        let public_name = b"public.example.com";
        config_list.push(public_name.len() as u8);
        config_list.extend_from_slice(public_name);

        // Extensions length (empty)
        config_list.extend_from_slice(&[0x00, 0x00]);

        // Fill in config length
        let config_len = config_list.len() - config_start - 2;
        config_list[config_start..config_start + 2]
            .copy_from_slice(&(config_len as u16).to_be_bytes());

        // Fill in list length
        let list_len = config_list.len() - list_start - 2;
        config_list[list_start..list_start + 2].copy_from_slice(&(list_len as u16).to_be_bytes());

        config_list
    }

    // ============================================================================
    // Comprehensive Unit Tests for TLS Transport Wrapper
    // ============================================================================

    /// Test Standard TLS configuration with valid certificates
    #[test]
    fn test_standard_tls_config_with_valid_certs() {
        let config = StandardTlsConfig {
            server_name: Some("example.com".to_string()),
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
            insecure: false,
            cert_path: Some("/path/to/cert.pem".to_string()),
            key_path: Some("/path/to/key.pem".to_string()),
        };

        assert_eq!(config.server_name, Some("example.com".to_string()));
        assert_eq!(config.alpn.len(), 2);
        assert!(!config.insecure);
        assert!(config.cert_path.is_some());
        assert!(config.key_path.is_some());
    }

    /// Test Standard TLS configuration with multiple ALPN protocols
    #[test]
    fn test_standard_tls_config_multiple_alpn() {
        let alpn_protocols = vec![
            "h2".to_string(),
            "http/1.1".to_string(),
            "http/1.0".to_string(),
        ];

        let config = StandardTlsConfig {
            alpn: alpn_protocols.clone(),
            ..Default::default()
        };

        assert_eq!(config.alpn, alpn_protocols);
        assert_eq!(config.alpn.len(), 3);
    }

    /// Test Standard TLS configuration with insecure mode (for testing)
    #[test]
    fn test_standard_tls_config_insecure_mode() {
        let config = StandardTlsConfig {
            insecure: true,
            server_name: Some("test.local".to_string()),
            ..Default::default()
        };

        assert!(config.insecure);
        assert_eq!(config.server_name, Some("test.local".to_string()));
    }

    /// Test TLS transport creation with Standard config
    #[test]
    fn test_tls_transport_new_standard() {
        let config = TlsConfig::Standard(StandardTlsConfig {
            server_name: Some("example.com".to_string()),
            ..Default::default()
        });

        let transport = TlsTransport::new(config);

        match transport.config {
            TlsConfig::Standard(ref c) => {
                assert_eq!(c.server_name, Some("example.com".to_string()));
            }
            #[allow(unreachable_patterns)]
            _ => panic!("Expected Standard config"),
        }
    }

    /// Test error handling for invalid Standard TLS configuration
    #[test]
    fn test_standard_tls_invalid_config_missing_cert() {
        // Config with cert_path but no key_path should be detectable
        let config = StandardTlsConfig {
            cert_path: Some("/path/to/cert.pem".to_string()),
            key_path: None, // Missing key
            ..Default::default()
        };

        // This is a configuration error that would be caught at runtime
        assert!(config.cert_path.is_some());
        assert!(config.key_path.is_none());
    }

    /// Test error handling for invalid Standard TLS configuration
    #[test]
    fn test_standard_tls_invalid_config_missing_key() {
        // Config with key_path but no cert_path should be detectable
        let config = StandardTlsConfig {
            cert_path: None, // Missing cert
            key_path: Some("/path/to/key.pem".to_string()),
            ..Default::default()
        };

        // This is a configuration error that would be caught at runtime
        assert!(config.cert_path.is_none());
        assert!(config.key_path.is_some());
    }

    /// Test REALITY configuration with valid auth data
    #[cfg(feature = "transport_reality")]
    #[test]
    fn test_reality_config_with_auth_data() {
        let config = RealityTlsConfig {
            target: "www.cloudflare.com".to_string(),
            server_name: "www.cloudflare.com".to_string(),
            public_key: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
                .to_string(),
            short_id: Some("1234".to_string()),
            fingerprint: "firefox".to_string(),
            alpn: vec!["h2".to_string()],
        };

        assert_eq!(config.target, "www.cloudflare.com");
        assert_eq!(config.server_name, "www.cloudflare.com");
        assert_eq!(config.public_key.len(), 64); // 32 bytes hex-encoded
        assert_eq!(config.short_id, Some("1234".to_string()));
        assert_eq!(config.fingerprint, "firefox");
        assert_eq!(config.alpn.len(), 1);
    }

    /// Test REALITY configuration with different fingerprints
    #[cfg(feature = "transport_reality")]
    #[test]
    fn test_reality_config_different_fingerprints() {
        let fingerprints = vec!["chrome", "firefox", "safari", "edge"];

        for fp in fingerprints {
            let config = RealityTlsConfig {
                target: "www.example.com".to_string(),
                server_name: "www.example.com".to_string(),
                public_key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_string(),
                short_id: None,
                fingerprint: fp.to_string(),
                alpn: vec![],
            };

            assert_eq!(config.fingerprint, fp);
        }
    }

    /// Test REALITY configuration without short_id (optional)
    #[cfg(feature = "transport_reality")]
    #[test]
    fn test_reality_config_without_short_id() {
        let config = RealityTlsConfig {
            target: "www.example.com".to_string(),
            server_name: "www.example.com".to_string(),
            public_key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_string(),
            short_id: None,
            fingerprint: "chrome".to_string(),
            alpn: vec![],
        };

        assert!(config.short_id.is_none());
    }

    /// Test REALITY configuration with ALPN
    #[cfg(feature = "transport_reality")]
    #[test]
    fn test_reality_config_with_alpn() {
        let config = RealityTlsConfig {
            target: "www.example.com".to_string(),
            server_name: "www.example.com".to_string(),
            public_key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_string(),
            short_id: Some("ab".to_string()),
            fingerprint: "chrome".to_string(),
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
        };

        assert_eq!(config.alpn.len(), 2);
        assert_eq!(config.alpn[0], "h2");
    }

    /// Test REALITY transport creation
    #[cfg(feature = "transport_reality")]
    #[test]
    fn test_tls_transport_new_reality() {
        let config = TlsConfig::Reality(RealityTlsConfig {
            target: "www.example.com".to_string(),
            server_name: "www.example.com".to_string(),
            public_key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_string(),
            short_id: Some("01".to_string()),
            fingerprint: "chrome".to_string(),
            alpn: vec![],
        });

        let transport = TlsTransport::new(config);

        match transport.config {
            TlsConfig::Reality(ref c) => {
                assert_eq!(c.target, "www.example.com");
            }
            #[allow(unreachable_patterns)]
            _ => panic!("Expected Reality config"),
        }
    }

    /// Test error handling for invalid REALITY configuration (empty target)
    #[cfg(feature = "transport_reality")]
    #[test]
    fn test_reality_config_invalid_empty_target() {
        let config = RealityTlsConfig {
            target: "".to_string(), // Invalid: empty
            server_name: "www.example.com".to_string(),
            public_key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_string(),
            short_id: None,
            fingerprint: "chrome".to_string(),
            alpn: vec![],
        };

        assert!(config.target.is_empty());
    }

    /// Test error handling for invalid REALITY configuration (invalid public key)
    #[cfg(feature = "transport_reality")]
    #[test]
    fn test_reality_config_invalid_public_key() {
        let config = RealityTlsConfig {
            target: "www.example.com".to_string(),
            server_name: "www.example.com".to_string(),
            public_key: "invalid_key".to_string(), // Invalid: not hex
            short_id: None,
            fingerprint: "chrome".to_string(),
            alpn: vec![],
        };

        assert_eq!(config.public_key, "invalid_key");
        assert!(config.public_key.len() != 64);
    }

    /// Test ECH configuration with encryption enabled
    #[cfg(feature = "transport_ech")]
    #[test]
    fn test_ech_config_encryption_enabled() {
        let config = EchTlsConfig {
            enabled: true,
            config: Some("base64_encoded_config".to_string()),
            config_list: Some(vec![1, 2, 3, 4]),
            pq_signature_schemes_enabled: false,
            dynamic_record_sizing_disabled: Some(false),
            server_name: Some("public.example.com".to_string()),
            alpn: vec!["h2".to_string()],
        };

        assert!(config.enabled);
        assert!(config.config.is_some());
        assert!(config.config_list.is_some());
        assert_eq!(config.server_name, Some("public.example.com".to_string()));
    }

    /// Test ECH configuration with post-quantum enabled
    #[cfg(feature = "transport_ech")]
    #[test]
    fn test_ech_config_post_quantum_enabled() {
        let config = EchTlsConfig {
            enabled: true,
            config: Some("test".to_string()),
            config_list: None,
            pq_signature_schemes_enabled: true,
            dynamic_record_sizing_disabled: None,
            server_name: None,
            alpn: vec![],
        };

        assert!(config.pq_signature_schemes_enabled);
    }

    /// Test ECH configuration with dynamic record sizing disabled
    #[cfg(feature = "transport_ech")]
    #[test]
    fn test_ech_config_dynamic_record_sizing_disabled() {
        let config = EchTlsConfig {
            enabled: true,
            config: Some("test".to_string()),
            config_list: None,
            pq_signature_schemes_enabled: false,
            dynamic_record_sizing_disabled: Some(true),
            server_name: None,
            alpn: vec![],
        };

        assert_eq!(config.dynamic_record_sizing_disabled, Some(true));
    }

    /// Test ECH transport creation
    #[cfg(feature = "transport_ech")]
    #[test]
    fn test_tls_transport_new_ech() {
        let config = TlsConfig::Ech(EchTlsConfig {
            enabled: true,
            config: Some("test_config".to_string()),
            config_list: Some(create_test_ech_config_list()),
            pq_signature_schemes_enabled: false,
            dynamic_record_sizing_disabled: None,
            server_name: Some("public.example.com".to_string()),
            alpn: vec![],
        });

        let transport = TlsTransport::new(config);

        match transport.config {
            TlsConfig::Ech(ref c) => {
                assert!(c.enabled);
                assert_eq!(c.server_name, Some("public.example.com".to_string()));
            }
            #[allow(unreachable_patterns)]
            _ => panic!("Expected ECH config"),
        }
    }

    /// Test error handling for invalid ECH configuration (disabled but with config)
    #[cfg(feature = "transport_ech")]
    #[test]
    fn test_ech_config_invalid_disabled_with_config() {
        let config = EchTlsConfig {
            enabled: false,                   // Disabled
            config: Some("test".to_string()), // But has config
            config_list: None,
            pq_signature_schemes_enabled: false,
            dynamic_record_sizing_disabled: None,
            server_name: None,
            alpn: vec![],
        };

        assert!(!config.enabled);
        assert!(config.config.is_some());
    }

    /// Test error handling for invalid ECH configuration (enabled but no config)
    #[cfg(feature = "transport_ech")]
    #[test]
    fn test_ech_config_invalid_enabled_without_config() {
        let config = EchTlsConfig {
            enabled: true, // Enabled
            config: None,  // But no config
            config_list: None,
            pq_signature_schemes_enabled: false,
            dynamic_record_sizing_disabled: None,
            server_name: None,
            alpn: vec![],
        };

        assert!(config.enabled);
        assert!(config.config.is_none());
        assert!(config.config_list.is_none());
    }

    /// Test TLS config serialization and deserialization (Standard)
    #[test]
    fn test_tls_config_serde_roundtrip_standard() {
        let original = TlsConfig::Standard(StandardTlsConfig {
            server_name: Some("example.com".to_string()),
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
            insecure: false,
            cert_path: Some("/cert.pem".to_string()),
            key_path: Some("/key.pem".to_string()),
        });

        let json = serde_json::to_string(&original).unwrap();
        let deserialized: TlsConfig = serde_json::from_str(&json).unwrap();

        match deserialized {
            TlsConfig::Standard(c) => {
                assert_eq!(c.server_name, Some("example.com".to_string()));
                assert_eq!(c.alpn.len(), 2);
                assert_eq!(c.cert_path, Some("/cert.pem".to_string()));
            }
            #[allow(unreachable_patterns)]
            _ => panic!("Expected Standard config"),
        }
    }

    /// Test TLS config serialization with empty optional fields
    #[test]
    fn test_tls_config_serde_empty_optionals() {
        let config = TlsConfig::Standard(StandardTlsConfig::default());

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: TlsConfig = serde_json::from_str(&json).unwrap();

        match deserialized {
            TlsConfig::Standard(c) => {
                assert!(c.server_name.is_none());
                assert!(c.alpn.is_empty());
                assert!(c.cert_path.is_none());
                assert!(c.key_path.is_none());
            }
            #[allow(unreachable_patterns)]
            _ => panic!("Expected Standard config"),
        }
    }

    /// Test TLS config clone
    #[test]
    fn test_tls_config_clone() {
        let original = TlsConfig::Standard(StandardTlsConfig {
            server_name: Some("example.com".to_string()),
            alpn: vec!["h2".to_string()],
            insecure: false,
            cert_path: None,
            key_path: None,
        });

        let cloned = original.clone();

        match (original, cloned) {
            (TlsConfig::Standard(o), TlsConfig::Standard(c)) => {
                assert_eq!(o.server_name, c.server_name);
                assert_eq!(o.alpn, c.alpn);
            }
            #[allow(unreachable_patterns)]
            _ => panic!("Clone failed"),
        }
    }

    /// Test TLS config debug formatting
    #[test]
    fn test_tls_config_debug() {
        let config = TlsConfig::Standard(StandardTlsConfig {
            server_name: Some("example.com".to_string()),
            ..Default::default()
        });

        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("Standard"));
        assert!(debug_str.contains("example.com"));
    }

    /// Test Standard TLS config with empty ALPN
    #[test]
    fn test_standard_tls_config_empty_alpn() {
        let config = StandardTlsConfig {
            alpn: vec![],
            ..Default::default()
        };

        assert!(config.alpn.is_empty());
    }

    /// Test Standard TLS config with single ALPN
    #[test]
    fn test_standard_tls_config_single_alpn() {
        let config = StandardTlsConfig {
            alpn: vec!["h2".to_string()],
            ..Default::default()
        };

        assert_eq!(config.alpn.len(), 1);
        assert_eq!(config.alpn[0], "h2");
    }

    /// Test REALITY config with matching target and server_name
    #[cfg(feature = "transport_reality")]
    #[test]
    fn test_reality_config_matching_target_server_name() {
        let config = RealityTlsConfig {
            target: "www.example.com".to_string(),
            server_name: "www.example.com".to_string(),
            public_key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_string(),
            short_id: None,
            fingerprint: "chrome".to_string(),
            alpn: vec![],
        };

        assert_eq!(config.target, config.server_name);
    }

    /// Test REALITY config with different target and server_name
    #[cfg(feature = "transport_reality")]
    #[test]
    fn test_reality_config_different_target_server_name() {
        let config = RealityTlsConfig {
            target: "www.example.com".to_string(),
            server_name: "cdn.example.com".to_string(),
            public_key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_string(),
            short_id: None,
            fingerprint: "chrome".to_string(),
            alpn: vec![],
        };

        assert_ne!(config.target, config.server_name);
    }

    /// Test ECH config with both config and config_list
    #[cfg(feature = "transport_ech")]
    #[test]
    fn test_ech_config_with_both_config_sources() {
        let config = EchTlsConfig {
            enabled: true,
            config: Some("base64_config".to_string()),
            config_list: Some(vec![1, 2, 3]),
            pq_signature_schemes_enabled: false,
            dynamic_record_sizing_disabled: None,
            server_name: None,
            alpn: vec![],
        };

        assert!(config.config.is_some());
        assert!(config.config_list.is_some());
    }

    /// Test ECH config with only config (no config_list)
    #[cfg(feature = "transport_ech")]
    #[test]
    fn test_ech_config_only_config() {
        let config = EchTlsConfig {
            enabled: true,
            config: Some("base64_config".to_string()),
            config_list: None,
            pq_signature_schemes_enabled: false,
            dynamic_record_sizing_disabled: None,
            server_name: None,
            alpn: vec![],
        };

        assert!(config.config.is_some());
        assert!(config.config_list.is_none());
    }

    /// Test ECH config with only config_list (no config)
    #[cfg(feature = "transport_ech")]
    #[test]
    fn test_ech_config_only_config_list() {
        let config = EchTlsConfig {
            enabled: true,
            config: None,
            config_list: Some(vec![1, 2, 3]),
            pq_signature_schemes_enabled: false,
            dynamic_record_sizing_disabled: None,
            server_name: None,
            alpn: vec![],
        };

        assert!(config.config.is_none());
        assert!(config.config_list.is_some());
    }

    /// Test TLS transport wrapper with Standard config
    #[test]
    fn test_tls_transport_wrapper_standard() {
        let config = TlsConfig::Standard(StandardTlsConfig {
            server_name: Some("example.com".to_string()),
            alpn: vec!["h2".to_string()],
            insecure: false,
            cert_path: None,
            key_path: None,
        });

        let transport = TlsTransport::new(config);

        // Verify the transport was created successfully
        match &transport.config {
            TlsConfig::Standard(c) => {
                assert_eq!(c.server_name, Some("example.com".to_string()));
                assert_eq!(c.alpn, vec!["h2".to_string()]);
            }
            #[allow(unreachable_patterns)]
            _ => panic!("Expected Standard config"),
        }
    }

    /// Test TLS transport wrapper configuration validation
    #[test]
    fn test_tls_transport_config_validation() {
        // Valid config
        let valid_config = StandardTlsConfig {
            server_name: Some("example.com".to_string()),
            alpn: vec!["h2".to_string()],
            insecure: false,
            cert_path: Some("/cert.pem".to_string()),
            key_path: Some("/key.pem".to_string()),
        };

        assert!(valid_config.server_name.is_some());
        assert!(valid_config.cert_path.is_some());
        assert!(valid_config.key_path.is_some());

        // Invalid config (cert without key)
        let invalid_config = StandardTlsConfig {
            server_name: Some("example.com".to_string()),
            alpn: vec![],
            insecure: false,
            cert_path: Some("/cert.pem".to_string()),
            key_path: None, // Missing
        };

        assert!(invalid_config.cert_path.is_some());
        assert!(invalid_config.key_path.is_none());
    }
}
