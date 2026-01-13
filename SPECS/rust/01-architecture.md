# 架构设计详解

## 1. 整体架构

singbox-rust 采用分层模块化架构，通过 Cargo workspace 组织：

```
app (应用入口层)
 │
 ├── sb-core (核心引擎层)
 │    ├── router (路由引擎)
 │    ├── dns (DNS 系统)
 │    ├── inbound (入站管理)
 │    ├── outbound (出站管理)
 │    ├── service (服务管理)
 │    └── endpoint (端点管理)
 │
 ├── sb-adapters (协议适配层)
 │    ├── inbound/* (入站协议实现)
 │    ├── outbound/* (出站协议实现)
 │    ├── endpoint/* (端点实现)
 │    └── service/* (服务实现)
 │
 ├── sb-transport (传输层)
 │    ├── tls.rs (TLS/REALITY)
 │    ├── websocket.rs
 │    ├── grpc.rs
 │    ├── quic.rs
 │    └── multiplex.rs
 │
 ├── sb-config (配置层)
 │    ├── 解析 (JSON/YAML)
 │    ├── 验证
 │    └── IR 转换
 │
 └── 辅助 crates
      ├── sb-tls (TLS 实现)
      ├── sb-metrics (监控)
      ├── sb-api (REST API)
      ├── sb-subscribe (订阅)
      ├── sb-runtime (运行时)
      └── sb-platform (平台适配)
```

---

## 2. 核心 Traits

### 2.1 OutboundConnector

出站连接器的核心 trait：

```rust
// sb-adapters/src/traits.rs

#[async_trait]
pub trait OutboundConnector: Send + Sync {
    /// 建立到目标的 TCP 连接
    async fn connect(&self, target: &Target) -> Result<BoxedStream>;
    
    /// 带选项的连接
    async fn connect_with_opts(
        &self, 
        target: &Target, 
        opts: &DialOpts
    ) -> Result<BoxedStream>;
    
    /// 协议类型名称
    fn protocol_type(&self) -> &'static str;
    
    /// 协议是否支持 UDP
    fn supports_udp(&self) -> bool { false }
}
```

### 2.2 OutboundDatagram

UDP 出站接口：

```rust
#[async_trait]
pub trait OutboundDatagram: Send + Sync {
    /// 发送 UDP 数据包
    async fn send_to(&self, data: &[u8], target: &Target) -> Result<()>;
    
    /// 接收 UDP 数据包
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, Target)>;
}
```

### 2.3 Target

连接目标抽象：

```rust
pub enum Target {
    /// IP 地址 + 端口
    Ip(IpAddr, u16),
    /// 域名 + 端口
    Domain(String, u16),
    /// FQDN + 端口
    Fqdn(String, u16),
}
```

### 2.4 TransportConfig

传输层配置：

```rust
pub struct TransportConfig {
    pub transport_type: TransportType,
    pub tls: Option<TlsConfig>,
    pub reality: Option<RealityConfig>,
    pub ws: Option<WsConfig>,
    pub grpc: Option<GrpcConfig>,
    pub mux: Option<MuxConfig>,
    // ...
}

pub enum TransportType {
    Tcp,
    Tls,
    Reality,
    WebSocket,
    Grpc,
    GrpcLite,
    Http2,
    HttpUpgrade,
    Quic,
}
```

---

## 3. 数据流

### 3.1 入站连接流程

```
[客户端]
    │
    ▼
[Inbound Listener] ── 监听端口，接受连接
    │
    ▼
[Protocol Handler] ── 协议握手，解析目标
    │
    ▼
[InboundContext] ─── 封装连接元数据
    │
    ▼
[Router.route()] ─── 规则匹配
    │
    ├── [Sniff] ───── 协议嗅探
    ├── [DNS] ─────── 解析域名
    └── [Match] ───── 规则匹配
    │
    ▼
[Outbound] ────────── 选择出站
    │
    ▼
[Transport] ───────── 传输层处理
    │
    ▼
[目标服务器]
```

### 3.2 出站连接流程

```
[Router 选择出站]
    │
    ▼
[OutboundConnector.connect()]
    │
    ├── [Dialer] ───── 基础连接
    │       │
    │       └── 超时/重试/绑定接口
    │
    ├── [Transport] ── 传输层包装
    │       │
    │       ├── TLS 握手
    │       ├── WebSocket 升级
    │       ├── gRPC 封装
    │       └── 多路复用
    │
    └── [Protocol] ─── 协议层包装
            │
            ├── SOCKS5 握手
            ├── VMess 加密
            ├── VLESS 认证
            └── Trojan 封装
    │
    ▼
[BoxedStream] ── 返回抽象流
```

---

## 4. 生命周期管理

### 4.1 启动流程

```rust
// app/src/bootstrap.rs

pub async fn bootstrap(config: Config) -> Result<Runtime> {
    // 1. 初始化日志
    init_logging(&config)?;
    
    // 2. 初始化 metrics
    init_metrics()?;
    
    // 3. 加载 GeoIP/GeoSite
    let geo = load_geo_data(&config)?;
    
    // 4. 构建 DNS 系统
    let dns = build_dns_resolver(&config)?;
    
    // 5. 构建路由器
    let router = Router::new(&config, dns, geo)?;
    
    // 6. 启动入站
    let inbounds = start_inbounds(&config, router)?;
    
    // 7. 启动后台服务
    let services = start_services(&config)?;
    
    // 8. 启动 Admin API
    let admin = start_admin_api(&config)?;
    
    Ok(Runtime { inbounds, services, admin })
}
```

### 4.2 热重载

```rust
// sb-core/src/router/hot_reload.rs

impl Router {
    pub async fn hot_reload(&self, new_config: Config) -> Result<()> {
        // 1. 解析新规则
        let new_rules = parse_rules(&new_config)?;
        
        // 2. 原子替换规则
        self.rules.swap(Arc::new(new_rules));
        
        // 3. 更新 DNS 配置
        self.dns.update(&new_config.dns)?;
        
        // 4. 更新出站
        self.outbound_manager.update(&new_config.outbounds)?;
        
        Ok(())
    }
}
```

### 4.3 优雅关闭

```rust
pub async fn shutdown_graceful(
    runtime: Runtime, 
    timeout: Duration
) -> Result<()> {
    // 1. 停止接受新连接
    runtime.inbounds.stop_accept().await?;
    
    // 2. 等待现有连接完成或超时
    tokio::select! {
        _ = runtime.connections.drain() => {}
        _ = tokio::time::sleep(timeout) => {
            // 强制关闭剩余连接
            runtime.connections.force_close().await;
        }
    }
    
    // 3. 停止后台服务
    runtime.services.shutdown().await?;
    
    Ok(())
}
```

---

## 5. 错误处理

### 5.1 错误类型层次

```rust
// sb-adapters/src/error.rs

#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Protocol error: {0}")]
    Protocol(String),
    
    #[error("TLS error: {0}")]
    Tls(#[from] TlsError),
    
    #[error("Timeout: {0}")]
    Timeout(#[from] tokio::time::error::Elapsed),
    
    #[error("DNS resolution failed: {0}")]
    DnsResolution(String),
    
    #[error("Authentication failed")]
    AuthFailed,
    
    #[error("Connection refused")]
    ConnectionRefused,
    
    #[error("Unsupported protocol: {0}")]
    Unsupported(String),
}
```

### 5.2 Result 类型别名

```rust
pub type Result<T> = std::result::Result<T, AdapterError>;
```

---

## 6. 并发模型

### 6.1 异步运行时

- 使用 **Tokio** 作为异步运行时
- 支持多线程调度器 (`multi_thread`)
- 支持工作窃取 (work-stealing)

### 6.2 连接处理

```rust
// 每个入站连接 spawn 独立 task
tokio::spawn(async move {
    if let Err(e) = handle_connection(conn, router).await {
        tracing::error!("Connection error: {}", e);
    }
});
```

### 6.3 共享状态

- 使用 `Arc<T>` 共享只读数据
- 使用 `Arc<RwLock<T>>` 共享可变数据
- 使用 `arc_swap::ArcSwap` 实现无锁热重载

---

## 7. 与 Go 版本对比

| 方面 | Go 版本 | Rust 版本 |
|------|---------|-----------|
| 并发模型 | Goroutine | Tokio async/await |
| 内存管理 | GC | 所有权系统 |
| 错误处理 | `error` interface | `Result<T, E>` |
| 模块化 | Go modules | Cargo workspace |
| 功能开关 | Build tags | Feature flags |
| 依赖注入 | Context | Trait objects + Arc |
| 协议注册 | Registry 模式 | Trait + Register 宏 |
