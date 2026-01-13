# sb-adapters crate - 协议适配器

## 1. 概述

`sb-adapters` 是协议适配器 crate，提供：
- 入站协议实现（服务端）
- 出站协议实现（客户端）
- 端点实现（WireGuard, Tailscale）
- 服务实现（Resolved, DERP, SSM-API）
- 传输层配置

---

## 2. 目录结构

```
sb-adapters/
├── Cargo.toml              # 9.8KB，大量 features
├── src/
│   ├── lib.rs              # 模块导出，trait re-export
│   ├── error.rs            # 错误类型 (11KB)
│   ├── traits.rs           # 核心 trait (23KB)
│   ├── transport_config.rs # 传输配置 (22KB)
│   ├── register.rs         # 注册函数 (104KB!)
│   │
│   ├── inbound/            # 入站协议 (38 个文件)
│   │   ├── mod.rs
│   │   ├── http/           # HTTP 入站
│   │   ├── socks/          # SOCKS 入站
│   │   ├── mixed/          # Mixed 入站
│   │   ├── shadowsocks/    # Shadowsocks 入站
│   │   ├── vmess/          # VMess 入站
│   │   ├── vless/          # VLESS 入站
│   │   ├── trojan/         # Trojan 入站
│   │   ├── tun/            # TUN 入站
│   │   ├── redirect/       # Redirect 入站
│   │   └── ...
│   │
│   ├── outbound/           # 出站协议 (27 个文件)
│   │   ├── mod.rs
│   │   ├── direct.rs       # Direct 出站
│   │   ├── socks5.rs       # SOCKS5 出站
│   │   ├── http.rs         # HTTP 出站
│   │   ├── shadowsocks.rs  # Shadowsocks 出站
│   │   ├── vmess.rs        # VMess 出站
│   │   ├── vless.rs        # VLESS 出站
│   │   ├── trojan.rs       # Trojan 出站
│   │   ├── shadowtls.rs    # ShadowTLS 出站
│   │   ├── anytls.rs       # AnyTLS 出站
│   │   ├── hysteria.rs     # Hysteria 出站
│   │   ├── hysteria2.rs    # Hysteria2 出站
│   │   ├── tuic.rs         # TUIC 出站
│   │   ├── wireguard.rs    # WireGuard 出站
│   │   ├── ssh.rs          # SSH 出站
│   │   ├── tor.rs          # Tor 出站
│   │   ├── naive.rs        # NaiveProxy 出站
│   │   └── ...
│   │
│   ├── endpoint/           # 端点 (3 个文件)
│   │   ├── mod.rs
│   │   ├── wireguard.rs
│   │   └── tailscale.rs
│   │
│   ├── service/            # 服务 (3 个文件)
│   │   ├── mod.rs
│   │   ├── resolved.rs
│   │   └── derp.rs
│   │
│   ├── endpoint_stubs.rs   # 端点存根 (7KB)
│   ├── service_stubs.rs    # 服务存根 (10KB)
│   │
│   ├── util/               # 工具
│   │   └── ...
│   │
│   └── testsupport/        # 测试工具
│       └── ...
│
├── tests/                  # 26 个测试
└── examples/               # 2 个示例
```

---

## 3. 核心 Traits

### 3.1 traits.rs 定义

```rust
// sb-adapters/src/traits.rs (23KB)

/// 出站连接器 trait
#[async_trait]
pub trait OutboundConnector: Send + Sync {
    /// 建立 TCP 连接
    async fn connect(&self, target: &Target) -> Result<BoxedStream>;
    
    /// 带选项连接
    async fn connect_with_opts(
        &self,
        target: &Target,
        opts: &DialOpts,
    ) -> Result<BoxedStream> {
        self.connect(target).await
    }
    
    /// 协议类型
    fn protocol_type(&self) -> &'static str;
    
    /// 是否支持 UDP
    fn supports_udp(&self) -> bool { false }
}

/// UDP 出站 trait
#[async_trait]
pub trait OutboundDatagram: Send + Sync {
    async fn send_to(&self, data: &[u8], target: &Target) -> Result<()>;
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, Target)>;
    fn local_addr(&self) -> Result<SocketAddr>;
}

/// 连接目标
#[derive(Debug, Clone)]
pub enum Target {
    Ip(IpAddr, u16),
    Domain(String, u16),
    Fqdn(String, u16),
}

impl Target {
    pub fn port(&self) -> u16 { ... }
    pub fn host(&self) -> String { ... }
    pub fn is_ip(&self) -> bool { ... }
    pub fn as_socket_addr(&self) -> Option<SocketAddr> { ... }
}

/// 抽象流类型
pub type BoxedStream = Box<dyn AsyncReadWrite + Send + Unpin>;

/// 传输类型枚举
#[derive(Debug, Clone)]
pub enum TransportKind {
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

/// 连接选项
#[derive(Debug, Clone, Default)]
pub struct DialOpts {
    pub timeout: Option<Duration>,
    pub retry: Option<RetryPolicy>,
    pub bind_interface: Option<String>,
    pub bind_address: Option<IpAddr>,
    pub tcp_fast_open: bool,
    pub tcp_multi_path: bool,
    pub resolve_mode: ResolveMode,
}

/// DNS 解析模式
#[derive(Debug, Clone, Default)]
pub enum ResolveMode {
    #[default]
    Local,
    Remote,
    PreferLocal,
    PreferRemote,
}

/// 重试策略
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    pub max_retries: u32,
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub multiplier: f64,
}
```

---

## 4. 入站协议

### 4.1 协议列表

| 协议 | 目录 | Feature | 描述 |
|------|------|---------|------|
| HTTP | `inbound/http/` | `adapter-http` | HTTP/HTTPS 代理 |
| SOCKS | `inbound/socks/` | `adapter-socks` | SOCKS4/5 代理 |
| Mixed | `inbound/mixed/` | `mixed` | HTTP + SOCKS |
| Shadowsocks | `inbound/shadowsocks/` | `adapter-shadowsocks` | SS 服务端 |
| VMess | `inbound/vmess/` | `adapter-vmess` | VMess 服务端 |
| VLESS | `inbound/vless/` | `adapter-vless` | VLESS 服务端 |
| Trojan | `inbound/trojan/` | `adapter-trojan` | Trojan 服务端 |
| TUN | `inbound/tun/` | `adapter-tun` | TUN 设备 |
| Redirect | `inbound/redirect/` | - | iptables redirect |
| TProxy | `inbound/tproxy/` | - | iptables tproxy |
| Hysteria | `inbound/hysteria/` | `adapter-hysteria` | Hysteria 服务端 |
| Hysteria2 | `inbound/hysteria2/` | `adapter-hysteria2` | Hysteria2 服务端 |
| TUIC | `inbound/tuic/` | `adapter-tuic` | TUIC 服务端 |
| Naive | `inbound/naive/` | `adapter-naive` | Naive 服务端 |
| ShadowTLS | `inbound/shadowtls/` | `adapter-shadowtls` | ShadowTLS 服务端 |
| AnyTLS | `inbound/anytls/` | `adapter-anytls` | AnyTLS 服务端 |

### 4.2 入站实现示例

```rust
// sb-adapters/src/inbound/socks/mod.rs

pub struct SocksInbound {
    tag: String,
    listen_addr: SocketAddr,
    auth: Option<SocksAuth>,
    router: Arc<dyn Router>,
}

impl SocksInbound {
    pub async fn start(self) -> Result<JoinHandle<()>> {
        let listener = TcpListener::bind(self.listen_addr).await?;
        
        Ok(tokio::spawn(async move {
            loop {
                let (stream, peer) = listener.accept().await?;
                let router = self.router.clone();
                let auth = self.auth.clone();
                
                tokio::spawn(async move {
                    if let Err(e) = handle_socks_connection(stream, peer, auth, router).await {
                        tracing::error!("SOCKS error: {}", e);
                    }
                });
            }
        }))
    }
}

async fn handle_socks_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    auth: Option<SocksAuth>,
    router: Arc<dyn Router>,
) -> Result<()> {
    // 1. SOCKS 握手
    let target = socks5_handshake(&mut stream, &auth).await?;
    
    // 2. 构建上下文
    let ctx = ConnectionContext {
        source: peer,
        destination: target.clone(),
        inbound: "socks".to_string(),
        network: Network::Tcp,
        // ...
    };
    
    // 3. 路由并连接
    let remote = router.route_connection(stream, ctx).await?;
    
    // 4. 双向转发
    copy_bidirectional(&mut stream, &mut remote).await?;
    
    Ok(())
}
```

---

## 5. 出站协议

### 5.1 协议列表

| 协议 | 文件 | Feature | 描述 |
|------|------|---------|------|
| Direct | `direct.rs` | - | 直连 |
| SOCKS5 | `socks5.rs` | `socks` | SOCKS5 代理 |
| HTTP | `http.rs` | `http` | HTTP 代理 |
| Shadowsocks | `shadowsocks.rs` | `shadowsocks` | SS 客户端 |
| VMess | `vmess.rs` | `vmess` | VMess 客户端 |
| VLESS | `vless.rs` | `vless` | VLESS 客户端 |
| Trojan | `trojan.rs` | `trojan` | Trojan 客户端 |
| ShadowTLS | `shadowtls.rs` | `adapter-shadowtls` | ShadowTLS 客户端 |
| AnyTLS | `anytls.rs` | `adapter-anytls` | AnyTLS 客户端 |
| Hysteria | `hysteria.rs` | `adapter-hysteria` | Hysteria 客户端 |
| Hysteria2 | `hysteria2.rs` | `adapter-hysteria2` | Hysteria2 客户端 |
| TUIC | `tuic.rs` | `adapter-tuic` | TUIC 客户端 |
| WireGuard | `wireguard.rs` | `adapter-wireguard` | WireGuard 客户端 |
| SSH | `ssh.rs` | `adapter-ssh` | SSH 隧道 |
| Tor | `tor.rs` | `adapter-tor` | Tor 网络 |
| Naive | `naive.rs` | `adapter-naive` | Naive 客户端 |

### 5.2 出站实现示例

```rust
// sb-adapters/src/outbound/vmess.rs

pub struct VMessOutbound {
    server: SocketAddr,
    uuid: Uuid,
    alter_id: u16,
    security: VMessSecurity,
    transport: TransportConfig,
    dialer: Arc<dyn Dialer>,
}

#[async_trait]
impl OutboundConnector for VMessOutbound {
    async fn connect(&self, target: &Target) -> Result<BoxedStream> {
        // 1. 建立底层连接
        let conn = self.dialer.dial(&self.server).await?;
        
        // 2. 应用传输层
        let conn = self.transport.wrap(conn).await?;
        
        // 3. VMess 握手
        let conn = vmess_handshake(conn, &self.uuid, target, &self.security).await?;
        
        Ok(Box::new(conn))
    }
    
    fn protocol_type(&self) -> &'static str {
        "vmess"
    }
    
    fn supports_udp(&self) -> bool {
        true
    }
}
```

---

## 6. 传输配置

### 6.1 TransportConfig

```rust
// sb-adapters/src/transport_config.rs (22KB)

#[derive(Debug, Clone)]
pub struct TransportConfig {
    pub transport_type: TransportType,
    pub tls: Option<TlsConfig>,
    pub reality: Option<RealityConfig>,
    pub ech: Option<EchConfig>,
    pub ws: Option<WsConfig>,
    pub grpc: Option<GrpcConfig>,
    pub http2: Option<Http2Config>,
    pub http_upgrade: Option<HttpUpgradeConfig>,
    pub mux: Option<MuxConfig>,
}

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub server_name: Option<String>,
    pub insecure: bool,
    pub alpn: Vec<String>,
    pub fingerprint: Option<String>,  // uTLS
    pub certificate: Option<String>,
    pub certificate_path: Option<PathBuf>,
    pub min_version: Option<String>,
    pub max_version: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RealityConfig {
    pub server_name: String,
    pub public_key: String,
    pub short_id: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone)]
pub struct WsConfig {
    pub path: String,
    pub headers: HashMap<String, String>,
    pub max_early_data: u32,
    pub early_data_header_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GrpcConfig {
    pub service_name: String,
    pub permit_without_stream: bool,
}

#[derive(Debug, Clone)]
pub struct MuxConfig {
    pub enabled: bool,
    pub protocol: MuxProtocol,
    pub max_connections: u32,
    pub min_streams: u32,
    pub max_streams: u32,
    pub padding: bool,
}

#[derive(Debug, Clone)]
pub enum MuxProtocol {
    Smux,
    Yamux,
    H2Mux,
}
```

---

## 7. 注册系统

```rust
// sb-adapters/src/register.rs (104KB)

/// 注册所有适配器到 sb-core
pub fn register_all(registry: &mut AdapterRegistry) {
    // 入站
    #[cfg(feature = "adapter-socks")]
    register_socks_inbound(registry);
    
    #[cfg(feature = "adapter-http")]
    register_http_inbound(registry);
    
    #[cfg(feature = "adapter-shadowsocks")]
    register_ss_inbound(registry);
    
    // ... 更多入站
    
    // 出站
    register_direct_outbound(registry);
    register_block_outbound(registry);
    
    #[cfg(feature = "socks")]
    register_socks_outbound(registry);
    
    #[cfg(feature = "vmess")]
    register_vmess_outbound(registry);
    
    // ... 更多出站
}

fn register_vmess_outbound(registry: &mut AdapterRegistry) {
    registry.register_outbound(
        "vmess",
        |config: &OutboundConfig| -> Result<Box<dyn OutboundConnector>> {
            let vmess_conf: VMessConfig = serde_json::from_value(config.settings.clone())?;
            Ok(Box::new(VMessOutbound::new(vmess_conf)?))
        },
    );
}
```

---

## 8. Feature Flags

| Feature | 功能 |
|---------|------|
| `adapter-socks` | SOCKS 入站/出站 |
| `adapter-http` | HTTP 入站/出站 |
| `adapter-shadowsocks` | Shadowsocks |
| `adapter-vmess` | VMess |
| `adapter-vless` | VLESS |
| `adapter-trojan` | Trojan |
| `adapter-hysteria` | Hysteria |
| `adapter-hysteria2` | Hysteria2 |
| `adapter-tuic` | TUIC |
| `adapter-wireguard` | WireGuard |
| `adapter-wireguard-endpoint` | WireGuard 端点 |
| `adapter-tun` | TUN 设备 |
| `adapter-shadowtls` | ShadowTLS |
| `adapter-anytls` | AnyTLS |
| `adapter-naive` | NaiveProxy |
| `adapter-tor` | Tor |
| `transport_tls` | TLS 传输 |
| `transport_reality` | REALITY 传输 |
| `transport_ech` | ECH 传输 |
| `transport_mux` | 多路复用 |
| `transport_ws` | WebSocket |
| `transport_grpc` | gRPC |
| `transport_quic` | QUIC |
| `transport_h2` | HTTP/2 |
| `mixed` | Mixed 入站 |
| `router` | 路由集成 |
| `metrics` | 指标收集 |
| `e2e` | E2E 测试 |
| `service_resolved` | Resolved 服务 |
| `service_ssmapi` | SSM-API 服务 |
| `service_derp` | DERP 服务 |
