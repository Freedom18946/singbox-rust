# sb-transport crate - 传输层

## 1. 概述

`sb-transport` 提供传输层实现：
- TLS / REALITY / ECH
- WebSocket
- gRPC / gRPC Lite
- HTTP/2 / HTTP Upgrade
- QUIC
- 多路复用 (smux/yamux)
- 重试 / 熔断
- SIP003 插件

---

## 2. 目录结构

```
sb-transport/
├── Cargo.toml
├── src/
│   ├── lib.rs              # 模块导出 (10KB)
│   │
│   ├── tls.rs              # TLS 实现 (101KB!)
│   ├── tls_secure.rs       # 安全 TLS (10KB)
│   │
│   ├── websocket.rs        # WebSocket (21KB)
│   ├── grpc.rs             # gRPC (21KB)
│   ├── grpc_lite.rs        # 轻量 gRPC (12KB)
│   ├── http2.rs            # HTTP/2 (21KB)
│   ├── httpupgrade.rs      # HTTP Upgrade (15KB)
│   ├── quic.rs             # QUIC (20KB)
│   │
│   ├── multiplex.rs        # 多路复用 (25KB)
│   ├── multiplex/          # 多路复用实现
│   │   └── ...
│   │
│   ├── dialer.rs           # 拨号器 (34KB)
│   ├── builder.rs          # 连接构建器 (8KB)
│   ├── retry.rs            # 重试策略 (20KB)
│   ├── circuit_breaker.rs  # 熔断器 (24KB)
│   ├── resource_pressure.rs # 资源压力 (18KB)
│   │
│   ├── simple_obfs.rs      # simple-obfs (13KB)
│   ├── sip003.rs           # SIP003 插件 (11KB)
│   │
│   ├── trojan.rs           # Trojan 传输 (13KB)
│   ├── uot.rs              # UDP over TCP (13KB)
│   ├── wireguard.rs        # WireGuard (18KB)
│   ├── tailscale_dns.rs    # Tailscale DNS (21KB)
│   │
│   ├── pool/               # 连接池
│   │   └── ...
│   │
│   ├── derp/               # DERP 传输
│   │   └── ...
│   │
│   ├── mem.rs              # 内存传输 (12KB)
│   ├── util.rs             # 工具 (13KB)
│   └── metrics_ext.rs      # 指标扩展 (4KB)
```

---

## 3. 核心组件

### 3.1 Dialer - 拨号器

```rust
// sb-transport/src/dialer.rs (34KB)

/// 通用拨号器
pub struct Dialer {
    /// 绑定接口
    bind_interface: Option<String>,
    /// 绑定地址
    bind_address: Option<IpAddr>,
    /// 连接超时
    connect_timeout: Duration,
    /// TCP Fast Open
    tcp_fast_open: bool,
    /// Multipath TCP
    tcp_multi_path: bool,
    /// 底层 socket 选项
    socket_opts: SocketOpts,
}

impl Dialer {
    pub async fn dial(&self, addr: &SocketAddr) -> Result<TcpStream> {
        let socket = self.create_socket(addr)?;
        
        // 绑定接口
        if let Some(iface) = &self.bind_interface {
            self.bind_to_interface(&socket, iface)?;
        }
        
        // 绑定地址
        if let Some(bind_addr) = self.bind_address {
            socket.bind(SocketAddr::new(bind_addr, 0))?;
        }
        
        // 连接（带超时）
        let stream = tokio::time::timeout(
            self.connect_timeout,
            socket.connect(*addr),
        ).await??;
        
        // 配置 socket
        self.configure_stream(&stream)?;
        
        Ok(stream)
    }
}

/// 带传输层的拨号器
pub struct TransportDialer {
    dialer: Dialer,
    transport: TransportConfig,
    dns_resolver: Arc<dyn DnsResolver>,
}

impl TransportDialer {
    pub async fn dial(&self, target: &Target) -> Result<BoxedStream> {
        // 1. DNS 解析
        let addr = self.resolve(target).await?;
        
        // 2. 底层连接
        let conn = self.dialer.dial(&addr).await?;
        
        // 3. 传输层包装
        let conn = self.wrap_transport(conn, target).await?;
        
        Ok(conn)
    }
    
    async fn wrap_transport(&self, conn: TcpStream, target: &Target) -> Result<BoxedStream> {
        let mut stream: BoxedStream = Box::new(conn);
        
        // TLS
        if let Some(tls) = &self.transport.tls {
            stream = self.wrap_tls(stream, tls, target).await?;
        }
        
        // REALITY
        if let Some(reality) = &self.transport.reality {
            stream = self.wrap_reality(stream, reality).await?;
        }
        
        // WebSocket
        if let Some(ws) = &self.transport.ws {
            stream = self.wrap_websocket(stream, ws).await?;
        }
        
        // gRPC
        if let Some(grpc) = &self.transport.grpc {
            stream = self.wrap_grpc(stream, grpc).await?;
        }
        
        // 多路复用
        if let Some(mux) = &self.transport.mux {
            stream = self.wrap_mux(stream, mux).await?;
        }
        
        Ok(stream)
    }
}
```

### 3.2 TLS 实现

```rust
// sb-transport/src/tls.rs (101KB)

/// TLS 客户端配置
pub struct TlsClientConfig {
    pub server_name: Option<String>,
    pub insecure: bool,
    pub alpn: Vec<String>,
    pub fingerprint: Option<TlsFingerprint>,
    pub certificate: Option<Vec<Certificate>>,
    pub min_version: TlsVersion,
    pub max_version: TlsVersion,
}

/// TLS 指纹（uTLS）
#[derive(Debug, Clone)]
pub enum TlsFingerprint {
    Chrome,
    Firefox,
    Safari,
    Edge,
    Ios,
    Android,
    Random,
    Custom(CustomFingerprint),
}

impl TlsClientConfig {
    pub async fn connect(&self, stream: TcpStream, server_name: &str) -> Result<TlsStream> {
        if let Some(fp) = &self.fingerprint {
            // 使用 uTLS
            self.connect_utls(stream, server_name, fp).await
        } else {
            // 标准 rustls
            self.connect_rustls(stream, server_name).await
        }
    }
}

/// REALITY 客户端
pub struct RealityClient {
    pub server_name: String,
    pub public_key: [u8; 32],
    pub short_id: [u8; 8],
    pub fingerprint: TlsFingerprint,
}

impl RealityClient {
    pub async fn connect(&self, stream: TcpStream) -> Result<RealityStream> {
        // 1. 生成临时密钥对
        let (private_key, client_hello) = generate_reality_handshake(&self)?;
        
        // 2. 发送 TLS ClientHello（带 REALITY 扩展）
        stream.write_all(&client_hello).await?;
        
        // 3. 读取 ServerHello
        let server_hello = read_server_hello(&mut stream).await?;
        
        // 4. 派生会话密钥
        let session_key = derive_reality_key(&private_key, &server_hello)?;
        
        // 5. 返回加密流
        Ok(RealityStream::new(stream, session_key))
    }
}
```

### 3.3 WebSocket

```rust
// sb-transport/src/websocket.rs (21KB)

pub struct WsConfig {
    pub path: String,
    pub headers: HashMap<String, String>,
    pub max_early_data: u32,
    pub early_data_header_name: Option<String>,
}

pub struct WebSocketTransport {
    config: WsConfig,
}

impl WebSocketTransport {
    pub async fn connect(&self, stream: BoxedStream, host: &str) -> Result<WsStream> {
        // 1. 生成 WebSocket key
        let key = generate_ws_key();
        
        // 2. 构造 HTTP Upgrade 请求
        let request = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {}\r\n\
             Sec-WebSocket-Version: 13\r\n\
             {}\r\n",
            self.config.path, host, key, self.headers_string()
        );
        
        // 3. 发送请求
        stream.write_all(request.as_bytes()).await?;
        
        // 4. 读取响应
        let response = read_http_response(&mut stream).await?;
        verify_ws_response(&response, &key)?;
        
        // 5. 返回 WebSocket 流
        Ok(WsStream::new(stream))
    }
}
```

### 3.4 gRPC

```rust
// sb-transport/src/grpc.rs (21KB)

pub struct GrpcConfig {
    pub service_name: String,
    pub permit_without_stream: bool,
}

pub struct GrpcTransport {
    config: GrpcConfig,
}

impl GrpcTransport {
    pub async fn connect(&self, stream: BoxedStream, host: &str) -> Result<GrpcStream> {
        // 使用 HTTP/2 建立 gRPC 连接
        let h2 = h2::client::handshake(stream).await?;
        
        // 创建 gRPC 通道
        let (send_request, connection) = h2.ready().await?;
        
        // 后台运行 HTTP/2 连接
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                tracing::error!("gRPC connection error: {}", e);
            }
        });
        
        // 打开双向流
        let request = http::Request::builder()
            .method("POST")
            .uri(format!("/{}/Tun", self.config.service_name))
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .body(())
            .unwrap();
        
        let (response, send_stream) = send_request.send_request(request, false)?;
        let recv_stream = response.await?;
        
        Ok(GrpcStream::new(send_stream, recv_stream.into_body()))
    }
}
```

### 3.5 多路复用

```rust
// sb-transport/src/multiplex.rs (25KB)

pub struct MuxConfig {
    pub protocol: MuxProtocol,
    pub max_connections: u32,
    pub min_streams: u32,
    pub max_streams: u32,
    pub padding: bool,
}

pub enum MuxProtocol {
    Smux,
    Yamux,
    H2Mux,
}

pub struct MuxClient {
    config: MuxConfig,
    connections: RwLock<Vec<Arc<MuxConnection>>>,
}

impl MuxClient {
    pub async fn open_stream(&self, conn: BoxedStream) -> Result<MuxStream> {
        // 1. 获取或创建多路复用连接
        let mux_conn = self.get_or_create_connection(conn).await?;
        
        // 2. 打开新流
        let stream = mux_conn.open_stream().await?;
        
        Ok(stream)
    }
    
    async fn get_or_create_connection(&self, conn: BoxedStream) -> Result<Arc<MuxConnection>> {
        let connections = self.connections.read().await;
        
        // 查找可用连接
        for mux_conn in connections.iter() {
            if mux_conn.stream_count() < self.config.max_streams {
                return Ok(mux_conn.clone());
            }
        }
        
        drop(connections);
        
        // 创建新连接
        let mux_conn = self.create_mux_connection(conn).await?;
        
        let mut connections = self.connections.write().await;
        connections.push(mux_conn.clone());
        
        Ok(mux_conn)
    }
}
```

### 3.6 重试策略

```rust
// sb-transport/src/retry.rs (20KB)

pub struct RetryPolicy {
    pub max_retries: u32,
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub multiplier: f64,
    pub jitter: f64,
}

impl RetryPolicy {
    pub async fn execute<F, T, E>(&self, mut f: F) -> Result<T>
    where
        F: FnMut() -> Pin<Box<dyn Future<Output = std::result::Result<T, E>> + Send>>,
        E: std::error::Error,
    {
        let mut attempts = 0;
        let mut delay = self.initial_delay;
        
        loop {
            match f().await {
                Ok(result) => return Ok(result),
                Err(e) if attempts < self.max_retries => {
                    attempts += 1;
                    tracing::warn!("Retry attempt {}: {}", attempts, e);
                    
                    // 带抖动的延迟
                    let jittered = self.add_jitter(delay);
                    tokio::time::sleep(jittered).await;
                    
                    // 指数退避
                    delay = (delay.as_secs_f64() * self.multiplier)
                        .min(self.max_delay.as_secs_f64());
                    delay = Duration::from_secs_f64(delay);
                }
                Err(e) => return Err(e.into()),
            }
        }
    }
}
```

### 3.7 熔断器

```rust
// sb-transport/src/circuit_breaker.rs (24KB)

#[derive(Debug, Clone, Copy)]
pub enum CircuitState {
    Closed,     // 正常
    Open,       // 熔断
    HalfOpen,   // 半开
}

pub struct CircuitBreaker {
    state: AtomicU8,
    failure_count: AtomicU32,
    success_count: AtomicU32,
    last_failure: AtomicU64,
    
    /// 失败阈值
    failure_threshold: u32,
    /// 成功阈值（半开时）
    success_threshold: u32,
    /// 熔断超时
    timeout: Duration,
}

impl CircuitBreaker {
    pub fn allow(&self) -> bool {
        match self.state() {
            CircuitState::Closed => true,
            CircuitState::Open => {
                // 检查是否可以转为半开
                if self.should_try_reset() {
                    self.set_state(CircuitState::HalfOpen);
                    true
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => true,
        }
    }
    
    pub fn record_success(&self) {
        match self.state() {
            CircuitState::HalfOpen => {
                let count = self.success_count.fetch_add(1, Ordering::SeqCst) + 1;
                if count >= self.success_threshold {
                    self.reset();
                }
            }
            _ => {}
        }
    }
    
    pub fn record_failure(&self) {
        let count = self.failure_count.fetch_add(1, Ordering::SeqCst) + 1;
        
        if count >= self.failure_threshold {
            self.trip();
        }
    }
}
```

---

## 4. Feature Flags

| Feature | 功能 |
|---------|------|
| `transport_tls` | TLS 传输 |
| `transport_reality` | REALITY 传输 |
| `transport_ech` | ECH 传输 |
| `transport_mux` | 多路复用 |
| `transport_ws` | WebSocket |
| `transport_grpc` | gRPC |
| `transport_grpc_lite` | 轻量 gRPC |
| `transport_h2` | HTTP/2 |
| `transport_httpupgrade` | HTTP Upgrade |
| `transport_quic` | QUIC |
| `circuit_breaker` | 熔断器 |
| `metrics` | 指标 |
