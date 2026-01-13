# 辅助 Crates

## 1. 概述

singbox-rust 包含多个辅助 crate，提供专门功能：

| Crate | 功能 |
|-------|------|
| `sb-tls` | TLS 实现（REALITY, ECH） |
| `sb-metrics` | Prometheus 指标 |
| `sb-api` | Clash/V2Ray REST API |
| `sb-subscribe` | 订阅解析 |
| `sb-runtime` | 运行时辅助 |
| `sb-platform` | 平台适配 |
| `sb-proto` | 协议定义 |
| `sb-types` | 共享类型 |
| `sb-common` | 通用工具 |
| `sb-security` | 安全工具 |
| `sb-test-utils` | 测试工具 |
| `sb-admin-contract` | 管理接口契约 |

---

## 2. sb-tls - TLS 实现

```
sb-tls/
├── src/
│   ├── lib.rs
│   ├── reality/        # REALITY 协议
│   │   ├── client.rs
│   │   ├── server.rs
│   │   └── crypto.rs
│   ├── ech/            # ECH 支持
│   │   ├── client.rs
│   │   └── config.rs
│   ├── utls/           # uTLS 指纹
│   │   └── fingerprints.rs
│   └── cert/           # 证书管理
│       └── store.rs
```

### 2.1 REALITY 客户端

```rust
// sb-tls/src/reality/client.rs

pub struct RealityClient {
    pub server_name: String,
    pub public_key: [u8; 32],
    pub short_id: [u8; 8],
    pub fingerprint: TlsFingerprint,
}

impl RealityClient {
    pub async fn handshake(&self, stream: TcpStream) -> Result<RealityStream> {
        // 1. 生成 x25519 密钥对
        let private = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let public = x25519_dalek::PublicKey::from(&private);
        
        // 2. 构造带 REALITY 扩展的 TLS ClientHello
        let client_hello = build_reality_client_hello(
            &self.server_name,
            &self.fingerprint,
            public.as_bytes(),
            &self.short_id,
        )?;
        
        // 3. 发送 ClientHello
        stream.write_all(&client_hello).await?;
        
        // 4. 读取 ServerHello
        let server_hello = read_tls_record(&mut stream).await?;
        
        // 5. 提取服务器公钥并派生共享密钥
        let server_public = extract_reality_public_key(&server_hello)?;
        let shared_secret = private.diffie_hellman(&server_public);
        
        // 6. 派生流量密钥
        let (read_key, write_key) = derive_traffic_keys(
            shared_secret.as_bytes(),
            &client_hello,
            &server_hello,
        )?;
        
        Ok(RealityStream::new(stream, read_key, write_key))
    }
}
```

### 2.2 ECH 支持

```rust
// sb-tls/src/ech/client.rs

pub struct EchConfig {
    pub config: Vec<u8>,       // ECHConfigList
    pub outer_sni: String,     // 外层 SNI
}

pub async fn connect_with_ech(
    stream: TcpStream,
    inner_sni: &str,
    ech_config: &EchConfig,
    tls_config: &TlsConfig,
) -> Result<TlsStream> {
    // 使用 ECH 加密内层 ClientHello
    // 外层 SNI 显示为 ech_config.outer_sni
    // 内层 SNI（加密）为 inner_sni
}
```

---

## 3. sb-metrics - 指标系统

```
sb-metrics/
├── src/
│   ├── lib.rs
│   ├── prometheus.rs   # Prometheus 导出
│   ├── registry.rs     # 指标注册
│   └── counters.rs     # 计数器定义
```

### 3.1 指标定义

```rust
// sb-metrics/src/lib.rs

use prometheus::{Counter, CounterVec, Gauge, GaugeVec, Histogram};

lazy_static! {
    // 连接指标
    pub static ref CONNECTIONS_TOTAL: CounterVec = register_counter_vec!(
        "singbox_connections_total",
        "Total number of connections",
        &["inbound", "outbound", "network"]
    ).unwrap();
    
    pub static ref CONNECTIONS_ACTIVE: GaugeVec = register_gauge_vec!(
        "singbox_connections_active",
        "Number of active connections",
        &["inbound", "outbound"]
    ).unwrap();
    
    // 流量指标
    pub static ref BYTES_SENT_TOTAL: CounterVec = register_counter_vec!(
        "singbox_bytes_sent_total",
        "Total bytes sent",
        &["inbound", "outbound"]
    ).unwrap();
    
    pub static ref BYTES_RECEIVED_TOTAL: CounterVec = register_counter_vec!(
        "singbox_bytes_received_total",
        "Total bytes received",
        &["inbound", "outbound"]
    ).unwrap();
    
    // DNS 指标
    pub static ref DNS_QUERIES_TOTAL: CounterVec = register_counter_vec!(
        "singbox_dns_queries_total",
        "Total DNS queries",
        &["server", "type", "status"]
    ).unwrap();
    
    pub static ref DNS_CACHE_HITS: Counter = register_counter!(
        "singbox_dns_cache_hits_total",
        "DNS cache hits"
    ).unwrap();
    
    // 路由指标
    pub static ref ROUTE_MATCHES_TOTAL: CounterVec = register_counter_vec!(
        "singbox_route_matches_total",
        "Total route rule matches",
        &["rule_id", "outbound"]
    ).unwrap();
    
    // 延迟指标
    pub static ref OUTBOUND_LATENCY: HistogramVec = register_histogram_vec!(
        "singbox_outbound_latency_seconds",
        "Outbound connection latency",
        &["outbound"]
    ).unwrap();
}
```

### 3.2 HTTP 导出器

```rust
// sb-metrics/src/prometheus.rs

pub async fn start_metrics_server(addr: SocketAddr) -> Result<()> {
    let app = Router::new()
        .route("/metrics", get(metrics_handler));
    
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;
    
    Ok(())
}

async fn metrics_handler() -> impl IntoResponse {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    
    (
        [(header::CONTENT_TYPE, encoder.format_type())],
        buffer,
    )
}
```

---

## 4. sb-api - REST API

```
sb-api/
├── src/
│   ├── lib.rs
│   ├── clash/          # Clash API
│   │   ├── mod.rs
│   │   ├── proxies.rs
│   │   ├── rules.rs
│   │   ├── connections.rs
│   │   ├── logs.rs
│   │   └── traffic.rs
│   └── v2ray/          # V2Ray API
│       ├── mod.rs
│       └── stats.rs
```

### 4.1 Clash API 端点

```rust
// sb-api/src/clash/mod.rs

pub fn clash_routes() -> Router {
    Router::new()
        // 版本
        .route("/", get(version))
        .route("/version", get(version))
        
        // 配置
        .route("/configs", get(get_configs))
        .route("/configs", patch(patch_configs))
        .route("/configs", put(reload_configs))
        
        // 代理
        .route("/proxies", get(list_proxies))
        .route("/proxies/:name", get(get_proxy))
        .route("/proxies/:name", put(switch_proxy))
        .route("/proxies/:name/delay", get(test_delay))
        
        // 提供者
        .route("/providers/proxies", get(list_providers))
        .route("/providers/proxies/:name", get(get_provider))
        .route("/providers/proxies/:name", put(update_provider))
        .route("/providers/proxies/:name/healthcheck", get(healthcheck))
        
        // 规则
        .route("/rules", get(list_rules))
        
        // 连接
        .route("/connections", get(list_connections))
        .route("/connections", delete(close_all_connections))
        .route("/connections/:id", delete(close_connection))
        
        // 日志 (WebSocket)
        .route("/logs", get(logs_websocket))
        
        // 流量 (WebSocket)
        .route("/traffic", get(traffic_websocket))
        
        // DNS
        .route("/dns/query", get(dns_query))
}
```

---

## 5. sb-subscribe - 订阅解析

```
sb-subscribe/
├── src/
│   ├── lib.rs
│   ├── clash/          # Clash 格式
│   │   ├── mod.rs
│   │   └── parser.rs
│   ├── singbox/        # SingBox 格式
│   │   └── parser.rs
│   ├── base64/         # Base64 格式
│   │   └── parser.rs
│   ├── surge/          # Surge 格式
│   │   └── parser.rs
│   └── merge.rs        # 合并逻辑
```

### 5.1 订阅解析

```rust
// sb-subscribe/src/lib.rs

pub async fn fetch_subscription(url: &str) -> Result<Vec<OutboundConfig>> {
    let response = reqwest::get(url).await?;
    let content = response.text().await?;
    
    // 自动检测格式
    if content.trim().starts_with('{') {
        // JSON 格式（SingBox 或 Clash）
        if let Ok(singbox) = parse_singbox(&content) {
            return Ok(singbox);
        }
        if let Ok(clash) = parse_clash_json(&content) {
            return Ok(clash);
        }
    } else if content.contains("proxies:") {
        // YAML Clash 格式
        return parse_clash_yaml(&content);
    } else {
        // Base64 编码
        let decoded = base64::decode(&content.trim())?;
        let decoded_str = String::from_utf8(decoded)?;
        return parse_base64_links(&decoded_str);
    }
    
    Err(anyhow!("Unknown subscription format"))
}
```

### 5.2 Clash 解析

```rust
// sb-subscribe/src/clash/parser.rs

#[derive(Debug, Deserialize)]
pub struct ClashConfig {
    pub proxies: Vec<ClashProxy>,
    #[serde(rename = "proxy-groups")]
    pub proxy_groups: Option<Vec<ClashProxyGroup>>,
}

#[derive(Debug, Deserialize)]
pub struct ClashProxy {
    pub name: String,
    #[serde(rename = "type")]
    pub proxy_type: String,
    pub server: String,
    pub port: u16,
    // 协议特定字段...
}

pub fn parse_clash_yaml(content: &str) -> Result<Vec<OutboundConfig>> {
    let clash: ClashConfig = serde_yaml::from_str(content)?;
    
    clash.proxies.into_iter()
        .map(|proxy| convert_clash_to_outbound(proxy))
        .collect()
}

fn convert_clash_to_outbound(proxy: ClashProxy) -> Result<OutboundConfig> {
    match proxy.proxy_type.as_str() {
        "ss" | "shadowsocks" => convert_ss_proxy(proxy),
        "vmess" => convert_vmess_proxy(proxy),
        "vless" => convert_vless_proxy(proxy),
        "trojan" => convert_trojan_proxy(proxy),
        "hysteria" => convert_hysteria_proxy(proxy),
        "hysteria2" => convert_hysteria2_proxy(proxy),
        other => Err(anyhow!("Unknown proxy type: {}", other)),
    }
}
```

---

## 6. sb-runtime - 运行时

```
sb-runtime/
├── src/
│   ├── lib.rs
│   ├── handshake.rs    # 握手测试
│   ├── scenario.rs     # 场景测试
│   ├── loopback.rs     # 回环测试
│   ├── tcp_local.rs    # 本地 TCP
│   ├── jsonl.rs        # JSONL 日志
│   └── protocols/      # 协议测试
│       └── ...
```

### 6.1 握手测试

```rust
// sb-runtime/src/handshake.rs

pub async fn test_handshake(
    outbound: &dyn OutboundConnector,
    target: &Target,
    timeout: Duration,
) -> Result<HandshakeResult> {
    let start = Instant::now();
    
    let result = tokio::time::timeout(
        timeout,
        outbound.connect(target),
    ).await;
    
    let elapsed = start.elapsed();
    
    match result {
        Ok(Ok(_stream)) => Ok(HandshakeResult {
            success: true,
            latency: elapsed,
            error: None,
        }),
        Ok(Err(e)) => Ok(HandshakeResult {
            success: false,
            latency: elapsed,
            error: Some(e.to_string()),
        }),
        Err(_) => Ok(HandshakeResult {
            success: false,
            latency: elapsed,
            error: Some("Timeout".to_string()),
        }),
    }
}
```

---

## 7. sb-types - 共享类型

```rust
// sb-types/src/lib.rs

/// 问题代码
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IssueCode {
    // 配置问题
    ConfigInvalid,
    ConfigMissing,
    
    // 网络问题  
    ConnectionFailed,
    ConnectionTimeout,
    
    // DNS 问题
    DnsResolutionFailed,
    
    // TLS 问题
    TlsHandshakeFailed,
    TlsCertificateInvalid,
    
    // 协议问题
    ProtocolError,
    AuthenticationFailed,
}

/// 网络类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Tcp,
    Udp,
}

/// IP 版本
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    V4,
    V6,
    Dual,
}
```

---

## 8. sb-admin-contract - 管理接口契约

```rust
// sb-admin-contract/src/lib.rs

/// 认证请求
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthRequest {
    pub token: String,
}

/// 认证响应
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResponse {
    pub valid: bool,
    pub user: Option<String>,
    pub roles: Vec<String>,
}

/// 限流配置
#[derive(Debug, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub requests_per_second: u32,
    pub burst: u32,
}

/// 管理操作
#[derive(Debug, Serialize, Deserialize)]
pub enum AdminAction {
    Reload,
    Shutdown,
    UpdateConfig(serde_json::Value),
    SwitchOutbound { group: String, outbound: String },
}
```

---

## 9. 依赖关系

```
app
├── sb-core (核心)
│   ├── sb-config (配置)
│   └── sb-types (类型)
├── sb-adapters (适配器)
│   ├── sb-transport (传输)
│   └── sb-tls (TLS)
├── sb-metrics (指标)
├── sb-api (API)
├── sb-subscribe (订阅)
└── sb-runtime (运行时)
```
