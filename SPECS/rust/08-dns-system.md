# DNS 系统详解

## 1. 概述

DNS 系统是 singbox-rust 的核心组件，负责：
- 多上游 DNS 查询
- DNS 规则匹配
- 缓存管理
- FakeIP
- Hosts 文件

---

## 2. 文件结构

```
sb-core/src/dns/
├── mod.rs              # 主模块 (57KB)
├── upstream.rs         # 上游解析 (90KB!)
├── rule_engine.rs      # DNS 规则 (37KB)
├── config_builder.rs   # 配置构建 (33KB)
├── resolve.rs          # 解析逻辑 (25KB)
├── resolver.rs         # 解析器 (18KB)
├── strategy.rs         # 策略 (20KB)
├── cache.rs            # 缓存 (17KB)
├── cache_v2.rs         # 缓存 V2 (4KB)
├── fakeip.rs           # FakeIP (13KB)
├── hosts.rs            # Hosts (12KB)
├── client.rs           # DNS 客户端 (20KB)
├── enhanced_client.rs  # 增强客户端 (15KB)
├── dns_router.rs       # DNS 路由 (6KB)
├── router.rs           # 路由器 (4KB)
├── rule_action.rs      # 规则动作 (8KB)
├── message.rs          # DNS 消息 (7KB)
├── handle.rs           # 句柄
├── global.rs           # 全局
├── stub.rs             # 存根 (3KB)
├── system.rs           # 系统 (1KB)
├── metrics.rs          # 指标 (2KB)
├── udp.rs              # UDP (6KB)
├── doh.rs              # DoH (1KB)
├── doq.rs              # DoQ (1KB)
├── dot.rs              # DoT (4KB)
├── http_client.rs      # HTTP 客户端
├── integration_tests.rs # 集成测试 (6KB)
└── transport/          # DNS 传输
    ├── mod.rs
    ├── udp.rs
    ├── tcp.rs
    ├── tls.rs
    ├── https.rs
    ├── quic.rs
    ├── dhcp.rs
    ├── hosts.rs
    ├── fakeip.rs
    ├── local.rs
    └── resolved.rs
```

---

## 3. 核心结构

### 3.1 DNS 解析器

```rust
// sb-core/src/dns/mod.rs

pub struct DnsResolver {
    /// 上游服务器
    upstreams: HashMap<String, Arc<DnsUpstream>>,
    
    /// DNS 规则
    rules: Vec<DnsRule>,
    
    /// 缓存
    cache: DnsCache,
    
    /// FakeIP 池
    fakeip: Option<FakeIpPool>,
    
    /// Hosts 文件
    hosts: HostsFile,
    
    /// 默认服务器
    default_server: String,
    
    /// 默认策略
    default_strategy: DnsStrategy,
    
    /// 反向映射
    reverse_mapping: bool,
    
    /// 客户端子网
    client_subnet: Option<IpAddr>,
}

impl DnsResolver {
    pub async fn lookup(&self, domain: &str, strategy: Option<DnsStrategy>) -> Result<Vec<IpAddr>> {
        // 1. 检查 hosts
        if let Some(ips) = self.hosts.lookup(domain) {
            return Ok(ips);
        }
        
        // 2. 检查缓存
        let strategy = strategy.unwrap_or(self.default_strategy);
        let cache_key = CacheKey::new(domain, strategy);
        
        if let Some(cached) = self.cache.get(&cache_key) {
            return Ok(cached);
        }
        
        // 3. DNS 规则匹配
        let server = self.match_dns_rules(domain)?;
        
        // 4. 执行查询
        let result = self.query_upstream(&server, domain, strategy).await?;
        
        // 5. 存入缓存
        self.cache.insert(cache_key, &result);
        
        // 6. 更新反向映射
        if self.reverse_mapping {
            for ip in &result {
                self.reverse_cache.insert(*ip, domain.to_string());
            }
        }
        
        Ok(result)
    }
    
    pub async fn lookup_reverse(&self, ip: IpAddr) -> Option<String> {
        // FakeIP 反向查找
        if let Some(fakeip) = &self.fakeip {
            if let Some(domain) = fakeip.lookup_reverse(ip) {
                return Some(domain);
            }
        }
        
        // 普通反向查找
        self.reverse_cache.get(&ip).cloned()
    }
}
```

### 3.2 DNS 上游

```rust
// sb-core/src/dns/upstream.rs (90KB)

pub struct DnsUpstream {
    /// 标签
    tag: String,
    
    /// 地址
    address: String,
    
    /// 传输类型
    transport: DnsTransport,
    
    /// 地址解析器
    address_resolver: Option<String>,
    
    /// 出站
    detour: Option<String>,
    
    /// 客户端子网
    client_subnet: Option<IpAddr>,
    
    /// 超时
    timeout: Duration,
}

pub enum DnsTransport {
    Udp(UdpTransport),
    Tcp(TcpTransport),
    Tls(TlsTransport),
    Https(HttpsTransport),
    Quic(QuicTransport),
    Dhcp(DhcpTransport),
    Local(LocalTransport),
    FakeIp(FakeIpTransport),
}

impl DnsUpstream {
    pub async fn exchange(&self, message: &Message) -> Result<Message> {
        match &self.transport {
            DnsTransport::Udp(t) => t.exchange(message).await,
            DnsTransport::Tcp(t) => t.exchange(message).await,
            DnsTransport::Tls(t) => t.exchange(message).await,
            DnsTransport::Https(t) => t.exchange(message).await,
            DnsTransport::Quic(t) => t.exchange(message).await,
            DnsTransport::Dhcp(t) => t.exchange(message).await,
            DnsTransport::Local(t) => t.exchange(message).await,
            DnsTransport::FakeIp(t) => t.exchange(message).await,
        }
    }
}
```

---

## 4. DNS 传输

### 4.1 UDP 传输

```rust
// sb-core/src/dns/transport/udp.rs

pub struct UdpTransport {
    server: SocketAddr,
    dialer: Arc<Dialer>,
    timeout: Duration,
}

impl UdpTransport {
    pub async fn exchange(&self, message: &Message) -> Result<Message> {
        let socket = self.dialer.dial_udp(&self.server).await?;
        
        // 发送请求
        let request = message.to_bytes()?;
        socket.send(&request).await?;
        
        // 接收响应
        let mut buf = vec![0u8; 4096];
        let (n, _) = tokio::time::timeout(
            self.timeout,
            socket.recv_from(&mut buf),
        ).await??;
        
        Message::from_bytes(&buf[..n])
    }
}
```

### 4.2 DoT 传输

```rust
// sb-core/src/dns/transport/tls.rs

pub struct TlsTransport {
    server: String,
    port: u16,
    server_name: String,
    dialer: Arc<TransportDialer>,
    timeout: Duration,
}

impl TlsTransport {
    pub async fn exchange(&self, message: &Message) -> Result<Message> {
        // 建立 TLS 连接
        let stream = self.dialer.dial(&Target::Domain(
            self.server.clone(),
            self.port,
        )).await?;
        
        // DNS over TCP 格式（2 字节长度前缀）
        let request = message.to_bytes()?;
        let length = (request.len() as u16).to_be_bytes();
        
        stream.write_all(&length).await?;
        stream.write_all(&request).await?;
        
        // 读取响应
        let mut length_buf = [0u8; 2];
        stream.read_exact(&mut length_buf).await?;
        let length = u16::from_be_bytes(length_buf) as usize;
        
        let mut response = vec![0u8; length];
        stream.read_exact(&mut response).await?;
        
        Message::from_bytes(&response)
    }
}
```

### 4.3 DoH 传输

```rust
// sb-core/src/dns/transport/https.rs

pub struct HttpsTransport {
    url: String,
    method: DoHMethod,
    headers: HashMap<String, String>,
    http_client: HttpClient,
    timeout: Duration,
}

pub enum DoHMethod {
    Get,   // RFC 8484 GET
    Post,  // RFC 8484 POST
}

impl HttpsTransport {
    pub async fn exchange(&self, message: &Message) -> Result<Message> {
        let request = message.to_bytes()?;
        
        let response = match self.method {
            DoHMethod::Get => {
                let encoded = base64_url::encode(&request);
                let url = format!("{}?dns={}", self.url, encoded);
                self.http_client.get(&url)
                    .header("Accept", "application/dns-message")
                    .send().await?
            }
            DoHMethod::Post => {
                self.http_client.post(&self.url)
                    .header("Content-Type", "application/dns-message")
                    .header("Accept", "application/dns-message")
                    .body(request)
                    .send().await?
            }
        };
        
        let body = response.bytes().await?;
        Message::from_bytes(&body)
    }
}
```

---

## 5. DNS 规则

```rust
// sb-core/src/dns/rule_engine.rs (37KB)

pub struct DnsRule {
    pub conditions: Vec<DnsRuleCondition>,
    pub action: DnsRuleAction,
    pub invert: bool,
}

pub enum DnsRuleCondition {
    // 出站条件
    Outbound(Vec<String>),
    
    // 域名条件
    Domain(Vec<String>),
    DomainSuffix(Vec<String>),
    DomainKeyword(Vec<String>),
    DomainRegex(Vec<Regex>),
    
    // Geo 条件
    GeoSite(Vec<String>),
    
    // 规则集
    RuleSet(Vec<String>),
    
    // 查询类型
    QueryType(Vec<RecordType>),
    
    // 网络
    Network(Vec<Network>),
    
    // 客户端子网
    ClientSubnet(Vec<IpNet>),
    
    // 逻辑条件
    And(Vec<DnsRuleCondition>),
    Or(Vec<DnsRuleCondition>),
}

pub enum DnsRuleAction {
    /// 使用指定服务器
    Route(String),
    
    /// 路由选项
    RouteOptions {
        server: String,
        disable_cache: bool,
        rewrite_ttl: Option<u32>,
        client_subnet: Option<IpAddr>,
    },
    
    /// 拒绝
    Reject(DnsRejectMethod),
}

pub enum DnsRejectMethod {
    Success,    // 空响应
    Refused,    // REFUSED
    NxDomain,   // NXDOMAIN
    Dropped,    // 丢弃
}
```

---

## 6. DNS 缓存

```rust
// sb-core/src/dns/cache.rs (17KB)

pub struct DnsCache {
    /// 缓存存储
    cache: RwLock<LruCache<CacheKey, CacheEntry>>,
    
    /// 容量
    capacity: usize,
    
    /// 禁用过期
    disable_expire: bool,
    
    /// 独立缓存
    independent: bool,
    
    /// 统计
    stats: CacheStats,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct CacheKey {
    domain: String,
    record_type: RecordType,
    strategy: DnsStrategy,
}

#[derive(Debug, Clone)]
pub struct CacheEntry {
    addresses: Vec<IpAddr>,
    ttl: u32,
    created_at: Instant,
}

impl DnsCache {
    pub fn get(&self, key: &CacheKey) -> Option<Vec<IpAddr>> {
        let cache = self.cache.read();
        
        if let Some(entry) = cache.get(key) {
            // 检查过期
            if !self.disable_expire {
                let elapsed = entry.created_at.elapsed().as_secs() as u32;
                if elapsed >= entry.ttl {
                    drop(cache);
                    self.cache.write().pop(key);
                    self.stats.misses.fetch_add(1, Ordering::Relaxed);
                    return None;
                }
            }
            
            self.stats.hits.fetch_add(1, Ordering::Relaxed);
            return Some(entry.addresses.clone());
        }
        
        self.stats.misses.fetch_add(1, Ordering::Relaxed);
        None
    }
    
    pub fn clear(&self) {
        self.cache.write().clear();
    }
}
```

---

## 7. FakeIP

```rust
// sb-core/src/dns/fakeip.rs (13KB)

pub struct FakeIpPool {
    /// IPv4 范围
    inet4_range: Ipv4Net,
    /// IPv6 范围
    inet6_range: Option<Ipv6Net>,
    
    /// 域名 -> FakeIP 映射
    forward: RwLock<HashMap<String, IpAddr>>,
    /// FakeIP -> 域名 映射
    reverse: RwLock<HashMap<IpAddr, String>>,
    
    /// 下一个可用 IPv4
    next_ipv4: AtomicU32,
    /// 下一个可用 IPv6
    next_ipv6: AtomicU128,
    
    /// 持久化存储
    store: Option<FakeIpStore>,
}

impl FakeIpPool {
    pub fn allocate(&self, domain: &str, ipv6: bool) -> IpAddr {
        // 检查已分配
        if let Some(ip) = self.forward.read().get(domain) {
            return *ip;
        }
        
        // 分配新 IP
        let ip = if ipv6 && self.inet6_range.is_some() {
            self.allocate_ipv6()
        } else {
            self.allocate_ipv4()
        };
        
        // 记录映射
        self.forward.write().insert(domain.to_string(), ip);
        self.reverse.write().insert(ip, domain.to_string());
        
        // 持久化
        if let Some(store) = &self.store {
            store.save(domain, ip);
        }
        
        ip
    }
    
    fn allocate_ipv4(&self) -> IpAddr {
        let offset = self.next_ipv4.fetch_add(1, Ordering::Relaxed);
        let base = u32::from(self.inet4_range.addr());
        let ip = Ipv4Addr::from(base + offset);
        IpAddr::V4(ip)
    }
    
    pub fn lookup_reverse(&self, ip: IpAddr) -> Option<String> {
        self.reverse.read().get(&ip).cloned()
    }
    
    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.inet4_range.contains(&v4),
            IpAddr::V6(v6) => {
                self.inet6_range.as_ref()
                    .map(|r| r.contains(&v6))
                    .unwrap_or(false)
            }
        }
    }
}
```

---

## 8. Hosts 文件

```rust
// sb-core/src/dns/hosts.rs (12KB)

pub struct HostsFile {
    /// 域名 -> IP 映射
    entries: HashMap<String, Vec<IpAddr>>,
    
    /// 通配符条目
    wildcards: Vec<(String, Vec<IpAddr>)>,
    
    /// 正则条目
    regex_entries: Vec<(Regex, Vec<IpAddr>)>,
}

impl HostsFile {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Self::parse(&content)
    }
    
    pub fn parse(content: &str) -> Result<Self> {
        let mut entries = HashMap::new();
        let mut wildcards = Vec::new();
        let mut regex_entries = Vec::new();
        
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }
            
            let ip: IpAddr = parts[0].parse()?;
            
            for domain in &parts[1..] {
                if domain.starts_with("*.") {
                    wildcards.push((domain[2..].to_string(), vec![ip]));
                } else if domain.starts_with("regexp:") {
                    let re = Regex::new(&domain[7..])?;
                    regex_entries.push((re, vec![ip]));
                } else {
                    entries.entry(domain.to_string())
                        .or_insert_with(Vec::new)
                        .push(ip);
                }
            }
        }
        
        Ok(Self { entries, wildcards, regex_entries })
    }
    
    pub fn lookup(&self, domain: &str) -> Option<Vec<IpAddr>> {
        // 精确匹配
        if let Some(ips) = self.entries.get(domain) {
            return Some(ips.clone());
        }
        
        // 通配符匹配
        for (pattern, ips) in &self.wildcards {
            if domain.ends_with(pattern) {
                return Some(ips.clone());
            }
        }
        
        // 正则匹配
        for (re, ips) in &self.regex_entries {
            if re.is_match(domain) {
                return Some(ips.clone());
            }
        }
        
        None
    }
}
```

---

## 9. DNS 策略

```rust
// sb-core/src/dns/strategy.rs (20KB)

#[derive(Debug, Clone, Copy, Default)]
pub enum DnsStrategy {
    /// 原样（不修改）
    #[default]
    AsIs,
    /// 优先 IPv4
    PreferIpv4,
    /// 优先 IPv6
    PreferIpv6,
    /// 仅 IPv4
    Ipv4Only,
    /// 仅 IPv6
    Ipv6Only,
}

impl DnsStrategy {
    pub fn filter(&self, addresses: Vec<IpAddr>) -> Vec<IpAddr> {
        match self {
            Self::AsIs => addresses,
            Self::PreferIpv4 => {
                let (v4, v6): (Vec<_>, Vec<_>) = addresses.into_iter()
                    .partition(|ip| ip.is_ipv4());
                if !v4.is_empty() { v4 } else { v6 }
            }
            Self::PreferIpv6 => {
                let (v6, v4): (Vec<_>, Vec<_>) = addresses.into_iter()
                    .partition(|ip| ip.is_ipv6());
                if !v6.is_empty() { v6 } else { v4 }
            }
            Self::Ipv4Only => {
                addresses.into_iter().filter(|ip| ip.is_ipv4()).collect()
            }
            Self::Ipv6Only => {
                addresses.into_iter().filter(|ip| ip.is_ipv6()).collect()
            }
        }
    }
    
    pub fn query_types(&self) -> Vec<RecordType> {
        match self {
            Self::AsIs | Self::PreferIpv4 | Self::PreferIpv6 => {
                vec![RecordType::A, RecordType::AAAA]
            }
            Self::Ipv4Only => vec![RecordType::A],
            Self::Ipv6Only => vec![RecordType::AAAA],
        }
    }
}
```
