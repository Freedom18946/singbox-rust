# sb-core crate - 核心引擎

## 1. 概述

`sb-core` 是 singbox-rust 的核心引擎 crate，包含：
- 路由引擎 (Router)
- DNS 系统
- 入站/出站管理
- 服务管理
- 端点管理
- 监控指标
- 诊断系统

---

## 2. 目录结构

```
sb-core/
├── Cargo.toml              # 8KB，大量 features
├── src/
│   ├── lib.rs              # 模块导出
│   │
│   ├── router/             # 路由引擎 (52 个文件)
│   │   ├── mod.rs          # 主模块 (115KB!)
│   │   ├── engine.rs       # 路由引擎 (65KB)
│   │   ├── rules.rs        # 规则系统 (76KB)
│   │   ├── conn.rs         # 连接路由 (41KB)
│   │   ├── sniff.rs        # 协议嗅探 (22KB)
│   │   ├── geo.rs          # GeoIP/GeoSite (17KB)
│   │   ├── hot_reload.rs   # 热重载 (18KB)
│   │   ├── analyze.rs      # 规则分析
│   │   ├── explain.rs      # 路由解释
│   │   ├── preview.rs      # 预览路由
│   │   ├── rule_set.rs     # 规则集
│   │   └── ...
│   │
│   ├── dns/                # DNS 系统 (40 个文件)
│   │   ├── mod.rs          # 主模块 (57KB)
│   │   ├── upstream.rs     # 上游解析 (90KB!)
│   │   ├── rule_engine.rs  # DNS 规则 (37KB)
│   │   ├── config_builder.rs # 配置构建 (33KB)
│   │   ├── resolve.rs      # 解析逻辑 (25KB)
│   │   ├── resolver.rs     # 解析器 (18KB)
│   │   ├── strategy.rs     # 策略 (20KB)
│   │   ├── cache.rs        # 缓存 (17KB)
│   │   ├── fakeip.rs       # FakeIP (13KB)
│   │   ├── hosts.rs        # Hosts (12KB)
│   │   ├── client.rs       # DNS 客户端 (20KB)
│   │   ├── enhanced_client.rs # 增强客户端 (15KB)
│   │   ├── transport/      # DNS 传输
│   │   │   ├── udp.rs
│   │   │   ├── tcp.rs
│   │   │   ├── dot.rs
│   │   │   ├── doh.rs
│   │   │   └── doq.rs
│   │   └── ...
│   │
│   ├── outbound/           # 出站模块 (54 个文件)
│   │   ├── mod.rs          # 主模块 (49KB)
│   │   ├── manager.rs      # 出站管理 (17KB)
│   │   ├── selector.rs     # 选择器 (14KB)
│   │   ├── selector_group.rs # 选择器组 (21KB)
│   │   ├── direct_connector.rs # Direct (21KB)
│   │   ├── hysteria2.rs    # Hysteria2 (62KB)
│   │   ├── ssh.rs          # SSH (41KB)
│   │   ├── tuic.rs         # TUIC (34KB)
│   │   ├── vmess.rs        # VMess (28KB)
│   │   ├── shadowsocks.rs  # Shadowsocks (28KB)
│   │   ├── wireguard.rs    # WireGuard (18KB)
│   │   ├── vless.rs        # VLESS (17KB)
│   │   ├── trojan.rs       # Trojan (16KB)
│   │   ├── health.rs       # 健康检查 (11KB)
│   │   └── ...
│   │
│   ├── inbound/            # 入站模块 (10 个文件)
│   │   ├── mod.rs          # 入站管理
│   │   └── ...
│   │
│   ├── services/           # 后台服务 (19 个文件)
│   │   ├── mod.rs
│   │   ├── ntp.rs          # NTP 时间同步
│   │   ├── resolved.rs     # systemd-resolved
│   │   ├── derp.rs         # Tailscale DERP
│   │   └── ssmapi.rs       # SSM API
│   │
│   ├── endpoint/           # 端点模块 (3 个文件)
│   │   ├── mod.rs
│   │   ├── wireguard.rs
│   │   └── tailscale.rs
│   │
│   ├── metrics/            # 监控指标 (13 个文件)
│   │   ├── mod.rs
│   │   ├── prometheus.rs
│   │   └── ...
│   │
│   ├── diagnostics/        # 诊断模块 (4 个文件)
│   │   ├── mod.rs
│   │   └── http_server.rs
│   │
│   ├── net/                # 网络工具 (14 个文件)
│   │   ├── mod.rs
│   │   ├── dialer.rs
│   │   ├── listener.rs
│   │   └── ...
│   │
│   ├── tls/                # TLS 工具 (4 个文件)
│   │   ├── mod.rs
│   │   └── ...
│   │
│   ├── transport/          # 传输工具 (4 个文件)
│   │   └── ...
│   │
│   ├── util/               # 工具函数 (5 个文件)
│   │   └── ...
│   │
│   ├── adapter/            # 适配器接口 (5 个文件)
│   │   └── ...
│   │
│   ├── context.rs          # 上下文 (31KB)
│   ├── error.rs            # 错误定义 (13KB)
│   ├── types.rs            # 类型定义 (9KB)
│   ├── service.rs          # 服务定义 (11KB)
│   ├── session.rs          # 会话
│   ├── telemetry.rs        # 遥测 (6KB)
│   └── ...
│
├── tests/                  # 126 个测试
├── examples/               # 16 个示例
└── benches/                # 6 个基准测试
```

---

## 3. 核心模块详解

### 3.1 Router 路由引擎

#### 3.1.1 结构定义

```rust
// sb-core/src/router/mod.rs

pub struct Router {
    /// 路由规则
    rules: Arc<ArcSwap<Vec<Rule>>>,
    
    /// DNS 解析器
    dns: Arc<DnsResolver>,
    
    /// GeoIP 数据库
    geoip: Arc<GeoIpReader>,
    
    /// GeoSite 数据库
    geosite: Arc<GeositeReader>,
    
    /// 规则集
    rule_sets: Arc<RwLock<HashMap<String, RuleSet>>>,
    
    /// 出站管理器
    outbounds: Arc<OutboundManager>,
    
    /// 嗅探器
    sniffers: Vec<Box<dyn Sniffer>>,
    
    /// 统计
    stats: RouterStats,
}
```

#### 3.1.2 路由方法

```rust
impl Router {
    /// 路由 TCP 连接
    pub async fn route_connection(
        &self,
        conn: TcpStream,
        ctx: &mut ConnectionContext,
    ) -> Result<BoxedStream> {
        // 1. 协议嗅探
        if ctx.sniff_enabled {
            self.sniff_connection(&mut conn, ctx).await?;
        }
        
        // 2. DNS 解析（如果需要）
        if let Some(domain) = &ctx.destination.domain() {
            self.resolve_domain(domain, ctx).await?;
        }
        
        // 3. 规则匹配
        let (matched_rule, outbound_tag) = self.match_rules(ctx)?;
        
        // 4. 选择出站
        let outbound = self.outbounds.get(&outbound_tag)?;
        
        // 5. 建立出站连接
        let remote = outbound.connect(&ctx.destination).await?;
        
        Ok(remote)
    }
    
    /// 规则匹配
    fn match_rules(&self, ctx: &ConnectionContext) -> Result<(Option<&Rule>, String)> {
        let rules = self.rules.load();
        
        for rule in rules.iter() {
            if rule.matches(ctx) {
                match &rule.action {
                    RuleAction::Route(tag) => return Ok((Some(rule), tag.clone())),
                    RuleAction::Reject => return Err(Error::Rejected),
                    RuleAction::HijackDns => return self.hijack_dns(ctx),
                }
            }
        }
        
        // 默认出站
        Ok((None, self.default_outbound.clone()))
    }
}
```

#### 3.1.3 规则类型

```rust
// sb-core/src/router/rules.rs (76KB)

pub struct Rule {
    pub conditions: Vec<RuleCondition>,
    pub action: RuleAction,
    pub invert: bool,
}

pub enum RuleCondition {
    // 网络条件
    Network(NetworkType),           // tcp / udp
    IpVersion(IpVersion),           // ipv4 / ipv6
    
    // 源地址条件
    SourceIpCidr(Vec<IpNet>),
    SourcePort(Vec<u16>),
    SourcePortRange(Vec<(u16, u16)>),
    
    // 目标地址条件
    Domain(Vec<String>),            // 精确匹配
    DomainSuffix(Vec<String>),      // 后缀匹配
    DomainKeyword(Vec<String>),     // 关键词匹配
    DomainRegex(Vec<Regex>),        // 正则匹配
    IpCidr(Vec<IpNet>),
    Port(Vec<u16>),
    PortRange(Vec<(u16, u16)>),
    
    // Geo 条件
    GeoIp(Vec<String>),             // CN, US, etc.
    GeoSite(Vec<String>),           // google, facebook, etc.
    
    // 入站条件
    Inbound(Vec<String>),
    
    // 进程条件
    ProcessName(Vec<String>),
    ProcessPath(Vec<String>),
    
    // 规则集引用
    RuleSet(Vec<String>),
    
    // 协议条件
    Protocol(Vec<String>),          // http, tls, quic, etc.
    
    // 用户条件
    User(Vec<String>),
    
    // 逻辑条件
    And(Vec<RuleCondition>),
    Or(Vec<RuleCondition>),
}

pub enum RuleAction {
    Route(String),      // 路由到指定出站
    Reject,             // 拒绝连接
    HijackDns,          // 劫持 DNS
    Sniff,              // 嗅探协议
    Resolve(DnsAction), // DNS 解析
}
```

### 3.2 DNS 系统

#### 3.2.1 DNS 解析器

```rust
// sb-core/src/dns/mod.rs

pub struct DnsResolver {
    /// 上游服务器
    upstreams: Vec<DnsUpstream>,
    
    /// DNS 规则
    rules: Vec<DnsRule>,
    
    /// 缓存
    cache: DnsCache,
    
    /// FakeIP 池
    fakeip: Option<FakeIpPool>,
    
    /// Hosts 文件
    hosts: HostsFile,
    
    /// 默认策略
    default_strategy: DnsStrategy,
}

impl DnsResolver {
    pub async fn lookup(&self, domain: &str) -> Result<Vec<IpAddr>> {
        // 1. 检查 hosts
        if let Some(ips) = self.hosts.lookup(domain) {
            return Ok(ips);
        }
        
        // 2. 检查缓存
        if let Some(cached) = self.cache.get(domain) {
            return Ok(cached);
        }
        
        // 3. DNS 规则匹配
        let upstream = self.match_dns_rules(domain)?;
        
        // 4. 执行查询
        let result = upstream.query(domain).await?;
        
        // 5. 存入缓存
        self.cache.insert(domain, &result);
        
        Ok(result)
    }
}
```

#### 3.2.2 DNS 传输

```rust
// sb-core/src/dns/transport/

pub enum DnsTransport {
    Udp(UdpTransport),      // UDP DNS
    Tcp(TcpTransport),      // TCP DNS
    Tls(TlsTransport),      // DNS over TLS (DoT)
    Https(HttpsTransport),  // DNS over HTTPS (DoH)
    Quic(QuicTransport),    // DNS over QUIC (DoQ)
}
```

#### 3.2.3 FakeIP

```rust
// sb-core/src/dns/fakeip.rs

pub struct FakeIpPool {
    /// IPv4 范围
    inet4_range: Ipv4Net,
    /// IPv6 范围
    inet6_range: Ipv6Net,
    /// 域名 -> FakeIP 映射
    forward: RwLock<HashMap<String, IpAddr>>,
    /// FakeIP -> 域名 映射
    reverse: RwLock<HashMap<IpAddr, String>>,
}

impl FakeIpPool {
    pub fn allocate(&self, domain: &str, ipv6: bool) -> IpAddr {
        // 分配 FakeIP
    }
    
    pub fn lookup_reverse(&self, ip: IpAddr) -> Option<String> {
        // 反向查找域名
    }
}
```

### 3.3 出站管理

```rust
// sb-core/src/outbound/manager.rs

pub struct OutboundManager {
    /// 出站映射
    outbounds: RwLock<HashMap<String, Arc<dyn Outbound>>>,
    
    /// 默认出站
    default: String,
    
    /// 选择器组
    selector_groups: RwLock<HashMap<String, SelectorGroup>>,
    
    /// URL 测试组
    urltest_groups: RwLock<HashMap<String, UrlTestGroup>>,
}

#[async_trait]
pub trait Outbound: Send + Sync {
    fn tag(&self) -> &str;
    fn protocol_type(&self) -> &str;
    fn supports_tcp(&self) -> bool;
    fn supports_udp(&self) -> bool;
    
    async fn connect(&self, target: &Target) -> Result<BoxedStream>;
    async fn connect_udp(&self, target: &Target) -> Result<BoxedDatagram>;
}
```

---

## 4. Feature Flags

| Feature | 功能 |
|---------|------|
| `router` | 路由引擎 |
| `scaffold` | 脚手架（启动基础设施） |
| `out_ss` | Shadowsocks 出站 |
| `out_vless` | VLESS 出站 |
| `out_vmess` | VMess 出站 |
| `out_trojan` | Trojan 出站 |
| `out_hysteria` | Hysteria 出站 |
| `out_hysteria2` | Hysteria2 出站 |
| `out_tuic` | TUIC 出站 |
| `out_ssh` | SSH 出站 |
| `v2ray_transport` | V2Ray 传输 |
| `explain` | 路由解释 |
| `rule_coverage` | 规则覆盖率 |
| `rules_capture` | 规则捕获 |
| `dsl_plus` | DSL 增强 |
| `dsl_analyze` | DSL 分析 |
| `dsl_derive` | DSL 派生 |
| `preview_route` | 预览路由 |
| `http_exporter` | HTTP 导出器 |
| `chaos` | 混沌测试 |
| `dns_dhcp` | DHCP DNS |
| `dns_resolved` | systemd-resolved |
| `dns_tailscale` | Tailscale DNS |
| `service_ntp` | NTP 服务 |
| `service_resolved` | Resolved 服务 |
| `service_ssmapi` | SSM API 服务 |
| `service_derp` | DERP 服务 |
