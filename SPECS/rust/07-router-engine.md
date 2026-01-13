# 路由引擎详解

## 1. 概述

路由引擎是 singbox-rust 的核心决策组件，负责：
- 规则匹配
- 协议嗅探
- DNS 集成
- 出站选择
- 热重载

---

## 2. 文件结构

```
sb-core/src/router/
├── mod.rs              # 主模块 (115KB) - Router 结构体, 启动逻辑
├── engine.rs           # 路由引擎 (65KB) - 规则匹配核心
├── rules.rs            # 规则系统 (76KB) - 规则定义和解析
├── conn.rs             # 连接路由 (41KB) - TCP/UDP 路由
├── sniff.rs            # 协议嗅探 (22KB) - HTTP/TLS/QUIC 等
├── geo.rs              # Geo 数据 (17KB) - GeoIP/GeoSite
├── hot_reload.rs       # 热重载 (18KB) - 配置热更新
├── analyze.rs          # 规则分析 (15KB) - 分析工具
├── explain.rs          # 路由解释 (7KB) - 调试工具
├── preview.rs          # 预览路由 (7KB) - 测试工具
├── rule_set.rs         # 规则集 (8KB) - 规则集加载
├── dns_bridge.rs       # DNS 桥接 (7KB) - DNS 集成
├── process_router.rs   # 进程路由 (15KB) - 进程匹配
├── matcher.rs          # 匹配器 (8KB)
├── matchers.rs         # 匹配器集合 (2KB)
├── keyword.rs          # 关键词匹配 (2KB)
├── suffix_trie.rs      # 后缀 Trie (2KB)
├── normalize.rs        # 规范化 (5KB)
├── coverage.rs         # 覆盖率 (1KB)
├── context_pop.rs      # 上下文 (6KB)
├── decision_intern.rs  # 决策缓存 (2KB)
├── rule_id.rs          # 规则 ID
├── minijson.rs         # Mini JSON (3KB)
├── json_bridge.rs      # JSON 桥接 (9KB)
├── builder.rs          # 构建器 (5KB)
├── runtime.rs          # 运行时 (2KB)
├── patch_plan.rs       # 补丁计划 (4KB)
├── patch_apply.rs      # 补丁应用 (2KB)
├── dsl_plus.rs         # DSL 增强 (6KB)
├── dsl_derive.rs       # DSL 派生 (5KB)
├── dsl_inspect.rs      # DSL 检查 (9KB)
├── explain_bridge.rs   # 解释桥接 (5KB)
├── explain_index.rs    # 解释索引 (11KB)
├── explain_util.rs     # 解释工具 (6KB)
├── hot_reload_cli.rs   # 热重载 CLI (9KB)
├── cache_hot.rs        # 热缓存 (3KB)
├── cache_stats.rs      # 缓存统计 (1KB)
├── cache_wire.rs       # 缓存序列化 (4KB)
├── rules_capture.rs    # 规则捕获
├── route_connection.rs # 连接路由 (6KB)
├── advanced.rs         # 高级功能 (12KB)
├── analyze_fix.rs      # 分析修复 (11KB)
└── ruleset/            # 规则集模块
    ├── mod.rs
    └── ...
```

---

## 3. 核心结构

### 3.1 Router 结构体

```rust
// sb-core/src/router/mod.rs

pub struct Router {
    /// 路由规则（支持热重载）
    rules: Arc<ArcSwap<CompiledRules>>,
    
    /// DNS 解析器
    dns: Arc<DnsResolver>,
    
    /// 出站管理器
    outbound_manager: Arc<OutboundManager>,
    
    /// GeoIP 数据库
    geoip: Arc<GeoIpReader>,
    
    /// GeoSite 数据库
    geosite: Arc<GeositeReader>,
    
    /// 规则集
    rule_sets: Arc<RwLock<HashMap<String, RuleSet>>>,
    
    /// 嗅探器配置
    sniff_config: SniffConfig,
    
    /// 进程匹配器
    process_matcher: Option<ProcessMatcher>,
    
    /// 默认出站
    default_outbound: String,
    
    /// 统计信息
    stats: RouterStats,
    
    /// 热重载句柄
    reload_handle: Option<ReloadHandle>,
}
```

### 3.2 CompiledRules

```rust
// 编译后的规则（优化匹配性能）
pub struct CompiledRules {
    /// 规则列表
    rules: Vec<CompiledRule>,
    
    /// 域名匹配索引
    domain_index: DomainIndex,
    
    /// IP CIDR 索引
    ip_index: IpIndex,
    
    /// 端口索引
    port_index: PortIndex,
    
    /// GeoIP 索引
    geoip_index: GeoIndex,
    
    /// GeoSite 索引
    geosite_index: GeoIndex,
}

pub struct CompiledRule {
    /// 规则 ID
    id: RuleId,
    
    /// 匹配器列表
    matchers: Vec<Box<dyn Matcher>>,
    
    /// 动作
    action: RuleAction,
    
    /// 是否取反
    invert: bool,
}
```

---

## 4. 规则匹配

### 4.1 匹配流程

```rust
// sb-core/src/router/engine.rs

impl Router {
    pub fn match_rules(&self, ctx: &ConnectionContext) -> MatchResult {
        let rules = self.rules.load();
        
        // 快速路径：检查索引
        if let Some(result) = self.try_index_match(ctx, &rules) {
            return result;
        }
        
        // 慢速路径：遍历规则
        for rule in &rules.rules {
            if self.match_rule(rule, ctx) {
                return MatchResult {
                    rule_id: Some(rule.id),
                    action: rule.action.clone(),
                };
            }
        }
        
        // 默认动作
        MatchResult {
            rule_id: None,
            action: RuleAction::Route(self.default_outbound.clone()),
        }
    }
    
    fn match_rule(&self, rule: &CompiledRule, ctx: &ConnectionContext) -> bool {
        let matched = rule.matchers.iter().all(|m| m.matches(ctx));
        
        if rule.invert {
            !matched
        } else {
            matched
        }
    }
}
```

### 4.2 匹配器 Trait

```rust
// sb-core/src/router/matcher.rs

pub trait Matcher: Send + Sync {
    fn matches(&self, ctx: &ConnectionContext) -> bool;
    fn matcher_type(&self) -> &'static str;
}

// 域名匹配器
pub struct DomainMatcher {
    exact: HashSet<String>,
    suffix: SuffixTrie,
    keyword: Vec<String>,
    regex: Vec<Regex>,
}

impl Matcher for DomainMatcher {
    fn matches(&self, ctx: &ConnectionContext) -> bool {
        let domain = match &ctx.destination {
            Target::Domain(d, _) => d,
            Target::Fqdn(d, _) => d,
            _ => return false,
        };
        
        // 精确匹配
        if self.exact.contains(domain) {
            return true;
        }
        
        // 后缀匹配
        if self.suffix.matches(domain) {
            return true;
        }
        
        // 关键词匹配
        for kw in &self.keyword {
            if domain.contains(kw) {
                return true;
            }
        }
        
        // 正则匹配
        for re in &self.regex {
            if re.is_match(domain) {
                return true;
            }
        }
        
        false
    }
}

// IP CIDR 匹配器
pub struct IpCidrMatcher {
    cidrs: Vec<IpNet>,
}

// GeoIP 匹配器
pub struct GeoIpMatcher {
    reader: Arc<GeoIpReader>,
    codes: HashSet<String>,
}

// 进程匹配器
pub struct ProcessMatcher {
    names: HashSet<String>,
    paths: Vec<PathBuf>,
    path_regex: Vec<Regex>,
}
```

---

## 5. 协议嗅探

```rust
// sb-core/src/router/sniff.rs (22KB)

pub struct SniffConfig {
    pub enabled: bool,
    pub override_destination: bool,
    pub sniffers: Vec<SnifferType>,
    pub timeout: Duration,
}

pub enum SnifferType {
    Http,
    Tls,
    Quic,
    Dns,
    Stun,
    BitTorrent,
    Dtls,
    Ssh,
    Rdp,
    Ntp,
}

pub async fn sniff_protocol(
    stream: &mut TcpStream,
    config: &SniffConfig,
) -> Result<SniffResult> {
    // 读取初始数据
    let mut buf = [0u8; 4096];
    let n = stream.peek(&mut buf).await?;
    let data = &buf[..n];
    
    // 尝试各个嗅探器
    if config.sniffers.contains(&SnifferType::Http) {
        if let Some(result) = sniff_http(data) {
            return Ok(result);
        }
    }
    
    if config.sniffers.contains(&SnifferType::Tls) {
        if let Some(result) = sniff_tls(data) {
            return Ok(result);
        }
    }
    
    if config.sniffers.contains(&SnifferType::Quic) {
        if let Some(result) = sniff_quic(data) {
            return Ok(result);
        }
    }
    
    // ... 更多嗅探器
    
    Ok(SniffResult::Unknown)
}

fn sniff_tls(data: &[u8]) -> Option<SniffResult> {
    // TLS 记录层
    if data.len() < 5 {
        return None;
    }
    
    // 检查 ContentType = Handshake
    if data[0] != 0x16 {
        return None;
    }
    
    // 检查版本
    let version = u16::from_be_bytes([data[1], data[2]]);
    if version < 0x0301 || version > 0x0303 {
        return None;
    }
    
    // 解析 ClientHello
    if let Some(sni) = parse_client_hello(&data[5..]) {
        return Some(SniffResult::Tls {
            sni,
            alpn: parse_alpn(&data[5..]),
        });
    }
    
    None
}
```

---

## 6. 热重载

```rust
// sb-core/src/router/hot_reload.rs (18KB)

pub struct HotReloadConfig {
    pub watch_paths: Vec<PathBuf>,
    pub debounce: Duration,
}

impl Router {
    pub async fn enable_hot_reload(&self, config: HotReloadConfig) -> Result<()> {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        
        // 启动文件监视
        let watcher = FileWatcher::new(config.watch_paths, tx)?;
        
        // 启动重载任务
        let rules = self.rules.clone();
        
        tokio::spawn(async move {
            let mut rx = rx;
            let mut last_reload = Instant::now();
            
            while let Some(event) = rx.recv().await {
                // 防抖
                if last_reload.elapsed() < config.debounce {
                    continue;
                }
                
                // 重新加载配置
                match reload_rules(&event.path).await {
                    Ok(new_rules) => {
                        rules.store(Arc::new(new_rules));
                        tracing::info!("Hot reload successful");
                    }
                    Err(e) => {
                        tracing::error!("Hot reload failed: {}", e);
                    }
                }
                
                last_reload = Instant::now();
            }
        });
        
        Ok(())
    }
}
```

---

## 7. Geo 数据

```rust
// sb-core/src/router/geo.rs (17KB)

pub struct GeoIpReader {
    reader: maxminddb::Reader<Vec<u8>>,
}

impl GeoIpReader {
    pub fn lookup(&self, ip: IpAddr) -> Option<String> {
        let record: GeoRecord = self.reader.lookup(ip).ok()?;
        Some(record.country.iso_code.to_string())
    }
}

pub struct GeositeReader {
    domains: HashMap<String, DomainMatcher>,
}

impl GeositeReader {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let data = std::fs::read(path)?;
        let domains = parse_geosite_data(&data)?;
        Ok(Self { domains })
    }
    
    pub fn matches(&self, category: &str, domain: &str) -> bool {
        if let Some(matcher) = self.domains.get(category) {
            matcher.matches(domain)
        } else {
            false
        }
    }
}
```

---

## 8. 连接上下文

```rust
// sb-core/src/context.rs (31KB)

#[derive(Debug, Clone)]
pub struct ConnectionContext {
    /// 源地址
    pub source: SocketAddr,
    
    /// 目标地址
    pub destination: Target,
    
    /// 入站标签
    pub inbound: String,
    
    /// 入站类型
    pub inbound_type: String,
    
    /// 网络类型
    pub network: Network,
    
    /// IP 版本
    pub ip_version: IpVersion,
    
    /// 用户
    pub user: Option<String>,
    
    /// 嗅探结果
    pub sniff_result: Option<SniffResult>,
    
    /// 协议
    pub protocol: Option<String>,
    
    /// 域名（嗅探到的）
    pub sniffed_domain: Option<String>,
    
    /// 进程信息
    pub process_info: Option<ProcessInfo>,
    
    /// 解析后的 IP
    pub resolved_ips: Option<Vec<IpAddr>>,
    
    /// GeoIP 代码
    pub geoip_code: Option<String>,
    
    /// FakeIP 标记
    pub is_fakeip: bool,
    
    /// 原始目标（FakeIP 前）
    pub original_destination: Option<Target>,
}

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub name: String,
    pub path: PathBuf,
    pub pid: u32,
    pub uid: Option<u32>,
}
```

---

## 9. 规则动作

```rust
// sb-core/src/router/rules.rs

#[derive(Debug, Clone)]
pub enum RuleAction {
    /// 路由到指定出站
    Route(String),
    
    /// 带选项的路由
    RouteOptions {
        outbound: String,
        override_destination: bool,
        network_strategy: Option<NetworkStrategy>,
    },
    
    /// 拒绝连接
    Reject,
    
    /// Reject with method
    RejectMethod(RejectMethod),
    
    /// 劫持 DNS
    HijackDns,
    
    /// 嗅探
    Sniff(SniffAction),
    
    /// DNS 解析
    Resolve(ResolveAction),
}

#[derive(Debug, Clone)]
pub enum RejectMethod {
    Default,
    Drop,
    Reset,
}

#[derive(Debug, Clone)]
pub struct SniffAction {
    pub sniffers: Vec<SnifferType>,
    pub override_destination: bool,
    pub timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct ResolveAction {
    pub strategy: DnsStrategy,
    pub server: Option<String>,
}
```
