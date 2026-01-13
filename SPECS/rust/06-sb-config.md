# sb-config crate - 配置系统

## 1. 概述

`sb-config` 提供配置解析、验证和转换：
- JSON/YAML 配置解析
- 配置验证
- IR (中间表示) 转换
- 配置合并
- 订阅解析

---

## 2. 目录结构

```
sb-config/
├── Cargo.toml
├── src/
│   ├── lib.rs              # 主模块 (28KB)
│   ├── model.rs            # 数据模型 (5KB)
│   ├── de.rs               # 反序列化 (4KB)
│   ├── defaults.rs         # 默认值 (1KB)
│   ├── normalize.rs        # 规范化 (4KB)
│   ├── json_norm.rs        # JSON 规范化 (2KB)
│   ├── merge.rs            # 配置合并 (5KB)
│   ├── minimize.rs         # 配置精简 (6KB)
│   ├── present.rs          # 配置展示 (13KB)
│   ├── compat.rs           # 兼容性 (6KB)
│   ├── inbound.rs          # 入站配置 (2KB)
│   ├── outbound.rs         # 出站配置 (15KB)
│   ├── subscribe.rs        # 订阅配置 (16KB)
│   ├── acme_config.rs      # ACME 配置 (3KB)
│   ├── schema_v2.rs        # Schema V2
│   │
│   ├── ir/                 # 中间表示
│   │   ├── mod.rs
│   │   └── ...
│   │
│   ├── rule/               # 规则配置
│   │   ├── mod.rs
│   │   └── ...
│   │
│   └── validator/          # 验证器
│       ├── mod.rs
│       └── ...
```

---

## 3. 配置结构

### 3.1 顶层配置

```rust
// sb-config/src/lib.rs

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// 日志配置
    #[serde(default)]
    pub log: LogConfig,
    
    /// DNS 配置
    #[serde(default)]
    pub dns: DnsConfig,
    
    /// NTP 配置
    #[serde(default)]
    pub ntp: Option<NtpConfig>,
    
    /// 端点配置
    #[serde(default)]
    pub endpoints: Vec<EndpointConfig>,
    
    /// 入站配置
    #[serde(default)]
    pub inbounds: Vec<InboundConfig>,
    
    /// 出站配置
    #[serde(default)]
    pub outbounds: Vec<OutboundConfig>,
    
    /// 路由配置
    #[serde(default)]
    pub route: RouteConfig,
    
    /// 实验性配置
    #[serde(default)]
    pub experimental: Option<ExperimentalConfig>,
}

impl Config {
    /// 从文件加载
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Self::parse(&content)
    }
    
    /// 解析配置字符串
    pub fn parse(content: &str) -> Result<Self> {
        // 尝试 JSON
        if let Ok(config) = serde_json::from_str(content) {
            return Ok(config);
        }
        // 尝试 YAML
        serde_yaml::from_str(content).map_err(Into::into)
    }
    
    /// 转换为 IR
    pub fn ir(&self) -> ConfigIr {
        ConfigIr::from(self)
    }
    
    /// 验证配置
    pub fn validate(&self) -> Result<()> {
        Validator::new().validate(self)
    }
}
```

### 3.2 入站配置

```rust
// sb-config/src/inbound.rs

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundConfig {
    /// 入站标签
    pub tag: String,
    
    /// 入站类型
    #[serde(rename = "type")]
    pub type_name: String,
    
    /// 监听地址
    pub listen: Option<String>,
    
    /// 监听端口
    pub listen_port: Option<u16>,
    
    /// 嗅探配置
    #[serde(default)]
    pub sniff: bool,
    
    /// 嗅探覆盖目标
    #[serde(default)]
    pub sniff_override_destination: bool,
    
    /// 域名策略
    pub domain_strategy: Option<String>,
    
    /// 协议特定配置
    #[serde(flatten)]
    pub settings: serde_json::Value,
}
```

### 3.3 出站配置

```rust
// sb-config/src/outbound.rs (15KB)

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundConfig {
    /// 出站标签
    pub tag: String,
    
    /// 出站类型
    #[serde(rename = "type")]
    pub type_name: String,
    
    /// 服务器地址
    pub server: Option<String>,
    
    /// 服务器端口
    pub server_port: Option<u16>,
    
    /// 传输配置
    pub transport: Option<TransportConfig>,
    
    /// TLS 配置
    pub tls: Option<TlsConfig>,
    
    /// 多路复用配置
    pub multiplex: Option<MuxConfig>,
    
    /// 拨号器配置
    #[serde(default)]
    pub dialer: DialerConfig,
    
    /// 协议特定配置
    #[serde(flatten)]
    pub settings: serde_json::Value,
}

// 协议特定配置示例
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowsocksOutboundConfig {
    pub method: String,
    pub password: String,
    #[serde(default)]
    pub plugin: Option<String>,
    #[serde(default)]
    pub plugin_opts: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VMessOutboundConfig {
    pub uuid: String,
    #[serde(default)]
    pub security: String,
    #[serde(default)]
    pub alter_id: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VLESSOutboundConfig {
    pub uuid: String,
    #[serde(default)]
    pub flow: Option<String>,
}
```

### 3.4 路由配置

```rust
// sb-config/src/rule/mod.rs

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    /// GeoIP 配置
    pub geoip: Option<GeoIpConfig>,
    
    /// GeoSite 配置
    pub geosite: Option<GeositeConfig>,
    
    /// 路由规则
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
    
    /// 规则集
    #[serde(default)]
    pub rule_set: Vec<RuleSetConfig>,
    
    /// 默认出站
    #[serde(rename = "final")]
    pub final_outbound: Option<String>,
    
    /// 进程查找
    #[serde(default)]
    pub find_process: bool,
    
    /// 自动检测接口
    #[serde(default)]
    pub auto_detect_interface: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConfig {
    /// 规则类型
    #[serde(rename = "type", default)]
    pub rule_type: String,
    
    // 匹配条件
    pub inbound: Option<Vec<String>>,
    pub network: Option<Vec<String>>,
    pub protocol: Option<Vec<String>>,
    pub domain: Option<Vec<String>>,
    pub domain_suffix: Option<Vec<String>>,
    pub domain_keyword: Option<Vec<String>>,
    pub domain_regex: Option<Vec<String>>,
    pub geosite: Option<Vec<String>>,
    pub source_geoip: Option<Vec<String>>,
    pub geoip: Option<Vec<String>>,
    pub source_ip_cidr: Option<Vec<String>>,
    pub ip_cidr: Option<Vec<String>>,
    pub source_port: Option<Vec<u16>>,
    pub source_port_range: Option<Vec<String>>,
    pub port: Option<Vec<u16>>,
    pub port_range: Option<Vec<String>>,
    pub process_name: Option<Vec<String>>,
    pub process_path: Option<Vec<String>>,
    pub rule_set: Option<Vec<String>>,
    
    pub invert: Option<bool>,
    
    // 动作
    pub outbound: Option<String>,
    pub action: Option<String>,
}
```

### 3.5 DNS 配置

```rust
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsConfig {
    /// DNS 服务器
    #[serde(default)]
    pub servers: Vec<DnsServerConfig>,
    
    /// DNS 规则
    #[serde(default)]
    pub rules: Vec<DnsRuleConfig>,
    
    /// 默认 DNS
    #[serde(rename = "final")]
    pub final_server: Option<String>,
    
    /// 策略
    pub strategy: Option<String>,
    
    /// 禁用缓存
    #[serde(default)]
    pub disable_cache: bool,
    
    /// 禁用过期
    #[serde(default)]
    pub disable_expire: bool,
    
    /// 独立缓存
    #[serde(default)]
    pub independent_cache: bool,
    
    /// 反向映射
    #[serde(default)]
    pub reverse_mapping: bool,
    
    /// FakeIP 配置
    pub fakeip: Option<FakeIpConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsServerConfig {
    pub tag: String,
    pub address: String,
    pub address_resolver: Option<String>,
    pub address_strategy: Option<String>,
    pub detour: Option<String>,
    pub client_subnet: Option<String>,
}
```

---

## 4. 配置验证

```rust
// sb-config/src/validator/mod.rs

pub struct Validator {
    errors: Vec<ValidationError>,
}

impl Validator {
    pub fn validate(&mut self, config: &Config) -> Result<()> {
        // 验证入站
        for inbound in &config.inbounds {
            self.validate_inbound(inbound)?;
        }
        
        // 验证出站
        for outbound in &config.outbounds {
            self.validate_outbound(outbound)?;
        }
        
        // 验证路由
        self.validate_route(&config.route)?;
        
        // 验证 DNS
        self.validate_dns(&config.dns)?;
        
        // 验证引用完整性
        self.validate_references(config)?;
        
        if self.errors.is_empty() {
            Ok(())
        } else {
            Err(ValidationErrors(self.errors.clone()).into())
        }
    }
    
    fn validate_outbound(&mut self, outbound: &OutboundConfig) -> Result<()> {
        // 验证类型
        if !VALID_OUTBOUND_TYPES.contains(&outbound.type_name.as_str()) {
            self.errors.push(ValidationError::InvalidOutboundType(
                outbound.tag.clone(),
                outbound.type_name.clone(),
            ));
        }
        
        // 验证必填字段
        if needs_server(&outbound.type_name) && outbound.server.is_none() {
            self.errors.push(ValidationError::MissingField(
                format!("outbounds[{}].server", outbound.tag),
            ));
        }
        
        Ok(())
    }
}
```

---

## 5. IR 转换

```rust
// sb-config/src/ir/mod.rs

/// 配置中间表示
pub struct ConfigIr {
    pub log: LogIr,
    pub dns: DnsIr,
    pub inbounds: Vec<InboundIr>,
    pub outbounds: Vec<OutboundIr>,
    pub route: RouteIr,
}

impl From<&Config> for ConfigIr {
    fn from(config: &Config) -> Self {
        ConfigIr {
            log: LogIr::from(&config.log),
            dns: DnsIr::from(&config.dns),
            inbounds: config.inbounds.iter().map(InboundIr::from).collect(),
            outbounds: config.outbounds.iter().map(OutboundIr::from).collect(),
            route: RouteIr::from(&config.route),
        }
    }
}

/// 出站 IR
pub struct OutboundIr {
    pub tag: String,
    pub connector: Box<dyn OutboundConnector>,
}
```

---

## 6. 配置合并

```rust
// sb-config/src/merge.rs (5KB)

pub fn merge_configs(configs: Vec<Config>) -> Result<Config> {
    let mut merged = Config::default();
    
    for config in configs {
        // 合并入站
        merged.inbounds.extend(config.inbounds);
        
        // 合并出站（去重）
        for outbound in config.outbounds {
            if !merged.outbounds.iter().any(|o| o.tag == outbound.tag) {
                merged.outbounds.push(outbound);
            }
        }
        
        // 合并规则
        merged.route.rules.extend(config.route.rules);
        
        // 合并 DNS
        merged.dns.servers.extend(config.dns.servers);
        merged.dns.rules.extend(config.dns.rules);
    }
    
    Ok(merged)
}
```
