# Go 设计参考（Go Design Reference）

> **来源**：从 `go_fork_source/sing-box-1.12.14` 和 `GUI_fork_source/GUI.for.SingBox-1.19.0` 提取
> **目的**：为 Rust 实现提供设计层面的参考和兼容性要求

---

## 1. 核心架构（Box 结构）

### 1.1 Box 主结构体

```go
// box.go - 核心服务容器
type Box struct {
    createdAt       time.Time
    logFactory      log.Factory
    logger          log.ContextLogger
    network         *route.NetworkManager      // 网络管理
    endpoint        *endpoint.Manager          // 端点管理
    inbound         *inbound.Manager           // 入站管理
    outbound        *outbound.Manager          // 出站管理
    service         *boxService.Manager        // 服务管理
    dnsTransport    *dns.TransportManager      // DNS 传输管理
    dnsRouter       *dns.Router                // DNS 路由
    connection      *route.ConnectionManager   // 连接管理
    router          *route.Router              // 主路由器
    internalService []adapter.LifecycleService // 内部服务
    done            chan struct{}
}
```

### 1.2 Rust 映射建议

| Go 组件 | Rust 位置 | 职责 |
|---------|----------|------|
| `Box` | `app/` | 组合根 |
| `NetworkManager` | `sb-platform/` | 网络接口管理 |
| `EndpointManager` | `sb-core/` | WireGuard/Tailscale 端点 |
| `InboundManager` | `sb-core/` | 入站协议管理 |
| `OutboundManager` | `sb-core/` | 出站协议管理 |
| `ServiceManager` | `sb-adapters/` | NTP/DERP/ssm 等服务 |
| `DNSTransportManager` | `sb-core/dns/` | DNS 传输层 |
| `DNSRouter` | `sb-core/dns/` | DNS 规则路由 |
| `ConnectionManager` | `sb-core/router/` | 连接追踪 |
| `Router` | `sb-core/router/` | 主路由引擎 |

---

## 2. 生命周期模式

### 2.1 四阶段启动

```go
// adapter/lifecycle.go
const (
    StartStateInitialize StartStage = iota  // 阶段0: 初始化
    StartStateStart                          // 阶段1: 启动
    StartStatePostStart                      // 阶段2: 启动后
    StartStateStarted                        // 阶段3: 已启动
)
```

### 2.2 启动顺序

```
PreStart:
  1. logFactory.Start()
  2. internalService[Initialize] (cache-file, clash-api, v2ray-api)
  3. [Initialize]: network, dnsTransport, dnsRouter, connection, router, outbound, inbound, endpoint, service
  4. [Start]: outbound, dnsTransport, dnsRouter, network, connection, router

Start:
  1. preStart()
  2. internalService[Start]
  3. [Start]: inbound, endpoint, service
  4. [PostStart]: outbound, network, dnsTransport, dnsRouter, connection, router, inbound, endpoint, service
  5. internalService[PostStart]
  6. [Started]: all
  7. internalService[Started]
```

### 2.3 Rust 实现建议

```rust
pub trait Lifecycle: Send + Sync {
    async fn start(&self, stage: StartStage) -> Result<()>;
    async fn close(&self) -> Result<()>;
}

pub enum StartStage {
    Initialize,
    Start,
    PostStart,
    Started,
}
```

---

## 3. 适配器接口

### 3.1 Inbound 接口

```go
type Inbound interface {
    Lifecycle
    Type() string
    Tag() string
}

type TCPInjectableInbound interface {
    Inbound
    ConnectionHandlerEx
}

type UDPInjectableInbound interface {
    Inbound
    PacketConnectionHandlerEx
}

type InboundManager interface {
    Lifecycle
    Inbounds() []Inbound
    Get(tag string) (Inbound, bool)
    Remove(tag string) error
    Create(...) error
}
```

### 3.2 Outbound 接口

```go
type Outbound interface {
    Type() string
    Tag() string
    Network() []string      // ["tcp", "udp"]
    Dependencies() []string // 依赖的其他 outbound
    N.Dialer                // 嵌入 Dialer
}

type OutboundManager interface {
    Lifecycle
    Outbounds() []Outbound
    Outbound(tag string) (Outbound, bool)
    Default() Outbound
    Remove(tag string) error
    Create(...) error
}
```

### 3.3 Router 接口

```go
type Router interface {
    Lifecycle
    ConnectionRouter
    PreMatch(metadata InboundContext) error
    ConnectionRouterEx
    RuleSet(tag string) (RuleSet, bool)
    NeedWIFIState() bool
    Rules() []Rule
    AppendTracker(tracker ConnectionTracker)
    ResetNetwork()
}

type ConnectionRouter interface {
    RouteConnection(ctx, conn, metadata) error
    RoutePacketConnection(ctx, conn, metadata) error
}

type ConnectionTracker interface {
    RoutedConnection(ctx, conn, metadata, matchedRule, matchOutbound) net.Conn
    RoutedPacketConnection(ctx, conn, metadata, matchedRule, matchOutbound) N.PacketConn
}
```

---

## 4. InboundContext（核心上下文）

```go
type InboundContext struct {
    // 基础信息
    Inbound     string      // 入站 tag
    InboundType string      // 入站类型
    IPVersion   uint8       // 4 或 6
    Network     string      // "tcp" 或 "udp"
    Source      M.Socksaddr // 源地址
    Destination M.Socksaddr // 目标地址
    User        string      // 认证用户
    Outbound    string      // 出站 tag

    // 嗅探信息
    Protocol     string   // 嗅探到的协议
    Domain       string   // 嗅探到的域名
    Client       string   // 客户端指纹
    SnifferNames []string // 启用的嗅探器
    SniffError   error    // 嗅探错误

    // 缓存/选项
    InboundDetour            string
    OriginDestination        M.Socksaddr
    RouteOriginalDestination M.Socksaddr
    UDPConnect               bool
    UDPTimeout               time.Duration
    TLSFragment              bool
    TLSFragmentFallbackDelay time.Duration
    TLSRecordFragment        bool

    // 网络策略
    NetworkStrategy     *C.NetworkStrategy
    NetworkType         []C.InterfaceType
    FallbackNetworkType []C.InterfaceType
    FallbackDelay       time.Duration

    // GeoIP/进程信息
    DestinationAddresses []netip.Addr
    SourceGeoIPCode      string
    GeoIPCode            string
    ProcessInfo          *process.Info
    QueryType            uint16
    FakeIP               bool

    // 规则缓存
    IPCIDRMatchSource            bool
    SourceAddressMatch           bool
    DestinationAddressMatch      bool
    DidMatch                     bool
    IgnoreDestinationIPCIDRMatch bool
}
```

### Rust 结构体建议

```rust
#[derive(Clone, Debug)]
pub struct InboundContext {
    pub inbound: String,
    pub inbound_type: String,
    pub ip_version: u8,
    pub network: Network,
    pub source: SocketAddr,
    pub destination: SocksAddr,
    pub user: Option<String>,
    pub outbound: Option<String>,
    
    // Sniff
    pub protocol: Option<String>,
    pub domain: Option<String>,
    pub client: Option<String>,
    
    // Options
    pub udp_connect: bool,
    pub udp_timeout: Option<Duration>,
    pub tls_fragment: bool,
    
    // Geo
    pub destination_addresses: Vec<IpAddr>,
    pub source_geoip_code: Option<String>,
    pub geoip_code: Option<String>,
    pub process_info: Option<ProcessInfo>,
    pub query_type: Option<u16>,
    pub fakeip: bool,
}
```

---

## 5. CLI 命令结构

### 5.1 主要命令

| 命令 | 功能 | Rust 实现位置 |
|------|------|--------------|
| `run` | 运行服务 | `app/src/bin/run.rs` |
| `check` | 检查配置 | `app/src/bin/check.rs` |
| `format` | 格式化配置 | `app/src/bin/format.rs` |
| `version` | 版本信息 | `app/src/bin/version.rs` |
| `merge` | 合并配置 | `app/src/bin/merge.rs` |
| `geoip` | GeoIP 工具 | `app/src/bin/geoip.rs` |
| `geosite` | GeoSite 工具 | `app/src/bin/geosite.rs` |
| `rule-set` | 规则集工具 | `app/src/bin/ruleset.rs` |
| `generate` | 生成工具 | `app/src/bin/generate.rs` |
| `tools` | 调试工具 | `app/src/bin/tools.rs` |

### 5.2 run 命令行为

```go
// cmd_run.go 关键行为
func run() error {
    osSignals := make(chan os.Signal, 1)
    signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
    
    for {
        instance, cancel, err := create()
        // ...
        for {
            osSignal := <-osSignals
            if osSignal == syscall.SIGHUP {
                // 热重载：检查配置，关闭旧实例，创建新实例
                err = check()
                if err != nil {
                    log.Error(E.Cause(err, "reload service"))
                    continue
                }
            }
            cancel()
            instance.Close()
            if osSignal != syscall.SIGHUP {
                return nil  // SIGTERM/SIGINT：退出
            }
            break  // SIGHUP：重新创建
        }
    }
}
```

### 5.3 Rust 信号处理建议

```rust
// 必须实现的信号处理
async fn run() -> Result<()> {
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sighup = signal(SignalKind::hangup())?;
    
    loop {
        let instance = create_box(&config).await?;
        
        loop {
            tokio::select! {
                _ = sigterm.recv() => {
                    instance.close().await?;
                    return Ok(());
                }
                _ = sigint.recv() => {
                    instance.close().await?;
                    return Ok(());
                }
                _ = sighup.recv() => {
                    // 热重载
                    if let Err(e) = check_config(&config) {
                        error!("reload service: {}", e);
                        continue;
                    }
                    instance.close().await?;
                    break;  // 重新创建
                }
            }
        }
    }
}
```

---

## 6. GUI 集成接口

### 6.1 GUI 调用方式

```go
// bridge/exec.go - GUI 如何调用 sing-box
func (a *App) Exec(path string, args []string, options ExecOptions) FlagResult {
    cmd := exec.Command(exePath, args...)
    cmd.Env = os.Environ()
    for key, value := range options.Env {
        cmd.Env = append(cmd.Env, key+"="+value)
    }
    out, err := cmd.CombinedOutput()
    // ...
}

func (a *App) ExecBackground(path string, args []string, outEvent string, endEvent string, options ExecOptions) FlagResult {
    cmd := exec.Command(exePath, args...)
    cmd.Start()
    pid := cmd.Process.Pid
    // PID 写入文件用于管理
    if pidPath != "" {
        os.WriteFile(pidPath, []byte(pid), os.ModePerm)
    }
    // 输出通过事件发送
    go scanAndEmit(stdout)
    // ...
}

func (a *App) KillProcess(pid int, timeout int) FlagResult {
    process, _ := os.FindProcess(pid)
    SendExitSignal(process)  // SIGTERM
    waitForProcessExitWithTimeout(process, timeout)
    // 超时则 Kill
}
```

### 6.2 Rust 兼容性要求

| 要求 | 实现方式 |
|------|---------|
| PID 管理 | 写入 PID 文件 |
| stdout/stderr | 流式输出 |
| SIGTERM 响应 | 优雅关闭 |
| 超时强杀 | SIGKILL 后备 |
| 环境变量 | 完整传递 |

---

## 7. 协议目录结构

### 7.1 Go 协议布局

```
protocol/
├── anytls/     # AnyTLS
├── block/      # Block (黑洞)
├── direct/     # Direct (直连)
├── dns/        # DNS inbound/outbound
├── group/      # Selector/URLTest
├── http/       # HTTP 代理
├── hysteria/   # Hysteria v1
├── hysteria2/  # Hysteria v2
├── mixed/      # Mixed (SOCKS+HTTP)
├── naive/      # NaiveProxy
├── redirect/   # Redirect (Linux)
├── shadowsocks/# Shadowsocks
├── shadowtls/  # ShadowTLS
├── socks/      # SOCKS5
├── ssh/        # SSH
├── tailscale/  # Tailscale (de-scoped)
├── tor/        # Tor
├── trojan/     # Trojan
├── tuic/       # TUIC
├── tun/        # TUN
├── vless/      # VLESS
├── vmess/      # VMess
└── wireguard/  # WireGuard
```

### 7.2 Rust 对应

| Go 协议 | Rust 位置 | 状态 |
|---------|----------|------|
| direct/block | `sb-core/` | ✅ |
| shadowsocks | `sb-adapters/outbound/` | ✅ |
| trojan | `sb-adapters/outbound/` | ✅ |
| vmess/vless | `sb-adapters/outbound/` | ✅ |
| hysteria/hysteria2 | `sb-adapters/outbound/` | ✅ |
| tuic | `sb-adapters/outbound/` | ✅ |
| socks/http | `sb-adapters/inbound/` | ✅ |
| tun | `sb-adapters/inbound/` | ✅ |
| group | `sb-core/outbound/` | ✅ |

---

## 8. 关键设计决策

### 8.1 依赖注入模式

Go 使用 `service.Context` 进行依赖注入：

```go
ctx = service.ContextWith[adapter.InboundRegistry](ctx, inboundRegistry)
ctx = service.ContextWith[adapter.OutboundRegistry](ctx, outboundRegistry)
// ...
registry := service.FromContext[adapter.InboundRegistry](ctx)
```

**Rust 建议**：使用 `Arc<dyn Trait>` 或 TypeMap 模式

### 8.2 配置合并

Go 支持多配置文件合并：

```go
mergedMessage, err = badjson.MergeJSON(globalCtx, options.options.RawMessage, mergedMessage, false)
```

**Rust 建议**：使用 `serde_json::Value` 深度合并

### 8.3 热重载

Go 使用 SIGHUP 触发热重载，不丢连接（通过完整重建实例）

**Rust 建议**：相同模式，但可考虑更精细的部分重载

---

*本文档提取自 Go 源码，用于指导 Rust 实现的设计决策。*
