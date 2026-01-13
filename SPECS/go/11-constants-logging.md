# 常量与日志系统

## 1. 常量定义 (constant/)

### 1.1 目录结构

```
constant/
├── certificate.go   # 证书存储类型
├── cgo.go           # CGO 编译标志
├── cgo_disabled.go  # CGO 禁用标志
├── dhcp.go          # DHCP 常量
├── dns.go           # DNS 策略常量
├── err.go           # 错误常量
├── goos/            # 平台特定常量
├── hysteria2.go     # Hysteria2 常量
├── network.go       # 网络类型常量
├── os.go            # 操作系统常量
├── path.go          # 路径常量
├── path_unix.go     # Unix 路径
├── protocol.go      # 协议常量
├── proxy.go         # 代理类型常量
├── quic.go          # QUIC 常量
├── rule.go          # 规则常量
├── speed.go         # 速度常量
├── time.go          # 时间常量
├── timeout.go       # 超时常量
├── v2ray.go         # V2Ray 常量
└── version.go       # 版本常量
```

### 1.2 代理类型 (proxy.go)

```go
const (
    TypeTun          = "tun"
    TypeRedirect     = "redirect"
    TypeTProxy       = "tproxy"
    TypeDirect       = "direct"
    TypeBlock        = "block"
    TypeDNS          = "dns"
    TypeSOCKS        = "socks"
    TypeHTTP         = "http"
    TypeMixed        = "mixed"
    TypeShadowsocks  = "shadowsocks"
    TypeVMess        = "vmess"
    TypeTrojan       = "trojan"
    TypeNaive        = "naive"
    TypeWireGuard    = "wireguard"
    TypeHysteria     = "hysteria"
    TypeTor          = "tor"
    TypeSSH          = "ssh"
    TypeShadowTLS    = "shadowtls"
    TypeAnyTLS       = "anytls"
    TypeShadowsocksR = "shadowsocksr"
    TypeVLESS        = "vless"
    TypeTUIC         = "tuic"
    TypeHysteria2    = "hysteria2"
    TypeTailscale    = "tailscale"
    
    // 组类型
    TypeSelector = "selector"
    TypeURLTest  = "urltest"
    
    // 服务类型
    TypeDERP     = "derp"
    TypeResolved = "resolved"
    TypeSSMAPI   = "ssm-api"
)
```

### 1.3 协议常量 (protocol.go)

```go
// 嗅探协议
const (
    ProtocolTLS        = "tls"
    ProtocolHTTP       = "http"
    ProtocolQUIC       = "quic"
    ProtocolDNS        = "dns"
    ProtocolSTUN       = "stun"
    ProtocolBitTorrent = "bittorrent"
    ProtocolDTLS       = "dtls"
    ProtocolSSH        = "ssh"
    ProtocolRDP        = "rdp"
    ProtocolNTP        = "ntp"
)

// TLS 客户端指纹
const (
    ClientChromium = "chromium"
    ClientSafari   = "safari"
    ClientFirefox  = "firefox"
    ClientQUICGo   = "quic-go"
    ClientUnknown  = "unknown"
)
```

### 1.4 网络类型 (network.go)

```go
type InterfaceType uint8

const (
    InterfaceTypeWIFI     InterfaceType = iota  // WiFi
    InterfaceTypeCellular                        // 蜂窝网络
    InterfaceTypeEthernet                        // 以太网
    InterfaceTypeOther                           // 其他
)

type NetworkStrategy uint8

const (
    NetworkStrategyDefault  NetworkStrategy = iota  // 默认策略
    NetworkStrategyFallback                          // 回退策略
    NetworkStrategyHybrid                            // 混合策略
)
```

### 1.5 超时常量 (timeout.go)

```go
const (
    TCPKeepAliveInitial        = 10 * time.Minute   // TCP 保活初始间隔
    TCPKeepAliveInterval       = 75 * time.Second   // TCP 保活间隔
    TCPConnectTimeout          = 5 * time.Second    // TCP 连接超时
    TCPTimeout                 = 15 * time.Second   // TCP 超时
    ReadPayloadTimeout         = 300 * time.Millisecond  // 读取负载超时
    DNSTimeout                 = 10 * time.Second   // DNS 超时
    UDPTimeout                 = 5 * time.Minute    // UDP 超时
    DefaultURLTestInterval     = 3 * time.Minute    // URL 测试间隔
    DefaultURLTestIdleTimeout  = 30 * time.Minute   // URL 测试空闲超时
    StartTimeout               = 10 * time.Second   // 启动超时
    StopTimeout                = 5 * time.Second    // 停止超时
    FatalStopTimeout           = 10 * time.Second   // 致命停止超时
    FakeIPMetadataSaveInterval = 10 * time.Second   // FakeIP 保存间隔
    TLSFragmentFallbackDelay   = 500 * time.Millisecond  // TLS 分片回退延迟
)

// 端口协议映射
var PortProtocols = map[uint16]string{
    53:   ProtocolDNS,
    123:  ProtocolNTP,
    3478: ProtocolSTUN,
    443:  ProtocolQUIC,
}
```

### 1.6 规则常量 (rule.go)

```go
// 规则类型
const (
    RuleTypeDefault = "default"
    RuleTypeLogical = "logical"
)

// 逻辑类型
const (
    LogicalTypeAnd = "and"
    LogicalTypeOr  = "or"
)

// 规则集类型
const (
    RuleSetTypeInline   = "inline"
    RuleSetTypeLocal    = "local"
    RuleSetTypeRemote   = "remote"
    RuleSetFormatSource = "source"
    RuleSetFormatBinary = "binary"
)

// 规则集版本
const (
    RuleSetVersion1 = 1 + iota
    RuleSetVersion2
    RuleSetVersion3
    RuleSetVersionCurrent = RuleSetVersion3
)

// 规则动作类型
const (
    RuleActionTypeRoute        = "route"
    RuleActionTypeRouteOptions = "route-options"
    RuleActionTypeDirect       = "direct"
    RuleActionTypeReject       = "reject"
    RuleActionTypeHijackDNS    = "hijack-dns"
    RuleActionTypeSniff        = "sniff"
    RuleActionTypeResolve      = "resolve"
    RuleActionTypePredefined   = "predefined"
)

// 拒绝方法
const (
    RuleActionRejectMethodDefault = "default"
    RuleActionRejectMethodDrop    = "drop"
)
```

### 1.7 DNS 策略 (dns.go)

```go
type DomainStrategy uint8

const (
    DomainStrategyAsIS       DomainStrategy = iota  // 原样
    DomainStrategyPreferIPv4                        // 优先 IPv4
    DomainStrategyPreferIPv6                        // 优先 IPv6
    DomainStrategyUseIPv4                           // 仅 IPv4
    DomainStrategyUseIPv6                           // 仅 IPv6
)
```

---

## 2. 日志系统 (log/)

### 2.1 目录结构

```
log/
├── export.go       # 导出接口
├── factory.go      # 日志工厂
├── format.go       # 格式化器
├── id.go           # 日志 ID
├── level.go        # 日志级别
├── log.go          # 主入口
├── nop.go          # 空日志
├── observable.go   # 可观察日志
├── override.go     # 日志覆盖
└── platform.go     # 平台日志
```

### 2.2 日志级别

```go
type Level = uint8

const (
    LevelPanic Level = iota  // 0 - 恐慌
    LevelFatal               // 1 - 致命
    LevelError               // 2 - 错误
    LevelWarn                // 3 - 警告
    LevelInfo                // 4 - 信息
    LevelDebug               // 5 - 调试
    LevelTrace               // 6 - 跟踪
)
```

### 2.3 日志工厂接口

```go
// log/export.go

type Factory interface {
    Level() Level
    SetLevel(level Level)
    Logger() ContextLogger
    NewLogger(tag string) ContextLogger
    Start() error
    Close() error
}

type ObservableFactory interface {
    Factory
    Observable() observable.Observable[Entry]
}

type Entry struct {
    Level   Level
    Message string
}
```

### 2.4 日志接口

```go
// log/export.go

type ContextLogger interface {
    logger.ContextLogger  // 继承 sing 的日志接口
    
    TraceContext(ctx context.Context, args ...any)
    DebugContext(ctx context.Context, args ...any)
    InfoContext(ctx context.Context, args ...any)
    WarnContext(ctx context.Context, args ...any)
    ErrorContext(ctx context.Context, args ...any)
    FatalContext(ctx context.Context, args ...any)
    PanicContext(ctx context.Context, args ...any)
    
    Trace(args ...any)
    Debug(args ...any)
    Info(args ...any)
    Warn(args ...any)
    Error(args ...any)
    Fatal(args ...any)
    Panic(args ...any)
}
```

### 2.5 日志格式化

```go
// log/format.go

type Formatter struct {
    BaseTime         time.Time
    DisableColors    bool
    DisableTimestamp bool
    FullTimestamp    bool
    TimestampFormat  string
}

func (f Formatter) Format(ctx context.Context, level Level, tag string, message string, timestamp time.Time) string {
    // 格式: [时间] [级别] [标签] 消息
    // 例如: [2024-01-08 10:30:00] [INFO] [router] connection matched rule[0]
}
```

### 2.6 创建日志

```go
// log/log.go

type Options struct {
    Context        context.Context
    Options        option.LogOptions   // 配置选项
    Observable     bool                // 是否可观察（Clash API 需要）
    DefaultWriter  io.Writer           // 默认写入器
    BaseTime       time.Time           // 基准时间
    PlatformWriter PlatformWriter      // 平台写入器
}

func New(options Options) (Factory, error) {
    // 1. 检查是否禁用日志
    if logOptions.Disabled {
        return NewNOPFactory(), nil
    }
    
    // 2. 确定输出目标
    switch logOptions.Output {
    case "":
        logWriter = options.DefaultWriter
    case "stderr":
        logWriter = os.Stderr
    case "stdout":
        logWriter = os.Stdout
    default:
        logFilePath = logOptions.Output  // 写入文件
    }
    
    // 3. 创建格式化器
    logFormatter := Formatter{...}
    
    // 4. 创建工厂
    factory := NewDefaultFactory(ctx, logFormatter, logWriter, logFilePath, 
                                  options.PlatformWriter, options.Observable)
    
    // 5. 设置级别
    factory.SetLevel(logLevel)
    
    return factory, nil
}
```

### 2.7 可观察日志

用于 Clash API 的实时日志流：

```go
// log/observable.go

type observableFactory struct {
    factory        Factory
    observable     *observable.Observer[Entry]
    subscriber     *observable.Subscriber[Entry]
}

func (f *observableFactory) Observable() observable.Observable[Entry] {
    return f.subscriber
}

// Clash API 使用 WebSocket 订阅日志
func (s *ClashServer) handleLogs(w http.ResponseWriter, r *http.Request) {
    subscription := f.logFactory.Subscribe()
    defer subscription.Close()
    
    for entry := range subscription {
        // 发送日志到 WebSocket
        conn.WriteJSON(entry)
    }
}
```

### 2.8 日志 ID

每个连接分配唯一的日志 ID：

```go
// log/id.go

type contextLogIDKey struct{}

func ContextWithNewID(ctx context.Context) context.Context {
    id := generateID()  // 生成唯一 ID
    return context.WithValue(ctx, (*contextLogIDKey)(nil), id)
}

func IDFromContext(ctx context.Context) string {
    id := ctx.Value((*contextLogIDKey)(nil))
    if id == nil {
        return ""
    }
    return id.(string)
}
```

### 2.9 平台日志

用于移动平台的日志输出：

```go
// log/platform.go

type PlatformWriter interface {
    WriteMessage(level Level, message string)
}

// Android/iOS 实现 PlatformWriter 来接收日志
```

---

## 3. 编译标签 (Build Tags)

### 3.1 可选功能

| 标签 | 功能 |
|------|------|
| `with_gvisor` | gVisor 用户态网络栈 |
| `with_quic` | QUIC 协议支持 |
| `with_wireguard` | WireGuard 协议支持 |
| `with_utls` | uTLS 指纹模拟 |
| `with_reality_server` | REALITY 服务端 |
| `with_clash_api` | Clash REST API |
| `with_v2ray_api` | V2Ray gRPC API |
| `with_tailscale` | Tailscale 集成 |
| `with_dhcp` | DHCP DNS 支持 |
| `with_acme` | ACME 证书管理 |

### 3.2 平台标签

| 标签 | 平台 |
|------|------|
| `linux` | Linux |
| `darwin` | macOS |
| `windows` | Windows |
| `android` | Android |
| `ios` | iOS |

### 3.3 CGO

```go
// constant/cgo.go (启用 CGO)
//go:build cgo

const CGO_ENABLED = true

// constant/cgo_disabled.go (禁用 CGO)  
//go:build !cgo

const CGO_ENABLED = false
```
