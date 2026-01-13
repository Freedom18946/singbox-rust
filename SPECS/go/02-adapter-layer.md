# 适配器层接口 (adapter/)

## 1. 目录结构

```
adapter/
├── certificate.go      # 证书存储接口
├── connections.go      # 连接管理接口
├── dns.go              # DNS 接口定义
├── endpoint.go         # 端点接口
├── experimental.go     # 实验性功能接口
├── fakeip.go           # FakeIP 接口
├── fakeip_metadata.go  # FakeIP 元数据
├── handler.go          # 连接处理器接口
├── inbound.go          # 入站接口
├── lifecycle.go        # 生命周期接口
├── lifecycle_legacy.go # 旧版生命周期
├── network.go          # 网络管理接口
├── outbound.go         # 出站接口
├── prestart.go         # 预启动钩子
├── router.go           # 路由接口
├── rule.go             # 规则接口
├── service.go          # 服务接口
├── ssm.go              # SSM API 接口
├── time.go             # 时间服务接口
├── upstream.go         # 上游处理器（新版）
├── upstream_legacy.go  # 上游处理器（旧版）
├── v2ray.go            # V2Ray 接口
├── endpoint/           # 端点管理器实现
├── inbound/            # 入站管理器实现
├── outbound/           # 出站管理器实现
└── service/            # 服务管理器实现
```

---

## 2. 核心接口

### 2.1 Lifecycle - 生命周期接口

```go
// adapter/lifecycle.go

type StartStage uint8

const (
    StartStateInitialize StartStage = iota  // 初始化
    StartStateStart                          // 启动
    StartStatePostStart                      // 启动后
    StartStateStarted                        // 已启动
)

// 所有组件必须实现
type Lifecycle interface {
    Start(stage StartStage) error
    Close() error
}

// 带名称的生命周期服务
type LifecycleService interface {
    Name() string
    Lifecycle
}
```

### 2.2 Inbound - 入站接口

```go
// adapter/inbound.go

type Inbound interface {
    Lifecycle
    Type() string  // 协议类型，如 "tun", "socks", "http"
    Tag() string   // 唯一标识
}

// TCP 注入入站
type TCPInjectableInbound interface {
    Inbound
    ConnectionHandlerEx
}

// UDP 注入入站
type UDPInjectableInbound interface {
    Inbound
    PacketConnectionHandlerEx
}

// 入站管理器
type InboundManager interface {
    Lifecycle
    Inbounds() []Inbound           // 获取所有入站
    Get(tag string) (Inbound, bool) // 按标签获取
    Remove(tag string) error        // 移除入站
    Create(...) error               // 动态创建
}
```

### 2.3 InboundContext - 入站上下文

```go
// adapter/inbound.go

type InboundContext struct {
    // 基本信息
    Inbound     string      // 入站标签
    InboundType string      // 入站类型
    IPVersion   uint8       // IP版本
    Network     string      // 网络类型 "tcp"/"udp"
    Source      M.Socksaddr // 源地址
    Destination M.Socksaddr // 目标地址
    User        string      // 用户名
    Outbound    string      // 出站标签

    // 嗅探结果
    Protocol     string   // 协议 "http"/"tls"/"quic" 等
    Domain       string   // 嗅探到的域名
    Client       string   // 客户端类型
    SniffContext any      // 嗅探上下文
    SnifferNames []string // 嗅探器名称列表
    SniffError   error    // 嗅探错误

    // 连接选项
    UDPConnect                bool
    UDPTimeout                time.Duration
    TLSFragment               bool
    TLSFragmentFallbackDelay  time.Duration
    TLSRecordFragment         bool

    // 网络策略
    NetworkStrategy     *C.NetworkStrategy
    NetworkType         []C.InterfaceType
    FallbackNetworkType []C.InterfaceType
    FallbackDelay       time.Duration

    // 解析结果
    DestinationAddresses []netip.Addr
    SourceGeoIPCode      string
    GeoIPCode            string
    ProcessInfo          *process.Info
    QueryType            uint16
    FakeIP               bool

    // 规则缓存
    IPCIDRMatchSource            bool
    IPCIDRAcceptEmpty            bool
    SourceAddressMatch           bool
    SourcePortMatch              bool
    DestinationAddressMatch      bool
    DestinationPortMatch         bool
    DidMatch                     bool
    IgnoreDestinationIPCIDRMatch bool
}
```

### 2.4 Outbound - 出站接口

```go
// adapter/outbound.go

type Outbound interface {
    Type() string           // 协议类型
    Tag() string            // 唯一标识
    Network() []string      // 支持的网络 ["tcp"] / ["udp"] / ["tcp", "udp"]
    Dependencies() []string // 依赖的其他出站
    N.Dialer                // 实现拨号接口
}

// 出站管理器
type OutboundManager interface {
    Lifecycle
    Outbounds() []Outbound          // 获取所有出站
    Outbound(tag string) (Outbound, bool)  // 按标签获取
    Default() Outbound              // 默认出站
    Remove(tag string) error        // 移除
    Create(...) error               // 动态创建
}
```

### 2.5 Router - 路由接口

```go
// adapter/router.go

type Router interface {
    Lifecycle
    ConnectionRouter
    PreMatch(metadata InboundContext) error  // 预匹配（用于拒绝）
    ConnectionRouterEx
    RuleSet(tag string) (RuleSet, bool)      // 获取规则集
    NeedWIFIState() bool                     // 是否需要WiFi状态
    Rules() []Rule                           // 获取所有规则
    AppendTracker(tracker ConnectionTracker) // 添加连接追踪器
    ResetNetwork()                           // 重置网络
}

type ConnectionRouter interface {
    RouteConnection(ctx context.Context, conn net.Conn, metadata InboundContext) error
    RoutePacketConnection(ctx context.Context, conn N.PacketConn, metadata InboundContext) error
}

type ConnectionRouterEx interface {
    ConnectionRouter
    RouteConnectionEx(ctx context.Context, conn net.Conn, metadata InboundContext, onClose N.CloseHandlerFunc)
    RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata InboundContext, onClose N.CloseHandlerFunc)
}
```

### 2.6 DNS 接口

```go
// adapter/dns.go

type DNSRouter interface {
    Lifecycle
    Exchange(ctx context.Context, message *dns.Msg, options DNSQueryOptions) (*dns.Msg, error)
    Lookup(ctx context.Context, domain string, options DNSQueryOptions) ([]netip.Addr, error)
    ClearCache()
    LookupReverseMapping(ip netip.Addr) (string, bool)
    ResetNetwork()
}

type DNSTransport interface {
    Lifecycle
    Type() string
    Tag() string
    Dependencies() []string
    Exchange(ctx context.Context, message *dns.Msg) (*dns.Msg, error)
}

type DNSQueryOptions struct {
    Transport      DNSTransport
    Strategy       C.DomainStrategy    // prefer_ipv4 / prefer_ipv6 / ipv4_only / ipv6_only
    LookupStrategy C.DomainStrategy
    DisableCache   bool
    RewriteTTL     *uint32
    ClientSubnet   netip.Prefix        // EDNS Client Subnet
}
```

### 2.7 Handler - 连接处理器

```go
// adapter/handler.go

// TCP 连接处理器（新版）
type ConnectionHandlerEx interface {
    NewConnectionEx(ctx context.Context, conn net.Conn, metadata InboundContext, onClose N.CloseHandlerFunc)
}

// UDP 数据包处理器（新版）
type PacketHandlerEx interface {
    NewPacketEx(buffer *buf.Buffer, source M.Socksaddr)
}

// UDP 连接处理器（新版）
type PacketConnectionHandlerEx interface {
    NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata InboundContext, onClose N.CloseHandlerFunc)
}

// 上游处理器
type UpstreamHandlerAdapterEx interface {
    N.TCPConnectionHandlerEx
    N.UDPConnectionHandlerEx
}
```

---

## 3. 管理器实现

### 3.1 Inbound Manager (adapter/inbound/)

```go
// adapter/inbound/manager.go

type Manager struct {
    logger          log.ContextLogger
    registry        *Registry
    endpoint        *endpoint.Manager
    access          sync.Mutex
    started         bool
    stage           adapter.StartStage
    inbounds        []adapter.Inbound
    inboundByTag    map[string]adapter.Inbound
}

// 方法
func (m *Manager) Start(stage adapter.StartStage) error
func (m *Manager) Close() error
func (m *Manager) Inbounds() []adapter.Inbound
func (m *Manager) Get(tag string) (adapter.Inbound, bool)
func (m *Manager) Remove(tag string) error
func (m *Manager) Create(...) error
```

### 3.2 Outbound Manager (adapter/outbound/)

```go
// adapter/outbound/manager.go

type Manager struct {
    logger           log.ContextLogger
    registry         *Registry
    endpoint         *endpoint.Manager
    defaultTag       string
    access           sync.Mutex
    started          bool
    stage            adapter.StartStage
    outbounds        []adapter.Outbound
    outboundByTag    map[string]adapter.Outbound
    defaultOutbound  adapter.Outbound
    defaultOutboundFallback adapter.Outbound
}
```

### 3.3 Registry 模式

```go
// adapter/inbound/registry.go

type Registry struct {
    access   sync.Mutex
    typeMap  map[string]any  // 类型 -> 构造函数
}

func Register[Options any](registry *Registry, protocolType string, 
    constructor func(ctx context.Context, router adapter.Router, 
                     logger log.ContextLogger, tag string, options Options) (adapter.Inbound, error))

// 使用示例
inbound.Register[option.SocksInboundOptions](registry, C.TypeSOCKS, NewInbound)
```

---

## 4. 实验性功能接口

```go
// adapter/experimental.go

type ClashServer interface {
    LifecycleService
    Mode() string
    ModeList() []string
    HistoryStorage() *urltest.HistoryStorage
    RoutedConnection(ctx context.Context, conn net.Conn, metadata InboundContext, matchedRule Rule, matchOutbound Outbound) net.Conn
    RoutedPacketConnection(ctx context.Context, conn N.PacketConn, metadata InboundContext, matchedRule Rule, matchOutbound Outbound) N.PacketConn
}

type V2RayServer interface {
    LifecycleService
    StatsService() V2RayStatsService
}

type CacheFile interface {
    LifecycleService
    StoreFakeIP() bool
    FakeIPStorage
    StoreRDRC() bool
    RDRCStore
    LoadMode() string
    StoreMode(mode string) error
    LoadSelected(group string) string
    StoreSelected(group string, selected string) error
    LoadGroupExpand(group string) (bool, bool)
    StoreGroupExpand(group string, expand bool) error
    LoadRuleSet(tag string) *SavedBinary
    SaveRuleSet(tag string, content *SavedBinary) error
}
```
