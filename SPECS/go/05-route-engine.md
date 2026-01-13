# 路由引擎 (route/)

## 1. 目录结构

```
route/
├── conn.go          # 连接路由实现
├── dns.go           # DNS 劫持处理
├── network.go       # 网络管理器
├── route.go         # 核心路由逻辑
├── router.go        # Router 结构体
├── rule_conds.go    # 规则条件辅助
└── rule/            # 规则实现
    ├── rule_abstract.go     # 规则抽象基类
    ├── rule_action.go       # 规则动作
    ├── rule_default.go      # 默认规则
    ├── rule_dns.go          # DNS 规则
    ├── rule_headless.go     # 无头规则（规则集用）
    ├── rule_item_*.go       # 各种规则条件项
    ├── rule_set.go          # 规则集
    ├── rule_set_local.go    # 本地规则集
    └── rule_set_remote.go   # 远程规则集
```

---

## 2. Router 路由器

### 2.1 结构定义

```go
// route/router.go

type Router struct {
    ctx               context.Context
    logger            log.ContextLogger
    inbound           adapter.InboundManager
    outbound          adapter.OutboundManager
    dns               adapter.DNSRouter
    dnsTransport      adapter.DNSTransportManager
    connection        adapter.ConnectionManager
    network           adapter.NetworkManager
    rules             []adapter.Rule       // 路由规则列表
    needFindProcess   bool                 // 是否需要查找进程
    ruleSets          []adapter.RuleSet    // 规则集列表
    ruleSetMap        map[string]adapter.RuleSet
    processSearcher   process.Searcher     // 进程查找器
    pauseManager      pause.Manager
    trackers          []adapter.ConnectionTracker
    platformInterface platform.Interface
    needWIFIState     bool
    started           bool
}
```

### 2.2 初始化

```go
func NewRouter(ctx context.Context, logFactory log.Factory, 
               options option.RouteOptions, dnsOptions option.DNSOptions) *Router

func (r *Router) Initialize(rules []option.Rule, ruleSets []option.RuleSet) error {
    // 1. 解析每条规则
    for i, options := range rules {
        rule, err := R.NewRule(r.ctx, r.logger, options, false)
        r.rules = append(r.rules, rule)
    }
    
    // 2. 解析规则集
    for i, options := range ruleSets {
        ruleSet, err := R.NewRuleSet(r.ctx, r.logger, options)
        r.ruleSets = append(r.ruleSets, ruleSet)
        r.ruleSetMap[options.Tag] = ruleSet
    }
}
```

---

## 3. 连接路由

### 3.1 TCP 连接路由

```go
// route/route.go

func (r *Router) RouteConnectionEx(ctx context.Context, conn net.Conn, 
                                    metadata adapter.InboundContext, 
                                    onClose N.CloseHandlerFunc) {
    err := r.routeConnection(ctx, conn, metadata, onClose)
    if err != nil {
        N.CloseOnHandshakeFailure(conn, onClose, err)
        // 错误日志
    }
}

func (r *Router) routeConnection(ctx context.Context, conn net.Conn,
                                  metadata adapter.InboundContext,
                                  onClose N.CloseHandlerFunc) error {
    // 1. 处理入站分流 (InboundDetour)
    if metadata.InboundDetour != "" {
        // 转发到另一个入站
    }
    
    // 2. 连接追踪检查
    conntrack.KillerCheck()
    metadata.Network = N.NetworkTCP
    
    // 3. 规则匹配
    selectedRule, selectedRuleIndex, buffers, _, err := r.matchRule(ctx, &metadata, false, conn, nil)
    
    // 4. 选择出站
    var selectedOutbound adapter.Outbound
    if selectedRule != nil {
        switch action := selectedRule.Action().(type) {
        case *R.RuleActionRoute:
            selectedOutbound, _ = r.outbound.Outbound(action.Outbound)
        case *R.RuleActionReject:
            return action.Error(ctx)
        case *R.RuleActionHijackDNS:
            return r.hijackDNSStream(ctx, conn, metadata, onClose)
        }
    }
    
    // 5. 使用默认出站
    if selectedOutbound == nil {
        selectedOutbound = r.outbound.Default()
    }
    
    // 6. 应用缓冲数据
    for _, buffer := range buffers {
        conn = bufio.NewCachedConn(conn, buffer)
    }
    
    // 7. 应用连接追踪器
    for _, tracker := range r.trackers {
        conn = tracker.RoutedConnection(ctx, conn, metadata, selectedRule, selectedOutbound)
    }
    
    // 8. 发起出站连接
    if outboundHandler, isHandler := selectedOutbound.(adapter.ConnectionHandlerEx); isHandler {
        outboundHandler.NewConnectionEx(ctx, conn, metadata, onClose)
    } else {
        r.connection.NewConnection(ctx, selectedOutbound, conn, metadata, onClose)
    }
    
    return nil
}
```

### 3.2 UDP 连接路由

```go
func (r *Router) routePacketConnection(ctx context.Context, conn N.PacketConn,
                                        metadata adapter.InboundContext,
                                        onClose N.CloseHandlerFunc) error {
    // 类似 TCP，但处理 PacketConn
    // 支持 FakeIP NAT 转换
    if metadata.FakeIP {
        conn = bufio.NewNATPacketConn(bufio.NewNetPacketConn(conn), 
                                      metadata.OriginDestination, 
                                      metadata.Destination)
    }
}
```

---

## 4. 规则匹配

### 4.1 匹配流程

```go
// route/route.go

func (r *Router) matchRule(
    ctx context.Context, 
    metadata *adapter.InboundContext, 
    preMatch bool,
    inputConn net.Conn, 
    inputPacketConn N.PacketConn,
) (
    selectedRule adapter.Rule, 
    selectedRuleIndex int,
    buffers []*buf.Buffer, 
    packetBuffers []*N.PacketBuffer, 
    fatalErr error,
) {
    // 1. 查找进程信息
    if r.processSearcher != nil && metadata.ProcessInfo == nil {
        processInfo, err := process.FindProcessInfo(r.processSearcher, ctx, 
                                                     metadata.Network, 
                                                     metadata.Source.AddrPort(),
                                                     originDestination)
        metadata.ProcessInfo = processInfo
    }
    
    // 2. 遍历规则匹配
    for ruleIndex, rule := range r.rules {
        metadata.ResetRuleCache()
        
        if rule.Match(metadata) {
            // 处理规则动作
            switch action := rule.Action().(type) {
            case *R.RuleActionSniff:
                // 协议嗅探
                buffers, fatalErr = r.actionSniff(ctx, metadata, action, inputConn)
                
            case *R.RuleActionResolve:
                // DNS 解析
                fatalErr = r.actionResolve(ctx, metadata, action)
                
            case *R.RuleActionRoute, *R.RuleActionReject, *R.RuleActionHijackDNS:
                // 终端动作
                return rule, ruleIndex, buffers, packetBuffers, nil
            }
        }
    }
    
    return nil, -1, buffers, packetBuffers, nil
}
```

### 4.2 规则接口

```go
// adapter/rule.go

type Rule interface {
    Type() string
    Action() RuleAction
    Match(metadata *InboundContext) bool
    String() string
}
```

---

## 5. 规则实现 (route/rule/)

### 5.1 规则结构

```go
// route/rule/rule_default.go

type DefaultRule struct {
    abstractDefaultRule
    allItems []RuleItem  // 所有规则条件项
}

type abstractDefaultRule struct {
    invert bool           // 是否取反
    action RuleAction     // 规则动作
}

func (r *DefaultRule) Match(metadata *adapter.InboundContext) bool {
    if r.allItems == nil {
        return true
    }
    
    for _, item := range r.allItems {
        if !item.Match(metadata) {
            return r.invert
        }
    }
    return !r.invert
}
```

### 5.2 规则条件项

| 文件 | 条件类型 | 描述 |
|------|----------|------|
| `rule_item_domain.go` | domain | 精确域名匹配 |
| `rule_item_domain_keyword.go` | domain_keyword | 域名关键词 |
| `rule_item_domain_regex.go` | domain_regex | 域名正则 |
| `rule_item_cidr.go` | ip_cidr / source_ip_cidr | IP CIDR 匹配 |
| `rule_item_port.go` | port / source_port | 端口匹配 |
| `rule_item_port_range.go` | port_range | 端口范围 |
| `rule_item_protocol.go` | protocol | 协议类型 (http/tls/quic等) |
| `rule_item_network.go` | network | 网络类型 (tcp/udp) |
| `rule_item_inbound.go` | inbound | 入站标签 |
| `rule_item_outbound.go` | outbound | 出站标签 |
| `rule_item_process_name.go` | process_name | 进程名 |
| `rule_item_process_path.go` | process_path | 进程路径 |
| `rule_item_user.go` | user | 用户名 |
| `rule_item_user_id.go` | user_id | 用户ID |
| `rule_item_package_name.go` | package_name | Android 包名 |
| `rule_item_wifi_ssid.go` | wifi_ssid | WiFi SSID |
| `rule_item_wifi_bssid.go` | wifi_bssid | WiFi BSSID |
| `rule_item_rule_set.go` | rule_set | 规则集引用 |
| `rule_item_clash_mode.go` | clash_mode | Clash 模式 |
| `rule_item_ip_is_private.go` | ip_is_private | 私有IP |
| `rule_item_query_type.go` | query_type | DNS 查询类型 |

### 5.3 规则条件项接口

```go
type RuleItem interface {
    Match(metadata *adapter.InboundContext) bool
}

// 示例：域名匹配
type RuleItemDomain struct {
    matcher *domain.Matcher  // 域名匹配器
}

func (r *RuleItemDomain) Match(metadata *adapter.InboundContext) bool {
    var domainHost string
    if metadata.Domain != "" {
        domainHost = metadata.Domain
    } else if metadata.Destination.IsFqdn() {
        domainHost = metadata.Destination.Fqdn
    }
    if domainHost == "" {
        return false
    }
    return r.matcher.Match(domainHost)
}
```

---

## 6. 规则动作

```go
// route/rule/rule_action.go

type RuleAction interface {
    Type() string
    String() string
}

// 路由动作
type RuleActionRoute struct {
    Outbound               string   // 出站标签
    NetworkStrategy        C.NetworkStrategy
    NetworkType            []C.InterfaceType
    FallbackNetworkType    []C.InterfaceType
    FallbackDelay          time.Duration
    UDPDisableDomainUnmapping bool
    UDPConnect             bool
    UDPTimeout             time.Duration
    TLSFragment            bool
    TLSFragmentFallbackDelay time.Duration
    TLSRecordFragment      bool
}

// 拒绝动作
type RuleActionReject struct {
    Method   C.RuleActionRejectMethod  // drop / reset / hijack
    NoDrop   bool
    dropQuic bool
}

// DNS 劫持动作
type RuleActionHijackDNS struct{}

// 嗅探动作
type RuleActionSniff struct {
    Sniffers       []string   // 嗅探器列表
    Timeout        time.Duration
    OverrideDestination bool  // 是否覆盖目标地址
}

// 解析动作
type RuleActionResolve struct {
    Strategy     C.DomainStrategy
    Server       string
    DisableCache bool
    RewriteTTL   *uint32
    ClientSubnet netip.Prefix
}
```

---

## 7. 规则集

### 7.1 本地规则集

```go
// route/rule/rule_set_local.go

type LocalRuleSet struct {
    ctx          context.Context
    cancel       context.CancelFunc
    logger       logger.Logger
    tag          string
    rules        []adapter.HeadlessRule
    metadata     adapter.RuleSetMetadata
    fileFormat   string
    watcher      *fswatch.Watcher  // 文件监视
}

func (s *LocalRuleSet) StartContext(ctx context.Context, startContext *adapter.HTTPStartContext) error {
    // 读取本地规则集文件
    content, err := os.ReadFile(s.path)
    // 解析规则
}
```

### 7.2 远程规则集

```go
// route/rule/rule_set_remote.go

type RemoteRuleSet struct {
    ctx            context.Context
    cancel         context.CancelFunc
    logger         logger.Logger
    options        option.RuleSet
    tag            string
    rules          []adapter.HeadlessRule
    metadata       adapter.RuleSetMetadata
    updateInterval time.Duration
    dialer         N.Dialer
    lastUpdated    time.Time
}

func (s *RemoteRuleSet) StartContext(ctx context.Context, startContext *adapter.HTTPStartContext) error {
    // 1. 尝试从缓存加载
    // 2. 从远程下载
    // 3. 启动定时更新
}
```

---

## 8. 网络管理器

```go
// route/network.go

type NetworkManager struct {
    ctx                context.Context
    logger             logger.ContextLogger
    interfaceFinder    *control.DefaultInterfaceFinder
    networkInterfaces  atomic.Pointer[[]adapter.NetworkInterface]
    wifiState          adapter.WIFIState
    defaultInterface   *control.Interface
    autoDetectInterface bool
    defaultMark        uint32
    networkMonitor     tun.NetworkUpdateMonitor
    interfaceMonitor   tun.DefaultInterfaceMonitor
    packageManager     tun.PackageManager
    powerListener      func()
}

func (m *NetworkManager) Start(stage adapter.StartStage) error
func (m *NetworkManager) InterfaceFinder() control.InterfaceFinder
func (m *NetworkManager) UpdateInterfaces() error
func (m *NetworkManager) DefaultNetworkInterface() *control.Interface
func (m *NetworkManager) NetworkInterfaces() []adapter.NetworkInterface
func (m *NetworkManager) WIFIState() adapter.WIFIState
func (m *NetworkManager) ResetNetwork()
```

---

## 9. 连接管理器

```go
// route/conn.go

type ConnectionManager struct {
    logger logger.ContextLogger
}

func NewConnectionManager(logger logger.ContextLogger) *ConnectionManager

func (m *ConnectionManager) NewConnection(ctx context.Context, 
                                           this adapter.Outbound,
                                           conn net.Conn, 
                                           metadata adapter.InboundContext, 
                                           onClose N.CloseHandlerFunc)

func (m *ConnectionManager) NewPacketConnection(ctx context.Context,
                                                  this adapter.Outbound,
                                                  conn N.PacketConn,
                                                  metadata adapter.InboundContext,
                                                  onClose N.CloseHandlerFunc)
```
