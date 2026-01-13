# 实验性功能 (experimental/)

## 1. 目录结构

```
experimental/
├── cachefile/       # 缓存文件
├── clashapi/        # Clash REST API
├── clashapi.go      # Clash API 接口
├── deprecated/      # 废弃功能警告
├── libbox/          # 移动平台库
│   ├── platform/    # 平台接口
│   └── internal/    # 内部实现
├── locale/          # 本地化
├── v2rayapi/        # V2Ray gRPC API
└── v2rayapi.go      # V2Ray API 接口
```

---

## 2. Clash API

### 2.1 概述

Clash API 提供 RESTful API 用于：
- 查看/切换代理节点
- 查看连接信息
- 获取实时日志
- 获取流量统计
- 切换模式 (Global/Rule/Direct)

### 2.2 服务器实现

```go
// experimental/clashapi/server.go

type Server struct {
    ctx                 context.Context
    logger              log.Logger
    httpServer          *http.Server
    trafficManager      *trafficontrol.Manager
    urlTestHistory      *urltest.HistoryStorage
    modeList            []string
    mode                string
    modeUpdateHook      chan<- struct{}
    storeMode           bool
    storeSelected       bool
    cacheFile           adapter.CacheFile
    externalController  string
    externalUI          string
    secret              string
}

func NewServer(ctx context.Context, logFactory log.ObservableFactory, 
               options option.ClashAPIOptions) (*Server, error)
```

### 2.3 API 端点

| 方法 | 路径 | 描述 |
|------|------|------|
| GET | `/` | 版本信息 |
| GET | `/logs` | 实时日志 (WebSocket) |
| GET | `/traffic` | 实时流量 (WebSocket) |
| GET | `/memory` | 内存使用 |
| GET | `/version` | 版本信息 |
| GET | `/configs` | 获取配置 |
| PATCH | `/configs` | 更新配置 |
| PUT | `/configs` | 重载配置 |
| GET | `/proxies` | 获取所有代理 |
| GET | `/proxies/:name` | 获取指定代理 |
| PUT | `/proxies/:name` | 切换代理 |
| GET | `/proxies/:name/delay` | 测试延迟 |
| GET | `/providers/proxies` | 获取代理提供者 |
| PUT | `/providers/proxies/:name` | 更新代理提供者 |
| GET | `/providers/proxies/:name/healthcheck` | 健康检查 |
| GET | `/rules` | 获取规则 |
| GET | `/connections` | 获取连接 |
| DELETE | `/connections` | 关闭所有连接 |
| DELETE | `/connections/:id` | 关闭指定连接 |
| GET | `/group/:name` | 获取组信息 |
| GET | `/group/:name/delay` | 组延迟测试 |

### 2.4 代理信息

```go
// experimental/clashapi/proxies.go

type ProxyInfo struct {
    Type    string   `json:"type"`
    Name    string   `json:"name"`
    UDP     bool     `json:"udp"`
    History []Delay  `json:"history"`
    All     []string `json:"all,omitempty"`  // 组
    Now     string   `json:"now,omitempty"`  // 当前选择
}

type Delay struct {
    Time  int64 `json:"time"`   // Unix 时间戳
    Delay int   `json:"delay"`  // 延迟 (ms)
}
```

### 2.5 连接追踪

```go
// experimental/clashapi/trafficontrol/manager.go

type Manager struct {
    connections sync.Map
    ticker      *time.Ticker
    snapshot    *Snapshot
}

type TrackerMetadata struct {
    ID          string    `json:"id"`
    Metadata    Metadata  `json:"metadata"`
    Upload      int64     `json:"upload"`
    Download    int64     `json:"download"`
    Start       time.Time `json:"start"`
    Chains      []string  `json:"chains"`
    Rule        string    `json:"rule"`
    RulePayload string    `json:"rulePayload"`
}
```

---

## 3. V2Ray API

### 3.1 概述

V2Ray API 提供 gRPC 接口用于：
- 流量统计
- 用户管理

### 3.2 服务器实现

```go
// experimental/v2rayapi/server.go

type Server struct {
    logger       log.Logger
    listen       string
    grpcServer   *grpc.Server
    statsService *StatsService
}

func NewServer(logger log.Logger, options option.V2RayAPIOptions) (*Server, error)
```

### 3.3 统计服务

```go
// experimental/v2rayapi/stats.go

type StatsService struct {
    createdAt  time.Time
    inbounds   map[string]bool
    outbounds  map[string]bool
    users      map[string]bool
    access     sync.Mutex
    counters   map[string]*atomic.Int64
}

// gRPC 方法
func (s *StatsService) GetStats(ctx context.Context, 
                                 request *GetStatsRequest) (*GetStatsResponse, error)
func (s *StatsService) QueryStats(ctx context.Context,
                                   request *QueryStatsRequest) (*QueryStatsResponse, error)
```

---

## 4. 缓存文件

### 4.1 概述

缓存文件用于持久化：
- FakeIP 映射
- 选择的代理
- 规则集缓存
- RDRC (Reject DNS Response Cache)
- Clash 模式

### 4.2 实现

```go
// experimental/cachefile/cache.go

type CacheFile struct {
    ctx  context.Context
    path string
    db   *bbolt.DB
}

func New(ctx context.Context, options option.CacheFileOptions) *CacheFile

// Buckets
const (
    bucketFakeIP    = "fakeip"
    bucketSelected  = "selected"
    bucketExpand    = "group_expand"
    bucketRuleSet   = "rule_set"
    bucketRDRC      = "rdrc"
    bucketMode      = "mode"
)

// 方法
func (c *CacheFile) LoadFakeIP() *fakeip.Memory
func (c *CacheFile) SaveFakeIP(memory *fakeip.Memory) error
func (c *CacheFile) LoadSelected(group string) string
func (c *CacheFile) StoreSelected(group string, selected string) error
func (c *CacheFile) LoadMode() string
func (c *CacheFile) StoreMode(mode string) error
func (c *CacheFile) LoadRuleSet(tag string) *adapter.SavedBinary
func (c *CacheFile) SaveRuleSet(tag string, content *adapter.SavedBinary) error
```

---

## 5. libbox - 移动平台库

### 5.1 概述

libbox 为 Android/iOS 提供 Gomobile 绑定。

### 5.2 目录结构

```
libbox/
├── build_info.go           # 构建信息
├── command*.go             # IPC 命令
├── config.go               # 配置处理
├── deprecated.go           # 废弃警告
├── dns.go                  # DNS 工具
├── http.go                 # HTTP 客户端
├── iterator.go             # 迭代器
├── log.go                  # 日志
├── memory.go               # 内存信息
├── monitor.go              # 状态监控
├── platform.go             # 平台接口
├── service.go              # 后台服务
├── setup.go                # 初始化
├── tun.go                  # TUN 支持
└── platform/               # 平台特定接口
    └── interface.go
```

### 5.3 平台接口

```go
// experimental/libbox/platform/interface.go

type Interface interface {
    // 系统相关
    UsePlatformAutoDetectInterfaceControl() bool
    AutoDetectInterfaceControl(fd int32) error
    OpenTun(options *tun.Options, platformOptions option.TunPlatformOptions) (tun.Tun, error)
    UsePlatformDefaultInterfaceMonitor() bool
    CreateDefaultInterfaceMonitor(logger logger.Logger) tun.DefaultInterfaceMonitor
    UsePlatformInterfaceGetter() bool
    Interfaces() ([]adapter.NetworkInterface, error)
    UnderNetworkExtension() bool
    IncludeAllNetworks() bool
    ClearDNSCache()
    
    // Android 特定
    ReadWIFIState() adapter.WIFIState
    
    // 进程查找
    FindProcessInfo(ctx context.Context, network string, 
                    source netip.AddrPort, destination netip.AddrPort) (*process.Info, error)
}
```

### 5.4 服务

```go
// experimental/libbox/service.go

type BoxService struct {
    ctx          context.Context
    cancel       context.CancelFunc
    instance     *box.Box
    pauseManager pause.Manager
    urlTestHistory *urltest.HistoryStorage
}

func NewService(configContent string, platformInterface PlatformInterface) (*BoxService, error)
func (s *BoxService) Start() error
func (s *BoxService) Close() error
func (s *BoxService) Sleep()     // 进入后台
func (s *BoxService) Wake()      // 返回前台
```

### 5.5 命令系统

libbox 使用 IPC 进行状态查询：

```go
// experimental/libbox/command.go

type CommandClient struct {
    conn      net.Conn
    options   CommandClientOptions
}

type CommandServer struct {
    listener  net.Listener
    handler   CommandServerHandler
}

// 命令类型
const (
    CommandLog          = 1
    CommandStatus       = 2
    CommandConnections  = 3
    CommandCloseConnection = 4
    CommandConntrack    = 5
    CommandGroup        = 6
    CommandSelectOutbound = 7
    CommandURLTest      = 8
    CommandDeprecatedReport = 9
    CommandClashMode    = 10
    CommandSetClashMode = 11
    CommandSystemProxy  = 12
    CommandPower        = 13
)
```

---

## 6. 废弃功能管理

```go
// experimental/deprecated/manager.go

type Manager struct {
    logger logger.Logger
    reported map[string]bool
}

func Report(ctx context.Context, feature Feature) {
    manager := service.FromContext[*Manager](ctx)
    if manager == nil {
        return
    }
    manager.report(feature)
}

type Feature struct {
    Name        string
    Description string
    Version     string  // 废弃版本
}
```

---

## 7. 本地化

```go
// experimental/locale/locale.go

var (
    ErrorUnsupportedPlatform = "unsupported platform"
    ErrorMissingOption       = "missing option: %s"
    // ...
)

func SetLocale(locale string) {
    switch locale {
    case "zh-CN":
        setChineseSimplified()
    case "zh-TW":
        setChineseTraditional()
    // ...
    }
}
```

---

## 8. 服务层 (service/)

### 8.1 目录结构

```
service/
├── derp/           # Tailscale DERP 服务
├── resolved/       # systemd-resolved 集成
└── ssmapi/         # SSM API 服务
```

### 8.2 Resolved 服务

与 systemd-resolved 集成：

```go
// service/resolved/service.go

type Service struct {
    ctx         context.Context
    logger      logger.Logger
    conn        *dbus.Conn
    linkIndex   int
    domains     []string
    servers     []netip.Addr
}

func (s *Service) SetDNS(domains []string, servers []netip.Addr) error
func (s *Service) ResetDNS() error
```

### 8.3 DERP 服务

Tailscale DERP 中继服务：

```go
// service/derp/service.go

type Service struct {
    ctx         context.Context
    logger      logger.Logger
    server      *derphttp.Server
}

func NewService(ctx context.Context, logger logger.Logger, 
                options option.DERPServiceOptions) (*Service, error)
```
