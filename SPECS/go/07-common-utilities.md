# 通用工具库 (common/)

## 1. 目录结构

```
common/
├── badtls/        # 不安全 TLS 配置
├── badversion/    # 版本检查
├── certificate/   # 证书管理
├── compatible/    # 兼容性处理
├── conntrack/     # 连接追踪
├── convertor/     # 类型转换
├── dialer/        # 网络拨号器
├── geoip/         # GeoIP 数据库
├── geosite/       # GeoSite 数据库
├── interrupt/     # 中断控制
├── ja3/           # JA3 指纹
├── listener/      # 网络监听器
├── mux/           # 多路复用
├── pipelistener/  # 管道监听器
├── process/       # 进程查找
├── redir/         # 重定向代理
├── settings/      # 系统设置
├── sniff/         # 协议嗅探
├── srs/           # SRS 规则格式
├── taskmonitor/   # 任务监控
├── tls/           # TLS 配置
├── tlsfragment/   # TLS 分片
├── uot/           # UDP over TCP
└── urltest/       # URL 测试
```

---

## 2. 核心工具

### 2.1 dialer/ - 网络拨号器

网络拨号的核心抽象，支持各种出站选项：

```go
// common/dialer/dialer.go

type Options struct {
    BindInterface       string
    BindAddress         netip.Addr
    RoutingMark        uint32
    ReuseAddr          bool
    ConnectTimeout     time.Duration
    TCPFastOpen        bool
    TCPMultiPath       bool
    UDPFragment        *bool
    UDPFragmentDefault bool
    DomainStrategy     C.DomainStrategy
    FallbackDelay      time.Duration
    NetworkStrategy    *C.NetworkStrategy
    NetworkType        []C.InterfaceType
    FallbackNetworkType []C.InterfaceType
    IsWireGuardListener bool
}

func New(ctx context.Context, options option.DialerOptions, 
         remoteIsDomain bool) (N.Dialer, error)
```

**支持功能**：
- 接口绑定 (`bind_interface`)
- 地址绑定 (`bind_address`)
- 路由标记 (`routing_mark`)
- TCP Fast Open
- Multipath TCP
- Happy Eyeballs（双栈优先）
- 域名解析策略

### 2.2 sniff/ - 协议嗅探

自动检测连接的应用层协议：

```go
// common/sniff/sniff.go

type Sniffer func(ctx context.Context, metadata *adapter.InboundContext, 
                  reader io.Reader) error

var Sniffers = map[string]Sniffer{
    "tls":        TLS,
    "http":       HTTP,
    "quic":       QUIC,
    "stun":       STUN,
    "dns":        DNS,
    "bittorrent": BitTorrent,
    "dtls":       DTLS,
    "ssh":        SSH,
    "rdp":        RDP,
}
```

**支持的协议**：

| 协议 | 文件 | 检测方法 |
|------|------|----------|
| HTTP | `http.go` | 请求行特征 |
| TLS | `tls.go` | ClientHello |
| QUIC | `quic.go` | QUIC 头部 + CRYPTO 帧 |
| DNS | `dns.go` | DNS 消息格式 |
| STUN | `stun.go` | STUN 消息头 |
| BitTorrent | `bittorrent.go` | 握手协议 |
| DTLS | `dtls.go` | DTLS 记录头 |
| SSH | `ssh.go` | SSH 版本字符串 |
| RDP | `rdp.go` | RDP 连接请求 |
| NTP | `ntp.go` | NTP 消息格式 |

### 2.3 tls/ - TLS 配置

统一的 TLS 配置管理：

```go
// common/tls/config.go

type Config interface {
    ServerName() string
    SetServerName(serverName string)
    NextProtos() []string
    SetNextProtos(nextProto []string)
    Config() (*tls.STDConfig, error)
    Client(conn net.Conn) (Conn, error)
    Clone() Config
}

// 标准 TLS
type STDConfig struct {
    config *tls.Config
}

// uTLS (指纹模拟)
type UTLSConfig struct {
    config *utls.Config
    id     utls.ClientHelloID
}
```

**uTLS 支持的指纹**：
- Chrome (各版本)
- Firefox (各版本)
- Safari
- iOS
- Edge
- Random
- Custom

### 2.4 geoip/ - GeoIP 支持

IP 地理位置查询：

```go
// common/geoip/reader.go

type Reader struct {
    reader *maxminddb.Reader
}

func (r *Reader) Lookup(ip netip.Addr) string {
    var record struct {
        Country struct {
            IsoCode string `maxminddb:"iso_code"`
        } `maxminddb:"country"`
    }
    r.reader.Lookup(ip.AsSlice(), &record)
    return record.Country.IsoCode
}
```

### 2.5 geosite/ - GeoSite 支持

域名分类数据库：

```go
// common/geosite/reader.go

type Reader struct {
    domainMatcher map[string]*domain.Matcher
}

func (r *Reader) Match(tag string, domain string) bool {
    matcher, ok := r.domainMatcher[tag]
    if !ok {
        return false
    }
    return matcher.Match(domain)
}
```

### 2.6 process/ - 进程查找

通过连接信息查找进程：

```go
// common/process/searcher.go

type Config struct {
    Logger         logger.Logger
    PackageManager tun.PackageManager
}

type Searcher interface {
    FindProcessInfo(ctx context.Context, network string, 
                    source netip.AddrPort, destination netip.AddrPort) (*Info, error)
}

type Info struct {
    ProcessPath string
    PackageName string  // Android
    User        string
    UserId      int32
}
```

**平台支持**：
- Linux: `/proc/net/tcp`、`/proc/net/udp`
- macOS: `lsof`
- Windows: `GetExtendedTcpTable`
- Android: 包管理器

### 2.7 mux/ - 多路复用

在单个连接上复用多个流：

```go
// common/mux/client.go

type Client struct {
    dialer        N.Dialer
    logger        logger.Logger
    protocol      Protocol    // smux / yamux / h2mux
    maxConnections int
    minStreams     int
    maxStreams     int
    padding        bool
    brutal         BrutalOptions
    connections    []*clientConnection
}

func (c *Client) DialContext(ctx context.Context, network string, 
                             destination M.Socksaddr) (net.Conn, error) {
    // 1. 获取或创建多路复用连接
    // 2. 在多路复用连接上打开新流
    // 3. 发送目标地址
    // 4. 返回流连接
}
```

**支持的协议**：
- SMux
- YAMux
- H2Mux

### 2.8 conntrack/ - 连接追踪

连接追踪和统计：

```go
// common/conntrack/tracker.go

type Tracker struct {
    connections sync.Map  // map[*trackedConn]struct{}
}

type Connection interface {
    ID() ID
    Metadata() Metadata
    Chains() []string
    Upload() int64
    Download() int64
    Start() time.Time
    Close() error
}

func (t *Tracker) TrackConnection(conn net.Conn, metadata adapter.InboundContext, 
                                   rule adapter.Rule, outbound adapter.Outbound) net.Conn
```

### 2.9 certificate/ - 证书管理

自定义证书存储：

```go
// common/certificate/store.go

type Store struct {
    ctx        context.Context
    logger     logger.Logger
    rootCAPool *x509.CertPool
    watcher    *fswatch.Watcher
}

func NewStore(ctx context.Context, logger logger.Logger, 
              options option.CertificateOptions) (*Store, error)

func (s *Store) RootCAs() *x509.CertPool
```

### 2.10 interrupt/ - 中断控制

优雅的连接中断：

```go
// common/interrupt/group.go

type Group struct {
    access sync.Mutex
    conns  map[net.Conn]struct{}
}

func (g *Group) Add(conn net.Conn)
func (g *Group) Remove(conn net.Conn)
func (g *Group) Interrupt()  // 关闭所有连接
```

### 2.11 urltest/ - URL 测试

延迟测试工具：

```go
// common/urltest/urltest.go

type Group struct {
    ctx        context.Context
    router     adapter.Router
    outbounds  []adapter.Outbound
    link       string
    interval   time.Duration
    tolerance  uint16
    history    *HistoryStorage
}

func (g *Group) URLTest(ctx context.Context, 
                        outbound adapter.Outbound) (uint16, error) {
    // 发送 HTTP 请求测量延迟
}

type HistoryStorage struct {
    history map[string][]URLTestHistory
}

type URLTestHistory struct {
    Time  time.Time
    Delay uint16
}
```

### 2.12 tlsfragment/ - TLS 分片

TLS 记录分片用于绕过 DPI：

```go
// common/tlsfragment/conn.go

type Conn struct {
    net.Conn
    fallbackDelay time.Duration
    recordFragment bool
    firstWrite     bool
}

func (c *Conn) Write(b []byte) (n int, err error) {
    if c.firstWrite && isTLSClientHello(b) {
        // 将 ClientHello 分成多个小片段发送
        return c.writeFragmented(b)
    }
    return c.Conn.Write(b)
}
```

### 2.13 listener/ - 网络监听器

统一的监听器创建：

```go
// common/listener/listener.go

func New(ctx context.Context, options option.ListenOptions, 
         tlsConfig tls.ServerConfig) (net.Listener, error)

func ListenSerial(ctx context.Context, 
                  options option.ListenOptions, 
                  tlsConfig tls.ServerConfig) (net.Listener, error)

func ListenUDP(ctx context.Context, 
               options option.ListenOptions) (net.PacketConn, error)
```

### 2.14 taskmonitor/ - 任务监控

启动任务超时监控：

```go
// common/taskmonitor/monitor.go

type Monitor struct {
    logger  log.ContextLogger
    timeout time.Duration
    timer   *time.Timer
    task    string
}

func New(logger log.ContextLogger, timeout time.Duration) *Monitor

func (m *Monitor) Start(taskName ...any) {
    m.task = fmt.Sprint(taskName...)
    m.timer = time.AfterFunc(m.timeout, func() {
        m.logger.Warn("task ", m.task, " is taking too long")
    })
}

func (m *Monitor) Finish() {
    m.timer.Stop()
}
```

### 2.15 srs/ - SRS 规则格式

sing-box Rule Set 格式处理：

```go
// common/srs/binary.go

func Read(reader io.Reader, recovery bool) ([]option.PlainRuleSetItem, error)
func Write(writer io.Writer, items []option.PlainRuleSetItem) error

// common/srs/compile.go

func Compile(items []option.PlainRuleSetItem) ([]adapter.HeadlessRule, error)
```

---

## 3. 平台相关

### 3.1 redir/ - 重定向代理

Linux 透明代理支持：

```go
// common/redir/redirect.go

func GetOriginalDestination(conn net.Conn) (netip.AddrPort, error)

// common/redir/tproxy.go

func GetOriginalDestinationFromOOB(oob []byte) (netip.AddrPort, error)
```

### 3.2 settings/ - 系统设置

系统代理设置：

```go
// common/settings/proxy_darwin.go
// common/settings/proxy_windows.go
// common/settings/proxy_linux.go

func SetSystemProxy(proxy *SystemProxy) error
func ClearSystemProxy() error
```

---

## 4. 安全相关

### 4.1 badtls/ - 不安全 TLS

允许不安全的 TLS 配置：

```go
// common/badtls/badtls.go

func NewTLSConfig() *tls.Config {
    return &tls.Config{
        InsecureSkipVerify: true,
        MinVersion:         tls.VersionTLS10,
        CipherSuites:       weakCipherSuites,
    }
}
```

### 4.2 ja3/ - JA3 指纹

JA3/JA3S 指纹生成：

```go
// common/ja3/ja3.go

func FromClientHello(clientHello []byte) string

type Fingerprint struct {
    SSLVersion       uint16
    Ciphers          []uint16
    Extensions       []uint16
    EllipticCurves   []uint16
    EllipticPoints   []uint8
}
```
