# DNS 系统 (dns/)

## 1. 目录结构

```
dns/
├── client.go                  # DNS 客户端
├── client_log.go              # 客户端日志
├── client_truncate.go         # 响应截断处理
├── extension_edns0_subnet.go  # EDNS Client Subnet
├── rcode.go                   # DNS 响应码
├── router.go                  # DNS 路由器
├── transport_adapter.go       # 传输适配器
├── transport_dialer.go        # 传输拨号器
├── transport_manager.go       # 传输管理器
├── transport_registry.go      # 传输注册
└── transport/                 # DNS 传输实现
    ├── dhcp/                  # DHCP DNS
    ├── fakeip/                # FakeIP
    ├── hosts/                 # Hosts 文件
    ├── local/                 # 本地 DNS
    ├── quic/                  # DNS over QUIC (DoQ)
    ├── https.go               # DNS over HTTPS (DoH)
    ├── https_transport.go     # DoH 传输
    ├── tcp.go                 # DNS over TCP
    ├── tls.go                 # DNS over TLS (DoT)
    └── udp.go                 # DNS over UDP
```

---

## 2. DNS 路由器

### 2.1 结构定义

```go
// dns/router.go

type Router struct {
    ctx               context.Context
    logger            log.ContextLogger
    client            adapter.DNSClient
    transportManager  adapter.DNSTransportManager
    outbound          adapter.OutboundManager
    rules             []adapter.DNSRule       // DNS 规则
    ruleSets          []adapter.RuleSet
    ruleSetMap        map[string]adapter.RuleSet
    defaultTransport  adapter.DNSTransport
    defaultDomainStrategy C.DomainStrategy
    disableCache      bool
    disableCacheExpire bool
    independentCache  bool
    cacheCapacity     uint32
    rdrc              adapter.RDRCStore       // Reject DNS Response Cache
    clientSubnet      netip.Prefix
}
```

### 2.2 DNS 查询

```go
// dns/router.go

func (r *Router) Exchange(ctx context.Context, message *dns.Msg, 
                          options adapter.DNSQueryOptions) (*dns.Msg, error) {
    // 1. 匹配 DNS 规则
    transport, action := r.matchDNSRule(ctx, &metadata)
    
    // 2. 处理动作
    switch action := action.(type) {
    case *rule.RuleActionReject:
        return nil, action.Error(ctx)
    case *rule.RuleActionRejectDNS:
        return r.handleReject(message, action)
    }
    
    // 3. 使用选定的传输查询
    return r.client.Exchange(ctx, transport, message, options, nil)
}

func (r *Router) Lookup(ctx context.Context, domain string, 
                        options adapter.DNSQueryOptions) ([]netip.Addr, error) {
    // 便捷方法，将域名查询转换为 DNS 消息
    message := &dns.Msg{}
    message.SetQuestion(dns.Fqdn(domain), dns.TypeA)  // 或 TypeAAAA
    
    response, err := r.Exchange(ctx, message, options)
    // 解析 A/AAAA 记录
    return parseAddresses(response)
}
```

---

## 3. DNS 客户端

```go
// dns/client.go

type Client struct {
    ctx                context.Context
    logger             log.ContextLogger
    cache              *cache.LRUCache[dns.Question, *dns.Msg]
    disableCache       bool
    disableCacheExpire bool
    independentCache   bool
}

func (c *Client) Exchange(ctx context.Context, transport adapter.DNSTransport,
                          message *dns.Msg, options adapter.DNSQueryOptions,
                          responseChecker func(responseAddrs []netip.Addr) bool) (*dns.Msg, error) {
    // 1. 检查缓存
    if !options.DisableCache {
        if cached := c.lookupCache(message.Question[0]); cached != nil {
            return cached, nil
        }
    }
    
    // 2. 添加 EDNS Client Subnet
    if options.ClientSubnet.IsValid() {
        addEDNSClientSubnet(message, options.ClientSubnet)
    }
    
    // 3. 执行查询
    response, err := transport.Exchange(ctx, message)
    
    // 4. 检查响应
    if responseChecker != nil {
        addrs := parseAddresses(response)
        if !responseChecker(addrs) {
            return nil, E.New("response rejected by checker")
        }
    }
    
    // 5. 存入缓存
    if !options.DisableCache && response.Rcode == dns.RcodeSuccess {
        c.storeCache(message.Question[0], response, options.RewriteTTL)
    }
    
    return response, nil
}
```

---

## 4. DNS 传输

### 4.1 传输接口

```go
// adapter/dns.go

type DNSTransport interface {
    Lifecycle
    Type() string
    Tag() string
    Dependencies() []string
    Exchange(ctx context.Context, message *dns.Msg) (*dns.Msg, error)
}
```

### 4.2 UDP 传输

```go
// dns/transport/udp.go

type UDPTransport struct {
    name       string
    ctx        context.Context
    dialer     N.Dialer
    serverAddr M.Socksaddr
    timeout    time.Duration
}

func (t *UDPTransport) Exchange(ctx context.Context, message *dns.Msg) (*dns.Msg, error) {
    // 1. 序列化 DNS 消息
    buffer, err := message.Pack()
    
    // 2. 建立 UDP 连接
    conn, err := t.dialer.DialContext(ctx, N.NetworkUDP, t.serverAddr)
    
    // 3. 发送请求
    conn.Write(buffer)
    
    // 4. 接收响应
    responseBuffer := make([]byte, 65535)
    n, err := conn.Read(responseBuffer)
    
    // 5. 解析响应
    response := new(dns.Msg)
    response.Unpack(responseBuffer[:n])
    
    return response, nil
}
```

### 4.3 TCP 传输

```go
// dns/transport/tcp.go

type TCPTransport struct {
    name       string
    ctx        context.Context
    dialer     N.Dialer
    serverAddr M.Socksaddr
    timeout    time.Duration
}

func (t *TCPTransport) Exchange(ctx context.Context, message *dns.Msg) (*dns.Msg, error) {
    // TCP DNS 使用 2 字节长度前缀
    conn, err := t.dialer.DialContext(ctx, N.NetworkTCP, t.serverAddr)
    
    // 写入长度 + 消息
    buffer, _ := message.Pack()
    length := make([]byte, 2)
    binary.BigEndian.PutUint16(length, uint16(len(buffer)))
    conn.Write(length)
    conn.Write(buffer)
    
    // 读取响应
    // ...
}
```

### 4.4 DoT (DNS over TLS)

```go
// dns/transport/tls.go

type TLSTransport struct {
    TCPTransport
    tlsConfig tls.Config
}

func (t *TLSTransport) Exchange(ctx context.Context, message *dns.Msg) (*dns.Msg, error) {
    // 1. 建立 TLS 连接
    conn, err := t.dialer.DialContext(ctx, N.NetworkTCP, t.serverAddr)
    tlsConn := tls.Client(conn, t.tlsConfig.STDConfig())
    tlsConn.Handshake()
    
    // 2. 使用 TCP 协议发送 DNS 请求
    // ...
}
```

### 4.5 DoH (DNS over HTTPS)

```go
// dns/transport/https.go

type HTTPSTransport struct {
    name         string
    ctx          context.Context
    dialer       N.Dialer
    serverAddr   M.Socksaddr
    serverURL    *url.URL
    httpClient   *http.Client
    headers      http.Header
}

func (t *HTTPSTransport) Exchange(ctx context.Context, message *dns.Msg) (*dns.Msg, error) {
    // 1. 序列化 DNS 消息
    buffer, _ := message.Pack()
    
    // 2. 创建 HTTP POST 请求
    request, _ := http.NewRequestWithContext(ctx, "POST", t.serverURL.String(), 
                                              bytes.NewReader(buffer))
    request.Header.Set("Content-Type", "application/dns-message")
    request.Header.Set("Accept", "application/dns-message")
    
    // 3. 发送请求
    response, err := t.httpClient.Do(request)
    
    // 4. 读取响应
    responseBody, _ := io.ReadAll(response.Body)
    
    // 5. 解析 DNS 响应
    dnsResponse := new(dns.Msg)
    dnsResponse.Unpack(responseBody)
    
    return dnsResponse, nil
}
```

### 4.6 DoQ (DNS over QUIC)

```go
// dns/transport/quic/transport.go

type Transport struct {
    name       string
    ctx        context.Context
    dialer     N.Dialer
    serverAddr M.Socksaddr
    tlsConfig  *tls.STDConfig
    quicConfig *quic.Config
    connection quic.Connection
}

func (t *Transport) Exchange(ctx context.Context, message *dns.Msg) (*dns.Msg, error) {
    // 1. 获取/创建 QUIC 连接
    conn := t.getConnection()
    
    // 2. 打开新的 QUIC 流
    stream, err := conn.OpenStreamSync(ctx)
    
    // 3. 发送 DNS 消息（带长度前缀）
    buffer, _ := message.Pack()
    stream.Write(lengthPrefix(buffer))
    stream.CloseWrite()
    
    // 4. 读取响应
    // ...
}
```

### 4.7 FakeIP 传输

```go
// dns/transport/fakeip/server.go

type Transport struct {
    name       string
    router     adapter.Router
    store      adapter.FakeIPStore
    inet4Range netip.Prefix    // 例如 198.18.0.0/15
    inet6Range netip.Prefix    // 例如 fc00::/18
}

func (t *Transport) Exchange(ctx context.Context, message *dns.Msg) (*dns.Msg, error) {
    question := message.Question[0]
    
    if question.Qtype == dns.TypeA {
        // 分配 IPv4 FakeIP
        fakeIP := t.store.Lookup(question.Name, false)
        if fakeIP == nil {
            fakeIP = t.allocate(question.Name, false)
        }
        return makeResponse(message, fakeIP), nil
    }
    
    // TypeAAAA 类似处理
}
```

### 4.8 本地 DNS

```go
// dns/transport/local/transport.go

type Transport struct {
    name   string
    logger logger.Logger
}

func (t *Transport) Exchange(ctx context.Context, message *dns.Msg) (*dns.Msg, error) {
    // 使用系统 DNS 解析器
    question := message.Question[0]
    name := strings.TrimSuffix(question.Name, ".")
    
    addrs, err := net.DefaultResolver.LookupIP(ctx, networkType, name)
    
    // 构造 DNS 响应
    return makeResponse(message, addrs), nil
}
```

---

## 5. DNS 传输管理器

```go
// dns/transport_manager.go

type TransportManager struct {
    ctx               context.Context
    logger            log.ContextLogger
    registry          adapter.DNSTransportRegistry
    outboundManager   adapter.OutboundManager
    defaultTag        string
    transports        []adapter.DNSTransport
    transportMap      map[string]adapter.DNSTransport
    defaultTransport  adapter.DNSTransport
    fakeIPTransport   adapter.FakeIPTransport
}

func (m *TransportManager) Initialize(defaultTransport adapter.DNSTransport)
func (m *TransportManager) Transport(tag string) (adapter.DNSTransport, bool)
func (m *TransportManager) Default() adapter.DNSTransport
func (m *TransportManager) FakeIP() adapter.FakeIPTransport
func (m *TransportManager) Create(...) error
func (m *TransportManager) Remove(tag string) error
```

---

## 6. DNS 规则

### 6.1 DNS 规则接口

```go
// adapter/rule.go

type DNSRule interface {
    Type() string
    Action() RuleAction
    Match(metadata *InboundContext) bool
    String() string
}
```

### 6.2 DNS 规则实现

```go
// route/rule/rule_dns.go

type DNSRule struct {
    abstractDefaultRule
    allItems []RuleItem
}

func NewDNSRule(ctx context.Context, logger log.ContextLogger, 
                options option.DNSRule) (adapter.DNSRule, error)
```

### 6.3 DNS 规则条件

DNS 规则支持的条件与路由规则类似，但有一些特定条件：

- `query_type`: A, AAAA, CNAME, MX, TXT 等
- `domain`, `domain_suffix`, `domain_keyword`, `domain_regex`
- `geosite`
- `rule_set`
- `client_subnet`

### 6.4 DNS 规则动作

```go
// route/rule/rule_action.go

// 路由到指定 DNS 传输
type RuleActionRoute struct {
    Outbound string  // DNS 传输标签
}

// 拒绝 DNS 查询
type RuleActionRejectDNS struct {
    Method C.RuleActionRejectDNSMethod  // success / refused / nxdomain / dropped
    NoDrop bool
}

// 返回预设响应
type RuleActionDNSRouteOptions struct {
    DisableCache bool
    RewriteTTL   *uint32
    ClientSubnet netip.Prefix
}
```

---

## 7. FakeIP

### 7.1 概念

FakeIP 为域名分配虚假 IP 地址，用于实现透明代理时保留域名信息。

### 7.2 存储接口

```go
// adapter/fakeip.go

type FakeIPStore interface {
    FakeIPMetadata
    Lookup(domain string, isIPv6 bool) netip.Addr    // 域名 -> FakeIP
    ReverseLookup(ip netip.Addr) (string, bool)      // FakeIP -> 域名
    Reset() error
}

type FakeIPMetadata interface {
    Inet4Range() netip.Prefix  // IPv4 范围
    Inet6Range() netip.Prefix  // IPv6 范围
}
```

### 7.3 FakeIP 工作流程

```
[客户端 DNS 查询]
       ↓
[FakeIP 传输分配假IP]
       ↓
[客户端使用假IP发起连接]
       ↓
[TUN 截获连接]
       ↓
[反向查询恢复域名]
       ↓
[使用真实域名路由]
```

---

## 8. RDRC (Reject DNS Response Cache)

用于缓存被拒绝的 DNS 响应，避免重复查询：

```go
// adapter/dns.go

type RDRCStore interface {
    LoadRDRC(transportName string, qName string, qType uint16) (rejected bool)
    SaveRDRC(transportName string, qName string, qType uint16) error
    SaveRDRCAsync(transportName string, qName string, qType uint16, logger logger.Logger)
}
```
