# 协议实现层 (protocol/)

## 1. 目录结构

```
protocol/
├── anytls/          # AnyTLS 协议
├── block/           # Block 伪协议（丢弃流量）
├── direct/          # Direct 直连
├── dns/             # DNS 出站
├── group/           # 出站组（Selector/URLTest）
├── http/            # HTTP 代理
├── hysteria/        # Hysteria 协议
├── hysteria2/       # Hysteria2 协议
├── mixed/           # Mixed (HTTP+SOCKS)
├── naive/           # NaiveProxy
├── redirect/        # 透明代理 Redirect/TProxy
├── shadowsocks/     # Shadowsocks
├── shadowtls/       # ShadowTLS
├── socks/           # SOCKS4/5 代理
├── ssh/             # SSH 隧道
├── tailscale/       # Tailscale 集成
├── tor/             # Tor 网络
├── trojan/          # Trojan 协议
├── tuic/            # TUIC 协议
├── tun/             # TUN 设备
├── vless/           # VLESS 协议
├── vmess/           # VMess 协议
└── wireguard/       # WireGuard VPN
```

---

## 2. 协议分类

### 2.1 入站协议 (Inbound)

| 协议 | 文件 | 描述 |
|------|------|------|
| TUN | `tun/inbound.go` | TUN 虚拟网卡，截获系统流量 |
| Redirect | `redirect/redirect.go` | Linux 透明代理 (iptables REDIRECT) |
| TProxy | `redirect/tproxy.go` | Linux 透明代理 (iptables TPROXY) |
| SOCKS | `socks/inbound.go` | SOCKS4/4a/5 代理服务器 |
| HTTP | `http/inbound.go` | HTTP/HTTPS 代理服务器 |
| Mixed | `mixed/inbound.go` | HTTP + SOCKS 混合代理 |
| Shadowsocks | `shadowsocks/inbound.go` | Shadowsocks 服务端 |
| VMess | `vmess/inbound.go` | VMess 服务端 |
| VLESS | `vless/inbound.go` | VLESS 服务端 |
| Trojan | `trojan/inbound.go` | Trojan 服务端 |
| Naive | `naive/inbound.go` | NaiveProxy 服务端 |
| Hysteria | `hysteria/inbound.go` | Hysteria 服务端 |
| Hysteria2 | `hysteria2/inbound.go` | Hysteria2 服务端 |
| TUIC | `tuic/inbound.go` | TUIC 服务端 |
| ShadowTLS | `shadowtls/inbound.go` | ShadowTLS 服务端 |
| AnyTLS | `anytls/inbound.go` | AnyTLS 服务端 |
| Direct | `direct/inbound.go` | 直接转发入站 |

### 2.2 出站协议 (Outbound)

| 协议 | 文件 | 描述 |
|------|------|------|
| Direct | `direct/outbound.go` | 直连出站 |
| Block | `block/outbound.go` | 阻止/丢弃流量 |
| DNS | `dns/outbound.go` | DNS 查询出站 |
| SOCKS | `socks/outbound.go` | SOCKS 代理客户端 |
| HTTP | `http/outbound.go` | HTTP 代理客户端 |
| Shadowsocks | `shadowsocks/outbound.go` | Shadowsocks 客户端 |
| VMess | `vmess/outbound.go` | VMess 客户端 |
| VLESS | `vless/outbound.go` | VLESS 客户端 |
| Trojan | `trojan/outbound.go` | Trojan 客户端 |
| Hysteria | `hysteria/outbound.go` | Hysteria 客户端 |
| Hysteria2 | `hysteria2/outbound.go` | Hysteria2 客户端 |
| TUIC | `tuic/outbound.go` | TUIC 客户端 |
| ShadowTLS | `shadowtls/outbound.go` | ShadowTLS 客户端 |
| SSH | `ssh/outbound.go` | SSH 隧道客户端 |
| Tor | `tor/outbound.go` | Tor 网络客户端 |
| WireGuard | `wireguard/outbound.go` | WireGuard 出站 |
| AnyTLS | `anytls/outbound.go` | AnyTLS 客户端 |

### 2.3 端点协议 (Endpoint)

| 协议 | 文件 | 描述 |
|------|------|------|
| WireGuard | `wireguard/endpoint.go` | WireGuard 端点 |
| Tailscale | `tailscale/endpoint.go` | Tailscale 端点 |

### 2.4 出站组 (Group)

| 类型 | 文件 | 描述 |
|------|------|------|
| Selector | `group/selector.go` | 手动选择出站 |
| URLTest | `group/urltest.go` | 自动测速选择 |

---

## 3. 协议详解

### 3.1 TUN 入站 (protocol/tun/)

TUN 是核心入站之一，用于截获系统所有网络流量：

```go
// protocol/tun/inbound.go

type Inbound struct {
    tag            string
    ctx            context.Context
    router         adapter.Router
    networkManager adapter.NetworkManager
    logger         log.ContextLogger
    inboundOptions option.InboundOptions
    tunOptions     tun.Options        // TUN 配置
    udpTimeout     time.Duration
    stack          string             // gvisor / system / lwip
    tunIf          tun.Tun            // TUN 接口
    tunStack       tun.Stack          // 网络栈
    platformInterface platform.Interface
    platformOptions   option.TunPlatformOptions
    autoRedirect      tun.AutoRedirect  // 自动重定向
    routeRuleSet      []adapter.RuleSet // 路由规则集
    routeAddressSet   []*netipx.IPSet
}

func RegisterInbound(registry *inbound.Registry) {
    inbound.Register[option.TunInboundOptions](registry, C.TypeTun, NewInbound)
}
```

**核心功能**：
- 创建 TUN 虚拟网卡
- 选择网络栈（gVisor 用户态栈 / system 系统栈）
- 支持自动路由和自动重定向
- 处理 IPv4/IPv6 地址和路由

### 3.2 Shadowsocks (protocol/shadowsocks/)

```go
// protocol/shadowsocks/outbound.go

type Outbound struct {
    outbound.Adapter
    logger          logger.ContextLogger
    dialer          N.Dialer
    method          shadowsocks.Method   // 加密方法
    serverAddr      M.Socksaddr
    plugin          sip003.Plugin        // SIP003 插件
    uotClient       *uot.Client          // UDP over TCP
    multiplexDialer *mux.Client          // 多路复用
}

func NewOutbound(ctx context.Context, router adapter.Router, 
                 logger log.ContextLogger, tag string, 
                 options option.ShadowsocksOutboundOptions) (adapter.Outbound, error)
```

**支持的加密方法**：
- AEAD: `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`
- AEAD-2022: `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`, `2022-blake3-chacha20-poly1305`

**入站支持**：
- 单用户模式 (`inbound.go`)
- 多用户模式 (`inbound_multi.go`)
- 中继模式 (`inbound_relay.go`)

### 3.3 VMess (protocol/vmess/)

```go
// protocol/vmess/inbound.go

type Inbound struct {
    service     *vmess.Service[int]
    users       []option.VMessUser
    // TLS 和传输配置
}

// protocol/vmess/outbound.go

type Outbound struct {
    outbound.Adapter
    client          *vmess.Client
    serverAddr      M.Socksaddr
    multiplexDialer *mux.Client
    tlsConfig       tls.Config
    transport       adapter.V2RayClientTransport
    packetAddr      bool
    xudp            bool
}
```

### 3.4 WireGuard (protocol/wireguard/)

```go
// protocol/wireguard/endpoint.go

type Endpoint struct {
    tag        string
    ctx        context.Context
    logger     logger.ContextLogger
    localAddr  []netip.Prefix
    device     *device.Device
    tunDevice  wireguard.Device
    natDevice  wireguard.NatDevice
    listener   *device.IpcListener
}

// protocol/wireguard/outbound.go

type Outbound struct {
    outbound.Adapter
    // 通过 endpoint 提供的 device 进行通信
}
```

### 3.5 出站组 (protocol/group/)

**Selector** - 手动选择：
```go
// protocol/group/selector.go

type Selector struct {
    outbound.Adapter
    ctx          context.Context
    outbound     adapter.OutboundManager
    connection   adapter.ConnectionManager
    logger       logger.ContextLogger
    tags         []string           // 可选出站列表
    defaultTag   string
    selected     adapter.Outbound   // 当前选中
    interruptGroup *interrupt.Group
}

func (s *Selector) SelectOutbound(tag string) bool
```

**URLTest** - 自动测速：
```go
// protocol/group/urltest.go

type URLTest struct {
    outbound.Adapter
    ctx            context.Context
    outboundManager adapter.OutboundManager
    logger          logger.ContextLogger
    tags            []string
    link            string           // 测试 URL
    interval        time.Duration    // 测试间隔
    tolerance       uint16           // 容差值
    group           *urltest.Group
}
```

---

## 4. 通用组件

### 4.1 Adapter 基类

```go
// adapter/outbound/adapter.go

type Adapter struct {
    protocol     string
    network      []string        // ["tcp", "udp"]
    tag          string
    dependencies []string
}

func NewAdapter(protocol string, tag string, network []string, dependencies []string) Adapter
func NewAdapterWithDialerOptions(protocol string, tag string, network []string, dialerOptions option.DialerOptions) Adapter
```

### 4.2 连接处理

每个入站协议接收连接后，调用路由器进行处理：

```go
// 示例：TUN 入站处理新连接
func (t *Inbound) NewConnectionEx(ctx context.Context, conn net.Conn, 
                                   source M.Socksaddr, destination M.Socksaddr, 
                                   onClose N.CloseHandlerFunc) {
    ctx = log.ContextWithNewID(ctx)
    var metadata adapter.InboundContext
    metadata.Inbound = t.tag
    metadata.InboundType = C.TypeTun
    metadata.Source = source
    metadata.Destination = destination
    metadata.InboundOptions = t.inboundOptions
    
    t.logger.InfoContext(ctx, "inbound connection from ", metadata.Source)
    t.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
    
    t.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}
```

### 4.3 出站拨号

每个出站协议实现 `N.Dialer` 接口：

```go
type Dialer interface {
    DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error)
    ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error)
}
```

---

## 5. 注册模式

所有协议通过 Register 函数注册到 Registry：

```go
// 入站注册
func RegisterInbound(registry *inbound.Registry) {
    inbound.Register[option.TunInboundOptions](registry, C.TypeTun, NewInbound)
}

// 出站注册
func RegisterOutbound(registry *outbound.Registry) {
    outbound.Register[option.ShadowsocksOutboundOptions](registry, C.TypeShadowsocks, NewOutbound)
}

// 端点注册
func RegisterEndpoint(registry *endpoint.Registry) {
    endpoint.Register[option.WireGuardEndpointOptions](registry, C.TypeWireGuard, NewEndpoint)
}
```

在 `include/registry.go` 中统一调用所有协议的注册函数。
