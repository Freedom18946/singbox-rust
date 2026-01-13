# 传输层实现 (transport/)

## 1. 目录结构

```
transport/
├── simple-obfs/      # simple-obfs 混淆
├── sip003/           # SIP003 插件系统
├── trojan/           # Trojan 传输
├── v2ray/            # V2Ray 传输适配器
├── v2raygrpc/        # gRPC 传输
├── v2raygrpclite/    # 轻量级 gRPC
├── v2rayhttp/        # HTTP/2 传输
├── v2rayhttpupgrade/ # HTTP Upgrade (WebSocket via HTTP)
├── v2rayquic/        # QUIC 传输
├── v2raywebsocket/   # WebSocket 传输
└── wireguard/        # WireGuard 传输
```

---

## 2. 传输协议概览

| 传输 | 目录 | 描述 | 支持协议 |
|------|------|------|----------|
| TCP | 基础 | 原始 TCP | 所有 |
| WebSocket | `v2raywebsocket/` | WebSocket over HTTP/HTTPS | VMess, VLESS, Trojan |
| HTTP/2 | `v2rayhttp/` | HTTP/2 多路复用 | VMess, VLESS |
| gRPC | `v2raygrpc/` | gRPC over HTTP/2 | VMess, VLESS |
| gRPC Lite | `v2raygrpclite/` | 轻量级 gRPC | VMess, VLESS |
| QUIC | `v2rayquic/` | QUIC 协议 | VMess, VLESS |
| HTTP Upgrade | `v2rayhttpupgrade/` | HTTP Upgrade | VMess, VLESS, Trojan |
| simple-obfs | `simple-obfs/` | HTTP/TLS 混淆 | Shadowsocks |
| SIP003 | `sip003/` | 插件系统 | Shadowsocks |

---

## 3. V2Ray 传输适配器

### 3.1 传输接口

```go
// adapter/v2ray.go

type V2RayServerTransport interface {
    Network() []string
    Serve(listener net.Listener) error
    ServePacket(listener net.PacketConn) error
    Close() error
}

type V2RayClientTransport interface {
    DialContext(ctx context.Context) (net.Conn, error)
}
```

### 3.2 WebSocket 传输 (v2raywebsocket/)

```go
// transport/v2raywebsocket/client.go

type Client struct {
    dialer            N.Dialer
    tlsConfig         tls.Config
    serverAddr        M.Socksaddr
    requestURL        url.URL
    requestURLString  string
    headers           http.Header
    maxEarlyData      uint32
    earlyDataHeaderName string
}

func (c *Client) DialContext(ctx context.Context) (net.Conn, error) {
    // 1. 建立 TCP 连接
    // 2. TLS 握手（如果启用）
    // 3. WebSocket 握手
    // 4. 返回 WebSocket 连接
}
```

```go
// transport/v2raywebsocket/server.go

type Server struct {
    ctx           context.Context
    logger        logger.ContextLogger
    handler       adapter.V2RayServerTransportHandler
    httpServer    *http.Server
    path          string
    maxEarlyData  uint32
    earlyDataHeaderName string
}

func (s *Server) Serve(listener net.Listener) error {
    return s.httpServer.Serve(listener)
}

func (s *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request)
```

### 3.3 gRPC 传输 (v2raygrpc/)

```go
// transport/v2raygrpc/client.go

type Client struct {
    ctx        context.Context
    dialer     N.Dialer
    serverAddr M.Socksaddr
    serviceName string
    tlsConfig  tls.Config
    dialOptions []grpc.DialOption
}

func (c *Client) DialContext(ctx context.Context) (net.Conn, error) {
    // 使用 gRPC 双向流建立连接
}
```

### 3.4 HTTP/2 传输 (v2rayhttp/)

```go
// transport/v2rayhttp/client.go

type Client struct {
    ctx         context.Context
    dialer      N.Dialer
    serverAddr  M.Socksaddr
    transport   *http2.Transport
    http2Client *http.Client
    url         *url.URL
    host        string
    headers     http.Header
}

func (c *Client) DialContext(ctx context.Context) (net.Conn, error) {
    // 通过 HTTP/2 CONNECT 建立隧道
}
```

### 3.5 QUIC 传输 (v2rayquic/)

```go
// transport/v2rayquic/client.go

type Client struct {
    ctx            context.Context
    dialer         N.Dialer
    serverAddr     M.Socksaddr
    tlsConfig      *tls.STDConfig
    quicConfig     *quic.Config
    congestion     string
}

func (c *Client) DialContext(ctx context.Context) (net.Conn, error) {
    // 1. 建立 QUIC 连接
    // 2. 打开 QUIC 流
    // 3. 返回基于流的连接
}
```

### 3.6 HTTP Upgrade 传输 (v2rayhttpupgrade/)

```go
// transport/v2rayhttpupgrade/client.go

type Client struct {
    dialer     N.Dialer
    tlsConfig  tls.Config
    serverAddr M.Socksaddr
    path       string
    headers    http.Header
    host       string
}

func (c *Client) DialContext(ctx context.Context) (net.Conn, error) {
    // 1. 建立 TCP 连接
    // 2. 发送 HTTP Upgrade 请求
    // 3. 切换到原始 TCP
}
```

---

## 4. SIP003 插件系统

### 4.1 插件接口

```go
// transport/sip003/plugin.go

type Plugin interface {
    DialContext(ctx context.Context) (net.Conn, error)
    Close() error
}
```

### 4.2 支持的插件

| 插件 | 用途 |
|------|------|
| `obfs-local` | HTTP/TLS 混淆 |
| `v2ray-plugin` | WebSocket/QUIC/gRPC 传输 |

### 4.3 插件创建

```go
// transport/sip003/plugin.go

func CreatePlugin(ctx context.Context, name string, options string,
                  router adapter.Router, dialer N.Dialer, 
                  serverAddr M.Socksaddr) (Plugin, error) {
    switch name {
    case "obfs-local":
        return newObfsLocal(options, dialer, serverAddr)
    case "v2ray-plugin":
        return newV2RayPlugin(ctx, options, router, dialer, serverAddr)
    default:
        // 外部进程插件
        return newExternalPlugin(ctx, name, options, dialer, serverAddr)
    }
}
```

---

## 5. simple-obfs 混淆

### 5.1 HTTP 混淆

```go
// transport/simple-obfs/http.go

type HTTPObfs struct {
    net.Conn
    host          string
    headerWritten bool
    headerRead    bool
    readRemain    int
}

// 伪装成 HTTP 请求/响应
func (c *HTTPObfs) Read(b []byte) (n int, err error)
func (c *HTTPObfs) Write(b []byte) (n int, err error)
```

### 5.2 TLS 混淆

```go
// transport/simple-obfs/tls.go

type TLSObfs struct {
    net.Conn
    host         string
    handshakeSent bool
    handshakeRead bool
}

// 伪装成 TLS ClientHello/ServerHello
func (c *TLSObfs) Read(b []byte) (n int, err error)
func (c *TLSObfs) Write(b []byte) (n int, err error)
```

---

## 6. Trojan 传输

```go
// transport/trojan/service.go

type Service[U comparable] struct {
    users      map[[56]byte]U  // 密码 -> 用户
    fallbackHandler Handler
}

func (s *Service[U]) NewConnection(ctx context.Context, conn net.Conn, 
                                    metadata M.Metadata) error {
    // 1. 读取 Trojan 头部
    // 2. 验证密码
    // 3. 解析目标地址
    // 4. 处理连接
}
```

---

## 7. WireGuard 传输

```go
// transport/wireguard/device.go

type Device interface {
    io.Closer
    tun.Device           // TUN 接口
    Start() error
    NewEndpoint() (Endpoint, error)
}

type Endpoint interface {
    DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error)
    ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error)
}
```

---

## 8. 传输层与协议层的关系

```
[Protocol Layer]
      │
      │ 使用传输
      ▼
[Transport Layer]
      │
      │ 底层网络
      ▼
[TCP/UDP/QUIC]
```

**示例：VMess + WebSocket + TLS**

```go
// VMess 出站创建时
if options.Transport != nil {
    switch options.Transport.Type {
    case C.V2RayTransportTypeWebsocket:
        transport, err = v2raywebsocket.NewClient(ctx, dialer, serverAddr, 
                                                   options.Transport.WebsocketOptions, tlsConfig)
    case C.V2RayTransportTypeGRPC:
        transport, err = v2raygrpc.NewClient(ctx, dialer, serverAddr,
                                              options.Transport.GRPCOptions, tlsConfig)
    // ...
    }
}

// 拨号时
func (h *Outbound) DialContext(ctx context.Context, network string, 
                               destination M.Socksaddr) (net.Conn, error) {
    // 1. 通过传输层建立连接
    conn, err := h.transport.DialContext(ctx)
    // 2. 在传输层连接上建立 VMess 协议
    return h.client.DialEarlyConn(conn, destination)
}
```
