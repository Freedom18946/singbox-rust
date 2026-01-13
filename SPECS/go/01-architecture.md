# 架构设计详解

## 1. Box 主引擎 (box.go)

### 1.1 核心结构体

```go
type Box struct {
    createdAt       time.Time
    logFactory      log.Factory
    logger          log.ContextLogger
    network         *route.NetworkManager      // 网络管理器
    endpoint        *endpoint.Manager          // 端点管理器
    inbound         *inbound.Manager           // 入站管理器
    outbound        *outbound.Manager          // 出站管理器
    service         *boxService.Manager        // 服务管理器
    dnsTransport    *dns.TransportManager      // DNS传输管理器
    dnsRouter       *dns.Router                // DNS路由器
    connection      *route.ConnectionManager   // 连接管理器
    router          *route.Router              // 主路由器
    internalService []adapter.LifecycleService // 内部服务
    done            chan struct{}
}
```

### 1.2 创建流程

Box 的创建通过 `New(options Options)` 函数完成，流程如下：

1. **上下文初始化**
   - 从 Context 中获取各类 Registry（Endpoint、Inbound、Outbound、DNS Transport、Service）
   - 设置 pause.Manager 用于暂停控制

2. **日志系统初始化**
   - 创建 log.Factory
   - 配置是否需要 Observable（Clash API 需要）

3. **证书存储初始化**（可选）
   - 创建 CertificateStore 用于自定义证书

4. **核心管理器创建**
   ```
   EndpointManager -> InboundManager -> OutboundManager
                                     -> DNSTransportManager
                                     -> ServiceManager
   ```

5. **路由系统初始化**
   - 创建 DNSRouter
   - 创建 NetworkManager
   - 创建 ConnectionManager
   - 创建 Router 并初始化规则

6. **实验性功能初始化**（可选）
   - CacheFile
   - ClashAPI Server
   - V2Ray API Server
   - NTP Service

### 1.3 生命周期

```
New() -> PreStart() -> Start() -> [运行中] -> Close()
           │              │
           │              ├── preStart() 
           │              │     ├── 启动日志
           │              │     ├── 初始化内部服务
           │              │     ├── Initialize 所有组件
           │              │     └── Start outbound/dns/network/connection/router
           │              │
           │              └── start()
           │                    ├── 启动内部服务
           │                    ├── 启动 inbound/endpoint/service
           │                    └── PostStart 所有组件
           │
           └── 日志启动、缓存文件初始化
```

---

## 2. 服务注册机制

### 2.1 Registry 模式

sing-box 使用 Registry 模式管理组件的创建：

```go
// 通用注册接口
type Registry[T any] interface {
    Create(ctx context.Context, ..., options any) (T, error)
}

// 具体实现
type InboundRegistry interface {
    option.InboundOptionsRegistry
    Create(ctx context.Context, router Router, logger log.ContextLogger, 
           tag string, inboundType string, options any) (Inbound, error)
}
```

### 2.2 组件注册（include/registry.go）

在 `include/registry.go` 中统一注册所有组件：

```go
func InboundRegistry() *inbound.Registry {
    registry := inbound.NewRegistry()
    
    // 注册各协议入站
    tun.RegisterInbound(registry)
    redirect.RegisterRedirect(registry)
    direct.RegisterInbound(registry)
    socks.RegisterInbound(registry)
    http.RegisterInbound(registry)
    mixed.RegisterInbound(registry)
    shadowsocks.RegisterInbound(registry)
    vmess.RegisterInbound(registry)
    trojan.RegisterInbound(registry)
    // ... 其他协议
    
    return registry
}
```

---

## 3. Context 服务注入

sing-box 大量使用 Context 进行依赖注入：

```go
// 注入服务
ctx = service.ContextWith[adapter.InboundManager](ctx, inboundManager)
ctx = service.ContextWith[adapter.OutboundManager](ctx, outboundManager)
ctx = service.ContextWith[adapter.Router](ctx, router)

// 获取服务
router := service.FromContext[adapter.Router](ctx)
outbound := service.FromContext[adapter.OutboundManager](ctx)
```

这种模式的优点：
- 解耦组件依赖
- 便于测试和模拟
- 支持层级覆盖

---

## 4. 数据流

### 4.1 入站连接处理流程

```
[外部连接] 
    ↓
[Inbound] ─────────── 接收连接，解析协议
    ↓
[InboundContext] ──── 封装连接元数据
    ↓
[Router.RouteConnection] ── 匹配路由规则
    │
    ├── [Sniff] ──── 协议嗅探 (HTTP/TLS/QUIC等)
    ├── [Process Lookup] ── 查找进程信息
    └── [Rule Match] ──── 规则匹配
    ↓
[Outbound] ─────────── 发起出站连接
    ↓
[Transport] ────────── 传输层处理
    ↓
[目标服务器]
```

### 4.2 DNS 查询流程

```
[DNS 请求]
    ↓
[DNSRouter.Exchange/Lookup]
    │
    ├── [DNS Rules] ── 匹配DNS规则
    └── [Select Transport] ── 选择DNS传输
    ↓
[DNSClient.Exchange]
    │
    ├── [Cache Check] ── 检查缓存
    └── [RDRC Check] ── 检查拒绝缓存
    ↓
[DNSTransport.Exchange] ── 实际DNS查询
    │
    ├── UDP Transport
    ├── TCP Transport  
    ├── DoT Transport
    ├── DoH Transport
    └── QUIC Transport
    ↓
[Response]
```

---

## 5. 错误处理

sing-box 使用 `github.com/sagernet/sing/common/exceptions` 包进行错误处理：

```go
import E "github.com/sagernet/sing/common/exceptions"

// 创建带原因的错误
E.Cause(err, "initialize router")

// 创建新错误
E.New("outbound not found: ", outboundTag)

// 追加错误
E.Append(err, closeErr, func(err error) error {
    return E.Cause(err, "close component")
})
```

---

## 6. 并发控制

### 6.1 任务监控

```go
monitor := taskmonitor.New(logger, C.StartTimeout)
monitor.Start("initialize rule-set")
// ... 执行任务
monitor.Finish()
```

### 6.2 任务组

```go
var ruleSetStartGroup task.Group
for i, ruleSet := range ruleSets {
    ruleSetStartGroup.Append0(func(ctx context.Context) error {
        return ruleSet.StartContext(ctx, cacheContext)
    })
}
ruleSetStartGroup.Concurrency(5)  // 最多5个并发
ruleSetStartGroup.FastFail()      // 快速失败
err := ruleSetStartGroup.Run(ctx)
```

### 6.3 暂停管理

```go
pauseManager := pause.ManagerFromContext(ctx)
pauseManager.WaitActive()  // 等待激活状态
```
