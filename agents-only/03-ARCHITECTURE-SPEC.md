# 架构规范（Architecture Specification）

> **整合自 singbox_archspec_v2**：定义 crate 边界、依赖方向和核心接口。

---

## 1. 依赖宪法（Dependency Constitution）

### 1.1 依赖方向图

```
sb-types   ← sb-config
   ↑            ↑
   │            │
sb-core   ← sb-adapters  ← sb-transport / sb-tls / sb-platform / sb-security
   ↑
   │
sb-api / sb-metrics / sb-runtime
   ↑
   │
  app (composition root)
```

**规则**：依赖只能单向，箭头方向表示 "被依赖"。

### 1.2 Crate 级职责边界

#### sb-types（契约层）
| 允许 | 禁止 |
|------|------|
| 领域类型、配置 IR 类型 | tokio/hyper/axum/tonic/reqwest |
| Ports traits、错误类型定义 | rustls/quinn/ws 库 |
| serde, bytes, ipnet | 系统调用/文件 I/O crate |

#### sb-core（引擎层）
| 允许 | 禁止 |
|------|------|
| 路由/策略/会话编排 | 具体协议实现（VMess/VLESS 等） |
| 流量调度、DNS 缓存策略 | 平台服务（NTP/resolved/DERP） |
| 通过 Ports 与外部交互 | Web 框架（axum/tonic/tower） |
| | TLS/QUIC/WS 实现 |

#### sb-adapters（协议适配器层）
| 允许 | 禁止 |
|------|------|
| 所有 inbound/outbound 协议实现 | 把 sb-core 当工具箱引用 |
| 协议解析、加密、握手、流控 | 承担控制面（HTTP API）职责 |
| 通过 sb-transport/sb-tls 连接底层 | |

#### sb-platform（平台服务层）
| 允许 | 禁止 |
|------|------|
| tun, tproxy, socket options | 协议实现（属于 adapters） |
| netlink, systemd-resolved, NTP | 路由策略（属于 core） |

---

## 2. 数据面架构（Data Plane）

### 2.1 连接流程

```
[Client] → [Inbound Adapter] → [Router Engine] → [Outbound Adapter] → [Server]
                                     ↓
                               [DNS Resolver]
                                     ↓
                               [Rule Engine]
```

### 2.2 核心组件

| 组件 | 位置 | 职责 |
|------|------|------|
| Router Engine | `sb-core/src/router/` | 路由决策、规则匹配 |
| DNS Resolver | `sb-core/src/dns/` | DNS 查询、缓存、FakeIP |
| Rule Engine | `sb-core/src/router/rules.rs` | 规则编译、匹配 |
| Connection Manager | `sb-core/src/router/conn.rs` | 连接管理、TLS 分片 |

---

## 3. 控制面架构（Control Plane）

### 3.1 API 层次

```
┌─────────────────────────────────┐
│           sb-api                │
│  ┌─────────────┐ ┌────────────┐ │
│  │ Clash API   │ │ V2Ray API  │ │
│  └──────┬──────┘ └─────┬──────┘ │
└─────────┼──────────────┼────────┘
          │              │
          ▼              ▼
    ┌─────────────────────────┐
    │     AdminPort/StatsPort  │ (via sb-types Ports)
    └─────────────────────────┘
```

### 3.2 服务隔离

- **sb-api** 只通过 Ports 调用 sb-core
- **sb-api** 不能直接调用 sb-adapters
- Web 框架（axum/tonic）只存在于 sb-api

---

## 4. 配置编译流程（Config Pipeline）

```
[JSON/YAML] → [sb-config: Parse] → [IR (Intermediate)] → [Compile] → [Runtime Objects]
                    ↓
              [Validation]
                    ↓
              [Error Report]
```

### 4.1 配置 IR 结构

| 层次 | 内容 |
|------|------|
| Schema | JSON Schema 验证 |
| IR | 类型安全的中间表示 |
| Compile | IR → 运行时对象 |

---

## 5. 可观测性架构（Observability）

### 5.1 Metrics 流程

```
[Runtime Events] → [sb-metrics] → [Prometheus Exporter]
                         ↓
                   [Grafana Dashboards]
```

### 5.2 Metrics 分类

| 类别 | 示例 |
|------|------|
| 连接计数 | `connections_total`, `connections_active` |
| 延迟直方图 | `request_duration_seconds` |
| 流量统计 | `bytes_sent`, `bytes_received` |
| DNS 统计 | `dns_queries_total`, `dns_cache_hits` |

---

## 6. 运行时模型（Runtime Model）

### 6.1 线程模型

- **Runtime**: tokio multi-thread
- **数据面任务**: 每入站连接一个任务
- **UDP/packet**: worker + channel
- **背压**: bounded channel + 超时 + 断路器

### 6.2 生命周期

```
[Init] → [Start] → [Running] → [Reload/Shutdown]
            ↓          ↑
       [PreStart]    [PostStart]
```

---

## 7. 传输层架构（Transport Layer）

### 7.1 传输抽象

| 传输 | 位置 | 特性 |
|------|------|------|
| TCP | `sb-transport/` | 基础传输 |
| UDP | `sb-transport/` | 基础传输 |
| WebSocket | `sb-transport/websocket.rs` | 升级传输 |
| HTTP/2 | `sb-transport/http2.rs` | 多路复用 |
| gRPC | `sb-transport/grpc.rs` | RPC 传输 |
| QUIC | `sb-transport/quic.rs` | 多路复用 |

### 7.2 TLS 层

| 功能 | 位置 | 特性 |
|------|------|------|
| Standard TLS | `sb-tls/` | rustls |
| REALITY | `sb-tls/reality/` | 反审查 |
| ECH | `sb-tls/ech/` | SNI 加密 |
| uTLS | `sb-tls/utls.rs` | 指纹模拟 |
| ACME | `sb-tls/acme.rs` | 自动证书 |

---

## 8. 模块树参考

```
singbox-rust/
├── app/                    # CLI 和组合根
├── crates/
│   ├── sb-core/           # 核心引擎
│   │   ├── src/
│   │   │   ├── router/    # 路由引擎
│   │   │   ├── dns/       # DNS 系统
│   │   │   ├── inbound/   # 入站管理
│   │   │   ├── outbound/  # 出站管理
│   │   │   ├── endpoint/  # 端点
│   │   │   └── services/  # 服务
│   ├── sb-adapters/       # 协议适配器
│   │   ├── src/
│   │   │   ├── inbound/   # 入站协议
│   │   │   ├── outbound/  # 出站协议
│   │   │   └── service/   # 服务实现
│   ├── sb-config/         # 配置解析
│   ├── sb-types/          # 契约层
│   ├── sb-transport/      # 传输层
│   ├── sb-tls/            # TLS 层
│   ├── sb-platform/       # 平台能力
│   ├── sb-api/            # 外部 API
│   ├── sb-metrics/        # 可观测性
│   ├── sb-runtime/        # 运行时
│   ├── sb-security/       # 安全
│   └── sb-common/         # 共享工具
├── tests/                 # 测试
└── docs/                  # 文档
```

---

*下一步：阅读 [04-IMPLEMENTATION-GUIDE.md](./04-IMPLEMENTATION-GUIDE.md) 了解实现指南*
