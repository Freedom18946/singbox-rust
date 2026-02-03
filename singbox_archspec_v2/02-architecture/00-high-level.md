# 总体架构（High-Level Architecture）

## 核心图（依赖与运行时职责）

```
                 ┌───────────────────────────┐
                 │           app             │
                 │  composition root + CLI   │
                 └─────────────┬─────────────┘
                               │
               ┌───────────────┴────────────────┐
               │                                 │
      ┌────────▼────────┐                ┌───────▼────────┐
      │     sb-api      │                │    sb-core     │
      │  control plane  │                │  data-plane     │
      └────────┬────────┘                └───────┬────────┘
               │                                 │
               │                          (Ports via sb-types)
               │                                 │
               │                         ┌───────▼────────┐
               │                         │   sb-adapters   │
               │                         │ protocol layer  │
               │                         └───┬─────┬──────┘
               │                             │     │
       ┌───────▼────────┐          ┌─────────▼┐  ┌▼──────────┐
       │ sb-metrics      │          │sb-transport│ │ sb-platform│
       │ observe/export  │          │ transport  │ │ OS/system  │
       └─────────────────┘          └──────┬─────┘ └─────┬─────┘
                                           │             │
                                        ┌──▼──┐      ┌──▼──┐
                                        │sb-tls│      │sb-security│
                                        └─────┘      └───────────┘
```

---

## 关键分工

- **sb-core**：路由/策略/会话编排（不会出现任何具体协议实现）
- **sb-adapters**：所有协议实现（inbound/outbound），实现 Ports
- **sb-transport**：WS/gRPC/HTTP2/QUIC 等传输形态
- **sb-tls / sb-security**：TLS/Reality/ECH/证书/密钥材料
- **sb-platform**：tun/tproxy/systemd-resolved/NTP 等平台能力
- **sb-api**：Clash/V2Ray 等控制面 API，只调用 core 的管理接口

---

## 运行时线程模型（默认）

- tokio multi-thread runtime
- 数据面任务：每入站连接一个任务；UDP/packet 采用 worker + channel
- 背压：通过 bounded channel + 超时 + 断路器策略

详细见：`02-architecture/01-data-plane.md`
