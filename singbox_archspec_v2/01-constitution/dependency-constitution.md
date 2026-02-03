# 依赖宪法（Dependency Constitution）

> 这份文件是“架构边界”的法律文本。**CI 必须强制执行**：任何新增依赖越界，PR 直接失败。

---

## 1. 允许的依赖方向（只能单向）

```
sb-types   <- sb-config
   ^            ^
   |            |
sb-core   <- sb-adapters  <- sb-transport / sb-tls / sb-platform / sb-security
   ^
   |
sb-api / sb-metrics / sb-runtime
   ^
   |
  app (composition root)
```

### 解释

- `sb-types` 是契约层：只包含 Ports + 领域类型，任何东西都可以依赖它；它几乎不依赖任何大库。
- `sb-core` 是引擎层：只依赖 `sb-types` 与少量 `sb-common`。
- `sb-adapters` 实现 Ports：可以依赖 `sb-transport/sb-tls/sb-platform` 等 infra。
- `sb-api` 是控制面：依赖 sb-core 暴露的“管理接口”（不可直接依赖 sb-adapters）。
- `app` 是组合根（composition root）：在这里把具体实现组装起来，并做 feature 聚合。

---

## 2. crate 级职责边界（必须遵守）

### sb-types（契约层）

允许：
- 领域类型、配置 IR 类型（可选）、Ports traits、错误类型定义（typed）
- `serde`（可选，用于配置/日志导出），`bytes`（可选），`ipnet`（可选）

禁止：
- tokio/hyper/axum/tonic/reqwest
- rustls/quinn/ws 库
- 任何系统调用/文件 I/O 相关 crate

### sb-core（引擎层）

允许：
- 路由/策略/会话编排、流量调度、DNS 缓存策略、Outbound 选择、熔断与健康策略
- 只通过 Ports 与外部交互

禁止：
- 任何具体协议实现（VMess/VLESS/Trojan/SS/WG/SSH/TUIC/Hysteria…）
- 任何平台/系统服务（NTP/systemd-resolved/DERP…）
- 任何 Web 框架/HTTP server（axum/tonic/tower/hyper）
- 任何 TLS/QUIC/WS 实现（rustls/quinn/tungstenite）

### sb-adapters（协议适配器层）

允许：
- 所有 inbound/outbound 协议实现
- 协议解析、加密、握手、流控、mux 等
- 通过 sb-transport/sb-tls 连接底层传输与安全能力

禁止：
- 把 sb-core 当工具箱引用（最多依赖 sb-types + sb-common + sb-config IR）
- 承担控制面（HTTP API server）职责

### sb-platform（平台服务层）

允许：
- 系统能力：tun、tproxy、socket options、netlink、systemd-resolved、NTP 等
- 与 OS/系统守护进程交互

禁止：
- 协议实现（属于 adapters）
- 路由策略（属于 core）

---

## 3. “违规示例”与正确做法

### 违规：sb-core 里出现协议实现
- 错：`sb-core/src/outbound/vmess.rs`
- 对：迁移到 `sb-adapters/src/outbound/vmess.rs`，并实现 `sb-types::OutboundConnector`

### 违规：sb-core 引入 axum/tonic
- 错：`sb-core` 暴露 HTTP server
- 对：`sb-core` 只暴露 `AdminService` trait；`sb-api` 用 axum/tonic 调用它

---

## 4. 强制执行（CI）

见：`01-constitution/ci-enforcement.md`
