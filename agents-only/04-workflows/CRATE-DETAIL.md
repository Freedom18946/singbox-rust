# Crate 详细职责（Crate Responsibilities Detail）

> **用途**：明确每个 crate 的边界，作为重构的依据

---

## sb-types（契约层）

**职责**：定义跨 crate 共享的类型和接口

| 允许 | 禁止 |
|------|------|
| 领域类型（Address, Protocol, Network） | 任何运行时依赖（tokio, async-std） |
| 配置 IR 类型 | I/O 操作 |
| Ports traits 定义 | 协议实现 |
| 错误类型（不含 anyhow） | Web 框架 |
| serde, bytes, ipnet | |

**当前状态**：⬜ 待审计

---

## sb-core（引擎层）

**职责**：路由引擎、DNS 策略、会话管理

| 允许 | 禁止 |
|------|------|
| 路由决策、规则匹配 | 协议实现（VMess/VLESS 等） |
| DNS 缓存、FakeIP 策略 | 平台服务（NTP/DERP） |
| 会话生命周期管理 | Web 框架（axum/tonic） |
| 通过 Ports 调用外部 | TLS/QUIC/WS 实现 |
| tokio 基础运行时 | 直接 HTTP 客户端（reqwest） |

**当前状态**：🔴 违规严重（见 DEPENDENCY-AUDIT.md）

---

## sb-adapters（协议层）

**职责**：所有协议实现

| 允许 | 禁止 |
|------|------|
| Inbound 协议（SOCKS/HTTP/TUN 等） | 反向依赖 sb-core |
| Outbound 协议（SS/Trojan/VMess 等） | 路由决策 |
| 协议握手、加密 | 控制面 API |
| 使用 sb-transport/sb-tls | |

**当前状态**：🟠 有违规（依赖 sb-core）

---

## sb-config（配置层）

**职责**：配置解析、验证、编译

| 允许 | 禁止 |
|------|------|
| JSON/YAML 解析 | 运行时对象创建 |
| Schema 验证 | 协议实现 |
| IR 生成 | 网络 I/O |
| 错误报告 | |

**当前状态**：⬜ 待审计

---

## sb-transport（传输层）

**职责**：底层传输抽象

| 允许 | 禁止 |
|------|------|
| TCP/UDP 传输 | 协议实现 |
| WebSocket 升级 | 路由决策 |
| HTTP/2、gRPC 传输 | 配置解析 |
| QUIC 传输 | |

**当前状态**：⬜ 待审计

---

## sb-tls（TLS 层）

**职责**：TLS 相关功能

| 允许 | 禁止 |
|------|------|
| Standard TLS (rustls) | 协议实现 |
| REALITY | 路由决策 |
| ECH | |
| uTLS 指纹 | |

**当前状态**：⬜ 待审计

---

## sb-platform（平台层）

**职责**：平台特定功能

| 允许 | 禁止 |
|------|------|
| TUN 管理 | 协议实现 |
| Socket options | 路由决策 |
| Netlink | 配置解析 |
| systemd-resolved | |

**当前状态**：⬜ 待审计

---

## sb-api（控制面）

**职责**：外部 API

| 允许 | 禁止 |
|------|------|
| Clash API | 直接调用 sb-adapters |
| V2Ray Stats API | 协议实现 |
| axum/tonic 框架 | 数据面逻辑 |
| 通过 Ports 调用 sb-core | |

**当前状态**：⬜ 待审计

---

## sb-metrics（可观测性）

**职责**：指标收集和导出

| 允许 | 禁止 |
|------|------|
| Prometheus 导出 | 业务逻辑 |
| 指标定义 | 协议实现 |
| Tracing 集成 | |

**当前状态**：⬜ 待审计

---

## sb-common（共享工具）

**职责**：跨 crate 工具函数

| 允许 | 禁止 |
|------|------|
| 通用工具函数 | 业务逻辑 |
| 编解码辅助 | 协议实现 |
| 日志辅助 | |

**当前状态**：⬜ 待审计
