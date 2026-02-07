# 依赖边界审计（Dependency Audit）

> **来源**：整合自 `singbox_archspec_v2/08-refactor-tracking/边界审计.md`
> **最后更新**：2026-02-07

---

## 当前违规清单

### 🔴 已确认违规

#### 1. sb-core 直接依赖 Web/TLS/QUIC 库
**违规依赖**：
- axum, axum-server
- hyper, reqwest
- rustls, rustls-pemfile, rustls-pki-types
- quinn, h3, h3-quinn
- tokio-tungstenite
- tonic, tower

**证据**：`crates/sb-core/Cargo.toml`

**违反规则**：`dependency-constitution.md` 禁止 sb-core 引入 Web/TLS/QUIC 大库

---

#### 2. sb-core 直接依赖 infra/平台 crates
**违规依赖**：
- sb-transport
- sb-tls
- sb-platform
- sb-config
- sb-metrics

**证据**：`crates/sb-core/Cargo.toml`

**违反规则**：sb-core 应仅依赖 `sb-types` / `sb-common`

---

#### 3. sb-adapters 反向依赖 sb-core
**违规依赖**：
- sb-core（启用 router/v2ray_transport 等特性）

**证据**：`crates/sb-adapters/Cargo.toml`

**违反规则**：adapters 不应反向依赖 core

---

### 🟡 待确认项

| 项目 | 位置 | 问题 | 状态 |
|------|------|------|------|
| sb-transport → sb-platform | android target | infra → platform 方向 | 待确认 |
| sb-api → sb-config | 直接依赖 | 控制面是否应直接解析配置 | 待确认 |
| sb-core → anyhow | 直接依赖 | 与 error-model 约束冲突 | 待确认 |
| sb-core → async-trait | 直接依赖 | 与 async-model 约束冲突 | 待确认 |

---

## 整改建议（优先级排序）

### P1: sb-core Web 依赖移出
```
sb-core 中的 axum/tonic/tower/hyper → 移至 sb-api（控制面）
sb-core 中的 rustls/quinn → 移至 sb-adapters/sb-transport（传输层）
sb-core 通过 Ports/traits 与外部交互
```

### P2: sb-core infra 依赖移除
```
sb-core → sb-transport/sb-tls/sb-platform/sb-config/sb-metrics
↓
改为 app 组合根注入 + sb-types Ports
sb-core 只接收 IR，不直接依赖 sb-config
```

### P3: sb-adapters 反向依赖解耦
```
sb-adapters → sb-core
↓
sb-adapters → sb-types Ports/IR
新建共享契约归属 sb-types，避免反向依赖
```

---

## 影响范围

| 直接影响 | 间接影响 |
|---------|---------|
| sb-core | app 组合根 |
| sb-adapters | feature 聚合 |
| sb-api | 测试布局 |
| sb-transport | CI 检查规则 |
| sb-platform | |
| sb-config | |
| sb-metrics | |

---

## 验证命令

```bash
# 检查 sb-core 依赖（预期：无 Web/TLS 库）
cargo tree -p sb-core | grep -E "axum|tonic|tower|hyper|rustls|quinn"

# 检查 sb-adapters 反向依赖（预期：无 sb-core）
cargo tree -p sb-adapters --invert sb-core

# 检查 sb-types 净度（预期：无运行时依赖）
cargo tree -p sb-types | grep -E "tokio|async-std"
```

---

*此文档追踪依赖边界违规，作为 L1（架构整固）的工作依据。*
