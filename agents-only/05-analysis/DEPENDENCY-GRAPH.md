# 依赖关系图（Dependency Graph）

> **分析日期**：2026-02-07（L1.3 后更新）
> **分析工具**：`cargo tree --depth 1 -e no-dev`
> **分析范围**：全 workspace sb-* crates + app

---

## 当前依赖图（实测）

```
                                    app (composition root)
                                     │
       ┌──────────┬──────────┬───────┼────────┬──────────┬──────────┐
       ▼          ▼          ▼       ▼        ▼          ▼          ▼
    sb-api    sb-core    sb-adapters  sb-config  sb-metrics  sb-subscribe  sb-transport
       │         │           │         │                      │
       │         │           │         ▼                      │
       │         │           │      sb-types                  │
       │         │           │                                │
       ├─────────┤           ├──── sb-core ❌ (反向依赖)       ├── sb-core ❌
       │         │           ├──── sb-config                  │
       ▼         │           ├──── sb-types                   │
    sb-config    │           │                                │
    sb-core      │           │                                │
       │         │           │                                │
       │    ┌────┼────┬──────┼────┬──────┬──────┐             │
       │    ▼    ▼    ▼      ▼    ▼      ▼      ▼             │
       │ sb-config sb-metrics sb-platform sb-tls sb-types sb-transport
       │                                                      │
       │                                                      ▼
       │                                                   sb-metrics
       │
       ▼
    sb-proto → sb-transport → sb-metrics
```

---

## 依赖矩阵（精确版）

依赖方向：行 → 列 = 行 依赖 列

| | types | config | metrics | tls | platform | transport | core | adapters | api | subscribe | proto | runtime | security | common | admin-c | test-u |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **sb-types** | - | | | | | | | | | | | | | | | |
| **sb-config** | ✅ | - | | | | | | | | | | | | | | |
| **sb-metrics** | | | - | | | | | | | | | | | | | |
| **sb-tls** | | | | - | | | | | | | | | | | | |
| **sb-platform** | | | | | - | | | | | | | | | | | |
| **sb-transport** | | | ✅ | | | - | | | | | | | | | | |
| **sb-core** | ✅ | ⚠️ | ❌ | ❌ | ❌ | ❌ | - | | | | | | | | | |
| **sb-adapters** | ✅ | ⚠️ | | | | | ❌ | - | | | | | | | | |
| **sb-api** | | ⚠️ | | | | | ⚠️ | | - | | | | | | | |
| **sb-subscribe** | | | | | | | ❌ | | | - | | | | | | |
| **sb-proto** | | | | | | ✅ | | | | | - | | | | | |
| **sb-runtime** | | | | | | | | | | | | - | | | | |
| **sb-security** | | | | | | | | | | | | | - | | | |
| **sb-common** | | | | | | | | | | | | | | - | | |
| **sb-admin-c** | | | | | | | | | | | | | | | - | |
| **sb-test-u** | | | | | | | | | | | | | | | | - |

**图例**：✅ 合规 | ⚠️ 需评估 | ❌ 违规 | 空 = 无依赖

---

## 违规路径分析

### 红色路径 ❌（必须消除）

| # | 违规路径 | 问题 | 消除策略 |
|---|---------|------|---------|
| 1 | `sb-core → sb-metrics` | 引擎层不应直接依赖指标库 | 定义 MetricsPort trait in sb-types |
| 2 | `sb-core → sb-platform` | 引擎层不应直接依赖平台层 | 定义 PlatformPort trait in sb-types |
| 3 | `sb-core → sb-tls` | 引擎层不应直接依赖 TLS 实现 | 定义 TlsPort trait in sb-types |
| 4 | `sb-core → sb-transport` | 引擎层不应直接依赖传输层 | 定义 TransportPort trait in sb-types |
| 5 | `sb-adapters → sb-core` | **反向依赖**，破坏层次 | ✅ outbound 全部独立；inbound 保留为合法依赖 |
| 6 | `sb-subscribe → sb-core` | 订阅层不应依赖引擎层 | ✅ sb-core 已变 optional |

### 黄色路径 ⚠️（需评估）

| # | 路径 | 问题 | 评估 |
|---|------|------|------|
| 1 | `sb-core → sb-config` | 引擎读配置 IR | 可能合理（配置 IR 是输入），但理想应通过 sb-types 定义接口 |
| 2 | `sb-adapters → sb-config` | 适配器读配置 IR | 同上 |
| 3 | `sb-api → sb-core` | API 层注入引擎 | 合理方向（控制面 → 数据面），但应通过 Ports |
| 4 | `sb-api → sb-config` | API 层读配置 | 同 #1 |

---

## 目标依赖图

```
                                    app (composition root)
                                     │
       ┌──────────┬──────────┬───────┼────────┬──────────┬──────────┐
       ▼          ▼          ▼       ▼        ▼          ▼          ▼
    sb-api    sb-core    sb-adapters  sb-subscribe  sb-runtime  ...
       │         │           │         │
       │         │ (Ports    │         │
       │         │  only)    │         │
       │         ▼           ▼         ▼
       │      sb-types    sb-transport  sb-types
       │         ▲           │
       │         │           ▼
       │         │        sb-tls
       │         │           │
       │         │           ▼
       │         └──────  sb-types
       │
       ├──── sb-config → sb-types
       └──── sb-core (通过 Ports)
```

### 目标状态关键约束

1. **sb-core** 仅依赖 **sb-types**（通过 Ports trait 与外部交互）
2. **sb-adapters** 不依赖 **sb-core**（共享契约在 sb-types）
3. **sb-api** 通过 Ports 注入 sb-core（合法方向）
4. **app** 作为 composition root 组装所有依赖（唯一允许全依赖的节点）

---

## 差距分析（L1 后）

| 指标 | L1 前 | L1 后 | 目标 |
|------|-------|-------|------|
| sb-core 非 optional 外部违规依赖 | 8 处 | 0 | 0 ✅ |
| sb-adapters outbound sb-core 依赖 | 全部 10 协议 | 0 | 0 ✅ |
| sb-subscribe sb-core 依赖 | 必选 | optional | 0 ✅ |
| check-boundaries.sh | N/A | exit 0 ✅ | exit 0 ✅ |
| sb-core sb-* 依赖数 | 6 | 6 (同，但外部 deps optional) | 1 (远期目标) |
| sb-adapters inbound sb-core 依赖 | ~192 处 | ~192 处 (合法) | 保留 |

### L1 已完成的消除项
```
✅ P0: sb-adapters outbound → sb-core 解耦（10/10 协议独立）
✅ P1: sb-core → axum/tonic optional 化（behind service_* features）
✅ P1: sb-core → rustls/quinn optional 化（behind tls_rustls/out_quic features）
✅ P1: sb-core → reqwest optional 化（behind dns_doh/service_derp）
✅ P3: sb-subscribe → sb-core optional 化
```

### 远期待消除项（不阻塞 L1 结项）
```
P2: sb-core → sb-platform/sb-transport/sb-tls 通过 Ports 抽象（需 MetricsPort 等）
P2: sb-adapters inbound → sb-core 解耦（超大工作量）
P3: feature flag 互斥关系分析 (B3)
```

---

## 验证命令

```bash
# 完整依赖树（当前状态快照）
cargo tree --workspace --depth 1 -e no-dev

# 检查 sb-core 禁止依赖
cargo tree -p sb-core | grep -E "axum|tonic|tower[^-]|hyper[^-]|rustls|quinn"

# 检查 sb-adapters 反向依赖
cargo tree -p sb-adapters --depth 1 | grep "sb-core"

# 检查 sb-types 纯净性
cargo tree -p sb-types | grep -E "tokio|async-std"

# 运行边界检查脚本
./agents-only/06-scripts/check-boundaries.sh
```

---

*初始分析：2026-02-07 | 更新：2026-02-07 L1.3 后 | Agent：Claude Code (Opus 4.6)*
