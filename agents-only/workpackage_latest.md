<!-- tier: S -->
# 工作阶段总览（Workpackage Map）

> **用途**：阶段划分 + 当前位置。S-tier，每次会话必读。
> **纪律**：Phase 关闭后压缩为一行状态。本文件严格 ≤120 行。
> **对比**：本文件管"在哪"；`active_context.md` 管"刚做了什么 / 下一步"。

---

## 已关闭阶段（一行总结）

| 阶段 | 交付 | 关闭时间 |
|------|------|----------|
| L1-L17 | 架构整固、功能对齐、CI / 发布收口 | 2026-01 ~ 2026-02 |
| MIG-02 / L21 | 隐式回退消除，541 V7 assertions，生产路径零隐式直连回退 | 2026-03-07 |
| L18 Phase 1-4 | 认证替换、证据模型收口、GUI gate 复验、长跑恢复决策门 | 2026-03-11 |
| L22 | dual-kernel parity 52/60 (86.7%)，16 个 both-case，Sniff Phase A+B | 2026-03-15 |
| 后 L22 补丁 | QUIC 多包重组、OverrideDestination、UDP datagram sniff、编译修复 | 2026-03-15 |

---

## 当前活跃：L23 — TUN / Sniff 运行时补全

**目标**: 补全 TUN UDP 转发、废弃 sniff 字段自动注入、TUN override_destination，消除剩余已知偏差。

### Tier 1 — 高价值 / 必做 ✅ 全部完成（2026-03-16）

| 任务 | 描述 | 状态 |
|------|------|------|
| L23-T3 | **TUN sniff `override_destination`** — `if let` 解构 + `Endpoint::Domain` 覆盖 | ✅ done |
| L23-T2 | **`sniff: true` 自动注入** — `RouteCtx` → `engine.rs` 前置注入 `Decision::Sniff` | ✅ done |
| L23-T1 | **TUN UDP 转发** — `tun/udp.rs` UDP NAT 表 + macOS 主循环集成 + 反向 relay | ✅ done |

### Tier 2 — 中价值 / 偏差消除（下一步）

| 任务 | 描述 | DIV | 状态 |
|------|------|-----|------|
| L23-T4 | **Provider 后台更新循环** — 实现定时轮询更新 | DIV-H-003 | pending |
| L23-T5 | **Provider 健康检查探针** — 实现实际探测代替 always-healthy | DIV-H-004 | pending |

### Tier 3 — 低优先级 / 结构性阻塞

| 任务 | 描述 | 状态 |
|------|------|------|
| L23-T6 | **SV 域 7 BHV** — Go/Rust 都 stub provider endpoint，结构性不可测 | blocked |
| L23-T7 | **Redirect IPv6** (DIV-H-002) — 平台限制，有限影响 | deferred |

### 构建基线（2026-03-16 更新）

| 构建 | 状态 |
|------|------|
| `cargo check --workspace --all-features --all-targets` | ✅ pass |
| `cargo clippy -p sb-adapters --all-features -- -D warnings` | ✅ pass |
| `cargo test -p sb-core --lib` | ✅ pass (504 tests) |
| `cargo test -p sb-adapters --all-features --lib -- tun::udp` | ✅ pass (2 tests) |
| pre-existing: `shutdown_lifecycle.rs:98` clippy | ⚠️ 不属于 L23 |
