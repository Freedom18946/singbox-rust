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
| L23 | TUN/Sniff 运行时补全、Provider wiring、T4 Protocol Suite (VLESS/VMess)、parity 92.9% | 2026-03-16 |

---

## 当前活跃：L24 — 性能 / 安全 / 质量 / 功能补全

**目标**: 从"功能完整"推向"生产就绪"。覆盖安全加固、Fuzz 基础设施、代码质量、热路径性能优化、功能补全。

**详细工作包**: `agents-only/planning/L24-workpackage.md`

### 任务总览

| Tier | 任务数 | S | M | L | 领域分布 |
|------|--------|---|---|---|----------|
| T1（必做） | 12 | 5 | 5 | 2 | 安全×1, Fuzz×3, 质量×3, 性能×2, 功能×2, Bench×1 |
| T2（中价值）| 10 | 3 | 5 | 2 | 性能×3, 质量×3, Fuzz×2, 功能×1, CI×1 |
| T3（可选） | 8 | 2 | 5 | 1 | 质量×4, 功能×4 |
| **合计** | **30** | **10** | **15** | **5** | |

### 执行批次

| 批次 | 内容 | 状态 |
|------|------|------|
| B1 | 安全修复 + Fuzz 基础设施 (T1-01~06, T2-08,10) | ✅ done |
| B2 | 性能热路径 + Benchmark (T1-08,09,12, T2-05,07,09) | 🟡 T1-08,09,12 done; T2-05,07,09 pending |
| B3 | 功能补全 + 错误处理 (T1-10,11, T2-01~04,06) | 🔲 pending |
| B4 | T3 按需 | 🔲 pending |

### 已交付任务清单

| 任务 | 交付 | 日期 |
|------|------|------|
| T1-01~06 | 安全修复 + fuzz targets 真实化 | 2026-03-16 |
| T2-08 | 114 seed corpus + regression framework | 2026-03-17 |
| T1-08 | domain suffix 零分配匹配 (3 处 format!() 消除) | 2026-03-17 |
| T1-09 | matches_host 零分配快路径 + 域名预 lowercase | 2026-03-17 |
| T1-12 | TCP relay e2e benchmark + domain_match benchmark | 2026-03-17 |

### 构建基线（2026-03-17）

| 构建 | 状态 |
|------|------|
| `cargo check --workspace --all-features --all-targets` | ✅ pass |
| `cargo test -p sb-core --lib` | ✅ pass (509 tests) |
| `cargo bench -p sb-benches --bench tcp_relay_e2e` | ✅ 2.4-3.0 GiB/s |
| `cargo +nightly fuzz build` | ✅ pass (20 targets) |
