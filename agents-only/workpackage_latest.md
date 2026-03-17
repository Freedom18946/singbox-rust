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
| L24 | 性能/安全/质量/功能补全，30 任务 (B1-B4) | 2026-03-17 |

---

## 当前状态：维护模式

**L22-L24 综合验收已完成**（2026-03-17）：41 项任务全量代码审查 + 构建/测试通过。
- 39 PASS / 2 PARTIAL（已知限制） / 0 FAIL
- 详见 `active_context.md` 验收结果节

### 构建基线（2026-03-17，综合验收后）

| 构建 | 状态 |
|------|------|
| `cargo check --workspace --all-features --all-targets` | ✅ pass |
| `cargo clippy --workspace --all-features --all-targets -- -D warnings` | ✅ pass |
| `cargo test -p sb-core --lib` | ✅ 509 passed |
| `cargo test -p sb-adapters` | ✅ pass |
| `cargo test -p sb-types` | ✅ 9 passed |
| `cargo test -p sb-api` | ✅ pass |
| `cargo test -p interop-lab` | ✅ 29 passed |
| `cargo doc -p sb-types --no-deps` | ✅ 零 warning |
