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
| **L22** | **dual-kernel parity 52/60 (86.7%)，16 个 both-case，Sniff Phase A+B** | **2026-03-15** |

## 当前状态：无活跃工作包

所有阶段已关闭。项目处于维护状态，等待新指令。

### L22 关闭总结

- **最终分数**: Both-Covered 52/60 (86.7%), strict 43/60, both-case 36/100
- **天花板**: 剩余 8 BHV 不可覆盖（7 SV 结构性阻塞 + 1 LC-003 已确认不可行）
- **Sniff Phase A**: `Decision::Sniff` 规则动作集成，DIV-C-003 关闭
- **Sniff Phase B**: QUIC Initial 包解密 SNI 提取（v1/v2/Draft-29），Go parity 测试通过
- **已归档**: `agents-only/archive/L22/`

### 构建状态

| 构建 | 状态 |
|------|------|
| `cargo check --workspace` | pass |
| `cargo clippy -p sb-core --all-features --lib` | pass (0 warnings) |
| `cargo test -p sb-core` | pass (504 tests) |
| `cargo test -p interop-lab` | pass (29 tests) |

## 候选方向（待用户指令）

- QUIC multi-packet reassembly（Chrome 多包 ClientHello）
- OverrideDestination（sniff 域名替换路由目标）
- UDP datagram sniff via rule action（TUN UDP 路径）
- 新功能开发 / 性能优化 / 新阶段规划
