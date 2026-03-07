# ADR-L19.3.1：`sb-core` 角色决议（路线 A/B 二选一）

---

## 决策信息

| 项目 | 值 |
|------|-----|
| 日期 | 2026-03-04 |
| 决策 ID | ADR-L19.3.1 |
| 状态 | ✅ 已批准 |
| 关联工作包 | L19.3.1 |

---

## 问题描述

`agents-only/01-spec/03-ARCHITECTURE-SPEC.md` 先前将 `sb-core` 定义为“纯引擎层”，并声明禁止 Web/TLS/QUIC 依赖与协议实现；但当前仓库现实中，`crates/sb-core/` 同时包含 `inbound/outbound/services/transport/tls` 等目录，且 `Cargo.toml` 存在 `axum/tonic/hyper/rustls/quinn/reqwest` 等依赖（以 optional + feature gate 方式引入）。

这导致“文档宪法”与“可执行现实”双口径并存，边界门禁也无法形成一致治理。

---

## 决策驱动因素

1. 先消除口径冲突，避免继续以不真实约束指导开发。
2. 在不做大规模迁移的前提下，给 L19.3.2（边界门禁 strict）提供可执行规则。
3. 保持与 L18 并行隔离，不引入高风险结构性重构。
4. 为后续 L19.3.3 重叠清单与迁移 backlog 提供统一起点。

---

## 考虑的选项

### 选项 A：`sb-core` 回归纯引擎层（强宪法）

**描述**：将协议实现、服务实现、TLS/QUIC/Web 相关代码全面迁出 `sb-core`，恢复“只保留路由/策略/编排”的目标形态。

**优点**：
- 与原始分层架构理想高度一致。
- 边界可更强约束，长期可维护性上限更高。

**缺点**：
- 当前代码现实差距大，迁移成本高，无法在 L19.3.1（S 级）窗口内完成。
- 会与正在并行的 L18/L19 主线产生较大耦合风险。

---

### 选项 B：承认 `sb-core` 为“内核合集层”（Kernel Aggregate）

**描述**：正式将 `sb-core` 定义为“内核合集层”，允许已存在的协议/服务/传输相关模块在 feature gate 下继续存在，同时把新增归属、重叠治理和迁移约束写入规则。

**优点**：
- 与当前 crate 现实一致，可立即消除文档与实现冲突。
- 可在本轮快速落地，为后续 strict 门禁和迁移计划提供稳定基线。

**缺点**：
- 在一段时期内保留“重叠实现”技术债，需要额外治理纪律。
- 架构纯度低于选项 A，需要持续跟踪迁移清单防止继续腐化。

---

## 决策

**选择**：选项 B（`sb-core` 内核合集层）

**理由**：
- L19.3.1 的目标是“结束双口径”，不是“本轮完成大迁移”。
- 选项 B 可在当前迭代内达成“文档口径 = crate 现实”，并可被脚本门禁持续约束。
- 选项 A 的迁移工作将拆分为后续 backlog，避免在本轮引入结构性回归风险。

---

## 决策条款（规范性）

1. `sb-core` 角色定义更新为“内核合集层（Kernel Aggregate）”，不再宣称纯引擎层。
2. `sb-core` 中 Web/TLS/QUIC 相关依赖允许存在，但必须是 `optional = true` 且由 feature gate 控制。
3. 新增协议实现默认归属 `sb-adapters`；若确需放在 `sb-core`，必须有显式 ADR 例外。
4. `sb-core` 与 `sb-adapters/sb-transport` 的重叠实现必须登记到迁移清单并明确 owner（由 L19.3.3 产出第一版）。
5. `check-boundaries.sh` 的 strict 升级（L19.3.2）应基于该决策口径实施，不再依赖“纯引擎层”前提。

---

## 影响

**正面**：
- 宪法文档与实现现实对齐，减少误导性设计决策。
- 为后续边界门禁升级提供可执行、可验证规则。
- 降低本轮并行窗口内的大改风险。

**负面**：
- `sb-core` 继续承载部分历史负担，短期结构复杂度仍高。
- 需要额外过程约束，防止“默认把新能力继续塞回 core”。

---

## 迁移策略

1. **Phase 0（本次 L19.3.1）**：统一宪法文档与验收口径，明确 `sb-core` 为内核合集层。
2. **Phase 1（L19.3.2）**：升级边界检查到 strict，重点校验 feature 闭包与绕过路径。
3. **Phase 2（L19.3.3）**：输出重叠实现矩阵 + 第一波迁移 backlog（至少 5 项，含 owner/优先级）。
4. **Phase 3（后续批次）**：按 backlog 渐进迁移，可在条件成熟后再评估向选项 A 收敛。

---

## 回滚策略

若出现以下任一情况，触发“回滚到路线 A（纯引擎层）”评审：

1. 重叠实现数量持续增长且无法收敛。
2. 边界门禁在 strict 模式下无法有效阻断新增绕过。
3. 关键故障复盘显示“core/adapters 双实现漂移”已成为高频根因。

触发后执行：

1. 冻结 `sb-core` 新增协议实现。
2. 创建专门迁移路线 ADR（A 路线执行计划）。
3. 将重叠模块按优先级迁出并强制所有新增协议只进入 `sb-adapters`。

---

## 证据（当前现实）

- 代码目录：`crates/sb-core/src/{inbound,outbound,services,transport,tls}` 存在。
- 依赖定义：`crates/sb-core/Cargo.toml` 含 `axum/tonic/hyper/rustls/quinn/reqwest`（optional + feature gate）。
- 边界脚本：`agents-only/06-scripts/check-boundaries.sh` 当前口径基于 feature gate 放行。

---

## 相关文档

- `agents-only/03-planning/13-L19-REALITY-ALIGNMENT-WORKPACKAGES.md`（L19.3.1/L19.3.2/L19.3.3）
- `reports/第一轮审计意见.md`（2.1/2.2）
- `agents-only/01-spec/03-ARCHITECTURE-SPEC.md`
- `agents-only/01-spec/01-REQUIREMENTS-ANALYSIS.md`
- `agents-only/01-spec/02-ACCEPTANCE-CRITERIA.md`
