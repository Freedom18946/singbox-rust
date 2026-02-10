# L4 开工前置信息收集与分析

> **日期**：2026-02-10  
> **用途**：在进入 L4 执行层任务前，统一“现状口径、阻塞项、环境前提、可执行任务拆分”，避免边做边对齐。  
> **输入来源**：`agents-only/active_context.md`、`agents-only/workpackage_latest.md`、`agents-only/03-planning/06-STRATEGIC-ROADMAP.md`、`reports/L3_AUDIT_2026-02-10*.md`、`scripts/test/*`。

---

## 0. 现状快照（L4 开工基线）

- 当前权威口径：Parity **208/209（99.52%）**，剩余 `PX-015`（Linux runtime/system bus 实机验证）。
- 质量里程碑口径：`M3.1/M3.2/M3.3` 在 `reports/L3_AUDIT_2026-02-10_REMEDIATION.md` 已给出 PASS（含环境受限 SKIP 语义）。
- 架构门禁现状：`./agents-only/06-scripts/check-boundaries.sh` 当前实测 `exit=0`（`V4a=24 <= threshold 25`）。
- 文档规划现状：`06-STRATEGIC-ROADMAP.md` 的 `L4: 当前执行任务` 区块仍为历史待办（与 L1/L2 实际完成态不一致）。

---

## 1. 关键证据与一致性检查

### 1.1 一致性脚本

- 命令：`./agents-only/06-scripts/verify-consistency.sh`
- 结果：PASS（`active_context.md` 与 `workpackage_latest.md` 存在且一致性检查通过）

### 1.2 质量脚本资产可执行性（静态检查）

- `scripts/test_feature_gates.sh`：`-rwxr-xr-x`
- `scripts/test/acceptance/*.sh`：均为可执行
- `scripts/test/bench/*.sh`：均为可执行，`p0-protocols.sh` 非空（588 bytes）
- `scripts/test/stress/run.sh`：已接入 `APP_FEATURES=${SB_STRESS_FEATURES:-long_tests}`

### 1.3 已知冲突/漂移

1. **L4 任务面板陈旧**
- `06-STRATEGIC-ROADMAP.md` 的 L4 区域仍包含“依赖边界 CI 检查待做”等历史事项。

2. **PX-015 优先级口径冲突**
- `workpackage_latest.md` / `active_context.md`：仍将 `PX-015` 作为唯一剩余闭环项。
- `reports/L3_AUDIT_2026-02-10_REMEDIATION.md`：记录了“本轮放弃 Linux runtime/system bus 验收”的用户决策。

3. **边界门禁回归（已解决）**
- 已通过 import 收敛恢复为 PASS（V4a=24）。

---

## 2. L4 开工前必须锁定的前置决策

### 2.1 决策 D1：PX-015 处理策略（必须先定）

- 选项 A（推荐，保持权威口径一致）：继续保留为剩余项，在 Linux 环境完成实机补证后闭环 209/209。
- 选项 B（口径变更）：正式标记为 `Accepted/Won't Fix`，同步更新 `GO_PARITY_MATRIX.md`、`workpackage_latest.md`、`active_context.md`、`ACCEPTANCE-GAPS-TRACKER.md`。

### 2.2 决策 D2：L4 执行目标定义

- 建议将 L4 明确为“执行层任务池”，只放当前周期的可执行项，不再保留历史已完成事项。

### 2.3 决策 D3：M3 PASS 的证据标准

- 建议拆分两类 PASS：
  - `PASS-STRICT`：无 SKIP、无环境豁免。
  - `PASS-ENV-LIMITED`：允许权限/平台限制导致的 SKIP，但需附证据。

---

## 3. 建议的 L4 任务拆分（开工版）

### L4.1 文档口径对齐（P0）
- 目标：修正 `06-STRATEGIC-ROADMAP.md` 的 L4 面板，使其与 L1/L2/L3 当前状态一致。
- 产物：更新后的 L4 任务表 + 与 `workpackage_latest.md` 的互链。

### L4.2 边界门禁回归消除（P0）
- 目标：将 `V4a` 从 26 收敛回 ≤ 25（或经决策后调整阈值并说明理由）。
- 验收：`./agents-only/06-scripts/check-boundaries.sh` exit 0。

### L4.3 PX-015 最终口径闭环（P0）
- 目标：执行 D1。
- 验收：
  - 若选 A：补齐 Linux 两场景证据（resolved 运行/停止）并更新矩阵状态。
  - 若选 B：文档统一改口径，不再作为 Remaining。

### L4.4 质量证据再归档（P1）
- 目标：将 `M3.1~M3.3` 当前可复现命令与日志路径固化为一份“可重复跑”说明。
- 产物：新的质量复验记录（含命令、环境变量、输出目录约定）。

---

## 4. 开工前检查清单（Checklist）

- [ ] 确认 D1（PX-015 的最终策略）
- [ ] 确认 D2（L4 的定义与任务池口径）
- [ ] 确认 D3（M3 PASS 标准）
- [ ] 处理 V4a 回归（不带语义改动优先）
- [ ] 更新 L4 面板并同步 `active_context/workpackage_latest`

---

## 5. 建议先跑的最小命令集

```bash
# 1) 文档一致性
./agents-only/06-scripts/verify-consistency.sh

# 2) 边界门禁
./agents-only/06-scripts/check-boundaries.sh

# 3) 质量 smoke（脚本链）
./scripts/test_feature_gates.sh
./scripts/test/acceptance/schema-v2.sh
./scripts/test/bench/run.sh
./scripts/test/stress/run.sh short
```

---

## 6. 结论

L4 开工的主要风险不在“代码未知”，而在**口径不统一**（PX-015 与 L4 面板陈旧）和**门禁回归未清零**（V4a 超阈值）。先锁定三项决策（D1~D3）并清理 P0 阻塞，再进入 L4 执行可显著降低返工概率。
