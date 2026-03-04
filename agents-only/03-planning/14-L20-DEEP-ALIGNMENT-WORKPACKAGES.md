# L20 详细工作包规划：深水区能力实证与迁移收敛

状态：🟡 执行中（A1 + C1 wave#1 已落地）
更新：2026-03-05 00:20 CST

## Context

- 输入来源：`reports/第一轮审计意见.md` + `reports/FIRST_REVIEW_EXECUTION_REPORT.md` + `reports/L19_REALITY_ALIGNMENT.md`。
- L19 已完成“事实源、门禁、能力探针、真实数据面脚本、GUI 强契约 v1”。
- 当前剩余高风险点主要集中在：
  1. `uTLS` 与 Go 语义差距的可测量证据不足（仅“implemented_unverified”）。
  2. `ECH/QUIC-ECH` 支持边界虽已护栏化，但缺少系统化互操作证据链。
  3. `sb-core` 与 `sb-adapters/sb-transport` 的重叠迁移仅完成规划，尚未落到代码收敛。

## L20 目标与边界

### 主目标

1. 把 `uTLS/ECH` 从“口径真实”推进到“证据可复算”。
2. 完成第一波重叠实现迁移，降低 `sb-core` 腐蚀风险。
3. 将 `/capabilities` 从“可读”推进到“可协商/可门禁”的 GUI 契约 v2。
4. 输出 L20 收口报告，确保下一轮迭代不回退到“文档闭环”。

### 非目标

- 不在 L20 承诺 server-side ECH 完整支持。
- 不在 L20 完成所有 `sb-core` 重叠清空；只完成第一波高收益迁移。
- 不在 L20 内替换全部历史 bench/stress 框架；优先改造与能力真实性直接相关的链路。

## 批次总览

| Batch | 工作包数 | 主题 | 依赖 |
| --- | ---: | --- | --- |
| A | 3 | uTLS 指纹真实性与证据化 | 无 |
| B | 3 | ECH/QUIC-ECH 运行边界与互操作实证 | A2 |
| C | 3 | `sb-core` 重叠迁移第一波 | L19.3.3 |
| D | 3 | GUI 契约 v2 与 L20 收口 | A/B/C |

总量：12 WP（单 WP 粒度控制在 2~6 小时）

---

## Batch A：uTLS 指纹真实性与证据化（P0）

### L20.1.1 — 指纹观测基线（Go vs Rust）

- **复杂度**: M | **优先级**: P0 | **依赖**: 无
- **内容**: 新增 ClientHello 指纹采样基线（JA3/扩展顺序摘要），同配置下对比 Go 与 Rust。
- **交付**:
  - `scripts/test/tls_fingerprint_baseline.sh`
  - `reports/security/tls_fingerprint_baseline.json`
- **验收**:
  - 产物至少包含 3 组 profile（chrome/firefox/randomized）对比结果。

### L20.1.2 — uTLS 能力矩阵细化（profile 级）

- **复杂度**: S | **优先级**: P0 | **依赖**: L20.1.1
- **内容**: 将 `tls.utls` 从单 capability 细分到 profile 级状态（如 `tls.utls.chrome`）。
- **交付**:
  - `scripts/capabilities/schema.json`（子能力扩展）
  - `docs/capabilities.md`（profile 级说明）
- **验收**:
  - claim guard 对高风险 uTLS 宣称可定位到具体 profile。

### L20.1.3 — 启动探针输出 uTLS 实际生效模式

- **复杂度**: M | **优先级**: P1 | **依赖**: L20.1.2
- **内容**: capability probe 增加 “requested profile / effective profile / fallback reason”。
- **交付**:
  - probe 输出字段扩展
  - `reports/runtime/capability_probe.json` 示例
- **验收**:
  - 启动日志与 `capabilities.json` 中的 probe 字段一致。

---

## Batch B：ECH/QUIC-ECH 边界与互操作实证（P0）

### L20.2.1 — ECH provider 决策外显化（配置 + API）

- **复杂度**: M | **优先级**: P0 | **依赖**: L20.1.2
- **内容**: 将 `SB_TLS_PROVIDER` 决策结果暴露到 `/capabilities` 与运行日志，形成双通道证据。
- **交付**:
  - `/capabilities` provider 字段
  - provider 决策一致性测试
- **验收**:
  - API 与日志 provider 信息一致，不允许分叉。

### L20.2.2 — QUIC-ECH 显式模式机（reject/experimental）

- **复杂度**: M | **优先级**: P0 | **依赖**: L20.2.1
- **内容**: 配置层新增模式开关：默认 `reject`，实验态显式 `experimental`（带风险提示）。
- **交付**:
  - config validator 更新
  - 文档模式说明（默认拒绝、不 silent fallback）
- **验收**:
  - 未开启 experimental 时严格拒绝；开启后行为可追踪。

### L20.2.3 — ECH 互操作最小证据链

- **复杂度**: L | **优先级**: P1 | **依赖**: L20.2.2
- **内容**: 建立 TCP-TLS ECH 与 QUIC-ECH（若 experimental）最小互操作场景。
- **交付**:
  - `scripts/test/ech_interop_minimal.sh`
  - `reports/security/ech_interop_minimal.json`
- **验收**:
  - 每个模式至少 1 组 PASS/FAIL 可复现样例与日志。

---

## Batch C：重叠迁移第一波（P0）

### L20.3.1 — 迁移波次 #1（3 项）

- **复杂度**: L | **优先级**: P0 | **依赖**: L19.3.3
- **内容**: 从 L19 重叠矩阵中挑选 3 项高收益实现，从 `sb-core` 迁移到目标 crate。
- **交付**:
  - 3 项迁移 PR（含 owner 与回滚点）
- **验收**:
  - `check-boundaries.sh --strict` 通过，且功能回归通过。

### L20.3.2 — strict gate 增加迁移追踪断言

- **复杂度**: M | **优先级**: P0 | **依赖**: L20.3.1
- **内容**: 边界脚本对“已迁移条目”加入硬断言，防止代码回流到 `sb-core`。
- **交付**:
  - `agents-only/06-scripts/check-boundaries.sh` 新断言段
  - allowlist 版本化记录
- **验收**:
  - 人工回流样例可触发阻断失败。

### L20.3.3 — 迁移后能力矩阵回填

- **复杂度**: S | **优先级**: P1 | **依赖**: L20.3.1
- **内容**: 更新 `docs/capabilities.md` 与重叠矩阵状态，标注迁移完成项。
- **交付**:
  - `agents-only/05-analysis/L19.3.3-SB-CORE-OVERLAP-MATRIX.md` 更新
- **验收**:
  - 迁移清单与代码现实一致，不出现“文档已迁移、代码未迁移”。

---

## Batch D：GUI 契约 v2 与收口（P0）

### L20.4.1 — `/capabilities` 契约 v2（协商字段）

- **复杂度**: M | **优先级**: P0 | **依赖**: L20.2.1
- **内容**: 新增协商字段：`contract_version`, `required_by_gui`, `breaking_changes`。
- **交付**:
  - API schema 文档
  - 版本协商单测
- **验收**:
  - GUI/脚本可基于协商字段决定是否继续运行测试。

### L20.4.2 — GUI 认证链路接入能力协商门禁

- **复杂度**: M | **优先级**: P0 | **依赖**: L20.4.1
- **内容**: `scripts/l18/gui_real_cert.sh` 在执行前读取 `/capabilities` 做前置兼容检查。
- **交付**:
  - GUI cert 报告增加 capability negotiation section
- **验收**:
  - 兼容不满足时 fail-fast 且输出明确原因。

### L20.4.3 — L20 Capstone 报告

- **复杂度**: S | **优先级**: P0 | **依赖**: L20 全部
- **内容**: 输出 `reports/L20_DEEP_ALIGNMENT.md`，逐 WP 回填证据与残余风险。
- **交付**:
  - L20 总报告
- **验收**:
  - 每个 WP 有命令、产物路径、结果状态三元组。

---

## 执行顺序建议

1. A（uTLS 可测化）与 C（迁移第一波）并行起步。
2. B 依赖 A2 的能力细分后推进。
3. D 在 A/B/C 收敛后统一接线并收口。

## 执行进展（2026-03-05）

- ✅ `L20.1.1`：已落地 `scripts/test/tls_fingerprint_baseline.sh`，并产出 `reports/security/tls_fingerprint_baseline.json`（覆盖 `chrome/firefox/randomized` 三组）。
- ✅ `L20.3.1`（wave#1）：已完成 3 项迁移子项（`direct` builder 收敛、`tailscale` direct 类型解耦、DoT 迁至 `sb-transport`），详见 `agents-only/05-analysis/L19.3.3-SB-CORE-OVERLAP-MATRIX.md` 的 `3A` 节。

## L20 完成定义（DoD）

1. `uTLS/ECH` 能力状态具备 profile/模式级证据，不再只有宏观标签。
2. `sb-core` 第一波迁移完成且有回流阻断门禁。
3. GUI 合同测试依赖 `/capabilities` 协商字段，不再依赖隐式行为。
4. L20 报告可追溯到每个 WP 的执行日志与产物。
