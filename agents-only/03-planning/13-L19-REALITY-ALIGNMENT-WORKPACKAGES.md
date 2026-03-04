# L19 详细工作包规划：事实收敛与能力实证

状态：🆕 规划冻结（待执行）  
更新：2026-03-04 21:36 CST

## Context

- 输入：`reports/第一轮审计意见.md` 的逐点复核结果（已确认）。
- 校准结论：9 条中 7 条成立，2 条部分成立，0 条不成立。
- 核心问题：文档宣称、构建能力、运行能力、验证证据之间存在断裂，影响“可替代 sing-box”目标可信度。

## L19 目标与边界

### 主目标

1. 建立唯一事实来源（Single Source of Truth），统一能力口径。
2. 将“编译可用”与“运行可用”拆分并可探测、可验证、可追溯。
3. 收敛 sb-core 边界治理，消除“宪法存在但门禁宽松”的执行断裂。
4. 补齐真实 TUN 数据面与性能口径验证，避免仅控制面/模拟闭环。
5. 把 GUI 兼容从隐式契约升级为强契约（版本/能力协商 + 合同测试）。

### 非目标

- 不在 L19 内完成所有大规模协议迁移；L19 只完成“收敛方案 + 首批落地 + 验证闭环”。
- 不在 L19 内承诺 server-side ECH/完整 QUIC-ECH 支持；只要求能力状态真实、可观测、可失败快报。

## 批次总览

| Batch | 工作包数 | 主题 | 阻断关系 |
|---|---:|---|---|
| A | 4 | 口径与事实源收敛 | B/C/D/E 依赖 A 的口径定义 |
| B | 4 | 运行能力探针与 TLS/ECH 真实化 | E 依赖 B 的能力输出 |
| C | 3 | 架构边界治理收紧 | D/E 可并行，建议先完成 C2 |
| D | 3 | 真实数据面与性能口径验证 | E 可并行 |
| E | 2 | GUI 强契约与 L19 结项 | 依赖 A+B，建议吸收 D 结果 |

总量：16 工作包（单 WP 拆分粒度控制在 1-4 小时）

---

## Batch A：口径与事实源收敛（P0）

### L19.1.1 — 能力三态模型定版（Implemented&Verified / Implemented-Unverified / Scaffold）

- **复杂度**: S | **优先级**: P0 | **依赖**: 无
- **内容**: 定义能力状态、证据字段、降级规则（含 accepted limitation 显示规范）。
- **交付**: `agents-only/01-spec/02-ACCEPTANCE-CRITERIA.md` 增补能力判定章；`agents-only/07-memory/LEARNED-PATTERNS.md` 新增能力标注模式。
- **验收**: 任一能力可被唯一判定到三态之一，且能给出证据路径。

### L19.1.2 — `capabilities.json` 结构与生成入口

- **复杂度**: M | **优先级**: P0 | **依赖**: L19.1.1
- **内容**: 定义 `capabilities.json` schema 与最小生成管线（probe/test/doc 汇总位）。
- **交付**: `docs/capabilities.md`（读者版）；`reports/capabilities.json`（机器版）；`scripts/capabilities/` 生成入口脚本。
- **验收**: 本地可一键生成；产物包含能力状态、证据、更新时间。

### L19.1.3 — 文档口径统一第一轮（去冲突）

- **复杂度**: M | **优先级**: P0 | **依赖**: L19.1.2
- **内容**: 统一 `README/STATUS/REQUIREMENTS/RUST_ENHANCEMENTS/platform-io/GO_PARITY_MATRIX` 口径，去除互相打脸项。
- **交付**: 相关文档更新与冲突映射表（before/after）。
- **验收**: 抽查 TUN、redirect/tproxy、uTLS、ECH、QUIC-ECH 五项时，不再出现“同仓多口径冲突”。

### L19.1.4 — 宣称门禁（CI Claim Guard）

- **复杂度**: S | **优先级**: P1 | **依赖**: L19.1.3
- **内容**: 增加文档宣称检查，禁止在能力未 Verified 时出现“production ready/full parity 完全支持”等高风险措辞。
- **交付**: `scripts/check_claims.sh` + CI 调用。
- **验收**: 人为制造冲突宣称时 CI 必须 fail。

---

## Batch B：运行能力探针与 TLS/ECH 真实化

### L19.2.1 — tun2socks `stub/real` 可切换化 + 构建标识

- **复杂度**: M | **优先级**: P0 | **依赖**: L19.1.1
- **内容**: 将 tun2socks 从全局 stub patch 改为可切换能力，构建产物写出 capability 标识。
- **交付**: `tun2socks-stub` / `tun2socks-real` 特性设计与接线；`version` 输出能力位。
- **验收**: `stub` 与 `real` 构建输出可区分，用户可见当前能力状态。

### L19.2.2 — 运行时能力探针框架（Capability Probe）

- **复杂度**: M | **优先级**: P0 | **依赖**: L19.2.1
- **内容**: 对 TUN/redirect/tproxy/uTLS/ECH/QUIC-ECH 增加启动探针与明确日志。
- **交付**: probe 模块 + 统一日志格式 + probe 结果写入 `capabilities.json`。
- **验收**: 启动日志可直接定位“编译支持/运行支持/降级原因”。

### L19.2.3 — ECH provider 单点决策与确定性日志

- **复杂度**: M | **优先级**: P0 | **依赖**: L19.2.2
- **内容**: 统一 provider 初始化入口，消除多处 `install_default` 竞争与不透明行为。
- **交付**: provider 初始化单点模块；启动日志明确 `provider=<ring|aws-lc>` 与 ECH 状态。
- **验收**: 任意运行路径只出现一个 provider 决策来源；日志可追踪。

### L19.2.4 — QUIC-ECH 明确支持边界与失败快报

- **复杂度**: M | **优先级**: P1 | **依赖**: L19.2.3
- **内容**: 在未完成完整接线前，显式“not supported”并输出替代路径（TCP-TLS ECH）。
- **交付**: QUIC/ECH 代码路径护栏、用户错误提示、文档能力矩阵更新。
- **验收**: 用户配置 QUIC-ECH 时得到确定性行为（明确拒绝或明确支持），无 silent fallback。

---

## Batch C：架构边界治理收紧

### L19.3.1 — `sb-core` 角色决议 ADR（路线 A/B 二选一）

- **复杂度**: S | **优先级**: P0 | **依赖**: 无
- **内容**: 正式决议 `sb-core` 是“纯引擎层”还是“内核合集层”，结束双口径。
- **交付**: ADR 文档（含影响面、迁移策略、回滚策略）。
- **验收**: 宪法文档与 crate 现实口径一致，不再互相冲突。

### L19.3.2 — `check-boundaries.sh` 严格模式升级

- **复杂度**: M | **优先级**: P0 | **依赖**: L19.3.1
- **内容**: 从“optional 即放行”升级为“默认特性闭包 + feature tree + 反向依赖”联合检查。
- **交付**: `agents-only/06-scripts/check-boundaries.sh` strict 模式；报告模式保留。
- **验收**: 构造 optional 绕过样例时 strict 必须识别并 fail。

### L19.3.3 — `sb-core` 与 `sb-adapters/sb-transport` 重叠清单 + 第一波迁移计划

- **复杂度**: M | **优先级**: P1 | **依赖**: L19.3.1
- **内容**: 生成重复实现清单并排序（风险/改造成本/影响面），产出第一波迁移 backlog。
- **交付**: 重叠矩阵文档 + 迁移优先级列表（至少 5 项）。
- **验收**: 每项重复实现都有唯一 owner 与迁移目标 crate。

---

## Batch D：真实数据面与性能口径验证

### L19.4.1 — Linux TUN 数据面 e2e Profile（netns/veth/iptables）

- **复杂度**: L | **优先级**: P0 | **依赖**: L19.2.2
- **内容**: 增加真实链路验证（MTU、UDP、DNS、路由回环、并发连接）。
- **交付**: `scripts/test/tun_linux_e2e.sh` + 对应报告模板。
- **验收**: 最小场景可复现，失败时有可定位证据（pcap/log/probe）。

### L19.4.2 — macOS TUN 长跑验证（10k 连接 + UDP + DNS 抖动）

- **复杂度**: L | **优先级**: P1 | **依赖**: L19.2.1, L19.2.2
- **内容**: 建立本机可重复的长时稳定性脚本与指标采样。
- **交付**: `scripts/test/tun_macos_longrun.sh` + `reports/stability/tun_macos_longrun.json`。
- **验收**: 可稳定跑完预设时长并输出内存/FD/失败率曲线。

### L19.4.3 — 性能验收口径重写（分层 + 测量方法固定）

- **复杂度**: M | **优先级**: P0 | **依赖**: L19.1.1
- **内容**: 将性能验收拆为 Baseline / Router+API / Parity 三层，固定 P50/P95/P99、冷热、feature 集、平台范围。
- **交付**: `agents-only/01-spec/02-ACCEPTANCE-CRITERIA.md` 性能章重写 + 基准脚本入口。
- **验收**: 每个指标均有可复算命令与产物路径，不再出现“口号型阈值”。

---

## Batch E：GUI 强契约与结项

### L19.5.1 — `/capabilities` 契约端点（schema_version + compat_version + capability matrix）

- **复杂度**: M | **优先级**: P0 | **依赖**: L19.1.2, L19.2.2
- **内容**: 增加机器可读能力端点，弱化对隐式行为与日志字符串的依赖。
- **交付**: Clash API 新端点与文档，字段向后兼容说明。
- **验收**: GUI/测试工具可通过端点判定能力，而非猜测行为细节。

### L19.5.2 — GUI 合同测试 + L19 Capstone 报告

- **复杂度**: M | **优先级**: P0 | **依赖**: L19.5.1, L19.4.3
- **内容**: 固定请求集与响应 JSON shape 检查，输出 L19 总结报告（真实性/有效性闭环）。
- **交付**: 合同测试套件、`reports/L19_REALITY_ALIGNMENT.md`。
- **验收**: 合同测试通过；L19 报告可追溯到每个 WP 的证据产物。

---

## 执行顺序建议

1. 先做 Batch A（定义事实源与口径）  
2. 并行启动 Batch B/C（能力探针 + 边界治理）  
3. Batch D 在 B 基础上执行真实数据面验证  
4. Batch E 最后收口，形成 GUI 强契约与 L19 总报告

## L19 完成定义（DoD）

1. 口径：README/STATUS/agents-only 与 `capabilities.json` 一致，无冲突宣称。  
2. 能力：关键能力均具备 compile/runtime/probe/e2e 证据链。  
3. 架构：`sb-core` 角色清晰，边界门禁可阻断绕过。  
4. 测试：新增真实 TUN 数据面验证，不再仅控制面闭环。  
5. GUI：具备显式 capabilities 协议与合同测试，不依赖隐式契约。
