# 第一次审议意见执行-汇报报告

## 1. 目的与范围

- 审议输入：`reports/第一轮审计意见.md`
- 覆盖条目：`1.1/1.2/1.3/2.1/2.2/3.1/3.2/4.1/5.1`（共 9 条）
- 本报告目标：逐点说明“是否执行、执行到什么程度、证据在哪里、残余风险是什么”。

## 2. 执行总览

- 已完成并推送的 L19 关键提交（本轮相关）：
  - `ed13cdf` (`L19.4.3`) 性能验收口径重写 + 分层执行入口
  - `0429a3e` (`L19.5.1`) `GET /capabilities` 强契约端点 + HTTP 合同覆盖
  - `06725a2` (`L19.5.2`) GUI 固定请求集合同测试 + L19 收口报告
- L20 已完成收口并回填证据链：
  - `5171cc1` (`L20.4.1`) `/capabilities` 契约 v2 协商字段
  - `c7d5607` (`L20.4.2`) GUI cert 接入 capability negotiation gate
  - `a3bf16e` (`L20.4.3`) L20 capstone 报告与最终状态回填
  - 对应报告：`reports/L20_DEEP_ALIGNMENT.md`
- 推送分支：`origin/codex/l19-batch-a`

## 3. 逐点回复（第一次审议意见）

| 审议条目 | 审议问题摘要 | 执行状态 | 对应工作包 | 核心证据 | 当前结论 |
| --- | --- | --- | --- | --- | --- |
| 1.1 | TUN/tun2socks 文档与实现状态断裂 | `CLOSED`（真实性闭环） | `L19.1.x`, `L19.2.1`, `L19.4.1`, `L19.4.2` | `reports/capabilities.json`, `docs/capabilities.md`, `scripts/test/tun_linux_e2e.sh`, `scripts/test/tun_macos_longrun.sh` | 已把“可编译/可运行/可验证”拆分并落地；默认 stub 仍保留为 accepted limitation。 |
| 1.2 | uTLS 宣称高估 | `CONTROLLED` | `L19.1.x`, `L19.1.3`, `L19.1.4` | `reports/capabilities.json`（`tls.utls=implemented_unverified`）, `scripts/check_claims.sh` | 已禁止无条件“full support”宣称；能力差距未伪装，后续实现深度进入 L20。 |
| 1.3 | ECH provider/QUIC 路径断裂 | `CONTROLLED` | `L19.2.2`, `L19.2.3`, `L19.2.4` | `reports/capabilities.json`, QUIC+ECH 配置硬拒绝逻辑（已接入） | 已实现单点决策+确定性失败快报；QUIC-ECH 仍未宣称可用。 |
| 2.1 | 宪法与边界检查可绕过 | `CLOSED` | `L19.3.1`, `L19.3.2` | ADR 决议文档 + strict boundary gate | 已完成“口径统一 + strict 门禁升级”，可阻断绕过路径。 |
| 2.2 | `sb-core` 与 adapters/transport 重叠腐烂风险 | `PARTIAL` | `L19.3.3` | 重叠矩阵与迁移 backlog（已建） | 已完成清单化和 owner 归属，迁移动作需在下一阶段持续执行。 |
| 3.1 | interop 偏控制面、缺少真实数据面 | `CLOSED` | `L19.4.1`, `L19.4.2` | Linux netns e2e + macOS longrun 脚本与报告模板 | 已新增真实数据面验证入口与证据产物，覆盖 MTU/UDP/DNS/并发等核心场景。 |
| 3.2 | 性能验收指标口号化、不可复算 | `CLOSED` | `L19.4.3` | `agents-only/01-spec/02-ACCEPTANCE-CRITERIA.md`, `scripts/test/bench/l19_perf_acceptance.sh` | 已改为 Baseline/Router+API/Parity 分层，固定 P50/P95/P99、冷热定义、产物路径。 |
| 4.1 | GUI 兼容依赖弱协议，缺少强契约 | `CLOSED` | `L19.5.1`, `L19.5.2` | `/capabilities` 端点 + `crates/sb-api/tests/capabilities_contract.rs` + `scripts/l19/capabilities_contract.sh` | 已形成“版本/能力协商 + 固定请求集 shape 合同测试”闭环。 |
| 5.1 | 多文档事实源冲突 | `CLOSED` | `L19.1.2`, `L19.1.3`, `L19.1.4` | `docs/capabilities.md`, `reports/capabilities.json`, claim guard | 已确立单一事实源并接入门禁，README/STATUS 不再独立定义高风险事实。 |

## 4. 本轮新增执行证据

- GUI 合同套件：`reports/l19/contracts/capabilities_contract.json`
- L19 收口报告：`reports/L19_REALITY_ALIGNMENT.md`
- 性能分层入口：`scripts/test/bench/l19_perf_acceptance.sh`

## 5. 复核命令结果

- `bash scripts/check_claims.sh` -> `PASS`
- `bash agents-only/06-scripts/check-boundaries.sh` -> `PASS`
- `bash scripts/ci/tasks/docs-links.sh` -> `PASS`
- `bash scripts/l19/capabilities_contract.sh` -> `PASS`

## 6. 残余风险与下一步建议（L20 收口后）

1. `uTLS`：仍是“可用但未达到 Go uTLS 全指纹等价”的受控差距。
2. `ECH/QUIC-ECH`：已硬护栏避免误导，但完整能力尚未开放。
3. `sb-core` 重叠迁移：治理框架已就绪，需持续执行迁移 backlog 直到重复实现收敛。

## 7. L20 回填状态

- 当前状态：`L20` 已收口完成（A1+A2+A3 + B1+B2+B3 + C1 wave#1+C2+C3 + D1+D2+D3）。
- 收口证据总入口：`reports/L20_DEEP_ALIGNMENT.md`。
- 最新工作包状态页：`agents-only/workpackage_latest.md`。
