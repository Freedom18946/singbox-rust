<!-- tier: S -->
# 当前上下文（Active Context）
> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。
---
## 战略状态
**当前阶段**: GUI 双内核差异归类收口（MT-GUI-03）完成 — 把 MT-GUI-01/02 所有差异落入 5 类分类体系，并把两条 deferred finding 以 `DIV-M-010`/`DIV-M-011` 登记进 golden spec
**Parity**: 52/60 (86.7%)，以 `labs/interop-lab/docs/dual_kernel_golden_spec.md` 为准（新增 2 条 COSMETIC DIV，不变更 oracle 行为）
**当前阶段焦点**: GUI 语境下的双内核差异已全部归类完毕 — 无 blocker，无新卡，无代码改动

## 最近闭环（2026-04-12）

### MT-GUI-03: GUI 双内核差异归类 + oracle 对账 — 已完成

- **不是** parity completion，**不是** 代码整改；只做差异归类、oracle 对账、证据收口
- 基于 MT-GUI-01 (15 scenarios) + MT-GUI-02 (35 scenarios) 的既有原始证据（本日 05:30 新鲜 re-run），无需新复跑
- 10 项 GUI 双内核差异全部归类：
  - **5 Covered by Existing Divergence**：`/configs`, `/proxies`, `/proxies/{name}/delay`, `/connections.memory`, `/dns/query` 成功应答 shape — 全部对应 DIV-M-005..009
  - **2 New Finding, Non-Blocking**：`/rules` list vs null、`/providers/rules` `{}` vs `[]` — 均 200 + 语义等价，不升级 DIV，不开卡
  - **1 Environment-Limited**：curl WS handshake — 已被 `p0_clash_api_contract*` + MT-GUI-02 DP-12 真 RFC 6455 覆盖
  - **2 Extension of Existing Accepted Limitation**：
    - CP-13 `/dns/query` 非可解析域名 Rust=500 Go=200 → 新增 `DIV-M-010`（设计级差异：Rust 诚实报错 / Go fake-IP 合成，不改 Rust）
    - DP-16 累计 `downloadTotal` Rust=0 Go=1055032 → 新增 `DIV-M-011`（Rust 仅 per-connection 计数，不跨关闭累计；GUI 带宽图用 WS `/traffic`，不受影响）
- Golden spec `§S4` 增补两行（纯文档，不改 oracle、不改 case、不改代码）
- 不更新 `GO_PARITY_MATRIX.md`（代码级 closure 口径无变化）、不更新 `ACCEPTANCE-CRITERIA.md`（tri-state 已覆盖）
- 报告：`agents-only/mt_gui_03_divergence_review.md`

### MT-GUI-02: GUI 驱动 + 本地公网模拟 全面验收 — 已完成（仍生效）

- **不是** parity completion；扩展 MT-GUI-01 的 surface，加 mock 公网基础设施让证据可复现
- 构建单文件纯 stdlib Python mock：HTTP/HTTPS(自签)/RFC 6455 WS/SSE/chunked/大 body/慢上游/订阅(Bearer+ETag+304)/early-close/RST/dead port
- 双内核同时运行 → 三个平面全部覆盖：
  - 控制平面 14 场景：12 PASS-STRICT / 1 PASS-ENV-LIMITED / 1 NEW FINDING / 0 FAIL
  - 数据平面 16 场景：15 PASS-STRICT / 1 CONFIRMED FINDING（MT-GUI-01 §5 重现） / 0 FAIL
  - 订阅刷新 5 场景：5 PASS-STRICT
- 总计 **35 场景：32 PASS-STRICT / 1 PASS-ENV-LIMITED / 1 NEW FINDING / 1 CONFIRMED FINDING / 0 FAIL**
- 5 个已知差异全部对得上 golden spec：DIV-M-005/006/007/008/009
- NEW FINDING：`/dns/query?name=mock-public.local`（不可解析域名）Rust=500 Go=200 + fake answer，设计级差异而非 parity bug
- CONFIRMED FINDING：MT-GUI-01 §5 重现 — 1 MiB 流量下 Rust `downloadTotal` 仍保持 0，Go=1055034；分类仍暂缓
- 报告：`agents-only/mt_gui_02_acceptance.md`、`agents-only/mt_gui_02_matrix.md`、`agents-only/mt_gui_02_mock_public_infra.md`
- 证据 + 脚本：`agents-only/mt_gui_02_evidence/`（orchestrator + mock + 4 个测试脚本 + 所有 raw txt/log）

### MT-GUI-01: GUI 驱动 Go/Rust 双内核对比验收 — 已完成（仍生效）

- 15 场景：10 PASS-STRICT / 4 PASS-ENV-LIMITED / 1 NEW FINDING
- 一个新观察项：post-close `downloadTotal` Rust=0 vs Go=2454；MT-GUI-02 已重现并记录为 CONFIRMED FINDING

### MT-DEPLOY-01: 部署验收基线 — 已完成（仍生效）

- 修复 `app/src/tracing_init.rs` 与 `app/Cargo.toml` 的 parity feature blocker
- 9 项部署链全部 PASS-STRICT

## 当前验证事实

- 双内核都能用同一 GUI-shape 配置启动并暴露 Clash API
- GUI 的 REST/WS 全面契约在两侧都可达，真实 RFC 6455 WS 通过 SOCKS5 CONNECT 在两侧均通
- 完整 SOCKS5 数据面覆盖：HTTP/HTTPS(self-signed)/SSE/chunked/1 MiB/slow/early-close/RST/dead port/TCP echo 全部在两侧一致
- 订阅拉取（Bearer + ETag + 304）+ 两侧 `check` 验证配置解析均通过
- 5 个已知 DIV-M-005..009 差异全部已记录；两个新的 cosmetic 差异（`/rules` list vs null、`/providers/rules` object vs array）仅记录不升级
- 两个 deferred finding 已在 MT-GUI-03 归类并登记为 `DIV-M-010` / `DIV-M-011`（纯 COSMETIC 文档补丁，无 oracle 变更、无代码改动、无新卡）

## 环境限制项（PASS-ENV-LIMITED）

- 控制平面 WS 探测仍用 curl `--http1.1`（covered by `p0_clash_api_contract*`）
- GUI 桌面二进制本身（Wails desktop）未构建运行，通过读 GUI 源码复现其 API 调用
- 真实上游代理链路 / Docker 镜像 / k8s / helm：未测试

## 当前默认准则

- GUI 全面取证已完成，维护状态继续
- 不把 MT-GUI-02 的实测结果改写成 parity completion
- NEW FINDING / CONFIRMED FINDING 都不开 follow-up card，除非信号反复出现
- 不推进 public `RuntimePlan` / `PlannedConfigIR` / generic query API
- 不恢复 `.github/workflows/*`，不恢复 `WP-30k` 风格微卡
