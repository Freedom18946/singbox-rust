<!-- tier: S -->
# 当前上下文（Active Context）
> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。
---
## 战略状态
**当前阶段**: GUI + 双内核实测验收（MT-GUI-01）已建立，部署基线（MT-DEPLOY-01）已完成
**Parity**: 92.9% (52/56)，以 `labs/interop-lab/docs/dual_kernel_golden_spec.md` 为准
**当前阶段焦点**: GUI 驱动的 Go/Rust 双内核行为对比已取证

## 最近闭环（2026-04-10）

### MT-GUI-01: GUI 驱动 Go/Rust 双内核对比验收 — 已完成
- **不是** parity completion；只是基于真实命令的 GUI 路径对比证据
- 通过阅读 `GUI_fork_source/GUI.for.SingBox-1.19.0/frontend/src/api/kernel.ts` 重建 GUI 完整 API 契约
- 使用 `labs/interop-lab/configs/l18_gui_{rust,go}.json` 作为 GUI-shape 同构配置
- 双内核同时运行 + 同一 REST/WS 路径调用 + SOCKS5 数据面拉通
- 共 15 个场景：**10 PASS-STRICT / 4 PASS-ENV-LIMITED / 1 NEW FINDING / 0 FAIL**
- 4 个已知差异全部对得上 golden spec：DIV-M-006/007/008/009
- 一个新观察项（不是 blocker）：post-close `downloadTotal` Rust=0 vs Go=2454，分类暂缓
- 报告：`agents-only/mt_gui_01_acceptance.md`、`agents-only/mt_gui_01_matrix.md`
- 证据脚本与原始输出：`agents-only/mt_gui_01_evidence/`

### MT-DEPLOY-01: 部署验收基线 — 已完成（仍生效）
- 修复 `app/src/tracing_init.rs` 与 `app/Cargo.toml` 的 parity feature blocker
- 9 项部署链全部 PASS-STRICT，详见 `agents-only/mt_deploy_01_acceptance.md`

## 当前验证事实
- 双内核都能用同一 GUI-shape 配置启动并暴露 Clash API
- GUI 的 REST/WS 全面契约在两侧都可达
- SOCKS5 数据面在两侧都可中继真实 HTTP 流量
- 4 个已知 cosmetic/structural 差异全部已记录
- 1 个新观察项 (`downloadTotal` 累计计数) 仅作为记录，不开新 maintenance 卡

## 环境限制项（PASS-ENV-LIMITED）
- WS 流通过 curl `--http1.1` 探测得到数据但不是真实 WS handshake（实际 WS 走 interop-lab 的 `p0_clash_api_contract*`）
- GUI 桌面二进制本身（Wails desktop）未在沙箱构建运行，转而通过读 GUI 源码复现其 API 调用
- E2E proxy 真实上游链路（需真实代理服务）：未测试
- Docker 镜像构建 / k8s / helm：未测试

## 当前默认准则
- GUI 驱动双内核对比已取证，不再扩散为新 maintenance 重构
- 不把 MT-GUI-01 的实测结果改写成 parity completion
- 不开 follow-up card 除非新观察项的信号反复出现
- 不恢复细碎 maintenance 排程
- 不推进 public `RuntimePlan`、public `PlannedConfigIR`、generic query API

## 暂停事项
- 不恢复 `.github/workflows/*`
- 不恢复 `WP-30k` 风格微卡
