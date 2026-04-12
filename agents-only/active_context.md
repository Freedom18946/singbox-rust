<!-- tier: S -->
# 当前上下文（Active Context）
> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。
---
## 战略状态
**当前阶段**: 声明完成能力全量逐项验收（MT-GUI-04）完成 — 55 项能力逐条清账，0 FAIL，0 NEW FINDING
**Parity**: 52/56 BHV (92.9%)，以 `labs/interop-lab/docs/dual_kernel_golden_spec.md` 为准
**当前阶段焦点**: 所有声明完成项已逐项验收闭环 — 无 blocker，无新发现，无代码改动

## 最近闭环（2026-04-12）

### MT-GUI-04: 声明完成能力全量逐项验收 — 已完成

- **不是** parity completion；是对所有声明完成项的 exhaustive per-capability acceptance sweep
- 从 golden spec §S3 + GUI kernel.ts + MT-DEPLOY-01 + MT-GUI-01/02 枚举出 55 项能力
- 6 个类别：启动/生命周期(5) + 控制平面API(21) + 流量面(17) + 订阅(5) + 可观察性(5) + 关闭(2)
- 双内核同时运行 + mock 公网 → 逐项测试每一项能力
- **结果：55/55 通过，0 FAIL，0 NEW FINDING**
  - 35 PASS-STRICT (63.6%)
  - 7 PASS-DIV-COVERED (12.7%) — 全部挂到 DIV-M-005..011
  - 13 PASS-ENV-LIMITED (23.6%) — 全部有 interop-lab 真实 WS 覆盖
- 报告：`mt_gui_04_acceptance.md`、`mt_gui_04_matrix.md`、`mt_gui_04_capability_inventory.md`、`mt_gui_04_gap_list.md`
- 证据：`mt_gui_04_evidence/raw_sweep.txt` + `exhaustive_sweep.sh`

### MT-GUI-03: GUI 双内核差异归类 — 已完成（仍生效）

- 10 项差异全部归类：5 Covered + 2 Non-Blocking + 1 Env-Limited + 2 Extension
- 新增 DIV-M-010 / DIV-M-011（COSMETIC，无 oracle 变更）

### MT-GUI-02/01/DEPLOY-01 — 已完成（仍生效）

- MT-GUI-02: 35 场景，32 PASS-STRICT / 1 ENV-LIMITED / 1 NEW / 1 CONFIRMED / 0 FAIL
- MT-GUI-01: 15 场景，10 PASS-STRICT / 4 ENV-LIMITED / 1 NEW
- MT-DEPLOY-01: 9 项部署链全 PASS-STRICT

## 当前验证事实

- 55 项声明完成能力全部逐条清账，无"粗颗粒已过、细项未清"空白
- 7 个 COSMETIC DIV (M-005..011) 覆盖所有已知差异
- 4 个 BHV (SV.2 provider + LC.3 service isolation) 因 Go 侧结构限制无法双核测试（不变）
- 双内核 GUI-shape 配置启动 + Clash API REST/WS 全面可达
- SOCKS5 数据面：HTTP/HTTPS/SSE/chunked/1MiB/slow/早关/RST/dead-port 全部双侧一致
- 订阅拉取（Bearer + ETag + 304）+ 配置解析双侧通过

## 环境限制项

- WS 探测用 curl probe（真实 WS 由 interop-lab p0/p1/p2 案例覆盖）
- GUI 桌面二进制未构建（通过读 GUI 源码复现 API 调用）
- 真实上游代理链路 / Docker / k8s：未测试

## 当前默认准则

- 全量逐项验收已完成，维护状态继续
- 不把验收结果改写成 parity completion
- 不推进 public RuntimePlan / PlannedConfigIR / generic query API
- 不恢复 .github/workflows/*
