<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: L18 Phase 4 全局静态审议整改  
**当前主线**: `shadowtls` runtime remodel / parity 收口（bounded v1 已闭环，继续盯 v3 outbound）  
**Acceptance Closure**: `UNVERIFIED (slim snapshot)`  
**MIG-02**: ACCEPTED（2026-03-07，541 V7 assertions）

## 已落地且可确认的 Phase 4 结果（2026-03-10）

- 证据模型 / 边界 containment 已入库：
  - `reports/capabilities.json` 已切到 `schema_version=1.1.0`
  - `scripts/check_claims.sh` 已对活跃 closure 话术做硬收口
  - `agents-only/reference/boundary-policy.json` 已成为边界 policy SoT
  - 产品路径已切到显式 registry / `start_with_registry(...)`
- L18 日常执行已显式拆分：
  - `daily-core`: 默认安全，不跑真实 GUI，不碰宿主机系统代理
  - `daily-host-gui`: 显式 opt-in，才跑真实 GUI
- `daily-core` 已稳定可跑：
  - batch: `reports/l18/batches/20260309T204410Z-l18-daily-preflight`
  - 结论：`overall=PARTIAL`，仅因 `gui_smoke=UNTESTED`
- `host-gui` 的 GUI gate 已拿到独立、干净的 `PROVEN` 证据：
  - 证据：`reports/l18/batches/20260310T115624Z-l18-daily-preflight/capstone_daily_hostgui_fixedcfg/r1/gui_direct3/gui_real_cert.json`
  - 结论：Go/Rust 两侧 `startup/load_config/switch_proxy/connections_panel/logs_panel` 全部 `PROVEN`
  - sandbox=`PROVEN`
  - 仅保留 note：`capabilities_negotiation_go_PARTIAL:http_error:404`

## 本轮新增修正（未提交到主线）

- `scripts/l18/gui_real_cert.sh`
  - `logs_panel` 不再依赖本地 kernel log 非空，改为验证 `/logs` WebSocket 握手（成功记 `/logs=101`）
  - 非必需的 Go `/capabilities` 404 仅保留为 note，不再拉低整体状态
  - `startup` 在 GUI pid + kernel ready 后会显式 frontmost GUI，并等待窗口出现，减少 `windows=0` 抖动

## 当前真实阻塞

1. **不是 GUI gate**
   - GUI gate 已通过独立复验 `PROVEN`
2. **长链路 batch 的主阻塞仍是 `workspace_test -> bench_outputs_json`**
   - 文件：`xtests/tests/bench_v1.rs`
   - 影响：会卡住完整 `daily-host-gui` batch，导致整条 batch 难以形成完整最终状态
   - 判断：这是 xtests / bench harness 问题，不是 GUI/system proxy 主链路回归
3. **协议 parity 的剩余单点已经收缩到 `shadowtls` v3 outbound**
   - `trojan`: established（最小双核本地模拟公网闭环已完成）
   - `shadowsocks`: established（最小双核本地模拟公网闭环已完成）
   - `shadowtls`: partial
   - 已闭环部分：`Shadowsocks -> detour=ShadowTLS(v1)` 本地双核 interop 已通过；outbound `version = 2` 与 inbound `version = 2` 链路均已有真实 runtime 证据
   - 当前阻塞：Rust TLS 栈未暴露 Go-compatible ShadowTLS v3 client auth 所需的 session-id hook

## 当前口径

- 缺失本地 batch 工件时，一律标记 `UNVERIFIED (slim snapshot)`
- `20260307T211512Z` / `20260307T230356Z` 仅保留为 provenance reference
- 只有本地存在 `evidence_manifest.json` 或等效独立证据时，才允许写成当前快照下已证实结论

## 下一步

1. 若继续协议 parity，优先决定 ShadowTLS v3 outbound 的实现路径：
   - 换可控 ClientHello / session-id 的 TLS 实现，或
   - 明确把 v3 client auth 标成当前 Rust 栈阻塞项
2. 在 v3 outbound 可执行后，再补：
   - `ShadowTLS(v3 out) -> ShadowTLS(v3 in)` 真实 e2e / interop
   - `strict_mode` fallback 与 `wildcard_sni` 分支证据
3. 与协议 track 并行的 batch track 仍是：先把 `bench_outputs_json` 从 `daily-host-gui` 主路径里隔离或修掉
4. 只有在完整 `daily-host-gui` batch 可复跑后，才重新评估是否恢复更长链路

## 关键文件速查

| 内容 | 路径 |
|------|------|
| L18 Phase 4 工作包 | `agents-only/planning/L18-PHASE4.md` |
| 当前工作包地图 | `agents-only/workpackage_latest.md` |
| capstone 脚本 | `scripts/l18/l18_capstone.sh` |
| 固定 profile 入口 | `scripts/l18/run_capstone_fixed_profile.sh` |
| GUI gate 脚本 | `scripts/l18/gui_real_cert.sh` |
| GUI `PROVEN` 证据 | `reports/l18/batches/20260310T115624Z-l18-daily-preflight/capstone_daily_hostgui_fixedcfg/r1/gui_direct3/gui_real_cert.json` |
