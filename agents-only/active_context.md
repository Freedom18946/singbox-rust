<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: L22 dual-kernel parity 收口
**当前工作包 ID**: `WP-L22`
**当前主线**: 直接提高 `labs/interop-lab/docs/dual_kernel_golden_spec.md` 的 `Both-Covered`
**Source of Truth**: `labs/interop-lab/docs/dual_kernel_golden_spec.md`
**当前口径**: 不把 Rust-only 单测、仓库级自动化或纯文档润色记成 dual-kernel parity 完成

## 当前已验证覆盖（2026-03-15）

- `Both-Covered = 50 / 60`，覆盖率 `83.3%`
- strict both 覆盖：`42 / 60`
- both-case ratio：`35 / 95`
- 最新已推到 `origin/main` 的基线提交：
  - `6aa3de8 interop: promote strict dual-kernel routing and dns parity`
- 本地在该基线后新增、待一并提交的真实 both 增量：
  - `p1_gui_connections_tracking` -> `BHV-DP-010` + `BHV-CP-006`
  - `p1_gui_ws_reconnect_behavior` -> `BHV-LC-008`
  - `p1_selector_switch_traffic_replay` -> `BHV-LC-006`
  - `p1_lifecycle_restart_reload_replay` -> `BHV-LC-009`
  - `p1_fakeip_dns_query_contract` -> `BHV-DP-016`
  - `p1_fakeip_cache_flush_contract` -> `BHV-DP-017`
  - `p0_clash_api_contract_strict` -> `BHV-PF-002`
  - `p1_rust_core_http_via_socks` -> `BHV-PF-001`
  - `p1_dns_cache_ttl_via_socks` -> `BHV-DP-018`
  - `p1_domain_rule_via_socks` -> `BHV-DP-012` (修复 direct_connect IPv6-first bug)
  - `p2_connections_ws_soak_dual_core` -> `BHV-PF-004` (spec 修正)
  - `p1_mixed_inbound_dual_protocol` -> `BHV-DP-004` (修复 mixed inbound peek→read_exact bug)
  - `p1_graceful_shutdown_drain` -> `BHV-LC-007` (新 TcpDrainDuringShutdown harness)
  - `p1_urltest_auto_select_replay` -> `BHV-DP-007` (修复 now() + 初始健康检查)

## 本轮已落地的关键产品修正

- `direct_connect` 修复为尝试所有解析地址而非仅 `[0]`
- mixed inbound `peek()` → `read_exact()` 修复（首字节重复）
- URLTest `now()` 修复为 URLTest 模式调用 `select_by_latency()`
- URLTest `start_health_check()` 修复为立即执行首次检查（Go parity）
- interop-lab 测试编译修复：`evaluate_assertion_op` 参数包裹 `Some()`

## 当前真实 blocker

1. `p1_service_failure_isolation` 仍不是诚实 both-case（Go 结构性 fail-fast，不可调和）
2. SV 域（7 BHVs）结构性阻塞：Go/Rust 双方均 stub 掉 provider 端点
3. BHV-DP-014 (sniff) KNOWN-GAP: DIV-C-003
4. BHV-LC-005 (hot-reload) KNOWN-GAP: DIV-H-001

## 下一步

1. 提交本地所有待提交的 both 增量（15 个 case + 3 个 bug fix + harness + spec 更新）
2. 剩余 10 个未覆盖 BHV 中，7 个 SV 结构性阻塞、2 个 KNOWN-GAP、仅 1 个可操作（LC-003 已确认不可行）
3. L22 实质性到达天花板：83.3% 是无结构性产品变更可达的上限

## 关键文件速查

| 内容 | 路径 |
|------|------|
| 当前工作包 | `agents-only/planning/L22-DUAL-KERNEL-PARITY.md` |
| 当前阶段地图 | `agents-only/workpackage_latest.md` |
| parity 入口规则 | `AGENTS.md` |
| SoT spec | `labs/interop-lab/docs/dual_kernel_golden_spec.md` |
| 兼容矩阵 | `labs/interop-lab/docs/compat_matrix.md` |
| case 积压 | `labs/interop-lab/docs/case_backlog.md` |
