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

## 当前已验证覆盖（2026-03-14）

- `Both-Covered = 45 / 60`，覆盖率 `75.0%`
- strict both 覆盖：`37 / 60`
- both-case ratio：`31 / 95`
- 最新已推到 `origin/main` 的基线提交：
  - `6aa3de8 interop: promote strict dual-kernel routing and dns parity`
- 本地在该基线后新增、待一并提交的真实 both 增量：
  - `p1_gui_connections_tracking` -> `/connections` live active entry 可见性打通
  - `p1_gui_ws_reconnect_behavior` -> `BHV-LC-008`
  - `p1_selector_switch_traffic_replay` -> `BHV-LC-006`
  - `p1_lifecycle_restart_reload_replay` -> `BHV-LC-009`
  - `p1_fakeip_dns_query_contract` -> `BHV-DP-016`
  - `p1_fakeip_cache_flush_contract` -> `BHV-DP-017`
  - `p0_clash_api_contract_strict` -> `BHV-PF-002`
  - `p1_rust_core_http_via_socks` -> `BHV-PF-001`
  - `p1_dns_cache_ttl_via_socks` -> `BHV-DP-018`

## 本轮已落地的关键产品 / harness 修正

- Rust Clash API 已把 `dns_resolver` 接入运行时，`GET /dns/query` 不再天然 `503`
  - 相关：`crates/sb-api/src/clash/server.rs`
  - 相关：`app/src/run_engine.rs`
  - 相关：`app/src/bootstrap.rs`
- Rust fakeip flush 已接到 core fakeip 状态，不再只是 sb-api 私有 stub
  - 相关：`crates/sb-api/src/managers.rs`
  - 相关：`crates/sb-core/src/dns/fakeip.rs`
  - 相关：`crates/sb-core/src/services/cache_file.rs`
- interop-lab 已支持更诚实的 both-case 编排：
  - `command_start` / `command_wait` / `api_http`
  - per-kernel `api_http` method/path/status override
  - `eq_ref` / `ne_ref` 断言
  - 相关：`labs/interop-lab/src/case_spec.rs`
  - 相关：`labs/interop-lab/src/orchestrator.rs`

## 最近已确认的 strict both artifacts

- `p1_gui_connections_tracking`
  - `labs/interop-lab/artifacts/p1_gui_connections_tracking/20260313T191327Z-6e7f6667-5d4c-472a-9103-7884533a6d99/`
- `p1_gui_ws_reconnect_behavior`
  - `labs/interop-lab/artifacts/p1_gui_ws_reconnect_behavior/20260313T205356Z-5b7cf97d-6e5d-463e-8073-6868f00c0427/`
- `p1_selector_switch_traffic_replay`
  - `labs/interop-lab/artifacts/p1_selector_switch_traffic_replay/20260313T222658Z-d6eb7e2c-1164-4bce-bbe0-5a1f19ee6049/`
- `p1_lifecycle_restart_reload_replay`
  - `labs/interop-lab/artifacts/p1_lifecycle_restart_reload_replay/20260313T225412Z-d0aa81be-d8d3-4eb8-9467-ea3c622f79da/`
- `p1_fakeip_dns_query_contract`
  - `labs/interop-lab/artifacts/p1_fakeip_dns_query_contract/20260313T195112Z-f594fae4-8589-4b12-a34b-76676b75ea10/`
- `p1_fakeip_cache_flush_contract`
  - `labs/interop-lab/artifacts/p1_fakeip_cache_flush_contract/20260313T202530Z-8ba22eab-8f1e-4796-a9b9-8743c1fb365f/`
- `p0_clash_api_contract_strict`
  - `labs/interop-lab/artifacts/p0_clash_api_contract_strict/20260314T001307Z-51a9f922-3013-47b2-b57e-1bababc1af1e/`
- `p1_rust_core_http_via_socks`
  - `labs/interop-lab/artifacts/p1_rust_core_http_via_socks/20260314T002122Z-f4af4a62-2000-4d39-aacb-ba3831f73ce0/`
- `p1_dns_cache_ttl_via_socks`
  - `labs/interop-lab/artifacts/p1_dns_cache_ttl_via_socks/20260314T021211Z-247eb412-7cb4-43ce-8a64-927df58a5ff7/`

## 当前真实 blocker

1. `p1_service_failure_isolation` 仍不是诚实 both-case
   - Go `service` 初始化失败会直接中止启动
   - Rust 仍是 best-effort build，当前语义不一致
2. `BHV-DP-012` domain-rule both-case 先前试验仍更像真实行为缺口，不要硬记
3. mixed inbound 仍有真实 Rust gap，不要先撞
4. `p1_urltest_auto_select_replay` 仍有 Rust vs Go 真实行为分歧，不要先撞
5. `/connections` 路径的 soak/trend/nightly 已接好，但不等于整体 `Both-Covered` 完成

## 下一步

1. 先评估 `p1_service_failure_isolation` 能否改造成真实 broken-service dual-core model，再决定是否可拿 `BHV-LC-003`
2. 若不适合，继续找能最快新增 `Both-Covered` 的 strict both routing / lifecycle / service case
3. 每完成一个 both-case，必须：
   - 更新 `dual_kernel_golden_spec.md` / `compat_matrix.md`
   - 必要时更新 `case_backlog.md`
   - 实跑 `cargo run -p interop-lab -- case run ... --kernel both --env-class strict`
   - 再跑 `cargo run -p interop-lab -- case diff ...`

## 关键文件速查

| 内容 | 路径 |
|------|------|
| 当前工作包 | `agents-only/planning/L22-DUAL-KERNEL-PARITY.md` |
| 当前阶段地图 | `agents-only/workpackage_latest.md` |
| parity 入口规则 | `AGENTS.md` |
| SoT spec | `labs/interop-lab/docs/dual_kernel_golden_spec.md` |
| 兼容矩阵 | `labs/interop-lab/docs/compat_matrix.md` |
| case 积压 | `labs/interop-lab/docs/case_backlog.md` |
