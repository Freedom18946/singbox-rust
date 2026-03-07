<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：更新时先删除 >7 天的快照段落，再写新内容。本文件严格 ≤100 行。
> **历史**：完整历史见 `archive/logs/` 和 git log。

---

## 战略状态

**当前阶段**: L18 capstone env 修复收尾
**执行焦点**: 把 Batch J 从 `PASS_ATTRIBUTED` 推进到可复算的 full PASS，然后进入 Phase 3
**Parity**: 100%（209/209 closed）
**MIG-02**: ACCEPTED（2026-03-07，541 V7 assertions）

## 本轮已确认修复（2026-03-08 持续中）

- capstone env 传播:
  - `scripts/l18/l18_capstone.sh`: HOT_RELOAD/SIGNAL 透传 `SINGBOX_BINARY`
  - `scripts/l18/l18_capstone.sh`: 稳定性配置不再写空 `{}`，改为带 `route.final` 的有效 JSON
  - `scripts/l18/run_capstone_fixed_profile.sh`: 清除泄漏的 `INTEROP_*` 环境变量
- workspace gate 确定性阻塞:
  - `app/tests/upstream_auth.rs`: 修正路由 `P -> B`，并补 inbound 就绪等待
  - `app/tests/version_test.rs`: 去掉测试内嵌 `cargo run`，避免 `cargo test --workspace` build lock 自锁
  - `crates/sb-core/tests/router_dns_integration.rs`: 默认回退断言校正为 `unresolved`，并修复 poison/env 污染
  - `crates/sb-core/tests/router_fakeip_integration.rs`: FakeIP 默认回退断言校正为 `unresolved`
- runtime bridge / selector:
  - `crates/sb-adapters/src/register.rs`: 为 named HTTP/SOCKS outbounds 补齐 `connect_io()`
  - `crates/sb-core/src/outbound/selector.rs`
  - `crates/sb-core/src/outbound/selector_group.rs`
- capstone 收尾:
  - `scripts/l18/l18_capstone.sh`: 去掉 `WORKSPACE_TEST` retry hack，恢复真实 gate 语义

## 当前验证状态

| 项目 | 状态 |
|------|------|
| `cargo test -p app --test upstream_auth upstream_http_basic_auth_sent` | ✅ PASS |
| `cargo test -p app --test upstream_socks_http outbound_scaffold_socks_and_http_connect` | ✅ PASS |
| `cargo test -p app --test version_test` | ✅ PASS |
| `cargo test -p sb-core --test router_dns_integration` | ✅ PASS |
| `cargo test -p sb-core --test router_fakeip_integration test_fakeip_routing_no_domain_rules_default` | ✅ PASS |
| `cargo fmt --all -- --check` | ✅ PASS（本地已补齐） |
| `hot_reload_stability` | ✅ 5x 独立 PASS；capstone 内 20x PASS |
| `signal_reliability` | ✅ 3x 独立 PASS；capstone 内 5x PASS |
| `dual_kernel_diff` | ✅ 5/5 PASS（独立验证） |
| clean capstone daily rerun | ⏳ 2026-03-08 03:21 CST：批次 `20260307T191724Z-l18-daily-preflight` 已过 `PREFLIGHT` / `ORACLE` / `BOUNDARIES`，正跑 `WORKSPACE_TEST` |

## 当前真实阻塞

1. 当前 clean rerun 批次 `20260307T191724Z-l18-daily-preflight` 正在 `WORKSPACE_TEST`
2. 旧 baseline `reports/l18/phase2_baseline.lock.json` 仍记录 env 传播归因，待 clean full PASS 后统一更新

## 最近一次 capstone 重跑

- 废弃批次:
  - `reports/l18/batches/20260307T180008Z-l18-daily-preflight`：用于收集 canary 证据，旧 `WORKSPACE_TEST/FMT` 结果已过时
  - `reports/l18/batches/20260307T191136Z-l18-daily-preflight`：暴露 `router_fakeip_integration` 默认回退断言过时，修复后中止
- 当前批次:
  - `reports/l18/batches/20260307T191724Z-l18-daily-preflight`
  - 当前阶段：`WORKSPACE_TEST` 进行中（`PREFLIGHT` / `ORACLE` / `BOUNDARIES` 已过）

## 下一步

1. 盯住当前 clean daily rerun，确认 `WORKSPACE_TEST` 越过 `router_dns` / `router_fakeip` / `upstream_auth` / `version_test`
2. 生成 clean `l18_capstone_status.json`
3. full PASS 后更新 `reports/l18/phase2_baseline.lock.json`
4. 更新 Phase 3 入口文档并启动 nightly 24h

## 关键文件速查

| 内容 | 路径 |
|------|------|
| 双核黄金基准 | `labs/interop-lab/docs/dual_kernel_golden_spec.md` |
| L18 工作包 | `agents-only/planning/L18-PHASE2.md` |
| capstone 脚本 | `scripts/l18/l18_capstone.sh` |
| 固定 profile 入口 | `scripts/l18/run_capstone_fixed_profile.sh` |
| 当前活动日志 | `agents-only/log.md` |
