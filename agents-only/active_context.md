<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：更新时先删除 >7 天的快照段落，再写新内容。本文件严格 ≤100 行。
> **历史**：完整历史见 `archive/logs/` 和 git log。

---

## 战略状态

**当前阶段**: L18 Phase 2 收尾完成
**执行焦点**: 以 `20260307T211512Z` clean full PASS 锁定 Phase 2 baseline，并切入 Phase 3 准备
**Parity**: 100%（209/209 closed）
**MIG-02**: ACCEPTED（2026-03-07，541 V7 assertions）

## 本轮已确认修复（2026-03-08）

- capstone env 传播:
  - `scripts/l18/l18_capstone.sh`: HOT_RELOAD/SIGNAL 透传 `SINGBOX_BINARY`
  - `scripts/l18/l18_capstone.sh`: 稳定性配置不再写空 `{}`，改为带 `route.final` 的有效 JSON
  - `scripts/l18/run_capstone_fixed_profile.sh`: 清除泄漏的 `INTEROP_*` 环境变量
- workspace gate 确定性阻塞:
  - `app/tests/upstream_auth.rs`: 修正路由 `P -> B`，并补 inbound 就绪等待
  - `app/tests/version_test.rs`: 去掉测试内嵌 `cargo run`，避免 `cargo test --workspace` build lock 自锁
  - `crates/sb-core/tests/router_dns_integration.rs`: 默认回退断言校正为 `unresolved`，并修复 poison/env 污染
  - `crates/sb-core/tests/router_fakeip_integration.rs`: FakeIP 默认回退断言校正为 `unresolved`
  - `crates/sb-core/src/router/rules.rs`: `parse_rules()` / `Decision::parse_decision()` 显式支持 `unresolved`，修复 `default=unresolved` 被整行跳过
  - `crates/sb-core/tests/router_rules_decide_with_meta.rs`: `decide_with_meta` 默认桶断言改为显式 `unresolved`
  - `crates/sb-core/tests/router_rules_index.rs`: 未知 rule kind 改为显式报错断言，和当前 “silent parse fallback is disabled” 语义对齐
  - `crates/sb-core/tests/router_select_ctx_meta.rs`: `suffix=direct` / `final=unresolved` 的元信息断言对齐当前实现
  - `crates/sb-core/tests/router_udp_rules.rs`: 默认 UDP 决策改为 `unresolved`，并把串行锁改为 poison-safe
  - `crates/sb-core/src/adapter/bridge.rs`: adapter registry miss 时为 `Direct` / `Block` 恢复 core-side fallback，修复 supervisor 启动时空 outbound bridge
  - `crates/sb-core/tests/shutdown_lifecycle.rs`: 使用最小可启动 `ConfigIR`（含 `Direct` outbound）
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
| `cargo test -p sb-core --test router_inbound_outbound_tag_matching test_parse_rules_with_inbound_outbound` | ✅ PASS |
| `cargo test -p sb-core --test router_auth_user_matching test_parse_rules_with_auth_user` | ✅ PASS |
| `cargo test -p sb-core --test router_rules_decide_with_meta -- --nocapture` | ✅ PASS |
| `cargo test -p sb-core --test router_rules_index rules_index_unknown_kind_is_rejected_explicitly -- --nocapture` | ✅ PASS |
| `cargo test -p sb-core --test router_udp_rules -- --nocapture` | ✅ PASS |
| `cargo test -p sb-core --test supervisor_lifecycle -- --nocapture` | ✅ PASS |
| `cargo test -p sb-core --test shutdown_lifecycle -- --nocapture` | ✅ PASS |
| `cargo fmt --all -- --check` | ✅ PASS（本地已补齐） |
| `cargo clippy --workspace --all-features --all-targets -- -D warnings` | ✅ PASS（独立验证，退出码 0） |
| `hot_reload_stability` | ✅ 5x 独立 PASS；capstone 内 20x PASS |
| `signal_reliability` | ✅ 3x 独立 PASS；capstone 内 5x PASS |
| `dual_kernel_diff` | ✅ 5/5 PASS（独立验证） |
| clean capstone daily rerun | ✅ PASS：`20260307T211512Z-l18-daily-preflight` 全量通过；`l18_capstone_status.json` 已生成，gate 结果为 `PASS/PASS/PASS/PASS/PASS/PASS/PASS/PASS/PASS/WARN/PASS/PASS/PASS/PASS`（仅 `docker` 为 `WARN`） |

## 当前真实阻塞

1. Phase 2 已无真实阻塞；`20260307T211512Z-l18-daily-preflight` 已产出 clean full PASS，总状态文件已落盘，下一工作面转为 Phase 3 nightly/certify 长时运行

## 最近一次 capstone 重跑

- 废弃批次:
  - `reports/l18/batches/20260307T180008Z-l18-daily-preflight`：用于收集 canary 证据，旧 `WORKSPACE_TEST/FMT` 结果已过时
  - `reports/l18/batches/20260307T191136Z-l18-daily-preflight`：暴露 `router_fakeip_integration` 默认回退断言过时，修复后中止
  - `reports/l18/batches/20260307T191724Z-l18-daily-preflight`：外部中断，停在 `monitoring_integration_test` 前后，无总状态文件
  - `reports/l18/batches/20260307T192727Z-l18-daily-preflight`：暴露 `router_inbound_outbound_tag_matching` 的 `default=unresolved` 解析缺口，修复后中止
  - `reports/l18/batches/20260307T193435Z-l18-daily-preflight`：暴露 `router_rules_decide_with_meta` 对默认桶仍断言 `Direct`，修复后中止
  - `reports/l18/batches/20260307T194543Z-l18-daily-preflight`：暴露 `router_rules_index` 仍假设未知 kind 只 lint 不失败，修复后中止
  - `reports/l18/batches/20260307T200336Z-l18-daily-preflight`：暴露 `router_udp_rules` 默认值/锁污染问题，修复后中止
  - `reports/l18/batches/20260307T203645Z-l18-daily-preflight`：暴露 `Supervisor::start()` 在 adapter registry miss 时失去 `Direct`/`Block` core fallback，修复后中止
  - `reports/l18/batches/20260307T205807Z-l18-daily-preflight`：暴露 `xtests/env_doc_drift`，指出 env 文档仍引用已删除的 `SB_SOCKS_UDP_PROXY_FALLBACK_DIRECT` / `SB_PROXY_HEALTH_FALLBACK_DIRECT`，修复后中止
- 当前批次:
  - `reports/l18/batches/20260307T211512Z-l18-daily-preflight`
  - 当前阶段：full PASS 已完成；`l18_capstone_status.json` 于 `2026-03-07T22:23:22Z` 生成，`WORKSPACE_TEST` / `FMT` / `CLIPPY` / `HOT_RELOAD` / `SIGNAL` / `GUI` / `CANARY` / `DUAL` / `PERF` 全部通过，`docker` 为 `WARN (no daemon)`
  - canary 摘要：`canary_7day.sh --duration-hours 1 --sample-interval-sec 300` 共采样 13 次，`health_code=200` 为 13/13，RSS 从 11024 KB 降至 7168 KB，无单调泄漏迹象
  - baseline：`reports/l18/phase2_baseline.lock.json` 已更新到当前 clean full PASS

## 下一步

1. 以 `reports/l18/phase2_baseline.lock.json` 为 Phase 2 锁定基线，避免再回看已收敛的 env/workspace 归因问题
2. 以 `agents-only/planning/L18-PHASE3.md` 为执行入口，准备 nightly/certify 级长时运行
3. 启动 Phase 3 首批 nightly 24h / certify 级任务，并只跟进新的真实失败

## 关键文件速查

| 内容 | 路径 |
|------|------|
| 双核黄金基准 | `labs/interop-lab/docs/dual_kernel_golden_spec.md` |
| L18 Phase 3 工作包 | `agents-only/planning/L18-PHASE3.md` |
| capstone 脚本 | `scripts/l18/l18_capstone.sh` |
| 固定 profile 入口 | `scripts/l18/run_capstone_fixed_profile.sh` |
