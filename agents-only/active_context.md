<!-- tier: S -->
# 当前上下文（Active Context）
> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。
---
## 战略状态
**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)，以 `labs/interop-lab/docs/dual_kernel_golden_spec.md` 为准
**当前维护线**: `MT-ADM-01` admin_debug compat surface close-out — 已完成；`MT-MLOG-01`、`MT-ADP-01`、`MT-PERF-01`、`MT-RD-01`、`MT-TEST-01`、`MT-SVC-01`、`MT-HOT-OBS-01`、`MT-RTC-03`、`MT-RTC-02`、`MT-RTC-01`、`MT-OBS-01` 与 `WP-30` 继续保持已完成 / 已归档状态

## 最近完成（2026-04-03）

### MT-ADM-01：admin_debug compat surface close-out — 已完成
- 本卡按当前源码与工作区事实推进，性质明确为 maintenance / admin-control-plane quality work，不是 dual-kernel parity completion；没有恢复 `.github/workflows/*`，也没有推进 `planned.rs`、public `RuntimePlan`、public `PlannedConfigIR`、generic query API
- 开工前复核确认：`app/src/admin_debug/endpoints/subs.rs` 仍散落 `cache::global()` / `breaker::global()` / `reloadable::get()` 读写壳；`app/src/admin_debug/endpoints/config.rs` 与 `app/src/admin_debug/http_server.rs` 仍走 reloadable compat helper；`middleware/rate_limit.rs`、`security_metrics.rs` 主体 owner/query seam 已基本稳定，不为凑卡硬改
- 本轮真实收口：
  - `app/src/admin_debug/cache.rs`：`CacheStore` 补 `entry()`、`store()`、`note_head_request()`、`reset()`，把 subs 读缓存 / 写缓存 / HEAD 计数路径收成 owner-first helper
  - `app/src/admin_debug/breaker.rs`：`BreakerStore` 补 `allows()`、`record_success()`、`record_failure()`、`reset()`，subs 不再直接摸 breaker compat/global 锁
  - `app/src/admin_debug/reloadable.rs`：`ReloadableConfigStore` 显式拥有 `apply()` / `apply_with_dryrun()`；legacy free functions 退成 compat shell；新增 `default_owner_ref()` 只作为少数 compat builder 入口
  - `app/src/admin_debug/endpoints/subs.rs`：新增 `SubsControlPlane`；`fetch_with_limits*` / `fetch_with_limits_to_cache*` 统一通过 `SubsControlPlane::compat()` 入场，内部不再散落 `cache::global()` / `breaker::global()` / `reloadable::get()`
  - `app/src/admin_debug/mod.rs`：`AdminDebugState` 新增 `reloadable_config()`、`apply_config_delta()`、`subs_control_plane()`，把 config / subs 邻接读路径明确挂到 state owner 上
  - `app/src/admin_debug/endpoints/config.rs` + `app/src/admin_debug/http_server.rs`：`/__config` GET/PUT 改走 `AdminDebugState` owner-first reloadable query/apply seam；旧 endpoint wrapper 继续保留 compat fallback
  - `app/src/admin_debug/security_metrics.rs`：test reset path 改走 cache/breaker owner helper，不再回到 compat/global 锁
- 本轮新增 / 强化的关键 pin：
  - `app/src/admin_debug/cache.rs`：`cache_store_owner_helpers_roundtrip_entries`
  - `app/src/admin_debug/breaker.rs`：`breaker_store_owner_helpers_roundtrip_state`
  - `app/src/admin_debug/endpoints/config.rs`：`config_endpoint_source_pin_prefers_admin_state_owner`
  - `app/src/admin_debug/endpoints/subs.rs`：`subs_control_plane_source_pin_keeps_cache_breaker_query_local`
  - `app/src/admin_debug/http_server.rs`：`http_server_routes_config_through_admin_state_owner`
  - 既有 `handle_with_metrics_records_private_target_block_on_explicit_owner`、`explicit_snapshot_with_control_plane_uses_supplied_owner_state`、`admin_debug_state_keeps_http_server_wiring_owner_local` 继续 pin 住边界

## 当前稳定事实
- `admin_debug` 下 cache / breaker / reloadable 的 compat surface 已压缩到少数明确入口：`SubsControlPlane::compat()`、`reloadable::{get,apply,apply_with_dryrun}` compat wrapper、`security_metrics::compat_snapshot()`
- `subs.rs` 的主读写链路现在围绕 `SubsControlPlane + CacheStore/BreakerStore` helper 展开，不再在多个分支重复散落 global/default/current 锁访问
- `__config` 控制面请求已明确经 `AdminDebugState` 读取/应用 reloadable owner，而不是从 `http_server` 直接落回模块级 helper
- `middleware/rate_limit.rs`、`http_server` accept/join lifecycle、`reload signal` owner、`security_metrics` snapshot seam 当前不值得继续为凑卡硬拆
- `planned.rs` 仍是 staged crate-private seam；当前仓库仍无 public `RuntimePlan`、public `PlannedConfigIR`、generic query API
- 当前 workspace 仍存在大量无关在制改动；本卡只触达 admin_debug 直接相关文件与 `agents-only` 文档，没有回滚或覆盖 unrelated workspace changes

## 当前验证事实
- 已通过：
  - `cargo test -p app --all-features --lib -- --test-threads=1`
  - `cargo test -p app --all-features --test admin_auth_contract -- --test-threads=1`
  - `cargo test -p app --all-features --test e2e_subs_security -- --test-threads=1`
  - `cargo clippy -p app --all-features --all-targets -- -D warnings`

## Future Work（高层方向）
- `admin_debug` 剩余债务现在应压缩成少数高层 boundary：
  - `security_metrics` 仍保留 `DEFAULT_STATE` / `with_current` compat wrapper；只有在真实 owner/query consumer 出现时再继续收
  - `subs` limiter 本体仍有 `MAX_CONC` / `RPS_*` 一层 static state；只有在出现明确 owner-bearing limiter consumer 时再处理
  - 更深层的 admin-control-plane manager/query 统一化，若再推进，应成组处理 config/subs/prefetch/security 生命周期，不继续散修 helper

## 归档判断
- `WP-30` 继续视为 archive baseline，`ef333bb7` 仍是归档基线
- `MT-ADM-01` 已完成；`admin_debug` 剩余债务已压缩成少数高层 future boundary，不值得继续拆很多小尾巴
