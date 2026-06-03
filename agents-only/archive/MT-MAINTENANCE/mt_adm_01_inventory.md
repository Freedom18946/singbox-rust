# MT-ADM-01 inventory

## 定位

- 主题：admin_debug compat surface close-out
- 性质：maintenance / admin-control-plane quality work
- 形式：10 合 1，但实际实现严格按当前源码事实，只围绕 `admin_debug` 下仍真实存在的 compat / query / owner / read-path seam 收口
- 非目标：dual-kernel parity completion、恢复 `.github/workflows/*`、推进 `planned.rs` 公共化、public `RuntimePlan`、public `PlannedConfigIR`、generic query API、扩散到 runtime actor/context、router/dns、tun/outbound、DERP/services、metrics/logging 主线

## 开工前复核结论

- 仓库处于 maintenance mode，L1-L25 全部 Closed；`WP-30` 已归档，`ef333bb7` 仍是 archive baseline
- `MT-OBS-01`、`MT-RTC-01/02/03`、`MT-HOT-OBS-01`、`MT-SVC-01`、`MT-TEST-01`、`MT-RD-01`、`MT-PERF-01`、`MT-ADP-01`、`MT-MLOG-01` 均已完成；本卡不能把维护工作表述成 parity completion
- 当前工作区有大量无关在制改动；本卡只围住 admin_debug 直接相关文件与 `agents-only` 文档推进，没有回滚或覆盖 unrelated workspace changes
- 按当前源码事实复核后，真正还值得收口的是：
  - `app/src/admin_debug/endpoints/subs.rs` 里 cache / breaker / reloadable 仍散落 `global()` / `get()` compat 读写壳
  - `app/src/admin_debug/endpoints/config.rs` / `app/src/admin_debug/http_server.rs` 仍把 `__config` 读写落回 reloadable 模块级 helper
  - `app/src/admin_debug/cache.rs` / `app/src/admin_debug/breaker.rs` 作为 owner store，query/read/write helper 还不够完整，导致 endpoint 继续摸锁
- 同时确认：
  - `app/src/admin_debug/middleware/rate_limit.rs` 当前只剩已有轻量工作区改动，不是这条线最值得优先处理的真实 read/query seam
  - `app/src/admin_debug/security_metrics.rs` 主 snapshot/query seam 已在前卡稳定，本轮只补邻接 reset helper，不重复 churn 主体
  - `app/src/admin_debug/http_server.rs` 的 accept/join lifecycle 与 `app/src/admin_debug/reloadable.rs` 的 reload signal owner 当前已稳定，不做无收益重构

## 本轮源码收口

### 1. owner-first store helper

- `app/src/admin_debug/cache.rs`
  - `CacheStore` 新增 `entry()`、`store()`、`note_head_request()`、`reset()`
  - subs 读缓存 / 写缓存 / HEAD 计数不再直接摸 `cache::global().lock()`
- `app/src/admin_debug/breaker.rs`
  - `BreakerStore` 新增 `allows()`、`record_success()`、`record_failure()`、`reset()`
  - subs 断路器检查 / success / failure 路径不再直接摸 `breaker::global().lock()`

### 2. reloadable owner/query seam

- `app/src/admin_debug/reloadable.rs`
  - `ReloadableConfigStore` 显式拥有 `apply()` / `apply_with_dryrun()`
  - legacy free helper `reloadable::{apply,apply_with_dryrun}` 退成 compat shell
  - 新增 `default_owner_ref()`，只保留给少数 compat builder / internal query seam 使用

### 3. subs compat 面集中收口

- `app/src/admin_debug/endpoints/subs.rs`
  - 新增 `SubsControlPlane`
  - `fetch_with_limits*` / `fetch_with_limits_to_cache*` 统一通过 `SubsControlPlane::compat()` 建 compat query
  - 主路径内部全部改走：
    - `query.cache().entry(...)`
    - `query.cache().store(...)`
    - `query.cache().note_head_request()`
    - `query.breaker().allows(...)`
    - `query.breaker().record_failure(...)`
    - `query.breaker().record_success(...)`
    - `query.config()`
  - 结果是 compat/default/current 壳被压到少数入口，不再散在每个分支里

### 4. admin state / config route 收口

- `app/src/admin_debug/mod.rs`
  - `AdminDebugState` 新增 `reloadable_config()`、`apply_config_delta()`、`subs_control_plane()`
  - state owner 现在可以显式承接 config / subs 邻接 query seam
- `app/src/admin_debug/endpoints/config.rs`
  - 新增 `handle_get_with_state(...)`
  - `handle_put(...)` 新增可选 `AdminDebugState`
  - `__config` 读写现在可显式走 state-owned reloadable owner
- `app/src/admin_debug/http_server.rs`
  - `route_full_request(...)` 与 plain route 对 `__config` 改走 `handle_config_get_with_state(..., Some(state))`
  - `PUT /__config` 改走 `handle_config_put(..., Some(state))`
- `app/src/admin_debug/endpoints/mod.rs`
  - 重新导出 `handle_config_get_with_state`

### 5. 邻接清理

- `app/src/admin_debug/security_metrics.rs`
  - test-only `reset_caches()` 改走 cache/breaker owner helper
  - 没有回头重做 `snapshot_with_control_plane(...)` 主体，也没有把 `security_metrics` 公共 query API 做大

## 本轮 10 合 1 实际切口

- `app/src/admin_debug/mod.rs`
- `app/src/admin_debug/cache.rs`
- `app/src/admin_debug/breaker.rs`
- `app/src/admin_debug/reloadable.rs`
- `app/src/admin_debug/http_server.rs`
- `app/src/admin_debug/security_metrics.rs`
- `app/src/admin_debug/endpoints/config.rs`
- `app/src/admin_debug/endpoints/subs.rs`
- `app/src/admin_debug/endpoints/mod.rs`
- 与上述直接相关的回归测试 / source pin

## 本轮测试 / pins

- `app/src/admin_debug/cache.rs`
  - `cache_store_owner_helpers_roundtrip_entries`
- `app/src/admin_debug/breaker.rs`
  - `breaker_store_owner_helpers_roundtrip_state`
- `app/src/admin_debug/endpoints/config.rs`
  - `config_endpoint_source_pin_prefers_admin_state_owner`
- `app/src/admin_debug/endpoints/subs.rs`
  - `subs_control_plane_source_pin_keeps_cache_breaker_query_local`
  - 既有 `handle_with_metrics_records_private_target_block_on_explicit_owner`
- `app/src/admin_debug/http_server.rs`
  - `http_server_routes_config_through_admin_state_owner`
- `app/src/admin_debug/mod.rs`
  - 既有 `admin_debug_state_keeps_http_server_wiring_owner_local`
- `app/src/admin_debug/security_metrics.rs`
  - 既有 `explicit_snapshot_with_control_plane_uses_supplied_owner_state`

## 验收命令

- `cargo test -p app --all-features --lib -- --test-threads=1`
- `cargo test -p app --all-features --test admin_auth_contract -- --test-threads=1`
- `cargo test -p app --all-features --test e2e_subs_security -- --test-threads=1`
- `cargo clippy -p app --all-features --all-targets -- -D warnings`

## 当前验证结论

- 上述命令已按当前 workspace 事实通过
- 本卡没有把 maintenance 工作误写成 parity completion
- 本卡没有推进 `planned.rs`、public `RuntimePlan`、public `PlannedConfigIR`
- 本卡没有为“去 compat”重新打穿 runtime / metrics / services / router-dns / tun-outbound 已稳定边界
- 本卡没有把当前工作区的 `rate_limit.rs`、`prefetch.rs` 等在制改动一并覆盖或回滚

## Future Work（高层方向）

- `security_metrics` 仍保留 `DEFAULT_STATE` / `with_current` compat wrapper；只有在真实 owner/query consumer 出现时再继续收
- `subs` limiter 当前仍有 `MAX_CONC` / `RPS_*` static state；若 future 继续推进，应围绕显式 limiter owner，而不是继续散改 fetch helper
- 更深层的 admin-control-plane manager/query/lifecycle 统一化仍是高层 future boundary；若再推进，应成组处理 config / subs / prefetch / security，而不是继续拆细卡
- 本卡结束后，`admin_debug` 剩余债务已压缩成少数高层 future boundary；当前阶段不值得继续做细碎 compat 卡
