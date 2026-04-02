# MT-RD-01 inventory

## 定位

- 主题：router / dns structural consolidation
- 性质：maintenance / structural quality work
- 形式：10 合 1，同类 owner / helper / query / shared-state seam 一批次收口
- 非目标：dual-kernel parity completion、恢复 `.github/workflows/*`、推进 `planned.rs` 公共化、public `RuntimePlan`、public `PlannedConfigIR`、generic query API、重新打开 runtime actor/context 主线

## 本轮复核结论

- 当前真实布局下，最值得优先收口的不是继续把 `router/mod.rs` 或 `dns/upstream.rs` 彻底拆光，而是先把最混乱的一层 shared-state / helper wiring 抽成独立 owner：
  - `crates/sb-core/src/router/mod.rs` 中 shared index owner、ENV refresh/cache、hot-reload bootstrap、runtime override cache/query 还混在同一 mega-file
  - `crates/sb-core/src/router/explain_util.rs` 还单独兜了一层 override read path，没有顺着真实 runtime override seam 查询
  - `crates/sb-core/src/dns/upstream.rs` 中 DHCP / resolved 两条 file-backed upstream 链路各自带 watcher / reload / fallback / round-robin / metrics helper，重复且 shared-state 入口不清楚
  - `crates/sb-core/src/dns/config_builder.rs` 已有 specialized builder helper，当前不值得再把 upstream special-case wiring 回灌到统一大层
- 因此这张卡的最佳收口方式，是把 router shared index / runtime override 与 dns file-backed upstream pool 这两层 owner seam 抽清，而不是为了凑数硬拆更多壳模块

## 本轮源码收口

### Router seam

- `crates/sb-core/src/router/shared_index.rs`
  - 新 owner：`SHARED_INDEX`、ENV cache、`shared_index()`、`router_index_from_env_with_reload()`、`empty_router_index(...)`
  - 统一 unresolved fallback index 的构造，不再在多个 compat/read 路径各自拼空索引
- `crates/sb-core/src/router/runtime_override.rs`
  - 新 owner：runtime override parse/cache/query seam
  - 明确暴露 `runtime_override_http(...)`、`runtime_override_udp(...)`、crate-private `runtime_override_ip(...)`
- `crates/sb-core/src/router/mod.rs`
  - 改为保留 facade / rule engine 主体，不再直接承载 shared index static 与 runtime override cache 实现
  - 只保留必要 re-export，让旧调用面继续稳定
- `crates/sb-core/src/router/explain_util.rs`
  - `try_override(...)` 改为走真实 runtime override query seam
  - 保留 `SB_ROUTER_DOMAIN_OVERRIDES` 的兼容补充路径，但不再自己重复解析 `SB_ROUTER_OVERRIDE`
- `crates/sb-core/src/router/engine.rs`
  - compat default index 改为复用 `empty_router_index(...)`

### DNS seam

- `crates/sb-core/src/dns/upstream_pool.rs`
  - 新 owner：file-backed upstream pool
  - 统一承接 watcher / reload / round-robin / fallback / metrics helper / nameserver file load
  - 当前 owner 专门服务 DHCP / resolved 这一层共享模式，不额外引入大而空抽象
- `crates/sb-core/src/dns/upstream.rs`
  - `DhcpUpstream` 与 `ResolvedUpstream` 改为显式持有 `FileBackedUpstreamPool`
  - 从原文件移除重复的 watcher / reload helper / fallback metrics helper
  - 保留协议实现本体与 transport-on-demand 行为，不借拆模块改变关键行为
- `crates/sb-core/src/dns/config_builder.rs`
  - 只补 source pin，确认 DHCP / Tailscale / resolved 仍通过 specialized helper 构建
- `crates/sb-core/src/dns/mod.rs`
  - 只引入 private `upstream_pool` 模块，不扩大公共 surface

## 本轮 10 合 1 实际切口

- `crates/sb-core/src/router/mod.rs`
- `crates/sb-core/src/router/explain_util.rs`
- `crates/sb-core/src/dns/upstream.rs`
- `crates/sb-core/src/dns/config_builder.rs`
- `crates/sb-core/src/dns/mod.rs`
- `crates/sb-core/src/router/engine.rs`
- `crates/sb-core/src/router/shared_index.rs`
- `crates/sb-core/src/router/runtime_override.rs`
- `crates/sb-core/src/dns/upstream_pool.rs`
- 与上述直接相关的 source-pin / regression tests（in-source）

## 本轮测试 / pins

- `router::migration_tests::shared_index_refreshes_when_router_rules_env_changes`
- `router::migration_tests::router_shared_state_owner_lives_in_dedicated_modules`
- `router::explain_util::tests::try_override_uses_runtime_override_query_seam`
- `dns::upstream::tests::file_backed_upstream_pool_owner_lives_in_upstream_pool_module`
- `dns::config_builder::tests::builder_keeps_special_upstream_wiring_in_specialized_helpers`

## 验收命令

- `cargo test -p sb-core --all-features router::migration_tests -- --test-threads=1`
- `cargo test -p sb-core --all-features dns::config_builder::tests -- --test-threads=1`
- `cargo test -p sb-core --all-features dns::upstream::tests -- --test-threads=1`
- `cargo test -p sb-core --all-features --lib -- --test-threads=1`
- `cargo test -p sb-core --all-features --tests -- --test-threads=1`
- `cargo clippy -p sb-core --all-features --all-targets -- -D warnings`

## 当前验证结论

- 上述命令已按当前 workspace 事实通过
- 本轮增量修正后再次复核：
  - `dns::upstream::tests` 通过
  - `cargo clippy -p sb-core --all-features --all-targets -- -D warnings` 通过
- 本卡没有把已稳定的 runtime close-out、services baseline、hotpath/metrics 边界重新打穿

## 当前边界

- 本卡没有把 maintenance 工作误写成 parity completion
- 本卡没有推进 `planned.rs`、public `RuntimePlan`、public `PlannedConfigIR`
- 本卡没有为了拆模块而改变 DHCP / resolved 的 fallback、reload、transport-on-demand 基本行为
- 本卡没有卷入当前工作区的 unrelated app / config / metrics / audit 脏改动

## Future Work（高层方向）

- `router/mod.rs` 仍保留更深层 rule-build / match / summary 体量；后续若继续推进，应按更高层 owner 面收，不再回到 shared index / override seam
- `dns/upstream.rs` 仍保留协议实现 bulk；后续若继续推进，可观察 protocol family 与 resolver selection / normalization 的更高层边界
- 本卡结束后，`router/dns` 剩余债务已经压缩成少数高层 future boundary；当前阶段不值得再继续做细碎拆卡
