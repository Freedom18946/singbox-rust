<!-- tier: B -->
# MIG-03 WP11 — SB_* 环境变量解析上收 app 组合根

Status: DONE (2026-07-11)
Priority: P1
Depends on: WP08（router/dns 文件冲突，强制串行）
Blocks: WP14

Primary evidence:

- sb-core：221 处 `env::var(` 调用、**161 个不同 SB_\***（2026-07-06 基线）；
  全仓 357 个不同 SB_*。
- 热点文件（env::var 计数）：`dns/mod.rs`(25)、`dns/resolve.rs`(16)、
  `dns/upstream.rs`(15)、`router/mod.rs`(12)、`router/engine.rs`(11)、
  `dns/client.rs`(8)、`router/shared_index.rs`(7)、`outbound/udp_socks5.rs`(5)、
  `outbound/udp_balancer.rs`(5)、`dns/fakeip.rs`(5)。
- 典型反模式：`router::RouterHandle::from_env()` 藏在 Engine 手柄获取路径
  （WP08 已把它提升到构造点，本包接手消化）。
- app 已有的 env 层雏形：`app/src/dns_env.rs`、`app/src/env_dump.rs`、
  `app/src/config_loader.rs`。
- 目标冲突：Go sing-box 纯配置文件驱动；161 个隐藏 env 使"drop-in 替换"
  的行为不可复现、双核对照存在暗变量。

## Goal

sb-core 内 `env::var` 收敛到一张**明示白名单**（D14：目标 **0** 项，
确需保留的例外 ≤5 项且逐项登记理由）；
其余全部改为：app 组合根解析一次 → 组装成显式配置结构 → 注入 core/adapters。
**每个现存 SB_* 的语义与默认值保持不变**（用户对外接口不变，变的只是读取位置）。

## Current Gap

内核行为受 161 个隐藏变量影响；部分热路径逐调用读 env（性能+可测性双输）；
测试之间通过进程级 env 互相污染的风险长期存在。

## Non-goals

- 不废弃任何 SB_* 变量（D14：MIG-03 全量保留兼容，废弃留给后续轨迹）。
- 不重新设计配置 schema（sb-config IR 不动；注入结构是运行时 Options，
  不是新的公共配置格式——注意与"不推进 public RuntimePlan"暂停项的边界）。
- adapters/app 内的 env 读取不在本包强制范围（登记现状即可，收敛可延后）。

## Task Split

1. **全量登记**（产出 `mig03_wp11_env_registry.md`，此表此后是 SB_* 的唯一权威）：
   每个 sb-core 内 SB_* 一行：变量名、读取点 file:line（可多处）、类型与默认值、
   语义一句话、消费时机（启动期 / 热路径逐调用）、去向（注入 / 白名单保留 /
   废弃提案）。357 个全仓变量中非 sb-core 部分列附表（仅登记不迁移）。
2. **注入结构设计**：按域拆小结构（`DnsRuntimeOptions`、`RouterRuntimeOptions`、
   `UdpRuntimeOptions`…），挂到既有构造路径（bridge 组装、dns config_builder、
   supervisor）；**禁止**造一个全局 God-config；禁止用全局静态存放（除白名单项）。
3. **逐域迁移**（顺序：dns → router → outbound/net → 其余；每域独立提交）：
   - core 侧读取点改为消费注入结构字段；
   - app 侧在组合根解析对应 env（复用/扩展 `dns_env.rs` 模式），默认值
     **逐字段断言**与原实现一致（写默认值对照单测）；
   - 热路径逐调用读取的变量改为构造期读取一次（D14：一律
     freeze-at-construction；census 若发现确有活跃消费方依赖"运行中重读"，
     按 D18 升级，不得默认保留热读）。
4. **白名单定稿**：剩余合理保留项（预期：panic/debug 类开关、测试专用注入点）
   逐项写理由；在 `env_dump.rs` 中保证白名单 + 注入型变量都可被 dump 审计。
5. **测试消毒**：core 测试中所有 `std::env::set_var` 用法改为构造注入结构，
   消灭测试间 env 污染（`grep -rn "set_var" crates/sb-core` 清零或仅剩白名单项）。
6. **度量记录**：sb-core 内不同 SB_* 计数 161 → 白名单实数；env::var 调用
   221 → 白名单读取点数。

## Acceptance

- [x] `grep -rhoE 'SB_[A-Z0-9_]+' crates/sb-core/src --include='*.rs' | sort -u`
      的输出与 env_registry 白名单**逐项相等**（命令与输出记录在包内）。
- [x] env_registry 无 TBD；每个迁移变量有"读取点→注入点"映射与默认值对照测试。
- [x] 空环境（unset 全部 SB_*)下：迁移前后 `app check` / `route explain` /
      dns 解析行为对比无差异（选 ≥5 个代表场景，对比记录写入包内）。
- [x] 设置代表性 SB_*（每域 ≥2 个）经 app 层注入后行为与迁移前一致（e2e 断言）。
- [x] 无变量被废弃（D14）；白名单 0。
- [x] 全局验收门禁五连全绿；`cargo test -p sb-core` 全绿。

## 验证命令

```bash
cargo fmt --all -- --check
cargo check --workspace --all-features
cargo clippy -p sb-core -p app --all-targets --all-features
cargo test -p sb-core
cargo test -p app
make boundaries
git diff --check
grep -rhoE 'SB_[A-Z0-9_]+' crates/sb-core/src --include='*.rs' | sort -u
```

## Risks / known traps

- 最大风险是**默认值漂移**：env 缺省时的 fallback 值散落在 161 处
  `unwrap_or`/`map_or` 里，迁移时必须逐个抄录进注入结构的 `Default` 并用
  单测钉住——这是本包工作量的大头，别低估。
- 有些 env 在 cfg(feature) 门内读取——登记表带 feature 维度，
  `--all-features` 与默认特性各跑一遍 grep。
- `SB_METRICS_ADDR` 等刚被 2026-07-03 审计线固化过启动契约（bind 失败阻止
  READY）——迁移这些变量时保持既有失败语义与测试。
- xtests/scripts/Makefile 里有对 SB_* 的直接使用（全仓 357 个的一部分），
  它们走 app 进程 env 仍然生效，但登记表要标注消费方，防止未来误删。

## 发现移交

完成 141 个 core-owned `SB_*` 兼容入口上收。app 在组合根一次解析为按域拆分的
`CoreRuntimeOptions`；supervisor → Context → Bridge 显式注入，DNS/router/network/service/
debug 消费方构造后冻结。core `SB_*` 字面量、直接读取、白名单均为 0；非 `SB_*` 平台/
第三方环境入口不属于 D14，保留并登记边界。

默认值由各域 `Default` 与 app 空环境结构相等测试锁定。代表行为覆盖 DNS pool/inflight/
TTL/FakeIP、router rule/DNS/override/cache/explain、UDP NAT/rate-limit、admin limits、health/
NTP/debug。迁移同时修复 RouterIndex explain exact/suffix 缺口、UDP explain options 索引，
并串行化 Clash/FakeIP 全局状态测试。

最终证据：`cargo check --workspace --all-features`、指定 clippy、`cargo test -p sb-core`、
`cargo test -p app`、fmt、boundaries 429 assertions、diff-check 全绿；core grep 输出为空。
完整变量登记见 `mig03_wp11_env_registry.md`。WP14 解锁。

测试 env 白名单（9 文件）：`dhcp_resolver`、`dns_bridge_simple`、`dns_doh_dot_local`、
`dns_doq_local`、`dns_doq_pool_local`、`dns_ir_config_end_to_end`、`dns_resolve`、
`dns_udp_pool`、`keyword_env_threshold`。这些是 legacy/public env 入口兼容 fixture 或 feature-gated
传输 smoke，不是 core 产品读取点；其余受迁移影响的 core 测试均已显式 options 化。后续删除这些
fixture 前必须先把同一兼容入口移至 app/adapters e2e，不能静默降低变量兼容覆盖。
