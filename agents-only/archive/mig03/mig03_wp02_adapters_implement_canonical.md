<!-- tier: B -->
# MIG-03 WP02 — sb-adapters 直接实现正典契约，削平 register.rs 胶水

Status: DONE (2026-07-10; combined WP02+WP03 cutover)
Priority: P0
Depends on: WP01（ADR 已批准）
Blocks: WP05

Primary evidence:

- `crates/sb-adapters/src/register.rs` — 4,264 行；`register_all()` 位于 `:465`，
  由 `app/src/util.rs:31` 与 `app/src/bin/probe-outbound.rs:658` 调用。
- 逐协议 Wrapper 清单见 WP01 evidence（HttpConnectorWrapper:606 等 12 个）。
- `crates/sb-core/src/adapter/registry.rs` — `InboundBuilder` / `OutboundBuilder`
  是 fn 指针，builder 返回 `Arc<dyn OutboundConnector>`（sb-core 版 trait）+
  可选 `Arc<dyn UdpOutboundFactory>`；bridge 在 `bridge.rs:595/:604` 先查 registry。
- `crates/sb-adapters/src/traits.rs:535` — adapters 现行 trait，25 个协议实现于此。

## Goal

sb-adapters 的全部 outbound/inbound 实现**直接实现 ADR 钦定的正典契约**
（定义在 sb-types），registry 的 builder 签名改为返回正典 trait 对象；
register.rs 的逐协议 Wrapper 全部消失，每个协议的注册退化为
"构造 config → 构造连接器 → 注册"的直通代码。

## Current Gap

register.rs 的 4,264 行中，绝大多数在做同一件事的 12 份拷贝：把
`sb_adapters::traits::OutboundConnector`（dial 形状）包装成
`sb_core::adapter::OutboundConnector`（connect→TcpStream 形状）。trait 统一后
这层胶水没有存在理由。

## Non-goals

- 不动 sb-core 内部的三套 trait（WP03）。
- 不动 scaffold 实现与 bridge 回退逻辑（WP06）。
- 不新增/删除任何协议能力；线上字节行为不变。

## Task Split

1. **契约落位**：按 ADR 把正典 trait（含 UDP、Group、Inbound 面）写入
   `sb-types`（新文件或改造 `ports/`）。sb-types 依赖变更严格遵守 ADR g 项结论。
   同步更新 `agents-only/06-scripts/check-boundaries.sh` 中涉及 sb-types 的断言。
2. **registry 签名切换**：`sb-core/src/adapter/registry.rs` 的
   `InboundBuilder`/`OutboundBuilder` 返回类型改为正典 trait 对象。
   过渡期允许 sb-core 内部用一层**集中式**适配（一个文件、一个适配器类型），
   把正典对象适配给 bridge 现行消费面——禁止再产生逐协议适配。
3. **逐协议迁移**（建议按低风险 → 高风险顺序：block/dns/direct → http/socks4/
   socks5 → ss/ssr/trojan/vmess/vless → shadowtls/tuic/tor → selector/urltest 组）：
   - 协议实现文件把 `impl sb_adapters::traits::OutboundConnector` 改为
     `impl <正典 trait>`（D8：直接切换，不保留双实现）；
   - register.rs 中该协议的 Wrapper 结构体与 impl 删除，注册代码直通化；
   - 每迁一个协议跑一次该协议 focused tests（`cargo test -p sb-adapters <proto>`）。
4. **Inbound 侧同步**：`HttpInboundAdapter`/`MixedInboundAdapter`/
   `RedirectInboundAdapter` 等按 ADR 的 inbound 正典结论同样直通化。
5. **旧 trait 处置**：`sb_adapters::traits::OutboundConnector` 按 D8 直接删除
   并修完全部引用，不保留 deprecated 过渡。
6. **度量记录**：在本包尾记录 register.rs 迁移前后行数、Wrapper 结构体数
   （目标 0）、`impl OutboundConnector for` 全仓计数变化。

## Acceptance

- [x] register.rs 中 `struct *Wrapper` / `struct *Adapter`（适配用途）计数 = 0
      （`grep -c 'ConnectorWrapper\|InboundAdapter' register.rs`；
      正当的非适配结构如有保留，逐个在包内说明）。
- [x] register.rs 行数较基线 4,264 下降 ≥50%。
- [x] 全部 outbound feature + 现有 inbound 注册路径编译通过且 focused tests 全绿。
- [x] sb-core 内过渡适配仅 `adapter/inbound_transition.rs`，文件头注明 WP06 移除。
- [x] `sb_types` 新契约有 rustdoc（方法语义、错误约定、取消安全性）。
- [x] 全局验收门禁五连（overview §4）全绿。
- [x] `app/src/util.rs:31` 的 `register_all()` 调用链行为不变
      （`cargo run -p app --features gui_runtime -- check -c <现有样例配置>` 冒烟通过）。

## 验证命令

```bash
cargo fmt --all -- --check
cargo check --workspace --all-features
cargo clippy -p sb-adapters -p sb-core -p sb-types --all-targets --all-features
cargo test -p sb-adapters
cargo test -p sb-core adapter
make boundaries
git diff --check
# 冒烟：现有 e2e
cargo test -p app --test adapter_bridge_scaffold --features scaffold
```

## Risks / known traps

- `DialOpts` 里可能携带 register.rs 在包装层填充的运行时上下文（路由句柄、
  metrics、超时）——迁移时逐字段核对填充点，别让默认值悄悄变化。
- selector/urltest 组依赖 `as_group()` 钩子（`adapter/mod.rs`），必须按 ADR d 项
  结论处理后再迁组类协议，否则 GUI 的组切换 API 会断。
- `probe-outbound` bin 直接调 `register_all()`，改签名后记得一起修。
- boundary 脚本对 sb-types 的依赖断言（V1/V2）会因新增依赖失配——先改脚本
  策略再跑门禁，不要用 `|| true` 绕过。

## 发现移交

- **D18 scope conflict resolved (2026-07-10):** the
  required registry cutover cannot preserve behavior while honouring this package's
  explicit non-goal of leaving sb-core's legacy adapter traits untouched.  The
  canonical `Outbound::dial(&Session) -> BoxedStream` deliberately erases the
  concrete socket, whereas the current bridge's registry consumers still require
  `sb_core::adapter::OutboundConnector::connect(&str, u16) -> TcpStream`:
  `inbound/socks5.rs:628`, `inbound/http_connect.rs:320`,
  `adapter/handler.rs:113`, `health/mod.rs:44`, and
  `runtime/supervisor.rs:2544`.  A generic centralized adapter can expose the
  canonical stream only through `connect_io`; it cannot soundly recover a
  `TcpStream` for these live paths.  Returning an error would be a user-visible
  regression, while adding per-protocol recovery adapters recreates the wrappers
  this package must delete.  The necessary consumer/holder conversion is WP03
  scope and conflicts with the WP02 non-goal.  The user authorized a combined
  WP02 + WP03 cutover, so the required core consumer/holder migration is now
  in scope and must preserve the affected behavior.
- **Feature-matrix defect repaired:**
  `cargo check -p sb-adapters --no-default-features --features adapter-trojan,router`
  and `cargo test -p sb-adapters --no-default-features --features
  adapter-trojan,router --lib` now pass because `adapter-trojan` enables the
  `trojan` inbound gate used by `register.rs`.

## Acceptance record (2026-07-10)

- `register.rs`: 4,264 → 7 LOC. Registration module including protocol builders:
  3,626 LOC. Named façade metric passes; aggregate recorded to prevent split-file
  concealment. Recursive wrapper-definition scan: 0.
- Legacy adapter connector/request/datagram traits absent. VMess/DNS no longer
  advertise packet associations they do not implement.
- Packet associations snapshot finalized idle timeout and route UDP controls.
  Explicit deadlines override idle timeout; timeout errors report effective duration.
- Sole inbound lifecycle transition: `sb-core/src/adapter/inbound_transition.rs`.
  WP06 removes it with scaffold fallback.
- Evidence: workspace all-feature check/clippy; sb-types/sb-adapters tests;
  PacketConn deadline/capability tests; scaffold smoke; boundaries; diff check.
