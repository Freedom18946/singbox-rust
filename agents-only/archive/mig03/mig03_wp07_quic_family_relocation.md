<!-- tier: B -->
# MIG-03 WP07 — hysteria / hysteria2 / naive / quic 家族迁出 sb-core

Status: DONE
Priority: P1
Depends on: WP06
Blocks: WP13（quinn/hyper 依赖与 out_* feature 的最终拆除在 WP13 收网）

Primary evidence:

- 实现在 sb-core：`crates/sb-core/src/outbound/hysteria/`、`hysteria2.rs`（1,721 行）
  + `hysteria2/`（含 inbound 子模块与 1,202 行 tests）、`naive_h2.rs`、
  `quic/common.rs`。
- 注册却在 adapters：`crates/sb-adapters/src/register.rs:2154/:3194` 直接引用
  `sb_core::outbound::hysteria2::inbound::MasqueradeConfig` 等内部类型；
  `crates/sb-adapters/src/outbound/hysteria.rs`、`hysteria2.rs` 是对 core 实现的
  包装（`Hysteria2AdapterConfig`/`Hysteria2Connector`）。
- runtime 纠缠：`crates/sb-core/src/runtime/switchboard.rs:537` 拼装
  `Hysteria2Config`。
- 依赖后果：sb-core 因此扛着 `dep:quinn`（out_quic）、`dep:hyper`（out_naive）。
- 测试资产：`crates/sb-core/tests/hysteria2_integration.rs`、
  `crates/sb-core/benches/hysteria2_bench.rs`、`app/tests/hysteria2_udp_e2e.rs`、
  `crates/sb-adapters/tests/hysteria2_smoke.rs`。
- 历史约定（CLAUDE.md 架构节）：L1 时代"Hysteria/Hysteria2 inbound 仍依赖
  sb-core"是登记过的例外——本包就是要关掉这个例外。

## Goal

hysteria/hysteria2（含 inbound/masquerade）/naive_h2/quic 公共层全部迁至
sb-adapters（`outbound/` 与 `inbound/` 对应模块 + `quic_util.rs` 合并），
sb-core 不再包含任何 QUIC 协议实现；`dep:quinn`、`dep:hyper`（naive 用）从
sb-core 移除的条件成熟（实际删除依赖与 feature 在 WP13 执行，本包完成代码迁移）。

## Current Gap

这不是 scaffold 双轨，而是"实现放错楼层"：唯一实现在 sb-core，adapters 只是
壳。删不得、绕不开，只能整体搬家并解开 switchboard/tests 的反向引用。

## Non-goals

- 不改协议行为（Hysteria2 的 salamander/brutal/masquerade 语义逐字节保持）。
- 不动 TUIC（实现本就在 adapters）。
- 不在本包删除 out_quic/out_naive feature 定义（WP13）。

## Task Split

1. **依赖面测绘**：列出 `sb_core::outbound::{hysteria,hysteria2,naive_h2,quic}`
   的全部外部引用（register.rs、switchboard、tests、benches、app tests），
   形成搬迁核对单。
2. **quic 公共层先行**：`outbound/quic/common.rs` → `sb-adapters/src/outbound/
   quic_util.rs`（与现有内容合并，去重）。
3. **hysteria v1 搬迁**：`outbound/hysteria/` 整目录 `git mv` 至 adapters，
   包装壳 `sb-adapters/outbound/hysteria.rs` 与实现合并为单层。
4. **hysteria2 搬迁**（最大件，含 inbound）：
   - `outbound/hysteria2.rs` + `hysteria2/`（含 inbound、tests）迁至 adapters；
     inbound 部分落 `sb-adapters/src/inbound/hysteria2*`，与现有
     `inbound/hysteria2.rs` 壳合并；
   - `MasqueradeConfig` 等类型的新家定稿后，修 register.rs 引用；
   - `switchboard.rs:537` 的配置拼装逻辑上移到注册层（adapters builder 内），
     switchboard 只持正典 trait 对象——这是解开 core→协议反向纠缠的关键步。
5. **naive_h2 搬迁**：`outbound/naive_h2.rs` → adapters；hyper 依赖随迁。
6. **测试/bench 搬迁**：evidence 列出的 4 处测试资产随实现迁移并全绿；
   `app/tests/hysteria2_udp_e2e.rs` 改 import 路径。
7. **度量记录**：sb-core LOC 下降数；`grep -rn "outbound::hysteria\|outbound::quic\|naive_h2" crates/sb-core/src` 清零证明。

## Acceptance

- [x] `crates/sb-core/src/outbound/` 下不再存在 hysteria*/quic/naive_h2 模块
      （`ls` + `grep` 双证）。
- [x] register.rs / switchboard 对 `sb_core::outbound::hysteria*` 引用 = 0。
- [x] 迁移后测试全绿：hysteria2_integration（新家）、hysteria2_smoke、
      hysteria2_udp_e2e、hysteria2_bench 可编译运行。
- [x] WP07 家族不再使 sb-core 源码依赖 quinn/hyper；现存 quinn/hyper 来自
      DNS DoQ/DoH3、DERP、dev-dependency 及兼容 feature（分别移交 WP09/WP13），
      `cargo tree -p sb-core -e features | grep -E 'quinn|hyper'` 输出记录在包内。
- [x] 全局验收门禁五连全绿。
- [x] 双核回归：现有 interop 订阅 YAML Rust case 通过；仓库无可运行的
      Hysteria/Hysteria2 Go-vs-Rust case，未虚构 parity 结论。

## 验证命令

```bash
cargo fmt --all -- --check
cargo check --workspace --all-features
cargo clippy -p sb-core -p sb-adapters --all-targets --all-features
cargo test -p sb-adapters hysteria
cargo test -p app --test hysteria2_udp_e2e
make boundaries
git diff --check
```

## Risks / known traps

- 用 `git mv` 而非删+建，保住 blame/rename 历史（1,700 行大文件尤其重要）。
- hysteria2 inbound 与 TLS 证书加载路径可能引用 sb-core 的 tls 影子模块
  （`sb-core/src/tls/`）——若有，此处**只改 import 到 sb-tls 等价物**，
  影子模块本体留给 WP12。
- `agents-only/archive/mt_real_02/mt_trojan_fresh_sample_intake.md` 被 trojan.rs 源码引用的先例
  说明协议文件里可能有指向 agents-only 文档的注释路径——搬家时检查注释内
  相对路径是否失效。
- benches 不在默认测试跑道上，容易漏编译——显式 `cargo bench -p <crate> --no-run`。

## 执行证据（2026-07-11）

- 协议所有权：hysteria v1/v2 inbound/outbound、naive_h2、QUIC 公共层均在
  `sb-adapters`；core 对四组旧模块精确引用为 0，switchboard 的 Hysteria2 IR
  拼装已上移 adapters builder。
- 正典能力：Hysteria2 同时声明 TCP/UDP，builder 保留 Brutal、CA path/PEM、
  ALPN/SNI、0-RTT、obfs/salamander；UDP 地址编解码、deadline、close、带宽限制、
  认证与 association 初始化均在 adapters。opt-in `SB_E2E_UDP=1` 回环实际通过。
- 测试资产：Hysteria v1 E2E 12/12；Hysteria2 integration 3/3；app UDP E2E 1/1；
  `cargo bench -p sb-adapters --bench hysteria2_bench --features bench,adapter-hysteria2`
  实际完成两项 Criterion benchmark。
- 全局门禁：workspace all-feature check、workspace all-target/all-feature clippy、
  core+adapters all-feature tests、fmt、boundaries（493 assertions）、diff-check 全绿。
- 度量：sb-core `src/**/*.rs` 102,101 → 97,393，净减 4,708 行；提交前 staged
  diff 为 +1,596/-5,008，净减 3,412 行（rename detection 会改变增删拆分，不改净值）。

## 发现移交

- WP09：DERP 仍直接使用 hyper 0.14。
- WP13：删除 sb-core `out_hysteria`/`out_hysteria2`/`out_naive`/`out_quic`
  兼容 feature 与其直接依赖边；quinn 仍由 DNS DoQ/DoH3 使用，hyper 还由
  sb-metrics/reqwest/tonic 与 dev-dependency 路径引入，不能宣称依赖树清零。
