<!-- tier: B -->
# MIG-03 WP07 — hysteria / hysteria2 / naive / quic 家族迁出 sb-core

Status: PLANNED
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

- [ ] `crates/sb-core/src/outbound/` 下不再存在 hysteria*/quic/naive_h2 模块
      （`ls` + `grep` 双证）。
- [ ] register.rs / switchboard 对 `sb_core::outbound::hysteria*` 引用 = 0。
- [ ] 迁移后测试全绿：hysteria2_integration（新家）、hysteria2_smoke、
      hysteria2_udp_e2e、hysteria2_bench 可编译运行。
- [ ] sb-core 的 quinn/hyper 依赖仅剩 feature 定义残留（登记给 WP13），
      `cargo tree -p sb-core -e features | grep -E 'quinn|hyper'` 输出记录在包内。
- [ ] 全局验收门禁五连全绿。
- [ ] 双核回归：hysteria/hysteria2 相关 interop case 无新增差分。

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

## 发现移交

（执行时填写。）
