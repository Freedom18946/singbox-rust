<!-- tier: B -->
# MIG-03 WP05 — 按覆盖矩阵把缺口语义补进 sb-adapters

Status: DONE
Priority: P0
Depends on: WP02（正典契约已落地）、WP04（矩阵已定稿且 SCAFFOLD-ONLY 项已按 D9 判定完毕）
Blocks: WP06
Implementation: `de25101d` (`main`, 2026-07-11)

Primary evidence:

- `agents-only/mig03/mig03_wp04_coverage_matrix.md`（本包唯一施工单）。
- adapters 侧目标文件：`crates/sb-adapters/src/outbound/*`、`inbound/*`。

## Goal

把 WP04 矩阵中全部 `GAP` 项和按 D9 判为"移植"的 `SCAFFOLD-ONLY` 项实现进
sb-adapters，使每个 scaffold 协议达到 `ADAPTERS-COVERS` 判定，为 WP06 的
删除扫清语义障碍。

## Closure

WP04 矩阵两组 GAP 已清零：

- SOCKS/mixed accept loop复用现有 per-IP limiter与变量默认值；SOCKS driver报告真实
  active TCP，并补发旧 Prometheus associate/packet/active surface。
- adapter owner现持有 upstream map与 SOCKS5 UDP session；实现复用 canonical
  `Socks5Connector + PacketConn`，保持 control lifetime、wire-size返回/计量、错误、观测、
  capacity/TTL语义。
- `socks -> socks-udp -> adapter-socks` 闭合产品 feature；app observe转发 adapter metrics。
- D14 变量在 service construction冻结；旧 receive-task/channel、observation、capacity、
  foreground/background timeout、proxy address precedence与 control-timeout alias均保留。
- core SOCKS UDP测试迁为 adapter/product active tests；core direct balancer测试保留给 WP12，
  ignored balancer failover不作为 WP05 gate。

## Non-goals

- 不删任何 scaffold 代码（WP06）。
- 不改 bridge 的回退逻辑（WP06）。
- 矩阵之外的"顺手增强"一律不做。

## Task Split

1. **施工排序**：按矩阵 GAP 数量从少到多排列协议，先易后难，逐协议独立提交。
2. **逐 GAP 实现**：每个 GAP 项对应：
   - adapters 侧实现（实现正典契约，不得引入对 scaffold 模块的新依赖）；
   - 一条以上锁定该语义的测试（单测或集成测；语义源自 scaffold 的，测试断言
     要与 scaffold 现行为逐字节/逐字段对齐）；
   - 矩阵中该行判定翻转为 `ADAPTERS-COVERS` 并附 commit 引用。
3. **metrics 对齐**：矩阵标记的打点差异按"以现有 Prometheus 面板消费的名称为准"
   原则对齐；如两套名称都被消费，登记进包尾"发现移交"交 WP14 统一。
4. **测试移植**：WP04 盘点的"需移植测试"逐个移到 adapters 侧并确认通过。
5. **半共享结构解耦**：矩阵标注的共享代码（如 `UpSocksSession`）在本包完成
   归属迁移（建议迁入 sb-adapters 或独立模块），并修好 sb-core 侧引用——
   这是 WP06 删除的前置。

执行锚点均为 `de25101d`；逐行测试/owner/feature证据见 WP04 matrix §4.1、§5.1、
§8、§9、§11。

## Acceptance

- [x] 矩阵中 GAP 项清零；每行翻转都有 commit 引用与测试锚点。
- [x] 按 D9 判为 DROP 的 SCAFFOLD-ONLY 项在矩阵中标记 `DROPPED-BY-DECISION`，
      并确认没有测试仍在锁定该行为；判为 Rust-only 扩展的项已挂 feature 且
      默认构建不启用。WP04 未发现需单列 `DROPPED-BY-DECISION` 的 SCAFFOLD-ONLY
      协议项；D9 DROP实体仍留 WP06执行。
- [x] `crates/sb-adapters/src/inbound/socks/udp.rs` 等交叉依赖点不再引用
      `sb_core::outbound::*` scaffold 符号。
- [x] `cargo test -p sb-adapters` 与 all-features全绿；新增测试均可单独复跑。
- [x] 全局验收门禁五连全绿。
- [x] 双核差分：矩阵涉及协议的 interop case 无新增差分（S4 归因）。

## 验证命令

```bash
cargo fmt --all -- --check
cargo check --workspace --all-features
cargo clippy --workspace --all-targets --all-features
cargo test -p sb-adapters
cargo test -p sb-adapters --all-features -- --test-threads=1
make boundaries
git diff --check
rg -n 'sb_core::(net::udp_upstream_map|outbound::socks5_udp|outbound::udp_socks5|outbound::udp_proxy_glue)' \
  crates/sb-adapters -g '*.rs' # 目标：0
```

## Acceptance Evidence

- 产品 profile：app `acceptance`、`gui_runtime`、`parity` check通过；
  `app/tests/socks_udp_direct_e2e.rs` 在 `gui_runtime` 下 active roundtrip通过。
- adapter数据面：all-features suite通过；limiter/active/metric、canonical PacketConn、
  adapter-owned session wire-size、legacy env freeze、router→proxy完整回环均为 active tests。
- core回归：`cargo test -p sb-core -- --test-threads=1` 通过；迁出三条 core SOCKS UDP
  scaffold tests后，generic direct balancer test仍通过。
- feature isolation：`--no-default-features --features socks,router` check与 SOCKS UDP
  focused tests通过。
- Python工具回归：reality probe/clienthello/dual-kernel verification三套共同行命令通过；
  同时修正 probe canonical-dial重构后的陈旧源码锚点。
- 双核 run均为 Rust/Go traffic success且 errors为空：
  - TCP SOCKS：`20260710T175426Z-d2364dcc-24b7-4343-9fd8-a32bb651e6ca`
  - UDP SOCKS：`20260710T175429Z-14c1ad48-6522-4f4e-9a69-fb3193dba7c3`
  - mixed SOCKS/HTTP：`20260710T175431Z-c0a094ba-aaa6-44ef-b5b9-cd37a96bfd87`
- 最终五项：fmt、workspace all-features check、workspace all-targets/all-features clippy、
  boundaries、diff-check全绿。

## Risks / known traps

- "补齐语义"最容易发生的事故是把 scaffold 的 bug 也当语义移植——按 D10：
  Go 内核行为是最高仲裁，与 Go 一致则保留、相悖则修正并在矩阵记录；
  仅当 Go 侧行为无法确证时才按 D18 升级。
- scaffold inbound 直连 `routing::engine::Engine`，adapters inbound 走
  `AdapterInboundContext`——集成面不同导致 sniff/DNS 行为可能有隐性差异，
  这类 GAP 必须用端到端测试锁（起 inbound → 发请求 → 断言路由决策），
  不能只靠单测。
- WP03 已关闭；不存在并行冲突。

## 发现移交

- 未出现 D18 项，也未扩大到后续包。
- core orphan scaffold实体与 bridge fallback删除仍严格留 WP06。
- selector/urltest及 generic balancer/group ownership仍严格留 WP12；现存 ignored
  `socks_udp_e2e_balancer` 不计 WP05 验收。
- Go users、SOCKS4/4a/UoT等 parity发现仍按 WP04 §10移交，未顺手实现。
