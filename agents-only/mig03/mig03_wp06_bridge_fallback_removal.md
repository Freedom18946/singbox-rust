<!-- tier: B -->
# MIG-03 WP06 — bridge 回退移除 + scaffold 实现与 feature 删除

Status: PLANNED
Priority: P0（本轨迹最大删码包，预计净删 1.5 万行级）
Depends on: WP05（矩阵全行 ADAPTERS-COVERS 或 DROPPED-BY-DECISION）
Blocks: WP07, WP08（文件冲突串行）

Primary evidence:

- `crates/sb-core/src/adapter/bridge.rs` — registry 未命中时落入 scaffold 分支
  （`#[cfg(feature = "scaffold")]` 区段，`:514` 起有辅助函数）。
- `scaffold` feature：`crates/sb-core/Cargo.toml:201` 定义；
  `app/Cargo.toml:192/:377/:440` 与 `crates/sb-adapters/Cargo.toml:61` 强制开启。
- 待删实现清单（以 WP04 矩阵终稿为准，立项时已知）：
  `sb-core/src/inbound/{socks5,http_connect,mixed}.rs`、
  `sb-core/src/outbound/{socks5,socks5_udp,udp_socks5,socks_upstream,http_proxy,http_upstream}.rs`、
  `sb-core/src/outbound/ss/`、direct/block 的冗余变体（正典变体保留，见任务 4）。
- 现有测试：`app/tests/adapter_bridge_scaffold.rs`（required-features 含 scaffold）。

## Goal

生产二进制中只存在一套协议实现（sb-adapters）。bridge 不再静默回退：
registry 未命中 → 返回**结构化错误**（错误信息含 kind 与"该协议未编译进本
构建"的提示）。`scaffold` feature 从全 workspace 消失。

## Current Gap

见 overview §1.2 第 2 条。删除的全部语义前提由 WP04/WP05 保障，本包是执行包。

## Non-goals

- hysteria/hysteria2/naive/quic 家族不动（WP07）。
- selector 家族实现不动（WP12；本包只处理 bridge 对它们的构造入口，若矩阵
  判定组类由 adapters 覆盖则一并切换，否则保留现构造入口）。
- 不改路由（WP08）。

## Task Split

1. **回退语义切换**：bridge 的 inbound/outbound 构造路径改为
   "registry 未命中 = 硬错误"。错误文案统一、可测试；启动期报错必须阻止
   `READY` 输出（对齐 2026-07-03 metrics-serve 包立下的启动契约）。
2. **逐文件删除**（严格按 WP04 矩阵终稿清单，每删一组跑一次门禁）：
   - 先删 bridge 内 scaffold 分支与 `cfg(feature = "scaffold")` 区段；
   - 再删实现文件；同步清理 `inbound/mod.rs`、`outbound/mod.rs` 的模块声明与
     re-export；
   - 同步删除/迁移挂在被删文件上的单测（WP04 已盘点归属）。
3. **feature 拆除**：
   - `sb-core/Cargo.toml:201` 删除 `scaffold` 定义；
   - `app/Cargo.toml` 三处、`sb-adapters/Cargo.toml:61` 移除引用；
   - 全仓 `grep -rn 'feature = "scaffold"'` 清零（基线 14 文件）；
   - `app/tests/adapter_bridge_scaffold.rs` 改造为"registry 直通"契约测试
     （改名 `adapter_bridge_registry.rs`），锁定未命中硬错误行为。
4. **direct/block 归位（D11 已定）**：adapters 的 direct.rs/block.rs 为正典；
   switchboard 等处的默认连接器一律改为消费 registry 注册的 direct，
   sb-core 不保留任何本地 direct/block 实现；确因初始化次序无法经 registry
   时按 D18 升级，不得静默保留本地变体。
5. **交叉引用扫尾**：`sb-core/src/net/udp_upstream_map.rs` 等对被删符号的引用
   按 WP05 解耦结论修复。
6. **度量记录**：删除文件数 / 净删行数 / 二进制体积变化
   （`cargo build -p app --release --features gui_runtime` 前后对比）。

## Acceptance

- [ ] `grep -rn 'scaffold' crates/*/Cargo.toml app/Cargo.toml` = 0；
      `grep -rn 'feature = "scaffold"' crates app` = 0。
- [ ] evidence 列出的实现文件全部删除（或在包内逐个说明保留理由）。
- [ ] bridge 未命中路径有专项测试：构造一个未注册 kind 的 IR → 启动失败、
      错误信息含 kind、无 `READY` 输出。
- [ ] `cargo test -p app --test adapter_bridge_registry` 全绿。
- [ ] 全局验收门禁五连全绿；`cargo test -p sb-core -p sb-adapters` 全绿。
- [ ] 双核回归：interop 全量现有 case 通过，无新增差分（S4 归因流程记录在包内）。
- [ ] gui_runtime 冒烟：GUI 样例配置 `check` + `run` 启动→listen→curl 经由
      mixed inbound 出流量成功（复用 MT-GUI 验收脚本路径，记录命令）。

## 验证命令

```bash
cargo fmt --all -- --check
cargo check --workspace --all-features
cargo clippy --workspace --all-targets --all-features
cargo test -p sb-core -p sb-adapters -p app
make boundaries
git diff --check
grep -rn 'feature = "scaffold"' crates app || echo CLEAN
```

## Risks / known traps

- **本包是行为漂移风险最高的一包**：此前"registry 未命中静默走 scaffold"的
  配置，在删除后会从"能跑"变成"启动报错"。这是立项批准的预期变化
  （消灭隐式回退，与 MIG-02 零隐式直连回退同一原则），但必须在包收尾的
  active_context Resume 里显式声明。
- `inbound/mixed.rs` 是 socks5+http_connect 的复合体，GUI 默认配置走 mixed——
  删除顺序必须保证 adapters 的 mixed 注册路径先被 e2e 锁定再删 scaffold 版。
- boundary 脚本 V4a/V4b 对 sb-core→协议模块的断言会大面积失配，按"更新策略
  文件"处理，不许放宽为跳过。
- 删除后 `out_socks`/`out_http` 等空 feature 的 cfg 块可能出现编译死角
  （cfg 内引用被删符号）——`--all-features` 检查是硬门禁，别只跑默认特性。

## 发现移交

（执行时填写。）
