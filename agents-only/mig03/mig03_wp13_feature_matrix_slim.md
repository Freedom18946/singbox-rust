<!-- tier: B -->
# MIG-03 WP13 — feature 矩阵瘦身（103 → 目标 -30%），legacy out_* 退役

Status: PLANNED
Priority: P2
Depends on: WP07（quinn/hyper 迁移完成）、WP12（影子模块/endpoint 门归位）
Blocks: WP14

Primary evidence:

- sb-core：**103 个 feature、1,077 个 `#[cfg(feature)]` 块**（2026-07-06 基线）。
- legacy 空 features（`crates/sb-core/Cargo.toml`）：`out_socks`/`out_http`/
  `out_shadowtls`/`out_ssh`/`out_ss`/`out_trojan`/`out_tuic`/`out_vless`/
  `out_vmess`/`out_wireguard` 均为 `[]` 且注释 "Legacy: protocol code removed"，
  但**空 feature 仍激活 cfg 块**：全仓 145 处 `feature = "out_` 引用，散布
  `telemetry.rs`、`metrics/outbound.rs`、`runtime/switchboard.rs`、
  `endpoint/mod.rs`、`router/engine.rs`、`services/mod.rs` 等 14 文件。
- 非空但应随 WP07 迁走的：`out_hysteria`/`out_hysteria2`（→out_quic,tls_rustls）、
  `out_naive`（dep:hyper）、`out_quic`（dep:quinn）、`out_tailscale`（dep:snow）。
- `router` 是 optional feature（`Cargo.toml:196` 为空数组），但 app default 即
  含 router，sb-api/sb-adapters 均强制开启——事实上的必选项却制造了
  `#[cfg(feature = "router")]` 大量分支（bridge/registry/supervisor 内随处可见）。
- 消费方：app 聚合 profile（`default`/`minimal`/`acceptance`/`gui_runtime`/
  `parity`）、Makefile、scripts/、xtests/ 的 feature 引用。

## Goal

sb-core feature 数较基线 103 下降 ≥30%，cfg 块较基线 1,077 下降 ≥25%；
legacy 空 out_* 全部退役；`router` 是否转常驻拿到 ADR 结论并执行。
每个保留 feature 在 Cargo.toml 内有一行注释说明"门的是什么依赖/能力"。

## Current Gap

feature 组合空间无法全测（103 个 feature 的组合爆炸），空 feature 门着活代码
意味着"关掉 feature ≠ 删掉能力"，构建配置的语义与直觉相反。

## Non-goals

- 不改变 app 五个聚合 profile 的**对外语义**（每个 profile 构建出的能力集不变；
  profile 内部引用的 feature 名允许变化）。
- 不动 dns_*/service_*/tls_* 中门控真实可选依赖的部分（只登记、不强删）。
- 不追求一步到位的"完美 feature 设计"——只做减法与归类，不发明新分层。

## Task Split

1. **全量普查**（产出 `mig03_wp13_feature_census.md`）：103 个 feature 逐个：
   名称、门控内容（真实依赖 / 纯代码块 / 空）、下游引用（app/adapters/api/
   Makefile/scripts/xtests 的 grep 计数）、判定（保留 / 删除 / 合并入 X / 常驻化）。
2. **legacy out_* 退役**（预期删 10 个空 feature）：
   - 逐文件处理 145 处 cfg 引用：块内代码若为 metrics 标签/telemetry 枚举等
     与协议注册无关的支撑代码 → 去门控常驻或改按运行时注册驱动；
     若为死支撑代码（对应协议早已在 adapters）→ 删除；
   - 同步修 app/adapters 侧对这些 feature 的透传引用。
3. **WP07 遗留拆除**：`out_hysteria`/`out_hysteria2`/`out_naive`/`out_quic` 的
   feature 与 `dep:quinn`/`dep:hyper` 从 sb-core Cargo.toml 移除（代码已随 WP07
   迁走）；adapters 侧对应 feature 归位命名（如 `adapter-hysteria2`，与现有
   adapters feature 命名风格对齐）。
4. **router 常驻化（D16 已定，无需请示）**：
   - 删除 `router` feature，删除全部 `#[cfg(feature = "router")]` 分支中的
     "无 router 版本"代码（bridge/registry/supervisor 是重灾区）；
   - 普查若发现真实的 no-router 消费方（证据说话），按 D18 升级，
     不得自行保留双版本。
5. **组合验证矩阵**：收网后逐一构建并记录：
   `default`、`minimal`、`acceptance`、`gui_runtime`、`parity`、`--all-features`、
   `--no-default-features`（sb-core 单独）。七种构建全过是硬门禁。
6. **度量记录**：feature 数、cfg 块数前后对比（命令与输出入包）。

## Acceptance

- [ ] `sed -n '/\[features\]/,$p' crates/sb-core/Cargo.toml | grep -c '='` ≤ 72
      （较 103 降 ≥30%）。
- [ ] `grep -rn '#\[cfg(feature' crates/sb-core/src | wc -l` ≤ 807（降 ≥25%）。
- [ ] `grep -rn 'feature = "out_' crates/sb-core/src` = 0（或仅剩 census 判定
      保留的、有注释理由的项）。
- [ ] feature census 无 TBD；Cargo.toml 每个保留 feature 有说明注释。
- [ ] 七种构建组合全部通过（任务 5 清单，输出记录在包内）。
- [ ] Makefile / scripts / xtests 中引用的 feature 名全部有效
      （`grep -rn "features" Makefile scripts/ xtests/ | grep -oE 'out_[a-z0-9_]+'` 无失配）。
- [ ] 全局验收门禁五连全绿。

## 验证命令

```bash
cargo fmt --all -- --check
cargo check --workspace --all-features
cargo check -p sb-core --no-default-features
for f in default minimal acceptance gui_runtime parity; do cargo check -p app --features "$f" --no-default-features || echo "FAIL $f"; done
cargo clippy --workspace --all-targets --all-features
make boundaries
git diff --check
```

## Risks / known traps

- 空 feature 的 cfg 块里藏着 **metrics 枚举分支**（`metrics/outbound.rs`、
  `telemetry.rs`）——去门控时确认标签集合不变，Prometheus 面板消费这些标签。
- `out_*` 命名是 L1 时代"保留名称兼容"的产物——下游脚本可能按名字 grep；
  删除前跑一遍全仓（含 scripts/、xtests/、docs/、labs/）名称搜索。
- boundary 脚本 V1/V2/V3 是 feature-gate 感知的——feature 删除会让策略失配，
  按"更新策略"处理（历史坑，见 CLAUDE.md 边界检查节）。
- `--no-default-features` 的 sb-core 单独构建此前可能从未在门禁里跑过，
  首跑预期翻出存量问题——存量问题登记移交，不在本包顺手修。

## 发现移交

（执行时填写。）
