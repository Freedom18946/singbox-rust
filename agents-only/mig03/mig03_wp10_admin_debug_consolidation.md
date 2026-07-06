<!-- tier: B -->
# MIG-03 WP10 — app/admin_debug 死代码清点与控制面收敛（需用户决策）

Status: PLANNED
Priority: P2
Depends on: 无（与 WP09 弱耦合，建议 WP09 先行以确定 sb-api 终形态）
Blocks: 无

Primary evidence:

- `app/src/admin_debug/` — 13,634 LOC：http_server.rs、endpoints/、middleware/、
  auth/、audit.rs、breaker.rs、cache.rs、prefetch.rs、security*.rs。
- `app/src/admin_debug/mod.rs:1` 起挂着整页
  `#![allow(dead_code, unused_imports, unused_variables, ...)]`——死代码规模未知，
  这是全仓唯一整模块屏蔽 lint 的地方。
- 重叠对象:sb-api 的 Clash API server（`crates/sb-api/src/clash/server.rs`）
  自带 axum 路由/auth;admin_debug 有自己的一套 HTTP server + auth + middleware。
- app 内消费:`admin_debug/endpoints/analyze.rs` 依赖 app/analyze 与 sb-core router。

## Goal

第一步（本包必做）：拿到一份可信的 admin_debug 资产清单——哪些 endpoint 被
真实消费（脚本/GUI/文档引用）、哪些是死代码；摘掉整页 lint 屏蔽。
第二步（按 D13 执行，无需请示）：控制面 HTTP/auth 栈统一到 sb-api，
app 侧自建 server/auth/middleware 拆除，死代码删除。census 决定成员归属，
D13 决定机制。

## Current Gap

13.6k 行控制面代码质量状态未知（lint 全屏蔽），与 sb-api 职责重叠但实现两套
HTTP/auth 栈。在弄清死活之前任何"合并"动作都是盲操作，所以本包审计先行、
决策居中、执行在后。

## Non-goals

- 不动 sb-api 的 Clash/V2Ray 对外契约（GUI 依赖）。
- 不动 `sb-explaind` 等独立调试 bin（另有 WP13/WP14 视 feature 归位处理）。
- 未经 census 复核证据（SUSPECT-DEAD 判定成立）不删任何 endpoint。

## Task Split

1. **消费面审计**（产出 `mig03_wp10_admin_debug_census.md`）：
   - endpoint 全量表：路径、方法、feature 门、被谁消费（grep scripts/、
     xtests/、docs/、GUI_fork_source/ 的引用；无消费证据的标 SUSPECT-DEAD）；
   - 逐文件死代码评估：临时移除 `#![allow(dead_code, ...)]`，收集
     `cargo check -p app --features admin_debug` 警告清单归类（真死 / 仅在
     其它 feature 组合下活 / 假阳性）；
   - 与 sb-api 重叠矩阵：auth、限流（breaker）、审计日志、cache——两套实现
     各自的能力与差异。
2. **执行方案（D13 已定，无需请示）**：控制面 HTTP/auth 栈全仓唯一，归 sb-api：
   - sb-api 暴露一个路由扩展点（组合根可注册额外路由域）；
   - census 判定的活 endpoint：仅依赖 core/api 状态的迁入 sb-api（`debug`
     feature 门控）；依赖 app 内部状态（analyze 等）的由 app 经扩展点注册，
     不再自建 HTTP server/auth/middleware；
   - admin_debug 自有 http_server.rs / auth/ / middleware/ 栈随迁移拆除。
3. **执行细则**：
   - `#![allow(...)]` 整页屏蔽必须摘除，逐文件修到 clippy 全绿
     （allow 只允许逐项、带理由注释）；
   - 删除类动作严格按 census 的 SUSPECT-DEAD 复核清单执行，每删一批跑
     `--features acceptance` 构建（admin_debug 在该聚合内）；
   - 保留 endpoint 的对外路径/响应契约不变（迁移只换宿主，D13 机制约束）。
4. **度量记录**：admin_debug LOC 前后、endpoint 数前后、allow 项数前后。

## Acceptance

- [ ] census 文档覆盖全部 endpoint 与文件，SUSPECT-DEAD 判定均有 grep 证据。
- [ ] D13 执行完毕：app 内不再有自建 HTTP server/auth 栈
      （`grep -rn "http_server" app/src/admin_debug` 仅剩扩展点注册代码或为空）。
- [ ] `app/src/admin_debug/mod.rs` 头部无整页 blanket allow；
      `cargo clippy -p app --features admin_debug --all-targets` 全绿。
- [ ] `--features acceptance` 构建 + 现有 admin_debug 相关测试全绿。
- [ ] 被保留 endpoint 的行为回归：审计/限流/auth 关键路径各 ≥1 条测试锁定。
- [ ] 全局验收门禁五连全绿。

## 验证命令

```bash
cargo fmt --all -- --check
cargo check -p app --features acceptance
cargo clippy -p app --features admin_debug --all-targets
cargo test -p app admin_debug
make boundaries
git diff --check
```

## Risks / known traps

- `agents-only/archive/MT-GUI/mt_gui_04_acceptance.md` 的能力验收可能引用过
  admin_debug 端点——census 时把 archive 的验收文档也纳入消费面 grep 范围，
  别把验收过的能力当死代码删了（验收基线是项目资产）。
- security*.rs 与 auth/ 涉及鉴权行为，摘 allow 时的"顺手重构"冲动要忍住——
  本包只清死代码，不改活代码逻辑。
- prefetch.rs 刚在 2026-07-03 被审计清理过（见 active_context Resume），
  是活代码，别误伤。

## 发现移交

（执行时填写。）
