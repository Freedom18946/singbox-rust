<!-- tier: B -->
# MIG-03 WP09 — derp / ssmapi / v2ray_api 迁出 sb-core，内核 axum/tonic 清零

Status: PLANNED
Priority: P1
Depends on: 无（可与 α/β 车道并行；不碰 bridge/router 文件）
Blocks: WP13（service_* feature 归位在 WP13 收网）

Primary evidence:

- `crates/sb-core/src/services/` — 14,016 LOC。其中：
  `derp/server.rs` **5,311 行单文件**；`v2ray_api.rs` 1,832；
  `ssmapi/server.rs` 1,439 + `ssmapi/` 其余；`cache_file.rs` 1,768；
  `dns_forwarder.rs`、`ntp.rs`、`time.rs`、`urltest_history.rs`、`tailscale/`。
- feature 门：`services/mod.rs:6-35`（service_derp / service_ntp /
  service_resolved / service_ssmapi）。
- 违反架构规范：`agents-only/reference/ARCHITECTURE-SPEC.md` §3.2 —
  "Web 框架优先放在 sb-api；sb-core 中仅允许在 service_* feature 下保留现有实现"
  （L19.3.1 的容忍条款，本包关闭该容忍）。
- 对照：sb-api（7,838 LOC）已承载 Clash/V2Ray API，依赖 sb-core features=["router"]。
- Go 对照：`go_fork_source/sing-box-1.13.13/service/` 独立于 route/dns 内核。

## Goal

sb-core 依赖图中 axum/tonic 出现次数 = 0。HTTP/gRPC 服务型组件迁出 sb-core：
v2ray_api、ssmapi 并入 sb-api；derp 迁入新 crate `crates/sb-service-derp`
（或 ADR 判定的等价落位）。sb-core 保留 `Service` trait、service_registry 与
**非 Web** 的内核服务（ntp/time/dns_forwarder/cache_file/urltest_history）。

## Current Gap

控制面 HTTP/gRPC 栈长在内核里：改一个 API handler 要重编 sb-core；
derp 单文件 5,311 行无法独立演进；tonic/axum 版本升级被内核锁死。

## Non-goals

- **不迁** cache_file / ntp / time / dns_forwarder / urltest_history（无 Web 框架
  依赖，属内核服务；cache_file 与 Clash selector 持久化耦合，动它风险大于收益）。
- 不改任何 API 的对外契约（路径、payload、鉴权行为）。
- 不动 app/admin_debug（WP10）。
- services/tailscale 若与 endpoint/tailscale 纠缠，登记给 WP12，本包不拆。

## Task Split

1. **落位已定（D12，无需请示）**：v2ray_api + ssmapi → sb-api；
   derp → 新 crate `crates/sb-service-derp`。
   核对依赖方向合法性：sb-api 依赖 sb-core 允许；新 crate 依赖 sb-core 允许；
   sb-core 不得反向依赖两者。
2. **注册机制外置**：supervisor 通过 `crate::service::{Service, StartStage}`
   启动服务——迁出后改为 app 组合根注册（对齐 adapters 的
   `register_all()` 模式）。sb-core 保留 service_registry 与 trait，
   删除对具体服务类型的直接构造。
3. **v2ray_api 迁移**：`services/v2ray_api.rs` + `services/v2ray/` → sb-api；
   tonic 依赖随迁；`service_v2ray_api` feature 在 sb-core 侧变透传（终删在 WP13）。
   `context.rs` 中 `V2RayServer`/`V2RayServerActivePhase`（supervisor 引用）改为
   经 Service trait 的泛化生命周期接口，消除内核对具体服务的类型知识。
4. **ssmapi 迁移**：同上模式 → sb-api；axum 依赖随迁。
5. **derp 迁移**：`services/derp/` → `crates/sb-service-derp`（workspace 新成员）；
   顺手把 5,311 行 server.rs 按职责拆文件（handshake/relay/mesh/http 面），
   **只拆文件不改逻辑**；derp 相关测试随迁。
6. **app 接线**：app 的 service 启动路径改为从新家注册；三个 app 聚合 profile
   （acceptance/gui_runtime/parity）中 service_* feature 的透传路径更新并逐一构建。
7. **度量记录**：`cargo tree -p sb-core -e features | grep -E 'axum|tonic'`
   清零证明；sb-core LOC 下降数。

## Acceptance

- [ ] `cargo tree -p sb-core --all-features | grep -E ' axum | tonic '` = 空。
- [ ] `crates/sb-core/src/services/` 下不再存在 derp/、ssmapi/、v2ray_api.rs、
      v2ray/（其余内核服务保留）。
- [ ] v2ray/ssmapi/derp 的现有测试在新家全绿；API 对外契约回归
      （现有 API 集成测试 + 手工 curl 冒烟记录在包内）。
- [ ] supervisor 不再 import 任何具体服务类型（`grep -n "V2RayServer\|derp\|ssmapi" runtime/supervisor.rs` 清零或仅剩泛化接口）。
- [ ] app 三聚合 profile 构建通过：
      `cargo check -p app --features acceptance`、`--features gui_runtime`、
      `--features parity`。
- [ ] 全局验收门禁五连全绿。

## 验证命令

```bash
cargo fmt --all -- --check
cargo check --workspace --all-features
cargo clippy -p sb-core -p sb-api -p sb-service-derp --all-targets --all-features
cargo test -p sb-api -p sb-service-derp
cargo check -p app --features acceptance && cargo check -p app --features gui_runtime && cargo check -p app --features parity
make boundaries
git diff --check
```

## Risks / known traps

- supervisor 的分阶段启动（StartStage 序列）对服务启动顺序有依赖——迁出后
  注册顺序必须复现原顺序，写一个锁启动顺序的单测。
- derp 与 `sb-transport/src/derp/` 存在同名目录——测绘清楚两者关系
  （transport 层 vs 服务层），别合并错对象。
- ssmapi 的 axum 版本与 admin_debug 的 HTTP 栈版本可能不一致，迁入 sb-api 时
  以 sb-api 现行版本为准，出现 API 破坏时停下登记。
- boundary 脚本对 sb-core service 模块的断言更新；workspace members 新增
  `sb-service-derp` 后 `deny.toml`/LICENSES 检查同步。

## 发现移交

（执行时填写。）
