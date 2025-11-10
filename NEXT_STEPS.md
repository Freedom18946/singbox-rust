Parity Plan — Rust vs sing-box 1.12.12

Last audited: 2025-11-10 10:45 UTC

## 宗旨
- 以 Go 版 `sing-box 1.12.12` 为目标，补齐 **可配置、可运行、可观测** 的核心链路：CLI → 配置 IR → 运行时桥接 → 协议/传输 → DNS/服务/端点。
- 先满足用户面（常用入/出站、DNS 策略、工具命令），再向端点/服务与高级协议扩展。

## 差距快照（vs `go_fork_source/sing-box-1.12.12`）

### 协议适配器现状（已改善）
- ✅ **Adapter 注册扩展**：`sb_adapters::register_all()` 现已注册 7 种入站（http/socks/mixed/shadowsocks/vmess/vless/trojan）和 8 种出站（http/socks/shadowsocks/trojan/vmess/vless/dns + stubs），stub 覆盖率达到 Go 协议清单的 ~70%
- ✅ **IR 枚举扩展**：`InboundType` 扩展到 16 种（新增 Naive/ShadowTLS/AnyTLS/Hysteria/Hysteria2/TUIC），`OutboundType` 扩展到 19 种（新增 Dns/Tor/AnyTLS/Hysteria v1/WireGuard），与 Go 基本对齐
- ⚠ **实现缺口**：
  - **入站**：TUN/Redirect/TProxy/Direct 实现文件存在但未注册；Naive/ShadowTLS/Hysteria/Hysteria2/TUIC/AnyTLS 仅为 stub
  - **出站**：Tor/AnyTLS/Hysteria v1/WireGuard 仅为 stub；TUIC/Hysteria2/SSH/ShadowTLS 走 scaffold 但不完整
  - **实际可用率**：入站 7/17 (41%)，出站 8/19 (42%)

### 端点与服务（完全缺失）
- ✗ **Endpoints**：Go 的 WireGuard/Tailscale endpoint 在 Rust 中完全没有 IR 结构或实现 (0/2)
- ✗ **Services**：Go 的 Resolved/SSM/DERP 服务在 Rust 中完全没有实现 (0/3)；Rust 独有 NTP 服务
- ✗ **IR 缺失**：`crates/sb-config/src/ir/mod.rs:382-404` 完全没有 `endpoints`/`services` 字段

### DNS 传输（部分支持）
- ✅ **已支持**：system/UDP/DoH/DoT/DoQ + hosts/fakeip overlay (7/12)
- ✗ **缺失**：HTTP3 (DoH over HTTP/3)、DHCP、tailscale、resolved 传输 (5/12)
- ✗ **覆盖率**：58% (7/12)

### 关键架构问题
1. **注册路径未连通**：TUN/Redirect/TProxy 等实现文件存在但未在 `register.rs` 中注册，配置层无法触发
2. **Scaffold 依赖过重**：大部分 QUIC 协议 (TUIC/Hysteria2) 仍走 scaffold，未迁移到 adapter
3. **IR 字段不完整**：协议特定配置（密码/UUID/传输参数）在 IR 中缺失，无法表达完整 Go 配置
4. **测试覆盖不足**：adapter 路径、热重载、Go ↔ Rust CLI diff 完全没有测试

## 工作流（Workstreams）

### WS-A — Adapter Registry & Inbound Wiring（P0）
- **目标**：让配置层能直达 adapter 实现，补齐 TUN/Redirect/TProxy/Direct 注册，并将 stub 入站升级为完整实现。
- **触点**：`crates/sb-config/src/ir/mod.rs`、`crates/sb-core/src/adapter/bridge.rs`、`crates/sb-adapters/src/inbound/*`、`crates/sb-adapters/src/register.rs`。
- **交付**：
  1. ✅ 扩展 `InboundType` 枚举到 16 种，与 Go 对齐（已完成）
  2. ✅ 为 Naive/ShadowTLS/Hysteria/Hysteria2/TUIC/AnyTLS 添加 stub builder（已完成）
  3. ◐ 为 TUN/Redirect/TProxy 添加注册入口，连通实现文件与 adapter registry
  4. ✅ 设计并实现协议特定 IR 字段（密码/UUID/多账户/传输参数）— 已完成 2025-11-10
  5. ✗ 升级 stub 入站为完整实现：Naive → Hysteria2 → TUIC（按优先级）
- **现状**：枚举已对齐，7 种入站完整可用，6 种为 stub，3 种未注册
- **待办**：
  - [x] 为 Naive/ShadowTLS/AnyTLS 等入站注册 stub builder 并记录 fallback
  - [ ] 在 `register.rs` 中添加 TUN/Redirect/TProxy 注册函数，连接到现有实现
  - [ ] 为 Direct 入站设计 IR schema 并提供最小实现
  - [x] 设计 Inbound IR schema v2（含协议字段扩展）— 已完成 2025-11-10
  - [ ] 将 Naive stub 升级为完整实现（HTTP/2 CONNECT + TLS）
  - [ ] 将 Hysteria/Hysteria2/TUIC stub 升级为完整实现（QUIC + congestion control）

### WS-B — Outbound Protocol Coverage（P0）
- **目标**：补齐 Go 列表中的 stub 出站（tor/anytls/wireguard/hysteria v1），并完善 scaffold 出站（TUIC/Hysteria2/SSH/ShadowTLS）。
- **触点**：`crates/sb-config/src/ir/mod.rs`、`crates/sb-core/src/adapter/bridge.rs`、`crates/sb-adapters/src/outbound/*`、`sb-transport`。
- **交付**：
  1. ✅ 扩展 `OutboundType` 枚举到 19 种，新增 Dns/Tor/AnyTLS/Hysteria v1/WireGuard（已完成）
  2. ✅ 为 Dns/Tor/AnyTLS/WireGuard/Hysteria v1 注册 stub builder（已完成）
  3. ✅ DNS outbound 完整实现，支持 UDP/TCP/DoT/DoH/DoQ（已完成，feature-gated）
  4. ◐ 完善 TUIC/Hysteria2 从 scaffold 到 adapter 的迁移
  5. ✗ WireGuard outbound MVP：key 管理、UDP factory、Selector/metrics 集成
  6. ✗ Tor outbound：SOCKS5 over Tor daemon 桥接
- **现状**：枚举已扩展，8 种出站完整可用，4 种为 stub，7 种走 scaffold 但不完整
- **待办**：
  - [x] 在 adapter registry 注册 dns/tor/anytls/wireguard/hysteria stub builder
  - [x] 完整实现 DNS outbound（支持多传输）
  - [ ] 设计 `OutboundIR` 扩展字段（WG key、dns upstream、AnyTLS param 等）
  - [ ] 迁移 TUIC/Hysteria2 从 scaffold 到 adapter，提供 UDP factory
  - [ ] 补齐 SSH outbound 的 host-key 校验与认证
  - [ ] 实现 WireGuard outbound MVP（依赖 boringtun 或内核接口）
  - [ ] 实现 Tor outbound（SOCKS5 over Tor daemon）
  - [ ] 在 Selector/URLTest 中处理新协议的错误/健康逻辑

### WS-C — DNS / Resolver / Transport Parity（P0）
- **目标**：支持 Go 端 HTTP3 DoH、DHCP、tailscale、resolved 传输，并统一 env/IR 双轨。
- **触点**：`app/src/bin/run.rs`、`crates/sb-core/src/dns/*`、`crates/sb-config/src/ir/mod.rs`、`crates/sb-core/src/services/*`。
- **交付**：
  1. ✅ 实现基础 DNS 传输：system/UDP/DoH/DoT/DoQ + hosts/fakeip overlay（已完成）
  2. ✗ 扩展 `DnsServerIR`，允许描述 HTTP3/DHCP/tailscale/resolved 传输类型
  3. ✗ `resolver_from_ir` 与 `dns::transport` 新增 HTTP3、DHCP、tailscale、resolved 实现
  4. ✗ `resolved` service stub，与 DNS transport 对齐
- **现状**：58% 覆盖率 (7/12 传输)，缺少 5 种高级传输
- **待办**：
  - [ ] 追加 HTTP3 over QUIC client（需 h3 crate + DoH over HTTP/3）
  - [ ] DHCP client 集成（平台相关，需条件编译）
  - [ ] tailscale/Resolved 桥接（需外部服务依赖或 stub）
  - [ ] 设计 env ↔ IR 映射流程，避免双重 source of truth
  - [ ] 为新传输类型添加 feature gate 与友好错误信息

### WS-D — Endpoints & Services（P1）
- **目标**：为 WireGuard/Tailscale endpoint 与 Resolved/DERP/SSM 服务提供 IR、构造与最小实现/Stub。
- **触点**：`sb-config`（新增 `endpoints`/`services`）、`crates/sb-core/src/services/*`、`go_fork_source/sing-box-1.12.12/include/*`。
- **交付**：
  1. ✗ 引入 endpoint/service IR 顶层字段，含 tag/feature gate/平台要求
  2. ✗ 提供 WireGuard/Tailscale endpoint stub（缺依赖时报错提示构建选项）
  3. ✗ Resolved/DERP/SSM service：最小实现或 compile-time stub
- **现状**：IR/运行期皆无端点/服务结构，NTP 为唯一服务
- **待办**：
  - [ ] 在 `crates/sb-config/src/ir/mod.rs` 添加 `endpoints: Vec<EndpointIR>`、`services: Vec<ServiceIR>` 字段
  - [ ] 设计 `EndpointIR` schema（type/tag/options），支持 wireguard/tailscale
  - [ ] 设计 `ServiceIR` schema（type/tag/options），支持 resolved/derp/ssm
  - [ ] 在 `crates/sb-core` 添加 endpoint/service registry 框架
  - [ ] 为 WireGuard/Tailscale endpoint 提供 stub builder
  - [ ] 为 Resolved/DERP/SSM service 提供 stub 或最小实现
  - [ ] 添加 feature gate：with_wireguard, with_tailscale, with_resolved, with_derp

### WS-E — CLI / Tests / Tooling（P1）
- **目标**：CLI 与 Go 工具对齐，并建立自动化对比/健康检测。
- **触点**：`app/src/bin/*`、`app/src/cli/*`、`app/tests/*`、`scripts/`。
- **交付**：
  1. ◐ `tools connect`/`run` 复用 router bridge，剔除直接 `Bridge::new_from_config` 调用
  2. ✗ 建立 Go ↔ Rust CLI 对比脚本（route explain、ruleset、geoip/geosite）
  3. ✗ 为 adapter/DNS/selector 添加 e2e 与 smoke tests，覆盖默认/feature 组合
- **现状**：CLI 没有 adapter 验证，测试仅覆盖路由解释逻辑，无 Go 对比
- **待办**：
  - [ ] 修改 `tools connect`/`run` 使用完整 router + adapter 路径（非 scaffold）
  - [ ] 添加 CLI 集成测试：验证 adapter 入站可启动、出站可连接
  - [ ] 创建 Go ↔ Rust route explain 对比脚本（`scripts/route_explain_compare.sh`）
  - [ ] 为 TUIC/Hysteria2/DNS outbound 添加 e2e 测试
  - [ ] 添加热重载测试：验证配置更新后 adapter 正确重建
  - [ ] 在 CI 中添加 adapter feature 组合测试矩阵
  - [ ] 添加 prefetch/geoip/geosite CLI 工具与 Go 输出对比

## 近期优先级（Top Tasks）

基于当前进展（入站 41% 完成，出站 42% 完成，DNS 58% 完成），按紧迫性排序：

1. **连通 TUN/Redirect/TProxy 注册路径**（WS-A，关键阻塞）
   - 在 `sb-adapters/src/register.rs` 中添加注册函数，连接到已有实现文件
   - 修复 `Bridge::to_inbound_param` 对 Redirect/TProxy 返回 `UnsupportedInbound` 的问题
   - 优先级：**P0**，影响：解锁 3 种核心入站

2. **迁移 TUIC/Hysteria2 到 adapter**（WS-B，用户高频）
   - 从 scaffold 实现迁移到 adapter registry，提供 UDP factory
   - 补齐 QUIC congestion control 与 multiplexing
   - 优先级：**P0**，影响：解锁 2 种高频出站

3. ✅ **扩展 Inbound IR v2 字段**（WS-A，基础设施）— 已完成 2025-11-10
   - ✅ 设计协议特定字段（password/uuid/users/transport）
   - ✅ 支持多账户配置（Shadowsocks/VMess/VLESS）
   - ✅ 添加传输层配置（ws/h2/grpc）与 TLS 选项
   - ✅ 添加 Multiplex 支持
   - 优先级：**P0**，影响：使现有协议可完整配置

4. **实现 DNS HTTP3 传输**（WS-C，部分用户需求）
   - 使用 h3 crate 实现 DoH over HTTP/3
   - 添加 QUIC 传输层复用
   - 优先级：**P1**，影响：DNS 覆盖率 → 67%

5. **添加 adapter 路径测试**（WS-E，质量保障）
   - 为已实现的 7 种入站 + 8 种出站添加 e2e 测试
   - 验证 feature gate 组合不会导致编译失败
   - 优先级：**P1**，影响：防止回归

6. **WireGuard outbound MVP**（WS-B，高级用户需求）
   - 集成 boringtun 或内核 WireGuard
   - 提供 key 管理与 UDP factory
   - 优先级：**P2**，影响：解锁 1 种高级出站

7. **引入 Endpoint/Service IR**（WS-D，架构基础）
   - 添加顶层 `endpoints`/`services` 字段
   - 设计 registry 框架
   - 优先级：**P2**，影响：为 WireGuard/Tailscale/DERP 打基础

## 验证/对齐策略

### 单元测试
- 为新增 IR 字段、adapter builder、DNS 传输补充正/逆向测试
- 覆盖 serde 默认值、错误分支、feature gate 组合
- 目标：每个 adapter builder 至少 1 个单测，每个 IR 类型至少 1 个 serde round-trip 测试

### 集成测试
- 准备覆盖常见协议 + DNS 策略 + selector/urltest 的最小 JSON
- 在 CI 中同时跑 Rust CLI 与 Go `sing-box`，比较 stdout/metrics
- 添加配置迁移测试：Go JSON → Rust IR → 验证等价性

### 端到端测试
- 为新增协议编写 TCP/UDP 成功/失败用例（放入 `xtests/`）
- 测试热重载/适配器切换幂等性
- 验证 adapter 路径与 scaffold 路径行为一致性

### 对比基准
- **协议覆盖率**：
  - 入站目标：90% (15/17)，当前：41% (7/17)
  - 出站目标：95% (18/19)，当前：42% (8/19)
  - DNS 目标：75% (9/12)，当前：58% (7/12)
- **性能基准**：与 Go 版本对比 throughput/latency（SOCKS/Shadowsocks/VMess）
- **配置兼容性**：所有 Go 基础配置应能无修改导入 Rust

## 风险与缓解

### 技术风险
1. **适配器未启用导致静默回退**
   - 缓解：在运行时检测 registry 为空时直接报错，阻止静默回落
   - 已完成：stub builder 已添加警告日志

2. **IR 兼容性破坏现有配置**
   - 缓解：通过 `serde(default)` 与 schema 版本化保持向后兼容
   - 考虑：提供 `go_compat` feature 便于关闭新字段

3. **平台依赖（WireGuard/Tailscale/DHCP）**
   - 缓解：先提供 stub + build flag 提示，必要时引入可选 crate（boringtun/tailscale-core）并限定平台
   - 策略：对于平台相关功能，使用条件编译与友好错误信息

4. **QUIC 协议实现复杂度**
   - 缓解：优先迁移 Hysteria2/TUIC 现有 scaffold 实现，渐进式优化
   - 考虑：共享 QUIC 传输层代码，避免重复实现

### 流程风险
1. **测试覆盖不足导致回归**
   - 缓解：把 route/adapter/DNS parity 测试加入提交前脚本，在 CI 中强制执行
   - 目标：每个 PR 必须包含相关协议的测试

2. **Go ↔ Rust 差异未被发现**
   - 缓解：建立自动化 CLI diff 脚本，定期运行
   - 考虑：在 CI 中添加 Go/Rust 并行测试

3. **Feature gate 组合爆炸**
   - 缓解：定义核心 feature 组合（minimal/standard/full），在 CI 中测试
   - 文档：明确各 feature 的依赖关系

## 附录：锚点与参考

### Go 基线
- **主注册表**：`go_fork_source/sing-box-1.12.12/include/registry.go`
- **Inbound 注册**：`go_fork_source/sing-box-1.12.12/adapter/inbound/registry.go`
- **Outbound 注册**：`go_fork_source/sing-box-1.12.12/adapter/outbound/registry.go`
- **Endpoint 注册**：`go_fork_source/sing-box-1.12.12/adapter/endpoint/registry.go`
- **Service 注册**：`go_fork_source/sing-box-1.12.12/adapter/service/registry.go`
- **QUIC 实现**：`go_fork_source/sing-box-1.12.12/include/quic.go`
- **WireGuard 实现**：`go_fork_source/sing-box-1.12.12/include/wireguard.go`
- **Tailscale 实现**：`go_fork_source/sing-box-1.12.12/include/tailscale.go`

### Rust 核心文件
- **IR 定义**：`crates/sb-config/src/ir/mod.rs`
- **Bridge 桥接**：`crates/sb-core/src/adapter/bridge.rs`
- **Adapter 注册**：`crates/sb-core/src/adapter/registry.rs`
- **Adapter 实现**：
  - 入站：`crates/sb-adapters/src/inbound/*`
  - 出站：`crates/sb-adapters/src/outbound/*`
  - 注册逻辑：`crates/sb-adapters/src/register.rs`
- **DNS 子系统**：
  - 配置构建：`crates/sb-core/src/dns/config_builder.rs`
  - 传输实现：`crates/sb-core/src/dns/transport/*`
  - Resolver：`crates/sb-core/src/dns/resolver.rs`
- **服务模块**：`crates/sb-core/src/services/mod.rs`
- **运行时/监督**：
  - Supervisor：`crates/sb-core/src/runtime/supervisor.rs`
  - Switchboard：`crates/sb-core/src/runtime/switchboard.rs`
- **CLI 工具**：
  - 主入口：`app/src/main.rs`
  - 工具命令：`app/src/cli/tools.rs`
  - 路由命令：`app/src/cli/route.rs`
- **Bootstrap**：`app/src/bootstrap.rs` (adapter feature gate)

### 测试文件
- **路由对比**：`app/tests/route_parity.rs`
- **配置测试**：`app/tests/p0_upstream_compatibility.rs`
- **Adapter 测试**：`app/tests/adapter_*.rs`
- **集成测试**：`xtests/tests/*.rs`

### 文档与脚本
- **对比矩阵**：`GO_PARITY_MATRIX.md`（本文档的配套详细对比）
- **变更日志**：`CHANGELOG.md`
- **质量门槛**：`QUALITY_GATE.md`
- **CI 脚本**：`scripts/ci/*.sh`
- **E2E 脚本**：`scripts/e2e/*.sh`

## 版本历史
- **2025-11-10**：大幅更新，基于详细的 Go ↔ Rust 对比分析
  - 新增详细的协议对比矩阵（入站/出站/DNS/endpoint/service）
  - 更新工作流优先级，反映当前进展（41-42% 完成率）
  - 新增 Top 7 Tasks，明确近期行动路线
  - 完善风险缓解策略
- **2025-11-09**：初始版本，识别基础差距
- **Earlier**：项目启动，初步架构设计
