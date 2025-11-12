Parity Plan — Rust vs sing-box 1.12.12

Last audited: 2025-11-10 10:45 UTC

## 宗旨
- 以 Go 版 `sing-box 1.12.12` 为目标，补齐 **可配置、可运行、可观测** 的核心链路：CLI → 配置 IR → 运行时桥接 → 协议/传输 → DNS/服务/端点。
- 先满足用户面（常用入/出站、DNS 策略、工具命令），再向端点/服务与高级协议扩展。

## 差距快照（vs `go_fork_source/sing-box-1.12.12`）

### 协议适配器现状（已改善）
- ✅ **Adapter 注册扩展**：`sb_adapters::register_all()` 现已注册 12 种完整可用入站（http/socks/mixed/shadowsocks/vmess/vless/trojan/naive/tun/redirect/tproxy/direct）和 12 种完整可用出站（http/socks/shadowsocks/trojan/vmess/vless/dns/tuic/hysteria2 等），覆盖率达到 Go 协议清单的 71%（入站）和 63%（出站）
- ✅ **IR 枚举扩展**：`InboundType` 扩展到 17 种（含 Naive/ShadowTLS/AnyTLS/Hysteria/Hysteria2/TUIC），`OutboundType` 扩展到 19 种（新增 Dns/Tor/AnyTLS/Hysteria v1/WireGuard），与 Go 基本对齐
- ⚠ **实现缺口**：
  - **入站**：Naive 已完整实现；ShadowTLS/Hysteria/Hysteria2/TUIC/AnyTLS 仍为 stub (5种)
  - **出站**：Tor/AnyTLS/Hysteria v1/WireGuard 仅为 stub (4种)；SSH/ShadowTLS 走 scaffold 但不完整 (2种)
  - **实际可用率**：入站 12/17 (71%)，出站 12/19 (63%)

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
  3. ✅ 为 TUN/Redirect/TProxy 添加注册入口，连通实现文件与 adapter registry — 已完成 2025-11-10
  4. ✅ 设计并实现协议特定 IR 字段（密码/UUID/多账户/传输参数）— 已完成 2025-11-10
  5. ✅ **Direct 入站实现** — 已完成 2025-11-11
     - 添加 Direct 入站适配器实现（`crates/sb-adapters/src/inbound/direct.rs`）
     - 在 adapter registry 中注册 Direct 入站（`crates/sb-adapters/src/register.rs:118-121, 885-898`）
     - 添加 `network` 字段到 `InboundParam` 以支持 TCP/UDP 模式选择
     - 更新 `to_inbound_param` 函数传递 network 字段
     - 添加 4 个测试验证 Direct 入站功能（`app/tests/direct_inbound_test.rs`）
     - 入站协议覆盖率提升至 **65% (11/17)**
  6. ◐ 升级 stub 入站为完整实现：Naive → Hysteria2 → TUIC（按优先级）
     - ✅ **Naive 入站实现** — 已完成 2025-11-12
       - 添加 Naive 入站适配器实现（`crates/sb-adapters/src/inbound/naive.rs`）
       - 实现 HTTP/2 CONNECT + TLS + Basic 认证
       - 添加 TLS 相关字段到 `InboundParam`（cert/key path 和 PEM 支持）
       - 在 `app/Cargo.toml` 的 `adapters` 特性中添加 `adapter-naive`
       - 添加 `StandardTlsConfig` 的 inline PEM 支持（`cert_pem`/`key_pem`）
       - 添加测试验证 Naive 入站注册（`app/tests/naive_inbound_test.rs`）
       - 入站协议覆盖率提升至 **71% (12/17)**
     - ✅ **Hysteria2 入站实现** — 已完成 2025-11-12
       - 添加 Hysteria2 入站适配器实现（`crates/sb-adapters/src/inbound/hysteria2.rs`）
       - 实现 QUIC + congestion control (BBR/Brutal) + obfuscation + multi-user auth
       - 添加 Hysteria2 相关字段到 `InboundIR`（users_hysteria2, congestion_control, salamander, obfs, brutal_up/down_mbps）
       - 添加 Hysteria2 相关字段到 `InboundParam` 并更新 bridge.rs 转换逻辑
       - 定义 `Hysteria2UserIR` 类型（name + password）
       - 在 `app/Cargo.toml` 的 `adapters` 特性中添加 `adapter-hysteria2`
       - 实现 `InboundService` trait 支持 serve()/request_shutdown()/active_connections()
       - 替换 `register.rs` 中的 stub 实现为完整的构建器函数
       - 添加测试验证 Hysteria2 入站字段（`crates/sb-adapters/src/register.rs` tests）
       - 入站协议覆盖率提升至 **76% (13/17)**
     - [ ] **TUIC 入站实现**：QUIC + congestion control + UDP relay
- **现状**：枚举已对齐，13 种入站完整可用（含 Naive 和 Hysteria2），4 种为 stub
- **待办**：
  - [x] 为 Naive/ShadowTLS/AnyTLS 等入站注册 stub builder 并记录 fallback
  - [x] 在 `register.rs` 中添加 TUN/Redirect/TProxy 注册函数，连接到现有实现 — 已完成 2025-11-10
  - [x] 为 Direct 入站设计 IR schema 并提供最小实现 — 已完成 2025-11-11
  - [x] 设计 Inbound IR schema v2（含协议字段扩展）— 已完成 2025-11-10
  - [x] 将 Naive stub 升级为完整实现（HTTP/2 CONNECT + TLS）— 已完成 2025-11-12
  - [x] 将 Hysteria2 stub 升级为完整实现（QUIC + congestion control + obfs）— 已完成 2025-11-12
  - [ ] 将 TUIC stub 升级为完整实现（QUIC + congestion control + UDP relay）

### WS-B — Outbound Protocol Coverage（P0）
- **目标**：补齐 Go 列表中的 stub 出站（tor/anytls/wireguard/hysteria v1），并完善 scaffold 出站（SSH/ShadowTLS）。
- **触点**：`crates/sb-config/src/ir/mod.rs`、`crates/sb-core/src/adapter/bridge.rs`、`crates/sb-adapters/src/outbound/*`、`sb-transport`。
- **交付**：
  1. ✅ 扩展 `OutboundType` 枚举到 19 种，新增 Dns/Tor/AnyTLS/Hysteria v1/WireGuard（已完成）
  2. ✅ 为 Dns/Tor/AnyTLS/WireGuard/Hysteria v1 注册 stub builder（已完成）
  3. ✅ DNS outbound 完整实现，支持 UDP/TCP/DoT/DoH/DoQ（已完成，feature-gated）
  4. ✅ 完善 TUIC/Hysteria2 从 scaffold 到 adapter 的迁移 — 已完成 2025-11-10
  5. ✗ WireGuard outbound MVP：key 管理、UDP factory、Selector/metrics 集成
  6. ✗ Tor outbound：SOCKS5 over Tor daemon 桥接
- **现状**：枚举已扩展，10 种出站完整可用（含 TUIC/Hysteria2），4 种为 stub，5 种走 scaffold 但不完整
- **待办**：
  - [x] 在 adapter registry 注册 dns/tor/anytls/wireguard/hysteria stub builder
  - [x] 完整实现 DNS outbound（支持多传输）
  - [x] 迁移 TUIC/Hysteria2 从 scaffold 到 adapter，提供 UDP factory — 已完成 2025-11-10
  - [ ] 补齐 SSH outbound 的 host-key 校验与认证
  - [ ] 实现 WireGuard outbound MVP（依赖 boringtun 或内核接口）
  - [ ] 实现 Tor outbound（SOCKS5 over Tor daemon）
  - [ ] 在 Selector/URLTest 中处理新协议的错误/健康逻辑

### WS-C — DNS / Resolver / Transport Parity（P0）
- **目标**：支持 Go 端 HTTP3 DoH、DHCP、tailscale、resolved 传输，并统一 env/IR 双轨。
- **触点**：`app/src/bin/run.rs`、`crates/sb-core/src/dns/*`、`crates/sb-config/src/ir/mod.rs`、`crates/sb-core/src/services/*`。
- **交付**：
  1. ✅ 实现基础 DNS 传输：system/UDP/DoH/DoT/DoQ + hosts/fakeip overlay（已完成）
  2. ✅ 实现 HTTP3 over QUIC (DoH3) 传输，支持 doh3:// 和 h3:// URL — 已完成 2025-11-10
  3. ✗ 扩展 `DnsServerIR`，允许描述 DHCP/tailscale/resolved 传输类型
  4. ✗ `resolver_from_ir` 与 `dns::transport` 新增 DHCP、tailscale、resolved 实现
  5. ✗ `resolved` service stub，与 DNS transport 对齐
- **现状**：67% 覆盖率 (8/12 传输)，已完成 HTTP3，缺少 4 种高级传输
- **待办**：
  - [x] 追加 HTTP3 over QUIC client（h3 crate + DoH over HTTP/3）— 已完成 2025-11-10
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

基于当前进展（入站 59% 完成，出站 42% 完成，DNS 58% 完成），按紧迫性排序：

1. ✅ **连通 TUN/Redirect/TProxy 注册路径**（WS-A，关键阻塞）— 已完成 2025-11-10
   - ✅ 在 `sb-adapters/src/register.rs` 中添加注册函数，连接到已有实现文件
   - ✅ TUN/Redirect/TProxy 已完整注册并集成到 adapter registry
   - 优先级：**P0**，影响：解锁 3 种核心入站 → **完成**

2. ✅ **迁移 TUIC/Hysteria2 到 adapter**（WS-B，用户高频）— 已完成 2025-11-10
   - ✅ TUIC/Hysteria2 outbound 已从 scaffold 迁移到 adapter registry
   - ✅ 提供完整的 UDP factory 与 QUIC congestion control
   - 优先级：**P0**，影响：解锁 2 种高频出站 → **完成**
   - 注：inbound 升级属于 WS-A Task 5 范畴

3. ✅ **扩展 Inbound IR v2 字段**（WS-A，基础设施）— 已完成 2025-11-10
   - ✅ 设计协议特定字段（password/uuid/users/transport）
   - ✅ 支持多账户配置（Shadowsocks/VMess/VLESS）
   - ✅ 添加传输层配置（ws/h2/grpc）与 TLS 选项
   - ✅ 添加 Multiplex 支持
   - 优先级：**P0**，影响：使现有协议可完整配置

4. ✅ **实现 DNS HTTP3 传输**（WS-C，部分用户需求）— 已完成 2025-11-10
   - ✅ 使用 h3 0.0.8 和 h3-quinn 0.0.10 crate 实现 DoH over HTTP/3
   - ✅ 添加 QUIC 传输层复用与连接池
   - ✅ 支持 doh3:// 和 h3:// URL schemes
   - ✅ 更新 http crate 到 v1.3 以兼容 h3
   - 优先级：**P1**，影响：DNS 覆盖率 → 67% (8/12)

5. ✅ **添加 adapter 路径测试**（WS-E，质量保障）— 已完成 2025-11-11
   - ✅ 完成测试覆盖审计（97个集成测试分析）
   - ✅ 创建 Go ↔ Rust 对比脚本（route explain, geodata）
   - ✅ 添加 CI parity 验证工作流
   - ✅ 文档化架构问题（ADAPTER_ARCHITECTURE_ISSUES.md）
   - ✅ 修复 VMess/VLESS adapter 注册编译错误
   - ✅ 修复 feature gate 不匹配问题（sb-adapters 与 sb-core 特性对齐）
   - ✅ Adapter 实例化测试（所有6个测试通过）
   - ✅ 修复 HTTP/SOCKS outbound trait 架构不匹配（2025-11-11 深夜）
   - ✅ DNS outbound e2e 测试（11个测试全部通过，2025-11-11）
   - ✅ 热重载 adapter 路径测试框架（2025-11-11）
   - ✅ 修复 TUIC tls_alpn 类型不匹配问题（2025-11-11）
   - ⚠ Feature gate 组合矩阵（待实现，P2优先级）
   - 优先级：**P0** → **完成** （90%，仅剩 feature gate 矩阵为 P2）
   - 影响：验证 HTTP/SOCKS/TUIC/Hysteria2/VMess/VLESS/Shadowsocks/Trojan/DNS adapter 实例化正确性
   - 详见：WS_E_TASK_5_REPORT.md, ADAPTER_ARCHITECTURE_ISSUES.md
   - 新增文件：
     - `app/tests/dns_outbound_e2e.rs` - DNS outbound 完整测试套件
     - `app/tests/reload_adapter_path.rs` - 热重载 adapter 测试框架
   - 完成于：2025-11-11

5.5. ✅ **扩展 OutboundIR v2 字段**（WS-A/B，解除 Task 5 阻塞）— 已完成 2025-11-11
   - ✅ 添加 VMess 特定字段：security, alter_id
   - ✅ 添加 VLESS 特定字段：encryption
   - ✅ Shadowsocks plugin, plugin_opts 字段已存在
   - ✅ Trojan tls_ca_paths, tls_ca_pem 字段已存在
   - ✅ HeaderEntry 字段可访问性已解决（key, value 公开）
   - ✅ tls_alpn 类型已完全标准化（Vec<String>）— 2025-11-11 深度修复
   - ✅ 更新 TuicConfig.alpn 为 Vec<String>，修复所有类型不匹配
   - ✅ 修复 bridge.rs/mod.rs/switchboard.rs 中的 tls_alpn 转换逻辑
   - 优先级：**P0** → **完成**
   - ETA：1-2 天 → 完成于 2025-11-11
   - 影响：解锁 VMess/VLESS/Shadowsocks/Trojan/TUIC adapter 实例化，解除 Task 5 阻塞
   - 详见：crates/sb-config/src/ir/mod.rs, crates/sb-core/src/outbound/tuic.rs, crates/sb-core/src/adapter/bridge.rs

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
  - 入站目标：90% (15/17)，**当前：59% (10/17)** - 2025-11-11 更新
  - 出站目标：95% (18/19)，**当前：63% (12/19)** - 2025-11-11 深夜更新（含 HTTP/SOCKS）
  - DNS 目标：75% (9/12)，**当前：67% (8/12)** - 2025-11-11 更新
  - 注：当前数据基于实际可工作的 adapter，不包括 stub 或因 IR 不完整无法实例化的 adapter
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
- **2025-11-12**：完成 Naive 入站实现（WS-A Task 6 部分完成）
  - ✅ 新增 Naive 入站适配器（`crates/sb-adapters/src/inbound/naive.rs`）
  - ✅ 实现 HTTP/2 CONNECT 代理 + TLS 握手 + Basic 认证
  - ✅ 在 adapter registry 中注册 Naive 入站（`register.rs:840-853`）
  - ✅ 扩展 `InboundParam` 添加 TLS 配置字段（`tls_cert_path`, `tls_key_path`, `tls_cert_pem`, `tls_key_pem`, `tls_server_name`, `tls_alpn`）
  - ✅ 扩展 `StandardTlsConfig` 添加 inline PEM 支持（`cert_pem`/`key_pem`）
  - ✅ 更新 `to_inbound_param` 函数传递 TLS 配置
  - ✅ 在 `app/Cargo.toml` 的 `adapters` 特性中添加 `sb-adapters/adapter-naive`
  - ✅ 添加 2 个测试验证 Naive 入站注册（`app/tests/naive_inbound_test.rs`）
  - 入站协议覆盖率提升至 **71% (12/17)**，新增 1 种完整可用入站
  - 详见：`crates/sb-adapters/src/inbound/naive.rs`, `crates/sb-core/src/adapter/mod.rs`, `crates/sb-transport/src/tls.rs`
- **2025-11-11 (晚)**：完成 Direct 入站实现（WS-A Task 4 完成）
  - ✅ 新增 Direct 入站适配器（`crates/sb-adapters/src/inbound/direct.rs`）
  - ✅ 在 adapter registry 中注册 Direct 入站（`register.rs:118-121, 885-898`）
  - ✅ 添加 `network` 字段到 `InboundParam` 以支持 TCP/UDP 模式选择
  - ✅ 更新 bridge.rs 的 `to_inbound_param` 传递 network 字段
  - ✅ 添加 4 个测试验证 Direct 入站功能（实例化、错误验证、网络模式）
  - 入站协议覆盖率提升至 **65% (11/17)**，新增 1 种完整可用入站
  - 详见：`app/tests/direct_inbound_test.rs`, `crates/sb-adapters/src/inbound/direct.rs`
- **2025-11-11 (下午)**：完成 WS-E Task 5 剩余子任务 + TUIC tls_alpn 深度修复
  - ✅ 添加 DNS outbound e2e 测试套件（11个测试全部通过）
  - ✅ 创建热重载 adapter 路径测试框架
  - ✅ **发现并修复 TUIC tls_alpn 类型不匹配问题**：
    - 将 `TuicConfig::alpn` 从 `Option<String>` 改为 `Option<Vec<String>>`
    - 移除 bridge.rs/mod.rs/switchboard.rs 中的字符串分割逻辑
    - 修复 tuic.rs 中的 ALPN 处理，正确将 Vec<String> 转换为 Vec<Vec<u8>>
    - 解决了 admin_debug feature 下的编译错误
  - Task 5 标记为 **完成**（90%，仅剩 feature gate 矩阵为 P2）
  - 新增文件：`app/tests/dns_outbound_e2e.rs`, `app/tests/reload_adapter_path.rs`
  - 详见：crates/sb-core/src/outbound/tuic.rs, crates/sb-core/src/adapter/bridge.rs
- **2025-11-11 (深夜晚)**：完成 HTTP/SOCKS outbound trait 架构修复
  - 修复 HTTP/SOCKS outbound trait 架构不匹配问题
  - 创建 HttpConnectorWrapper 和 Socks5ConnectorWrapper 适配器
  - 正确处理 sb_config::outbound config 结构（server: String host:port 格式）
  - 使用 ir.credentials 替代不存在的 username/password 字段
  - 所有 6 个 adapter 实例化测试通过
  - 出站协议覆盖率提升至 63% (12/19)，新增 HTTP/SOCKS 支持
  - 详见：crates/sb-adapters/src/register.rs:134-282, ADAPTER_ARCHITECTURE_ISSUES.md
- **2025-11-11 (深夜)**：完成 Task 5（Adapter 路径测试）
  - 修复 feature gate 不匹配：sb-adapters 与 sb-core 特性对齐
  - 更新 `crates/sb-adapters/src/register.rs`：添加 `out_ss`, `out_trojan`, `out_vmess`, `out_vless` feature 依赖
  - 更新 `crates/sb-adapters/Cargo.toml`：adapter-* features 现在启用对应的 sb-core features
  - 修复 adapter 实例化测试：所有 6 个测试通过
  - 文档化 HTTP/SOCKS trait 架构不匹配问题（已知问题）
  - Task 5 标记为基本完成，剩余子任务：feature gate 矩阵、DNS e2e、热重载测试
  - 详见：crates/sb-adapters/src/register.rs:184-523, crates/sb-adapters/Cargo.toml:127-130
- **2025-11-11 (晚)**：完成 Task 5.5（OutboundIR v2 扩展）
  - 添加 VMess security/alter_id、VLESS encryption 字段到 OutboundIR
  - 修复 bridge.rs 中 tls_alpn Vec<String> 到 String 的类型转换
  - 验证 Shadowsocks/Trojan 字段已存在，HeaderEntry 字段已公开
  - 解除 WS-E Task 5 阻塞，adapter 实例化测试现可进行
  - 详见：crates/sb-config/src/ir/mod.rs, crates/sb-core/src/adapter/bridge.rs
- **2025-11-11**：Task 5 (WS-E) 进展更新与架构问题发现
  - 完成 WS-E Task 5（adapter 路径测试）的 60%，发现架构阻塞问题
  - 新增 Task 5.5（OutboundIR v2 扩展）作为 P0 解除阻塞任务
  - 创建 Go ↔ Rust 自动对比脚本（route_explain_parity.sh, geodata_parity.sh）
  - 添加 CI parity 验证工作流（parity-tests.yml）
  - 文档化 5 类架构问题（ADAPTER_ARCHITECTURE_ISSUES.md）
  - 修复 adapter 注册编译错误（VMess/VLESS 字段不匹配）
  - 更新协议覆盖率：入站 59%，出站 53%，DNS 67%
  - 详见：WS_E_TASK_5_REPORT.md
- **2025-11-10**：大幅更新，基于详细的 Go ↔ Rust 对比分析
  - 新增详细的协议对比矩阵（入站/出站/DNS/endpoint/service）
  - 更新工作流优先级，反映当前进展（41-42% 完成率）
  - 新增 Top 7 Tasks，明确近期行动路线
  - 完善风险缓解策略
- **2025-11-09**：初始版本，识别基础差距
- **Earlier**：项目启动，初步架构设计
