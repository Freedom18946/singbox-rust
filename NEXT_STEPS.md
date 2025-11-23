Parity Plan — Rust vs sing-box 1.12.12

Last audited: 2025-11-10 10:45 UTC

## 宗旨
- 以 Go 版 `sing-box 1.12.12` 为目标，补齐 **可配置、可运行、可观测** 的核心链路：CLI → 配置 IR → 运行时桥接 → 协议/传输 → DNS/服务/端点。
- 先满足用户面（常用入/出站、DNS 策略、工具命令），再向端点/服务与高级协议扩展。

## 差距快照（vs `go_fork_source/sing-box-1.12.12`）

### 协议适配器现状（已改善）
- ✅ **Adapter 注册完备**：`sb_adapters::register_all()` 现注册 17 种入站 / 19 种出站（含 AnyTLS/Hysteria v1&2/TUIC/WireGuard/Tor/Direct/Block），覆盖率 **100%/100%**
- ✅ **IR 枚举对齐**：`InboundType` 17 种、`OutboundType` 19 种，与 Go 1.12.12 对齐；协议特定字段已补齐
- ✅ **Selector/URLTest 适配器化**：已完整注册到 adapter registry（`sb-adapters/src/register.rs:77-80`），支持动态成员解析、健康探测与多种负载均衡策略 — 已完成 2025-11-22

### 端点与服务（部分完成）
- ✅ **IR + Registry + 运行时接入**：顶层 `endpoints`/`services` 字段已加入 IR；Bridge 会构建并挂载，Supervisor 在启动/热重载/关停时按生命周期阶段启动/关闭
- ✅ **WireGuard Endpoint**：userspace MVP（boringtun + tun），feature `adapter-wireguard-endpoint`；Tailscale endpoint 仍为 stub
- ◐ **Services**: Resolved implemented (Linux D-Bus, feature-gated `service_resolved`); **DERP complete** (完整 DERP 协议 + client registry + **mesh networking** + **TLS** + **PSK auth** + **rate limiting** + **metrics** + STUN + HTTP 健康 + TCP mock relay); SSM implemented (HTTP API, `service_ssmapi`)

### DNS 传输（部分支持）
- ✅ **已支持**：system/UDP/DoH/DoT/DoQ/DoH3 + hosts/fakeip overlay (8/12)
- ◐ **部分支持**：DHCP/resolved/tailscale 通过 resolv.conf 或显式地址解析（无本地 daemon 集成）
- ✅ **完整**：local (LocalUpstream + LocalTransport)
- 覆盖率：**67% 完整 + 25% 部分**

### 关键架构问题（最新）
1. **DERP 生产特性缺失**：DERP 协议已完整实现（frame-based relay + client registry + peer presence），并支持 rustls TLS 终止（derp_tls_cert_path/key_path）+ HTTP/DERP 复用同端口；仍缺生产特性：mesh networking (服务器联邦)、高级认证 (beyond PSK)、速率限制与监控指标
2. **平台依赖**：WireGuard/Tailscale 依赖外部接口或未来 tailscale-go 集成；DNS DHCP/resolved 依赖主机配置
3. **测试覆盖**：Selector/URLTest 需补充更完整的契约测试与观测集成 (✅ Completed 2025-11-22)
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
     - ✅ **TUIC 入站实现** — 已完成 2025-11-12
       - 复用现有 TUIC 服务器实现（`crates/sb-adapters/src/inbound/tuic.rs`）
       - 实现 QUIC + congestion control (BBR/Cubic/NewReno) + UUID/token auth + UDP relay
       - 添加 `TuicUserIR` 类型（uuid + token）到 IR schema
       - 添加 `users_tuic` 字段到 `InboundIR` 和 `InboundParam`
       - 更新 bridge.rs 的 `to_inbound_param` 传递 TUIC 用户配置
       - 创建 `TuicInboundAdapter` 实现 `InboundService` trait
       - 在 `register.rs` 中替换 stub 为完整构建器函数（`build_tuic_inbound`）
       - 在 `app/Cargo.toml` 的 `adapters` 特性中添加 `sb-adapters/adapter-tuic`
       - 在 `sb-adapters/Cargo.toml` 添加 `rustls-pemfile` 依赖到 `tuic` feature
       - 添加 4 个测试验证 TUIC 入站功能（`app/tests/tuic_inbound_test.rs`）
       - 入站协议覆盖率提升至 **82% (14/17)**
     - ✅ **ShadowTLS 入站实现** — 已完成 2025-11-12
       - 利用现有 ShadowTLS 实现（`crates/sb-adapters/src/inbound/shadowtls.rs`，232行完整代码）
       - 实现 TLS masquerading + Standard TLS/REALITY/ECH 支持
       - 创建 `ShadowTlsInboundAdapter` wrapper 实现 `InboundService` trait
       - 在 `register.rs` 中添加完整构建器函数（`build_shadowtls_inbound`）
       - 修复 parking_lot::Mutex 迁移问题（20个实例，所有 adapter）
       - 修复 ALPN 类型转换（String ↔ Vec<String>）在 shadowtls.rs, tuic.rs, mod.rs
       - 修复模块路径解析（`sb_adapters::` → `crate::`）
       - 在 `sb-adapters/Cargo.toml` 已有 `adapter-shadowtls` feature（含 sb-transport/transport_tls）
       - 成功编译验证（16.23s，dev profile）
       - 入站协议覆盖率提升至 **88% (15/17)** - 达到 90% 目标
- **现状**：枚举已对齐，17 种入站完整可用（含 Naive、Hysteria2、TUIC、ShadowTLS、AnyTLS），0 种 stub
- **待办**：
  - [x] 为 Naive/ShadowTLS/AnyTLS 等入站注册 stub builder 并记录 fallback
  - [x] 在 `register.rs` 中添加 TUN/Redirect/TProxy 注册函数，连接到现有实现 — 已完成 2025-11-10
  - [x] 为 Direct 入站设计 IR schema 并提供最小实现 — 已完成 2025-11-11
  - [x] 设计 Inbound IR schema v2（含协议字段扩展）— 已完成 2025-11-10
  - [x] 将 Naive stub 升级为完整实现（HTTP/2 CONNECT + TLS）— 已完成 2025-11-12
  - [x] 将 Hysteria2 stub 升级为完整实现（QUIC + congestion control + obfs）— 已完成 2025-11-12
  - [x] 将 AnyTLS stub 升级为完整实现（需引入 `anytls` crate 或类似实现）— 已完成 2025-11-15
    - 使用 `anytls-rs` 0.5.4 作为核心实现，提供包含 TLS 握手 + 多用户认证 + padding scheme 的完整服务
    - 新增 `users_anytls`、`anytls_padding` IR 字段，并将 `AnyTLS` 入站接入 `InboundParam` → `sb-adapters` 桥接链路
    - 服务器采用 `tokio-rustls` 读取证书/私钥（支持文件或 inline PEM），并复用 Router 规则/Selector 逻辑进行出站路由
    - 每个 stream 复用 anytls SYNACK 语义，连接失败时返回具体错误信息；转发路径使用 copy-bidi + metrics 钩子
    - `adapter_instantiation_e2e` 与 registry smoke 测试更新后，AnyTLS 不再属于 stub 列表，入站覆盖率提升至 100% (17/17)
  - [x] 将 TUIC stub 升级为完整实现（QUIC + congestion control + UDP relay）— 已完成 2025-11-12

### WS-B — Outbound Protocol Coverage（P0）
- **目标**：补齐 Go 列表中的 stub 出站（tor/anytls/wireguard/hysteria v1）。
- **触点**：`crates/sb-config/src/ir/mod.rs`、`crates/sb-core/src/adapter/bridge.rs`、`crates/sb-adapters/src/outbound/*`、`sb-transport`。
- **交付**：
  1. ✅ 扩展 `OutboundType` 枚举到 19 种，新增 Dns/Tor/AnyTLS/Hysteria v1/WireGuard（已完成）
  2. ✅ 为 Dns/Tor/AnyTLS/WireGuard/Hysteria v1 注册 stub builder（已完成）
  3. ✅ DNS outbound 完整实现，支持 UDP/TCP/DoT/DoH/DoQ（已完成，feature-gated）
  4. ✅ 完善 TUIC/Hysteria2 从 scaffold 到 adapter 的迁移 — 已完成 2025-11-10
  5. ✅ SSH outbound 完整实现，支持密码/公钥认证、host-key 校验 — 已完成 2025-11-12（41个测试全部通过）
  6. ✅ **ShadowTLS outbound 完整实现** — 已完成 2025-11-12
     - 添加 ShadowTLS outbound 适配器注册（`crates/sb-adapters/src/register.rs:1230-1309`）
     - 创建 `ShadowTlsConnectorWrapper` 实现 `OutboundConnector` trait
     - 支持 TLS SNI/ALPN 配置、证书验证选项
     - 在 `register_all()` 中注册 ShadowTLS outbound（line 67）
     - 添加测试验证 ShadowTLS outbound 注册（`test_shadowtls_outbound_registration`）
     - 出站协议覆盖率提升至 **74% (14/19)**
  7. ✅ **Direct outbound 完整实现** — 已完成 2025-11-12
     - 添加 Direct outbound 适配器（`crates/sb-adapters/src/register.rs:1198-1238`）
     - 创建 `DirectConnectorWrapper` 实现 `OutboundConnector` trait
     - 支持直接连接到目标地址（IP 或域名）
     - 在 `register_all()` 中注册 Direct outbound（line 43）
     - 添加 4 个测试验证 Direct outbound 功能（`app/tests/direct_block_outbound_test.rs`）
     - 出站协议覆盖率提升至 **79% (15/19)**
  8. ✅ **Block outbound 完整实现** — 已完成 2025-11-12
     - 添加 Block outbound 适配器（`crates/sb-adapters/src/register.rs:1240-1289`）
     - 创建 `BlockConnectorWrapper` 实现 `OutboundConnector` trait
     - 所有连接请求返回错误（阻断功能）
     - 在 `register_all()` 中注册 Block outbound（line 46）
     - 添加 4 个测试验证 Block outbound 功能（`app/tests/direct_block_outbound_test.rs`）
     - 出站协议覆盖率提升至 **84% (16/19)** - ✅ **向 95% 目标前进 10%**
  9. ✅ **WireGuard outbound MVP** — 已完成 2025-11-15
     - `WireGuardOutbound` 绑定系统接口（Linux/Android 通过 `SO_BINDTODEVICE`，其它平台友好降级），使用 `SB_WIREGUARD_INTERFACE`/`SB_WIREGUARD_SOURCE_*` 环境变量确定接口与源地址
     - `WireGuardConfig::from_ir()` 统一解析 IR + env，提供 TCP keepalive/timeout（`SB_WIREGUARD_TCP_KEEPALIVE_SECS`、`SB_WIREGUARD_CONNECT_TIMEOUT_MS`）并沿用已有 key/env（`SB_WIREGUARD_*KEY`、`SB_WIREGUARD_ALLOWED_IPS` 等）
     - 新增 `WireGuardUdpSession` 提供 IPv4 UDP factory，URLTest/Selector 可探测 WireGuard 出站；TCP/UDP 路径都计入 `wireguard_connect_total{result=`ok|timeout|error`}`
  10. ✅ **Tor outbound 完整实现** — 已完成 2025-11-12
     - 添加 Tor outbound 适配器注册（`crates/sb-adapters/src/register.rs:1297-1361`）
     - 实现为 SOCKS5 代理到 Tor daemon（默认：127.0.0.1:9050）
     - 支持自定义 Tor 代理地址（`tor_proxy_addr` 字段）
     - 添加 Tor-specific 配置字段到 OutboundIR（`tor_proxy_addr`, `tor_executable_path`, `tor_extra_args`, `tor_data_directory`, `tor_options`）
     - 在 `register_all()` 中注册 Tor outbound（line 52）
     - 添加 4 个测试验证 Tor outbound 功能（`app/tests/tor_outbound_test.rs`）
     - 出站协议覆盖率提升至 **89% (17/19)** - ✅ **向 95% 目标前进 5%**
  11. ✅ **Hysteria v1 outbound 完整实现** — 已完成 2025-11-12
     - 添加 Hysteria v1-specific IR 字段（`hysteria_protocol`, `hysteria_auth`, `hysteria_recv_window_conn`, `hysteria_recv_window`）
     - 复用现有 Hysteria v1 实现（`crates/sb-core/src/outbound/hysteria/v1.rs`，605行完整代码）
     - 添加 Hysteria v1 outbound 适配器注册（`crates/sb-adapters/src/register.rs:1375-1466`）
     - 创建 `HysteriaConnectorWrapper` 实现 `OutboundConnector` trait
     - 支持 QUIC + 自定义协议类型（udp/wechat-video/faketcp）+ 拥塞控制 + obfs
     - 在 `app/Cargo.toml` 的 `adapters` 特性中添加 `adapter-hysteria`
     - 在 `register_all()` 中注册 Hysteria v1 outbound（line 61）
     - 添加 6 个测试验证 Hysteria v1 outbound 功能（`app/tests/hysteria_outbound_test.rs`）
     - 出站协议覆盖率提升至 **95% (18/19)** - ✅ **达到 95% 覆盖率目标！**
  12. ✅ **AnyTLS outbound 完整实现** — 已完成 2025-11-19
     - 完整实现 AnyTLS outbound 适配器（`crates/sb-adapters/src/outbound/anytls.rs`，430行完整代码）
     - 实现 TLS + AnyTLS 协议握手 + 密码认证 + 自定义 padding scheme
     - 支持多路复用 session 管理，自动重连与后台任务处理
     - 支持 TLS SNI/ALPN 配置、自定义 CA 证书、跳过证书验证
     - 实现 SOCKS5 风格目标地址编码与 TCP stream 桥接
     - 在 `app/Cargo.toml` 的 `adapters` 特性中添加 `sb-adapters/adapter-anytls`
     - 在 `register_all()` 中启用 AnyTLS outbound（line 55）
     - 添加 6 个测试验证 AnyTLS outbound 功能（`app/tests/anytls_outbound_test.rs`）
     - 出站协议覆盖率提升至 **100% (19/19)** - ✅ **达到 100% 出站覆盖率！**
- **现状**：架构已扩展，19 种出站全部完整实现（含 TUIC/Hysteria/Hysteria2/SSH/ShadowTLS/Direct/Block/Tor/AnyTLS/WireGuard），selector/urltest 已完整 adapter 化，支持 UDP factory
- **待办**：
  - [x] 在 adapter registry 注册 dns/tor/anytls/wireguard/hysteria stub builder
  - [x] 完整实现 DNS outbound（支持多传输）
  - [x] 迁移 TUIC/Hysteria2 从 scaffold 到 adapter，提供 UDP factory — 已完成 2025-11-10
  - [x] 补齐 SSH outbound 的 host-key 校验与认证 — 已完成 2025-11-12（41个测试全部通过）
  - [x] 完整实现 ShadowTLS outbound（TLS SNI/ALPN + adapter wrapper）— 已完成 2025-11-12
  - [x] 完整实现 Direct outbound（直连功能）— 已完成 2025-11-12
  - [x] 完整实现 Block outbound（阻断功能）— 已完成 2025-11-12
  - [x] 完整实现 Tor outbound（SOCKS5 over Tor daemon）— 已完成 2025-11-12
  - [x] 完整实现 Hysteria v1 outbound（QUIC + 拥塞控制 + obfs）— 已完成 2025-11-12
  - [x] 完整实现 AnyTLS outbound（TLS + AnyTLS 协议 + session multiplexing）— 已完成 2025-11-19
  - [x] 实现 WireGuard outbound MVP（系统接口绑定版）
    - ✅ `WireGuardConfig::from_ir` 统一解析 IR + 环境变量，要求 `SB_WIREGUARD_INTERFACE`，可选 `SB_WIREGUARD_SOURCE_V4/SB_WIREGUARD_SOURCE_V6`、`SB_WIREGUARD_CONNECT_TIMEOUT_MS`、`SB_WIREGUARD_TCP_KEEPALIVE_SECS`
    - ✅ `WireGuardOutbound` 通过 `SO_BINDTODEVICE`（Linux/Android）或友好降级绑定系统接口，TCP/UDP 都可经由现有 WireGuard 接口发送；未配置接口时立即报错（避免静默直连）
    - ✅ Adapter 层新增 `adapter-wireguard`，`app` `adapters` feature 默认启用，CLI/Go parity 流程均可注册 WireGuard 出站
  - [x] 在 Selector/URLTest 中处理新协议的错误/健康逻辑
    - ✅ 为 `SelectorGroup` 增加永久失败状态：当出站报告 `io::ErrorKind::Unsupported`（例如 WireGuard stub、UDP-only 协议）时，成员会被标记为不可用，并从健康检查/选择逻辑中剔除（`crates/sb-core/src/outbound/selector_group.rs`）
    - ✅ URLTest 健康检查现在跳过已标记的成员，并输出明确日志，避免重复告警；所有选择策略（latency/round-robin/random/least-connections）只返回仍可用的成员
    - ✅ 新增单测验证 `ProxyHealth` 永久失败行为（`crates/sb-core/src/outbound/selector_group_tests.rs`）

### WS-C — DNS / Resolver / Transport Parity（P0）
- **目标**：支持 Go 端 HTTP3 DoH、DHCP、tailscale、resolved 传输，并统一 env/IR 双轨。
- **触点**：`app/src/bin/run.rs`、`crates/sb-core/src/dns/*`、`crates/sb-config/src/ir/mod.rs`、`crates/sb-core/src/services/*`。
- **交付**：
  1. ✅ 实现基础 DNS 传输：system/UDP/DoH/DoT/DoQ + hosts/fakeip overlay（已完成）
  2. ✅ 实现 HTTP3 over QUIC (DoH3) 传输，支持 doh3:// 和 h3:// URL — 已完成 2025-11-10
  3. ✅ 扩展 `DnsServerIR`，允许描述 DHCP/tailscale/resolved 传输类型（address 支持 dhcp:// / tailscale:// / resolved://，目前回退到 system 上游并给出警告）
  4. ✅ `resolver_from_ir` 与 `dns::transport` 新增 DHCP、tailscale、resolved 实现（解析 resolv.conf/systemd-resolved stub 或显式地址；不可用时优雅回退并提示）
  5. ✅ `resolved` service stub，与 DNS transport 对齐（`sb-adapters/src/service_stubs.rs`，已在 endpoint/service registry 中注册）
- **现状**：75% 传输完全实现 (9/12: udp/dot/doq/doh/doh3/system/local/enhanced_udp/tcp)，另外 3 种（DHCP/resolved/tailscale）通过文件/显式地址实现部分能力
- **待办**：
  - [x] 追加 HTTP3 over QUIC client（h3 crate + DoH over HTTP/3）— 已完成 2025-11-10
  - [x] DHCP client 集成（平台相关，需条件编译）
    - ✅ 新增 `DhcpUpstream`：从 `/etc/resolv.conf`（或 `SB_DNS_DHCP_RESOLV_CONF`、`dhcp://?resolv=` 指定路径）解析 DHCP 下发的 nameserver，构建原生 UDP 上游并周期性刷新（`crates/sb-core/src/dns/upstream.rs`）
    - ✅ `dhcp://iface` 地址现在映射到独立 upstream，可在 `DnsIR.servers` 中直接引用；默认情况下回退到系统 resolver，当解析失败或平台不支持时会记录降级日志
    - ✅ 新增单元测试覆盖 spec 解析与 resolv.conf 解析逻辑，并在 `cargo test dhcp --package sb-core --lib` 中验证
  - [x] tailscale/Resolved 桥接（需外部服务依赖或 stub）
    - ✅ resolved：新增 `ResolvedUpstream`，解析 systemd-resolved stub (`/run/systemd/resolve/*.conf` 或 `SB_DNS_RESOLVED_STUB`) 并将 nameserver 映射为 UDP upstream（`crates/sb-core/src/dns/upstream.rs`）
    - ✅ tailscale：新增 `tailscale://` upstream 解析器，可从地址参数或 `SB_TAILSCALE_DNS_ADDRS` 环境变量生成 round-robin UDP upstream，提供明确报错与日志（`crates/sb-core/src/dns/upstream.rs`, `config_builder.rs`）
  - [x] 设计 env ↔ IR 映射流程，避免双重 source of truth
    - ✅ `hydrate_dns_ir_from_env` 会在构建 resolver 前克隆 `DnsIR`，将 `SB_DNS_*` 环境变量反映回 IR 字段，再由 `apply_env_from_ir` 推送到运行时；此举保证 CLI/diagnostic 能展示真实运行参数（`crates/sb-core/src/dns/config_builder.rs`，含单元测试）
  - [x] 为新传输类型添加 feature gate 与友好错误信息
    - ✅ 在 `crates/sb-core/Cargo.toml` 新增 `dns_dhcp`/`dns_resolved`/`dns_tailscale` 特性，并默认开启，便于按需裁剪
    - ✅ `dns::config_builder` 在解析 `dhcp://`/`resolved://`/`tailscale://` 上游时会检查对应特性，缺失时返回指向 `--features sb-core/<feature>` 的错误提示

### WS-D — Endpoints & Services（P1）
- **目标**：为 WireGuard/Tailscale endpoint 与 Resolved/DERP/SSM 服务提供 IR、构造与最小实现/Stub。
- **触点**：`sb-config`（新增 `endpoints`/`services`）、`crates/sb-core/src/services/*`、`go_fork_source/sing-box-1.12.12/include/*`。
- **交付**：
  1. ✅ 引入 endpoint/service IR 顶层字段，含 tag/feature gate/平台要求
  2. ✅ 提供 WireGuard/Tailscale endpoint stub（缺依赖时报错提示构建选项）
  3. ✅ Resolved/DERP service: stub; SSM service: complete HTTP API
  4. ✅ Bridge/Supervisor 生命周期接入：bridge 构建 endpoints/services，supervisor 在启动/热重载/关闭时按阶段启动/停止（2025-11-21）
- **现状**：IR + registry + 运行时生命周期全部连通；WireGuard userspace endpoint 完整实现（feature gate），Tailscale endpoint/stub services 未落地真实实现
- **待办**：
  - [x] 在 `crates/sb-config/src/ir/mod.rs` 添加 `endpoints: Vec<EndpointIR>`、`services: Vec<ServiceIR>` 字段 — 已完成 2025-11-13
  - [x] 设计 `EndpointIR` schema（type/tag/options），支持 wireguard/tailscale — 已完成 2025-11-13
  - [x] 设计 `ServiceIR` schema（type/tag/options），支持 resolved/derp/ssm — 已完成 2025-11-13
  - [x] 在 `crates/sb-core` 添加 endpoint/service registry 框架 — 已完成 2025-11-13
  - [x] 为 WireGuard/Tailscale endpoint 提供 stub builder — 已完成 2025-11-13
  - [x] 为 Resolved/DERP 提供 stub; SSM 已完整实现 (HTTP API) — 已完成 2025-11-13/21
  - [x] 添加 feature gate：with_wireguard, with_tailscale, with_resolved, with_derp — 已完成 2025-11-13

### WS-E — CLI / Tests / Tooling（P1）
- **目标**：CLI 与 Go 工具对齐，并建立自动化对比/健康检测。
- **触点**：`app/src/bin/*`、`app/src/cli/*`、`app/tests/*`、`scripts/`。
- **交付**：
  1. ✅ `tools connect`/`run` 复用 router bridge，剔除直接 `Bridge::new_from_config` 调用 — 已完成 2025-11-13
     - `tools connect` 现使用 `sb_core::adapter::bridge::build_bridge` 而非 `Bridge::new_from_config`
     - 在构建 bridge 前调用 `sb_adapters::register_all()` 注册 adapter
     - 支持 router engine 集成（当 router feature 启用时）
     - 优先使用 adapter 注册表，回退到 scaffold 实现
     - TCP 和 UDP 连接均已更新为使用 adapter 路径
     - **tools feature 现包含 router + adapters**（确保工具始终使用完整 adapter 路径）
  2. ✅ **CLI 集成测试框架**（完成 2025-11-14）
     - ✅ 创建 CLI 集成测试文件（`app/tests/cli_tools_adapter_test.rs`）
     - ✅ 添加 10 个测试用例覆盖 adapter 注册、配置解析、工具命令
     - ✅ 验证 adapter 注册在测试环境中工作（`test_adapter_registration_in_tests` 通过）
     - ✅ 通过测试：tools help, geodata-update, direct/block/socks/http outbound、多出站配置等（8/8，全绿）
     - ✅ 修复 HTTP/SOCKS adapter 在 CLI 工具中未找到的问题
       - 通过 `sb-config::validator::v2::to_ir_v1` 中将 Go 风格 `tag` 映射为 `OutboundIR.name`、接受 `server_port` 字段，保证 `Bridge::assemble_outbounds` 注册的名字与 CLI `--outbound` 一致
       - CLI 集成测试与 `adapter_instantiation_e2e` 中的 HTTP/SOCKS 相关用例均通过
  3. ✅ 建立 Go ↔ Rust CLI 对比脚本（route explain、ruleset、geoip/geosite）— 已完成 2025-11-14
  4. ✅ 为 adapter/DNS/selector 添加 e2e 与 smoke tests，覆盖默认/feature 组合（ route explain CLI 合同测试加入 trycmd，selector/smoke 用例已补齐）
- **现状**：CLI 已使用 adapter 路径，测试框架就绪但部分失败，需调试 adapter 实例化问题
- **待办**：
  - [x] 修改 `tools connect`/`run` 使用完整 router + adapter 路径（非 scaffold）— 已完成 2025-11-13
  - [x] 创建 CLI 集成测试框架 — 已完成 2025-11-13（但需修复失败用例）
  - [x] 修复 HTTP/SOCKS adapter 实例化问题（CLI 工具与 adapter_instantiation_e2e 均通过）— 完成 2025-11-14
  - [x] 添加更多 adapter outbound 测试（Shadowsocks/VMess/VLESS/Trojan）— `app/tests/adapter_instantiation_e2e.rs` 已覆盖并通过
  - [x] 创建 Go ↔ Rust route explain 对比脚本（`scripts/route_explain_compare.sh` 已存在并可用）
  - [x] 创建 Go ↔ Rust ruleset CLI 对比脚本（`scripts/ruleset_parity.sh` 支持 validate/match 等子命令，并可 diff Rust/Go 输出）
  - [x] 为 TUIC/Hysteria2/DNS outbound 添加 e2e 测试（`tuic_outbound_e2e.rs`、`hysteria2_udp_e2e.rs`、`dns_outbound_e2e.rs` 已落地并通过）
  - [x] 添加热重载测试：验证配置更新后 adapter 正确重建（`app/tests/reload_adapter_path.rs` 已存在）
  - [x] 在 CI 中添加 adapter feature 组合测试矩阵（`scripts/test_feature_gates.sh` 提供 sb-core 特性组合 build 检查）
  - [x] 添加 prefetch/geoip/geosite CLI 工具与 Go 输出对比
    - ✅ geoip/geosite：`scripts/geodata_parity.sh` 已提供 Rust `tools geoip/geosite match` 与 Go `sing-box tools geoip/geosite match` 的对比脚本，可在本地或 CI 严格校验匹配情况
    - ✅ prefetch：新增 `scripts/prefetch_parity.sh`，比较 Rust/Go `tools prefetch stats --json` 输出（支持 CI/strict 模式，Go 未提供该命令时会降级提示）
  - [x] 添加 ruleset CLI 合同测试（`app/tests/ruleset_cli.rs` 覆盖 validate/info/format/match，确保 `app ruleset` 与 Go 行为一致）
  - [x] 扩展 ruleset CLI 测试覆盖 compile/convert（JSON ↔ SRS round-trip），防止数据管线回归
  - [x] 补充 ruleset merge/upgrade 测试（`ruleset_merge_combines_inputs`、`ruleset_upgrade_sets_target_version`）确保多文件合并与版本升级过程可回归
  - [x] 新增 route explain UDP 与 domain/IP 对比测试（`route_parity.rs` + trycmd `route_explain_*`），覆盖 `--udp`、`--with-trace`、人类/JSON 输出合同

## 近期优先级（Top Tasks）

基于当前进展（入站 100% 完成，出站 100% 完成，DNS 67% 完成 + 3 项部分支持），按紧迫性排序：

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
  - ✅ Feature gate 组合矩阵（原 P2）— 完成 2025-11-16
    - 新增 `cargo xtask feature-matrix`（`xtask/src/main.rs`, `xtask/README.md`），一次性运行 32 组 app/sb-core/sb-adapters 组合，覆盖 CLI 预设、DNS 传输和主力 adapter
    - `scripts/test_feature_gates.sh` 现调用该命令，保持历史脚本入口
    - 最新一次运行 (`cargo run -p xtask -- feature-matrix`) 全部通过，日志附带逐项结果
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

6. ✅ **WireGuard outbound MVP**（WS-B，高级用户需求）— 完成 2025-11-15
   - 实现 `WireGuardOutbound`，通过 `SO_BINDTODEVICE` 绑定到现有系统接口（`SB_WIREGUARD_INTERFACE`）并可选绑定源地址（`SB_WIREGUARD_SOURCE_V4/SB_WIREGUARD_SOURCE_V6`），同时提供 TCP keepalive/timeout 环境变量（`SB_WIREGUARD_TCP_KEEPALIVE_SECS`、`SB_WIREGUARD_CONNECT_TIMEOUT_MS`）
   - `WireGuardConfig::from_ir()` 统一解析 IR + env，供 switchboard 与 adapter 共享（`crates/sb-core/src/outbound/wireguard.rs`）
   - 新增 UDP factory，实现 `WireGuardUdpSession`（IPv4）供 URLTest/Selector 调用
   - `sb-adapters` 注册 `adapter-wireguard`，在 `app` 的 `adapters` feature 下自动启用，同时向 CLI/Go parity 流程暴露
   - 支持 JSON 配置中的 `system_interface`/`interface_name`/`local_address`/`allowed_ips`（`LegacyWireGuardOutboundOptions`）直接落入 IR：无需强依赖环境变量即可指定 iface/源地址，`WireGuardConfig::from_ir` 优先读取 IR 字段，缺失时再回退到 `SB_WIREGUARD_*`

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
  - 入站目标：100% (17/17)，**当前：100% (17/17)** - 2025-11-15 更新（含 AnyTLS/ShadowTLS/Hysteria/TUIC）
  - 出站目标：100% (19/19)，**当前：100% (19/19)** - 2025-11-19 更新（含 AnyTLS/WireGuard/Hysteria v1）
  - DNS 目标：75% (9/12)，**当前：67% (8/12 完整 + DHCP/resolved/tailscale 部分支持)** - 2025-11-11 更新
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
- **2025-11-23**：**文档完善 - 迁移指南创建**
  - ✅ **创建 MIGRATION_GUIDE.md**：完整的 Go → Rust 迁移指南，文档化 100% 协议覆盖率
  - ✅ 特性对比表：17/17 入站、19/19 出站、9/12 完整 DNS 传输 + 3 部分支持
  - ✅ 配置兼容性：文档化配置迁移路径、Breaking changes（无）、行为差异
  - ✅ Tailscale 限制说明：详细说明构建问题和三种替代方案（WireGuard endpoint、外部 Tailscale、监控上游）
  - ✅ WireGuard 说明：userspace MVP 状态和生产建议
  性能对比：ChaCha20-Poly1305 123.6 MiB/s、线性并发扩展到 1000+ 连接
  - ✅ 故障排除指南：常见迁移问题和解决方案
  - 📝 更新 task.md：标记所有文档任务完成，进入 README 更新阶段
- **2025-11-22 (晚)**：**DERP 生产特性完整性发现与文档更新**
  - ✅ **发现 mesh networking 已完整实现**：代码审计发现文档过时，mesh 功能实际已完成
  - ✅ Mesh 特性清单：`ForwardPacket` frame (protocol.rs:42)、mesh peer registry (client_registry.rs:217-230)、remote client tracking、HTTP upgrade handshake (server.rs:730-815)、cross-server packet relay (client_registry.rs:307-321)
  - ✅ E2E mesh 测试通过：`test_mesh_forwarding` (mesh_test.rs) 验证 Client1@ServerA → Client2@ServerB 跨服务器中继
  - ✅ TLS 支持已完成：rustls acceptor、cert/key 加载 (server.rs:141-145)、`test_derp_protocol_over_tls_end_to_end` 通过
  - ✅ PSK 认证已完成：mesh PSK via HTTP header (server.rs:514-533)、legacy relay token 验证 (server.rs:567-579)
  - ✅ Rate limiting 已完成：per-IP sliding window (server.rs:42-76)、rate_limited metrics
  - ✅ Metrics 已完成：DerpMetrics 跟踪 connections/packets/bytes/lifetimes/STUN/HTTP/relay failures
  - ✅ 21 个测试全部通过：protocol (11)、client_registry (7)、server (8)、mesh E2E (1)
  - 📝 更新文档：NEXT_STEPS.md、GO_PARITY_MATRIX.md 反映 DERP 从 "Substantial" 提升至 "Complete (mesh networking)"
  - 💡 可选增强（非阻塞）：JWT/token auth (beyond PSK)、per-client rate limits (beyond per-IP)、bandwidth throttling
- **2025-11-22 (早)**：DERP 协议完整实现（DERP protocol + client registry + packet relay）
  - ✅ DERP 完整协议实现：`protocol.rs` (592行) 提供 10 种 frame 类型序列化/反序列化 (ServerKey/ClientInfo/SendPacket/RecvPacket/KeepAlive/Ping/Pong/PeerGone/PeerPresent/ForwardPacket)
  - ✅ ClientRegistry 管理客户端会话，支持 peer presence 通知与 packet 转发
  - ✅ 真实 DERP 客户端握手：ServerKey → ClientInfo 交换，然后 frame-based 双向通信
  - ✅ E2E 测试：`test_derp_protocol_end_to_end` 验证完整 client1 → client2 packet relay 流程
  - ✅ 前期已有：STUN server、HTTP 健康端点、TCP mock relay (backward compatibility)
- **2025-11-21**：Endpoint/Service 运行时生命周期接入
  - ✅ Bridge 构建 endpoints/services 并随其他 adapter 一起挂载；Supervisor 在启动/热重载/关停时统一启动/关闭（Initialize → Start → PostStart → Started）
  - ✅ 服务 stub 在启动阶段返回明确的 "not implemented" 错误，避免静默成功
  - ✅ 新增测试：`app/tests/service_instantiation_e2e.rs` 覆盖 service IR 解析与 Bridge 构建
  - 影响：端点/服务链路不再悬空，热重载与关停流程覆盖 endpoints/services
- **2025-11-20**：WireGuard userspace endpoint 完整实现（WS-D 部分完成）
  - ✅ 实现基于 `boringtun` 的 WireGuard userspace endpoint (`crates/sb-adapters/src/endpoint/wireguard.rs`, 247行完整实现)
  - ✅ 支持完整 WireGuard 协议功能：
    - TUN 设备创建与管理（支持 Linux/macOS/Windows，通过 `tun` crate）
    - 使用 `boringtun` 进行 Noise protocol 加密/解密
    - UDP 数据包封装/解封装（encapsulate/decapsulate）
    - 定时器管理（周期性握手与 keepalive）
    - 对等点（peer）管理（支持 pre-shared key、persistent keepalive）
  - ✅ Feature-gated 实现：当 `adapter-wireguard-endpoint` 启用时使用真实实现，否则返回友好提示的 stub
  - ✅ 端点注册与生命周期管理：实现 `Endpoint` trait，支持 start/close 操作
  - ✅ 创建集成测试套件 (`app/tests/wireguard_endpoint_test.rs`，2个测试通过)
    - IR 序列化/反序列化测试
    - Stub 行为验证（无 feature 时返回友好错误）
  - ✅ 创建 E2E 测试套件 (`app/tests/wireguard_endpoint_e2e.rs`，6个测试通过)
    - 配置解析测试（完整配置与最小配置）
    - Pre-shared key (PSK) 支持测试
    - 双栈（IPv4 + IPv6）配置测试
    - 配置验证测试
    - 端点生命周期测试
    - 性能基准测试（serde: 平均 3μs/iteration）
  - ✅ 依赖配置：
    - `boringtun` 0.6.0 (from cloudflare/boringtun master branch)
    - `tun` 0.8.4 (async TUN device support)
    - `ipnet` 2.7 (CIDR address parsing)
  - ⚠️ 当前为 userspace 实现 MVP，需要权限创建 TUN 设备；生产环境建议使用 kernel WireGuard
  - 端点覆盖率：WireGuard endpoint 从 **stub** 提升至 **Partial (userspace MVP)**
  - 测试覆盖率：8个测试 (2个集成 + 6个 e2e)，100% 通过
  - 详见：`crates/sb-adapters/src/endpoint/wireguard.rs`, `crates/sb-adapters/src/endpoint_stubs.rs:84-92`, `app/tests/wireguard_endpoint_test.rs`, `app/tests/wireguard_endpoint_e2e.rs`
- **2025-11-16**：CLI geodata-update 离线模式 + 合同测试
  - ✅ `tools geodata-update` 现在支持 `file://` URL，可直接从本地文件读取 GeoIP/Geosite 数据并复用 SHA 校验（`app/src/cli/tools.rs:392-462` 新增 `file_url_to_path` 辅助函数）
  - ✅ 新增 `app/tests/tools_geodata_update_test.rs`，在 CI/本地通过临时文件 + sha256 断言验证输出，确保 geodata 工具的 CLI 行为有自动化覆盖
  - 影响：CLI 子命令覆盖率提升，Go Parity Matrix 中对 geodata-update 缺乏合同测试的缺口被填补
  - ✅ `cargo xtask feature-matrix`（`xtask/src/main.rs`, `scripts/test_feature_gates.sh`）落地，提供 32 组 CLI/DNS/adapter feature gate 组合编译验证；最新运行结果已在日志中记录，可用于本地/CI
- **2025-11-15**：WireGuard outbound MVP（系统接口绑定版）
  - ✅ `crates/sb-core/src/outbound/wireguard.rs` 重写为可运行实现：提供 `WireGuardConfig::from_ir`、系统接口绑定、UDP factory 与 metrics
  - ✅ `crates/sb-core/src/runtime/switchboard.rs` 复用上述配置，`wireguard` 出站支持 TCP/UDP 注册（`WireGuardConnector`）
  - ✅ `crates/sb-adapters/src/register.rs` 新增 `adapter-wireguard`，`app/Cargo.toml` 将其纳入 `adapters` 聚合；CLI/路由均可直接构建 WireGuard 出站
  - ✅ `sb-config` 解析 Go 风格 `system_interface`/`interface_name`/`local_address`/`allowed_ips` 字段（`OutboundIR` 扩展），`WireGuardConfig::from_ir` 优先使用 IR 字段并仅在缺失时回退环境变量，方便 JSON/CLI 一致配置
  - ⚠️ 目前依赖外部 WireGuard 接口（需用户提前 `wg-quick` 或 `Kernel WireGuard`），后续任务可在此基础上接入 boringtun/内核态实现
- **2025-11-13 (晚)**：完成 WS-E Task 1 最终修复 + 部分完成 Task 2（CLI 集成测试框架）
  - ✅ 修复 `build_bridge()` 调用：非 router 模式下使用 `()` 参数而非回退到 `new_from_config`
  - ✅ 添加 `router` feature 到 `tools` feature 依赖（确保 Engine 始终可用）
  - ✅ 添加 `adapters` feature 到 `tools` feature 依赖（确保工具始终包含 adapter 支持）
  - ✅ 添加 `adapter-http` 和 `http` features 到 dev-dependencies
  - ✅ 创建 CLI 集成测试文件（`app/tests/cli_tools_adapter_test.rs`）包含 10 个测试
  - ✅ 修复测试配置字段名（`server_port` → `port`）以匹配 IR structure
  - ✅ 验证 adapter 注册机制在测试环境中工作
  - ⚠ 3 个测试仍失败（HTTP/SOCKS adapter 未在 bridge 中找到）
  - 需要：深入调试为何 `build_http_outbound`/`build_socks_outbound` 返回 None
  - 文档更新：NEXT_STEPS.md 标记 WS-E Task 2 部分完成
  - 详见：`app/src/cli/tools.rs:129-136, 203-210`, `app/tests/cli_tools_adapter_test.rs`, `app/Cargo.toml:44, 339`
- **2025-11-13 (早)**：完成 WS-E Task 1（tools connect/run adapter path 迁移）
  - ✅ 修改 `tools connect` TCP 和 UDP 函数使用 adapter 路径
  - ✅ 在构建 bridge 前调用 `sb_adapters::register_all()` 注册 adapter
  - ✅ 替换 `Bridge::new_from_config` 为 `sb_core::adapter::bridge::build_bridge`
  - ✅ 集成 router engine（当 router feature 启用时）
  - ✅ 优先使用 adapter 注册表，回退到 scaffold 实现
  - 文档更新：NEXT_STEPS.md 标记 WS-E Task 1 完成
  - 详见：`app/src/cli/tools.rs:116-172, 183-211`
- **2025-11-12 (深夜 最晚)**：完成 Hysteria v1 入站实现（WS-A Task 6 部分完成）
  - ✅ 新增 Hysteria v1 入站适配器（`crates/sb-adapters/src/inbound/hysteria.rs`，190行完整实现）
  - ✅ 实现 QUIC + 自定义协议类型（udp/wechat-video/faketcp）+ 拥塞控制 + obfuscation
  - ✅ 添加 Hysteria v1 相关字段到 `InboundIR`（users_hysteria, hysteria_protocol, hysteria_obfs, hysteria_up_mbps, hysteria_down_mbps, hysteria_recv_window_conn, hysteria_recv_window）
  - ✅ 添加 Hysteria v1 相关字段到 `InboundParam` 并更新 bridge.rs 转换逻辑
  - ✅ 定义 `HysteriaUserIR` 类型（name + auth）到 IR schema
  - ✅ 在 `register.rs` 中替换 stub 为完整构建器函数（`build_hysteria_inbound`，lines 941-1045）
  - ✅ 实现 `InboundService` trait 支持 serve()/request_shutdown()
  - ✅ 支持 TLS 证书配置（文件路径或 inline PEM）
  - ✅ 支持多用户认证（name + auth）
  - ✅ 支持自定义 QUIC 接收窗口（recv_window_conn/recv_window）
  - ✅ 添加 4 个测试验证 Hysteria v1 入站功能（`app/tests/hysteria_inbound_test.rs`）
  - ✅ 所有测试通过（4 passed; 0 failed）
  - ✅ 修复编译错误：Tor outbound feature gate 闭合，UDP session Arc clone issue
  - 入站协议覆盖率从 **88% (15/17)** 提升至 **94% (16/17)** - ✅ **达到 94% 覆盖率，超过 90% 目标**
  - 文档更新：NEXT_STEPS.md 标记 Hysteria v1 入站完成
  - 详见：`crates/sb-adapters/src/inbound/hysteria.rs`, `crates/sb-adapters/src/register.rs:941-1045`, `app/tests/hysteria_inbound_test.rs`
- **2025-11-12 (深夜 晚)**：完成 Tor 出站实现（WS-B Task 10 完成）
  - ✅ 新增 Tor outbound 适配器注册（`crates/sb-adapters/src/register.rs:1297-1361`）
  - ✅ 实现为 SOCKS5 代理到 Tor daemon（默认：127.0.0.1:9050）
  - ✅ 支持自定义 Tor 代理地址（`tor_proxy_addr` 字段）
  - ✅ 添加 Tor-specific 配置字段到 OutboundIR：
    - `tor_proxy_addr`: Tor SOCKS5 proxy address
    - `tor_executable_path`: Tor executable path (future)
    - `tor_extra_args`: Extra Tor command-line arguments (future)
    - `tor_data_directory`: Tor data directory (future)
    - `tor_options`: Torrc configuration options (future)
  - ✅ 在 `register_all()` 中注册 Tor outbound（line 52）
  - ✅ 添加 4 个测试验证 Tor outbound 功能（`app/tests/tor_outbound_test.rs`）
  - ✅ 所有测试通过（4 passed; 0 failed）
  - 出站协议覆盖率从 **84% (16/19)** 提升至 **89% (17/19)** - ✅ **向 95% 目标前进 5%**
  - 文档更新：NEXT_STEPS.md, GO_PARITY_MATRIX.md 标记 Tor outbound 完成
  - 详见：`crates/sb-adapters/src/register.rs:1297-1361`, `app/tests/tor_outbound_test.rs`
- **2025-11-12 (深夜)**：完成 Direct/Block 出站实现（WS-B Task 7-8 完成）
  - ✅ 新增 Direct outbound 适配器（`crates/sb-adapters/src/register.rs:1198-1238`）
  - ✅ 创建 `DirectConnectorWrapper` 实现 `OutboundConnector` trait
  - ✅ 支持直接连接到目标地址（IP 或域名），带超时控制
  - ✅ 在 `register_all()` 中注册 Direct outbound（line 43）
  - ✅ 新增 Block outbound 适配器（`crates/sb-adapters/src/register.rs:1240-1289`）
  - ✅ 创建 `BlockConnectorWrapper` 实现 `OutboundConnector` trait
  - ✅ 所有连接请求返回错误（阻断功能）
  - ✅ 在 `register_all()` 中注册 Block outbound（line 46）
  - ✅ 添加 4 个测试验证 Direct/Block outbound 功能（`app/tests/direct_block_outbound_test.rs`）
  - ✅ 所有测试通过（4 passed; 0 failed）
  - 出站协议覆盖率从 **74% (14/19)** 提升至 **84% (16/19)** - ✅ **向 95% 目标前进 10%**
  - 文档更新：NEXT_STEPS.md, GO_PARITY_MATRIX.md 标记 Direct/Block outbound 完成
  - 详见：`crates/sb-adapters/src/register.rs:1198-1289, 43, 46`, `app/tests/direct_block_outbound_test.rs`
- **2025-11-12 (深夜)**：完成 ShadowTLS 出站实现（WS-B Task 6 完成）
  - ✅ 新增 ShadowTLS outbound 适配器注册（`crates/sb-adapters/src/register.rs:1230-1309`）
  - ✅ 创建 `ShadowTlsConnectorWrapper` 实现 `OutboundConnector` trait
  - ✅ 支持 TLS SNI/ALPN 配置、证书验证选项（`skip_cert_verify`）
  - ✅ 在 `register_all()` 中注册 ShadowTLS outbound（line 67）
  - ✅ 添加测试验证 ShadowTLS outbound 注册（`test_shadowtls_outbound_registration`）
  - ✅ 利用现有 sb-core ShadowTLS 实现（`crates/sb-core/src/outbound/shadowtls.rs`）
  - ✅ 利用现有 sb-adapters 适配器包装（`crates/sb-adapters/src/outbound/shadowtls.rs`）
  - 出站协议覆盖率从 **68% (13/19)** 提升至 **74% (14/19)** - ✅ **向 95% 目标前进 6%**
  - 文档更新：NEXT_STEPS.md, GO_PARITY_MATRIX.md 标记 ShadowTLS outbound 完成
  - 详见：`crates/sb-adapters/src/register.rs:1230-1309, 67`, `crates/sb-adapters/src/outbound/shadowtls.rs`
- **2025-11-12 (晚)**：完成 ShadowTLS 入站实现（WS-A Task 6 完成，达成 90% 目标）
  - ✅ 利用现有 232 行 ShadowTLS 实现（`crates/sb-adapters/src/inbound/shadowtls.rs`）
  - ✅ 创建 `ShadowTlsInboundAdapter` wrapper，实现 `InboundService` trait
  - ✅ 在 `register.rs` 中添加完整构建器函数（`build_shadowtls_inbound`，lines 869-928）
  - ✅ 修复所有 adapter 的 parking_lot::Mutex 迁移（20个实例）：
    - 移除 `.map_err(io::Error::other)?` 模式（parking_lot 不返回 Result）
    - 更新 10 个 adapter：HTTP, SOCKS, VMess, VLESS, TUN, Trojan, Mixed, Shadowsocks, Redirect, TProxy
  - ✅ 修复 ALPN 类型转换问题（3个文件）：
    - shadowtls.rs: String → Vec<String> (lines 86-91)
    - tuic.rs: String → Vec<String> (lines 77-82, 143-148)
    - mod.rs: Vec<String> → String (line 285)
  - ✅ 修复模块路径解析（E0433）：`sb_adapters::` → `crate::` (3个位置)
  - ✅ 修复 SNI 字段错误分配（mod.rs:281, tls_alpn → tls_sni）
  - ✅ 成功编译（16.23s，dev profile）
  - 入站协议覆盖率从 **82% (14/17)** 提升至 **88% (15/17)** - ✅ **达成 90% 目标**
  - 文档更新：NEXT_STEPS.md 标记 ShadowTLS 完成，更新所有覆盖率指标
  - 详见：`crates/sb-adapters/src/register.rs:869-1837`, `crates/sb-adapters/Cargo.toml:15,104,134`
  - 架构模式：建立 parking_lot::Mutex 和 ALPN 转换的标准模式供未来 adapter 使用
- **2025-11-12 (下午)**：完成 SSH 出站验证与代码修复（WS-B 部分完成）
  - ✅ 验证 SSH 出站完整实现（41个测试全部通过）
  - ✅ 修复 `crates/sb-core/src/dns/upstream.rs` 中重复的 tests 模块定义问题
  - ✅ 修复 `crates/sb-core/src/outbound/selector_group_tests.rs` 中 parse_test_url 元组解构错误
  - ✅ SSH 出站已包含完整特性：
    - 密码认证
    - 公钥认证（支持 passphrase）
    - Host key 验证（trust-on-first-use）
    - 连接池
    - TCP 隧道通过 SSH channels
    - 53个全面的单元测试
    - 完整的 adapter 注册
  - ✅ 更新 NEXT_STEPS.md 标记 SSH 出站为完成状态
  - 出站协议覆盖率提升至 **68% (13/19)**，SSH 正式标记为完成
  - 详见：`crates/sb-core/src/outbound/ssh_stub.rs`, `crates/sb-adapters/src/register.rs:1339-1429`
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
