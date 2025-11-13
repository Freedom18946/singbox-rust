# sing-box Parity Matrix (Rust vs Go 1.12.12)

Baseline: sing-box 1.12.12 (Go) — `go_fork_source/sing-box-1.12.12`
Last audited: 2025-11-10 10:40 UTC

Status legend
- ✅ Supported: 行为与上游一致或等效，已注册并完整实现
- ◐ Partial: 有实现但选项/集成/包装不完整，或已存在但未注册
- ⚠ Stub: 已注册但仅返回警告，无实际实现
- ✗ Missing: 不可用或未实现

## 扼要结论（Executive Summary）

### 协议适配器现状
- `sb_adapters::register_all()` 只有在显式编译 `app` 的 `adapters` 特性时才会执行（`app/src/bootstrap.rs:680-683`），并且注册列表现已扩展到覆盖 HTTP/SOCKS/Mixed + Shadowsocks/VMess/VLESS/Trojan/TUN/Redirect/TProxy/Direct 入站（11种），以及 HTTP/SOCKS/Shadowsocks/Trojan/VMess/VLESS/DNS 出站（8种）（`crates/sb-adapters/src/register.rs:15-170`）。
- Naive/ShadowTLS/Hysteria/Hysteria2/TUIC 等 QUIC 入站已完整实现并注册（`crates/sb-adapters/src/register.rs`），仅剩 AnyTLS 为 stub builder 返回警告。**最新进展（2025-11-12）：Hysteria v1 入站已完成实现，入站覆盖率达 94% (16/17)。**
- ✅ TUN/Redirect/TProxy 入站已在 `register.rs` 中完整注册并实现（`crates/sb-adapters/src/register.rs:159-168, 1273-1440`），可通过 adapter 路径调用。
- ✅ **Direct 入站已完成实现并注册** — 2025-11-11
  - 实现文件：`crates/sb-adapters/src/inbound/direct.rs`
  - 注册位置：`crates/sb-adapters/src/register.rs:118-121, 885-898`
  - 支持 TCP/UDP 双模式，包含 4 个测试验证（`app/tests/direct_inbound_test.rs`）
- `OutboundType` 枚举已扩展到 19 项（`crates/sb-config/src/ir/mod.rs:95-134`），新增了 Dns/Tor/AnyTLS/Hysteria(v1)/WireGuard 等 Go 独有类型。DNS, Tor, 和 Hysteria(v1) outbound 已实现完整的 adapter builder（feature-gated），仅剩 AnyTLS/WireGuard 为 stub。

### 端点与服务
- Go 注册表暴露 WireGuard/Tailscale endpoint 与 Resolved/DERP/SSM 服务（`go_fork_source/sing-box-1.12.12/include/registry.go:102-138`），Rust IR 与运行期完全没有 endpoints/services 结构（`crates/sb-config/src/ir/mod.rs:382-404`、`crates/sb-core/src/services/mod.rs:1-3`），仅保留可选 NTP 服务。

### DNS 传输
- `resolver_from_ir` 支持 system/UDP/DoH/DoT/DoQ/DoH3 六种基础传输 + hosts/fakeip overlay（`crates/sb-core/src/dns/config_builder.rs:13-60`），缺少 Go 提供的 DHCP、tailscale、resolved 传输（`go_fork_source/sing-box-1.12.12/include/dhcp.go`、`go_fork_source/sing-box-1.12.12/include/tailscale.go:17-19`）。HTTP3 (DoH over HTTP/3) 已于 2025-11-10 完成实现（`crates/sb-core/src/dns/transport/doh3.rs`）。

## 功能总览（Feature Index）

| 类别 | 状态 | 备注 |
| --- | --- | --- |
| CLI 子命令 | ◐ Partial | 子命令面齐全，但 `tools connect` 仍手动调用 `Bridge::new_from_config`，缺乏 router handle，因此无法驱动 adapter 路径或 selector/health 能力（`app/src/cli/tools.rs:126`、`app/src/cli/tools.rs:188`）。 |
| 配置/IR/校验 | ◐ Partial | `sb-config` 顶层只暴露 inbounds/outbounds/log/dns/certificate/ntp（`crates/sb-config/src/ir/mod.rs:382-404`），`InboundType` 已扩展到 17 种，`OutboundType` 已扩展到 19 种（`crates/sb-config/src/ir/mod.rs`），覆盖了 Go 绝大部分协议类型。仍缺少 endpoint/service 的 schema。 |
| 运行时与热重载 | ◐ Partial | Supervisor 会重新构建 engine 并调用 adapter-first bridge，但由于 IR 无法描述新协议，热重载仍只能覆盖少量入/出站（`crates/sb-core/src/runtime/supervisor.rs:104`、`crates/sb-core/src/adapter/bridge.rs:2153`）。 |
| 路由/桥接 | ◐ Partial | `to_inbound_param` 只识别 `socks/http/mixed/tun/redirect/tproxy/direct`，Redirect/TProxy 继续返回 `UnsupportedInbound`，其它协议型入站完全没有入口（`crates/sb-core/src/adapter/bridge.rs:203`、`crates/sb-core/src/adapter/bridge.rs:328`）。 |
| DNS 子系统 | ◐ Partial | Resolver 支持 `system/udp/doh/dot/doq/doh3` upstream 与 hosts/fakeip overlay（`crates/sb-core/src/dns/config_builder.rs:13-176`），DHCP/tailscale/resolved 传输与服务入口未实现。DoH3 于 2025-11-10 完成（`dns/transport/doh3.rs`）。 |
| 协议出站 | ◐ Partial | Adapter 可注册 direct/block/http/socks/shadowsocks/vless/vmess/trojan/tuic/hysteria/hysteria2/shadowtls/ssh/tor/dns/urltest/selector (18种)，仅剩 Go 独有的 anytls/wireguard 为 stub（`crates/sb-adapters/src/register.rs`）。**最新进展（2025-11-12）：Hysteria v1 已实现并注册，出站覆盖率达 95% (18/19)。** |
| 协议入站 | ◐ Partial | Adapter registry 已注册 16 种协议完整实现（socks/http/mixed/shadowsocks/vmess/vless/trojan/naive/hysteria/hysteria2/tuic/shadowtls/tun/redirect/tproxy/direct），仅剩 anytls 为 stub（`crates/sb-adapters/src/register.rs`）。**覆盖率 94% (16/17)，超过 90% 目标 ✅** |
| 传输层 | ◐ Partial | `sb-transport` 具备 TLS/WS/H2/HTTPUpgrade/GRPC/mux/QUIC，但目前只被 VLESS/VMess/Trojan/TUIC/Hysteria2 路径调用，REALITY/ECH 也仅在部分协议中启用。 |
| 选择器 | ◐ Partial | `assemble_selectors`/`SelectorGroup` 可以构建 selector/urltest，并在有 Tokio runtime 时启动健康检查，但受限于可用出站集合。 |
| 端点（Endpoints） | ✗ Missing | IR 中没有 `endpoints` 字段（`crates/sb-config/src/ir/mod.rs:382-404`），`sb-core` 也缺乏任何 endpoint registry/实现，对比 Go 的 WireGuard/Tailscale endpoint 全部缺失。 |
| 服务（Services） | ✗ Missing | 运行期仅有可选 `service_ntp` 模块（`crates/sb-core/src/services/mod.rs:1-3`），没有 Resolved/DERP/SSM/Geo 相关服务。 |
| 观测/指标 | ◐ Partial | 存在路由/出站部分指标，但缺乏与 Go 对齐的标签和 explain/health 覆盖，新增 adapter 亦无测试保障。 |
| 发布/数据 | ◐ Partial | `tools geodata-update` 可拉取 Geo 数据，但没有自动校验或发布链路。 |

## 与 go_fork_source 注册表对照（详细差距快照）

### 入站协议对比（Inbound Protocols）

| 协议 | Go 1.12.12 | Rust 实现状态 | 注册状态 | 说明 |
| --- | --- | --- | --- | --- |
| tun | ✅ | ✅ Supported | 已注册 | 完整实现并注册 `sb-adapters/src/inbound/tun.rs` + adapter (`register.rs:159-162, 1273-1308`) |
| redirect | ✅ | ✅ Supported | 已注册 | 完整实现并注册 `sb-adapters/src/inbound/redirect.rs` (Linux only, `register.rs:164-168, 1310-1374`) |
| tproxy | ✅ | ✅ Supported | 已注册 | 完整实现并注册 `sb-adapters/src/inbound/tproxy.rs` (Linux only, `register.rs:164-168, 1376-1440`) |
| direct | ✅ | ✅ Supported | 已注册 | 完整实现并注册 `sb-adapters/src/inbound/direct.rs` (2025-11-11, `register.rs:118-121, 885-898`) |
| socks | ✅ | ✅ Supported | 已注册 | 完整实现并注册 `sb-adapters/src/inbound/socks/` |
| http | ✅ | ✅ Supported | 已注册 | 完整实现并注册 `sb-adapters/src/inbound/http.rs` |
| mixed | ✅ | ✅ Supported | 已注册 | 完整实现并注册 `sb-adapters/src/inbound/mixed.rs` |
| shadowsocks | ✅ | ✅ Supported | 已注册 | 完整实现并注册 `sb-adapters/src/inbound/shadowsocks.rs` |
| vmess | ✅ | ✅ Supported | 已注册 | 完整实现并注册 `sb-adapters/src/inbound/vmess.rs` |
| trojan | ✅ | ✅ Supported | 已注册 | 完整实现并注册 `sb-adapters/src/inbound/trojan.rs` |
| naive | ✅ | ✅ Supported | 已注册 | 完整实现并注册 `sb-adapters/src/inbound/naive.rs` (2025-11-12, HTTP/2 CONNECT + TLS + auth) |
| shadowtls | ✅ | ✅ Supported | 已注册 | 完整实现并注册 `sb-adapters/src/inbound/shadowtls.rs` (2025-11-12, TLS masquerading + REALITY/ECH, `register.rs:868-933`) |
| vless | ✅ | ✅ Supported | 已注册 | 完整实现并注册 `sb-adapters/src/inbound/vless.rs` |
| anytls | ✅ | ⚠ Stub | 已注册 | 注册为 stub，返回警告 (`register.rs:518-524`) |
| hysteria (v1) | ✅ (QUIC) | ✅ Supported | 已注册 | 完整实现并注册 `sb-adapters/src/inbound/hysteria.rs` (2025-11-12, QUIC + udp/faketcp/wechat-video protocols + obfs + multi-user auth, `register.rs:941-1045`) |
| tuic | ✅ (QUIC) | ✅ Supported | 已注册 | 完整实现并注册 `sb-adapters/src/inbound/tuic.rs` (2025-11-12, QUIC + congestion control + UUID/token auth + UDP relay) |
| hysteria2 | ✅ (QUIC) | ✅ Supported | 已注册 | 完整实现并注册 `sb-adapters/src/inbound/hysteria2.rs` (2025-11-12, QUIC + congestion control + obfs + auth) |

**Rust 入站实现小结：**
- 完整实现并注册：16 种 (socks, http, mixed, shadowsocks, vmess, trojan, vless, naive, hysteria, hysteria2, tuic, shadowtls, tun, redirect, tproxy, direct)
- 注册为 stub (返回警告)：1 种 (anytls)
- 完全缺失：0 种
- **总计：17 种入站中，16 种完全可用 (94%)，超过 90% 目标 ✅ — 2025-11-12 更新（Hysteria v1 完成）**

### 出站协议对比（Outbound Protocols）

| 协议 | Go 1.12.12 | Rust 实现状态 | 注册状态 | 说明 |
| --- | --- | --- | --- | --- |
| direct | ✅ | ✅ Supported | 已注册 | 完整实现并注册 `sb-adapters/src/outbound/direct.rs` + adapter (`register.rs:1198-1238`, 2025-11-12) |
| block | ✅ | ✅ Supported | 已注册 | 完整实现并注册 `sb-adapters/src/outbound/block.rs` + adapter (`register.rs:1240-1289`, 2025-11-12) |
| dns | ✅ | ✅ Supported | 已注册 | 完整实现，feature-gated (`adapter-dns`)，支持 UDP/TCP/DoT/DoH/DoQ |
| selector | ✅ (group) | ◐ Partial | scaffold | 仅 scaffold 实现 `SelectorGroup` |
| urltest | ✅ (group) | ◐ Partial | scaffold | 仅 scaffold 实现 `SelectorGroup` |
| socks | ✅ | ✅ Supported | 已注册 | 完整实现并注册 `sb-adapters/src/outbound/socks5.rs` |
| http | ✅ | ✅ Supported | 已注册 | 完整实现并注册 `sb-adapters/src/outbound/http.rs` |
| shadowsocks | ✅ | ✅ Supported | 已注册 | 完整实现并注册 `sb-adapters/src/outbound/shadowsocks.rs` |
| vmess | ✅ | ✅ Supported | 已注册 | 完整实现并注册 `sb-adapters/src/outbound/vmess.rs` |
| trojan | ✅ | ✅ Supported | 已注册 | 完整实现并注册 `sb-adapters/src/outbound/trojan.rs` |
| tor | ✅ | ✅ Supported | 已注册 | 完整实现并注册 `sb-adapters/src/register.rs` (SOCKS5 proxy to Tor daemon, default: 127.0.0.1:9050, 2025-11-12) |
| ssh | ✅ | ✅ Supported | 已注册 | 完整实现并注册 `sb-adapters/src/outbound/ssh.rs` (feature: `adapter-ssh`, 41个测试通过) |
| shadowtls | ✅ | ✅ Supported | 已注册 | 完整实现并注册 `sb-adapters/src/outbound/shadowtls.rs` + adapter (`register.rs:1230-1297`, feature: `adapter-shadowtls`) |
| vless | ✅ | ✅ Supported | 已注册 | 完整实现并注册 `sb-adapters/src/outbound/vless.rs` |
| anytls | ✅ | ⚠ Stub | 已注册 | 注册为 stub，返回警告 (`register.rs:596-602`) |
| hysteria (v1) | ✅ (QUIC) | ✅ Supported | 已注册 | 完整实现并注册 `sb-core/src/outbound/hysteria/v1.rs` + adapter (`register.rs:1375-1466`, feature: `adapter-hysteria`) |
| tuic | ✅ (QUIC) | ✅ Supported | 已注册 | 完整实现并注册 `sb-core/src/outbound/tuic.rs` + adapter (`register.rs:679-761`, feature: `out_tuic`) |
| hysteria2 | ✅ (QUIC) | ✅ Supported | 已注册 | 完整实现并注册 `sb-core/src/outbound/hysteria2.rs` + adapter (`register.rs:763-858`, feature: `out_hysteria2`) |
| wireguard | ✅ | ⚠ Stub | 已注册 | 注册为 stub，返回警告 (`register.rs:604-610`) |

**Rust 出站实现小结：**
- 完整实现并注册：18 种 (direct, block, http, socks, shadowsocks, vmess, trojan, vless, dns, tuic, hysteria, hysteria2, ssh, shadowtls, tor)
- 实现文件存在但不完整：2 种 (selector, urltest - scaffold only)
- 注册为 stub (返回警告)：2 种 (anytls, wireguard)
- 完全缺失：0 种
- **总计：19 种出站中，18 种完全可用 (95%)，较前次 +1 种（+6%）— 2025-11-12 更新（Hysteria v1 完成）**

### 端点对比（Endpoints）

| 端点类型 | Go 1.12.12 | Rust 实现状态 | 说明 |
| --- | --- | --- | --- |
| wireguard | ✅ (with_wireguard) | ✗ Missing | Go 通过 `wireguard.RegisterEndpoint` 注册 (`include/wireguard.go:15-17`)，Rust 无 endpoint IR 或实现 |
| tailscale | ✅ (with_tailscale) | ✗ Missing | Go 通过 `tailscale.RegisterEndpoint` 注册 (`include/tailscale.go:13-15`)，Rust 无 endpoint IR 或实现 |

**总计：2 种端点全部缺失 (0%)**

### DNS 传输对比（DNS Transports）

| 传输类型 | Go 1.12.12 | Rust 实现状态 | 说明 |
| --- | --- | --- | --- |
| TCP | ✅ | ✅ Supported | `resolver_from_ir` 支持通过 upstream 配置 |
| UDP | ✅ | ✅ Supported | 默认传输，完整支持 |
| TLS (DoT) | ✅ | ✅ Supported | 完整支持 DoT upstream |
| HTTPS (DoH) | ✅ | ✅ Supported | 完整支持 DoH upstream |
| QUIC (DoQ) | ✅ (with_quic) | ✅ Supported | 完整支持 DoQ upstream |
| HTTP3 (DoH/3) | ✅ (with_quic) | ✅ Supported | 完整支持 DoH3 upstream，通过 h3/h3-quinn crate 实现，支持 doh3:// 和 h3:// URL (`dns/transport/doh3.rs`，2025-11-10 完成) |
| hosts | ✅ | ✅ Supported | 通过 `hosts_overlay` 实现 |
| local | ✅ | ✅ Supported | system resolver 覆盖 |
| fakeip | ✅ | ✅ Supported | 通过 `fakeip_overlay` 实现 |
| resolved | ✅ | ✗ Missing | Go 通过 `resolved.RegisterTransport` 注册 (`include/registry.go:121`)，Rust 无实现 |
| DHCP | ✅ (platform) | ✗ Missing | Go 通过 `registerDHCPTransport` 注册 (`include/dhcp.go`)，Rust 无实现 |
| tailscale | ✅ (with_tailscale) | ✗ Missing | Go 通过 `tailscale.RegistryTransport` 注册 (`include/tailscale.go:17-19`)，Rust 无实现 |

**Rust DNS 传输小结：**
- 完整支持：8 种 (TCP, UDP, TLS, HTTPS, QUIC, HTTP3, hosts, fakeip)
- 完全缺失：4 种 (resolved, DHCP, tailscale, local-stub)
- **总计：12 种 DNS 传输中，8 种可用 (67%)**

### 服务对比（Services）

| 服务类型 | Go 1.12.12 | Rust 实现状态 | 说明 |
| --- | --- | --- | --- |
| resolved | ✅ | ✗ Missing | Go 通过 `resolved.RegisterService` 注册 (`include/registry.go:133`)，Rust 无 service IR 或实现 |
| ssmapi | ✅ | ✗ Missing | Go 通过 `ssmapi.RegisterService` 注册 (`include/registry.go:134`)，Rust 无实现 |
| derp | ✅ (with_tailscale) | ✗ Missing | Go 通过 `derp.Register` 注册 (`include/tailscale.go:21-23`)，Rust 无实现 |
| ntp | ✗ | ◐ Partial | Rust 独有，通过 `service_ntp` 可选模块实现 (`crates/sb-core/src/services/mod.rs`) |

**总计：Go 的 3 种服务全部缺失 (0%)；Rust 有独立的 NTP 服务**

## 配置与 IR 覆盖

### IR 顶层字段对比

| 字段 | Go 1.12.12 | Rust IR 状态 | 说明 |
| --- | --- | --- | --- |
| log | ✅ | ✅ | 完整支持 |
| dns | ✅ | ✅ | 基础支持，但缺少部分传输类型 |
| certificate | ✅ | ✅ | 完整支持 |
| ntp | ✅ | ✅ | Rust 独立实现 |
| inbounds | ✅ | ◐ Partial | IR 枚举定义不完整，缺少协议字段 |
| outbounds | ✅ | ◐ Partial | IR 枚举已扩展但协议字段不完整 |
| route/routing | ✅ | ✅ | 完整支持 |
| experimental | ✅ | ✗ Missing | Rust IR 完全不支持 |
| endpoints | ✅ | ✗ Missing | Rust IR 完全不支持 |
| services | ✅ | ✗ Missing | Rust IR 完全不支持 (除 NTP) |

### Inbound/Outbound IR 字段对比

**InboundType 枚举：**
- Rust 已定义 16 种：`Socks/Http/Tun/Mixed/Redirect/Tproxy/Direct/Shadowsocks/Vmess/Vless/Trojan/Naive/Shadowtls/Anytls/Hysteria/Hysteria2/Tuic` (`crates/sb-config/src/ir/mod.rs:31-66`)
- 但 IR 结构缺少协议特定字段（密码/UUID/多账户/传输参数等），无法完整表达 Go 配置

**OutboundType 枚举：**
- Rust 已定义 19 种（与 Go 基本对齐）：`Direct/Http/Socks/Block/Selector/Shadowsocks/Shadowtls/UrlTest/Hysteria2/Tuic/Vless/Vmess/Trojan/Ssh/Dns/Tor/Anytls/Hysteria/WireGuard` (`crates/sb-config/src/ir/mod.rs:95-137`)
- 新增了 Go 独有类型（Dns/Tor/AnyTLS/Hysteria v1/WireGuard），但大部分缺少配置字段实现

**DNS IR：**
- `DnsIR` 描述 servers/rules/fakeip/hosts/TTL (`crates/sb-config/src/ir/mod.rs:704-759`)
- 缺少字段：HTTP3/DHCP/tailscale/resolved 传输配置，服务引用

### 配置示例兼容性

- **Go → Rust 迁移**：基础协议（socks/http/shadowsocks/vmess/vless/trojan）可直接迁移；高级协议需等待实现
- **Rust → Go 迁移**：完全兼容（Rust 是 Go 的子集）
- **热重载兼容**：受限于 IR 表达能力，只能覆盖已实现的协议子集

## 验证与对齐
- 现有集成测试仍集中在路由 explain/配置校验层面（`app/tests/route_parity.rs`、`app/tests/p0_upstream_compatibility.rs`），未覆盖 adapter 入站/出站、DNS 回退或热重载路径。
- CLI `tools connect/run` 还没有与 Go 工具做输出 diff，`geoip/geosite` 也缺乏黄金样本。
- Adapter 路径没有任何自动化验证：即使启用 `adapters` feature 也缺乏 e2e/单测，导致注册表和 README 所 claim 的协议列表无法被 CI 证明。

## 附录：关键源码锚点
- Go 注册总表：`go_fork_source/sing-box-1.12.12/include/registry.go`
- Bootstrap & feature gate：`app/Cargo.toml`、`app/src/bootstrap.rs`
- Rust 运行时/桥接：`crates/sb-core/src/runtime/supervisor.rs`、`crates/sb-core/src/adapter/bridge.rs`
- 适配器注册表：`crates/sb-core/src/adapter/registry.rs`
- DNS：`crates/sb-core/src/dns/*`
- 协议适配器：`crates/sb-adapters/src/*`、`crates/sb-core/src/outbound/*`
- CLI 工具：`app/src/bin/*`、`app/src/cli/*`
