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
- `sb_adapters::register_all()` 只有在显式编译 `app` 的 `adapters` 特性时才会执行（`app/src/bootstrap.rs:680-683`），并且注册列表现已扩展到覆盖 HTTP/SOCKS/Mixed + Shadowsocks/VMess/VLESS/Trojan/TUN/Redirect/TProxy 入站（10种），以及 HTTP/SOCKS/Shadowsocks/Trojan/VMess/VLESS/DNS 出站（8种）（`crates/sb-adapters/src/register.rs:15-170`）。
- Naive/ShadowTLS/Hysteria/Hysteria2/TUIC/AnyTLS 等 QUIC 入站已在注册表中添加 stub builder（`crates/sb-adapters/src/register.rs:537-583`），但仅返回警告而无实际实现。
- ✅ TUN/Redirect/TProxy 入站已在 `register.rs` 中完整注册并实现（`crates/sb-adapters/src/register.rs:159-168, 1273-1440`），可通过 adapter 路径调用。Direct 入站虽然在 `sb-adapters/src/inbound/` 中有实现文件，但尚未在 adapter 注册表中。
- `OutboundType` 枚举已扩展到 19 项（`crates/sb-config/src/ir/mod.rs:95-134`），新增了 Dns/Tor/AnyTLS/Hysteria(v1)/WireGuard 等 Go 独有类型，但只有 DNS outbound 实现了完整的 adapter builder（feature-gated），其余均为 stub。

### 端点与服务
- Go 注册表暴露 WireGuard/Tailscale endpoint 与 Resolved/DERP/SSM 服务（`go_fork_source/sing-box-1.12.12/include/registry.go:102-138`），Rust IR 与运行期完全没有 endpoints/services 结构（`crates/sb-config/src/ir/mod.rs:382-404`、`crates/sb-core/src/services/mod.rs:1-3`），仅保留可选 NTP 服务。

### DNS 传输
- `resolver_from_ir` 支持 system/UDP/DoH/DoT/DoQ/DoH3 六种基础传输 + hosts/fakeip overlay（`crates/sb-core/src/dns/config_builder.rs:13-60`），缺少 Go 提供的 DHCP、tailscale、resolved 传输（`go_fork_source/sing-box-1.12.12/include/dhcp.go`、`go_fork_source/sing-box-1.12.12/include/tailscale.go:17-19`）。HTTP3 (DoH over HTTP/3) 已于 2025-11-10 完成实现（`crates/sb-core/src/dns/transport/doh3.rs`）。

## 功能总览（Feature Index）

| 类别 | 状态 | 备注 |
| --- | --- | --- |
| CLI 子命令 | ◐ Partial | 子命令面齐全，但 `tools connect` 仍手动调用 `Bridge::new_from_config`，缺乏 router handle，因此无法驱动 adapter 路径或 selector/health 能力（`app/src/cli/tools.rs:126`、`app/src/cli/tools.rs:188`）。 |
| 配置/IR/校验 | ◐ Partial | `sb-config` 顶层只暴露 inbounds/outbounds/log/dns/certificate/ntp（`crates/sb-config/src/ir/mod.rs:382-404`），`InboundType`/`OutboundType` 仍停留在 7/13 个内建项（`crates/sb-config/src/ir/mod.rs:21-80`），没有 endpoint/service/dns outbound/wireguard/tor/anytls/hysteria(v1) 的 schema。 |
| 运行时与热重载 | ◐ Partial | Supervisor 会重新构建 engine 并调用 adapter-first bridge，但由于 IR 无法描述新协议，热重载仍只能覆盖少量入/出站（`crates/sb-core/src/runtime/supervisor.rs:104`、`crates/sb-core/src/adapter/bridge.rs:2153`）。 |
| 路由/桥接 | ◐ Partial | `to_inbound_param` 只识别 `socks/http/mixed/tun/redirect/tproxy/direct`，Redirect/TProxy 继续返回 `UnsupportedInbound`，其它协议型入站完全没有入口（`crates/sb-core/src/adapter/bridge.rs:203`、`crates/sb-core/src/adapter/bridge.rs:328`）。 |
| DNS 子系统 | ◐ Partial | Resolver 支持 `system/udp/doh/dot/doq/doh3` upstream 与 hosts/fakeip overlay（`crates/sb-core/src/dns/config_builder.rs:13-176`），DHCP/tailscale/resolved 传输与服务入口未实现。DoH3 于 2025-11-10 完成（`dns/transport/doh3.rs`）。 |
| 协议出站 | ◐ Partial | Adapter/scaffold 仅能构建 direct/block/http/socks/shadowsocks/vless/vmess/trojan/tuic/hysteria2/shadowtls/ssh/urltest/selector，但 `adapter-dns` 现在可注册 `dns` 连接（需 IP `server` 和 new `dns_*` IR 字段）；Go 独有的 tor/anytls/wireguard/hysteria(v1) 仍缺席（`crates/sb-core/src/adapter/bridge.rs:239-257`、`crates/sb-core/src/adapter/bridge.rs:500-730`、`crates/sb-adapters/src/register.rs:530-577`）。 |
| 协议入站 | ✗ Missing | `InboundType` 只有 `socks/http/mixed/tun/redirect/tproxy/direct`（`crates/sb-config/src/ir/mod.rs:21-45`），即便 adapter 提供 Naive/ShadowTLS/Trojan/TUIC/Hysteria(H1/H2) 模块也无法被 IR/Bridge 调用。 |
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
| direct | ✅ | ✗ Missing | 未注册 | IR 枚举中定义但无实现 |
| socks | ✅ | ✅ Supported | 已注册 | 完整实现并注册 `sb-adapters/src/inbound/socks/` |
| http | ✅ | ✅ Supported | 已注册 | 完整实现并注册 `sb-adapters/src/inbound/http.rs` |
| mixed | ✅ | ✅ Supported | 已注册 | 完整实现并注册 `sb-adapters/src/inbound/mixed.rs` |
| shadowsocks | ✅ | ✅ Supported | 已注册 | 完整实现并注册 `sb-adapters/src/inbound/shadowsocks.rs` |
| vmess | ✅ | ✅ Supported | 已注册 | 完整实现并注册 `sb-adapters/src/inbound/vmess.rs` |
| trojan | ✅ | ✅ Supported | 已注册 | 完整实现并注册 `sb-adapters/src/inbound/trojan.rs` |
| naive | ✅ | ⚠ Stub | 已注册 | 实现文件存在但注册为 stub，返回警告 (`register.rs:478-484`) |
| shadowtls | ✅ | ⚠ Stub | 已注册 | 实现文件存在但注册为 stub，返回警告 (`register.rs:486-492`) |
| vless | ✅ | ✅ Supported | 已注册 | 完整实现并注册 `sb-adapters/src/inbound/vless.rs` |
| anytls | ✅ | ⚠ Stub | 已注册 | 注册为 stub，返回警告 (`register.rs:518-524`) |
| hysteria (v1) | ✅ (QUIC) | ⚠ Stub | 已注册 | 实现文件存在但注册为 stub，返回警告 (`register.rs:494-500`) |
| tuic | ✅ (QUIC) | ⚠ Stub | 已注册 | 实现文件存在但注册为 stub，返回警告 (`register.rs:510-516`) |
| hysteria2 | ✅ (QUIC) | ⚠ Stub | 已注册 | 实现文件存在但注册为 stub，返回警告 (`register.rs:502-508`) |

**Rust 入站实现小结：**
- 完整实现并注册：10 种 (socks, http, mixed, shadowsocks, vmess, trojan, vless, tun, redirect, tproxy)
- 注册为 stub (返回警告)：6 种 (naive, shadowtls, hysteria, hysteria2, tuic, anytls)
- 完全缺失：1 种 (direct)
- **总计：17 种入站中，10 种完全可用 (59%)，较前次 +3 种（+18%）**

### 出站协议对比（Outbound Protocols）

| 协议 | Go 1.12.12 | Rust 实现状态 | 注册状态 | 说明 |
| --- | --- | --- | --- | --- |
| direct | ✅ | ◐ Partial | scaffold | 仅 scaffold 实现，无 adapter |
| block | ✅ | ◐ Partial | scaffold | 仅 scaffold 实现，无 adapter |
| dns | ✅ | ✅ Supported | 已注册 | 完整实现，feature-gated (`adapter-dns`)，支持 UDP/TCP/DoT/DoH/DoQ |
| selector | ✅ (group) | ◐ Partial | scaffold | 仅 scaffold 实现 `SelectorGroup` |
| urltest | ✅ (group) | ◐ Partial | scaffold | 仅 scaffold 实现 `SelectorGroup` |
| socks | ✅ | ✅ Supported | 已注册 | 完整实现并注册 `sb-adapters/src/outbound/socks5.rs` |
| http | ✅ | ✅ Supported | 已注册 | 完整实现并注册 `sb-adapters/src/outbound/http.rs` |
| shadowsocks | ✅ | ✅ Supported | 已注册 | 完整实现并注册 `sb-adapters/src/outbound/shadowsocks.rs` |
| vmess | ✅ | ✅ Supported | 已注册 | 完整实现并注册 `sb-adapters/src/outbound/vmess.rs` |
| trojan | ✅ | ✅ Supported | 已注册 | 完整实现并注册 `sb-adapters/src/outbound/trojan.rs` |
| tor | ✅ | ⚠ Stub | 已注册 | 注册为 stub，返回警告 (`register.rs:588-594`) |
| ssh | ✅ | ◐ Partial | scaffold | 实现文件存在但仅走 scaffold 路径 |
| shadowtls | ✅ | ◐ Partial | scaffold | 实现文件存在但不完整 |
| vless | ✅ | ✅ Supported | 已注册 | 完整实现并注册 `sb-adapters/src/outbound/vless.rs` |
| anytls | ✅ | ⚠ Stub | 已注册 | 注册为 stub，返回警告 (`register.rs:596-602`) |
| hysteria (v1) | ✅ (QUIC) | ⚠ Stub | 已注册 | 注册为 stub，返回警告 (`register.rs:612-618`) |
| tuic | ✅ (QUIC) | ✅ Supported | 已注册 | 完整实现并注册 `sb-core/src/outbound/tuic.rs` + adapter (`register.rs:679-761`, feature: `out_tuic`) |
| hysteria2 | ✅ (QUIC) | ✅ Supported | 已注册 | 完整实现并注册 `sb-core/src/outbound/hysteria2.rs` + adapter (`register.rs:763-858`, feature: `out_hysteria2`) |
| wireguard | ✅ | ⚠ Stub | 已注册 | 注册为 stub，返回警告 (`register.rs:604-610`) |

**Rust 出站实现小结：**
- 完整实现并注册：10 种 (direct-scaffold, http, socks, shadowsocks, vmess, trojan, vless, dns, tuic, hysteria2)
- 实现文件存在但不完整：3 种 (selector, urltest, ssh, shadowtls)
- 注册为 stub (返回警告)：4 种 (tor, anytls, hysteria v1, wireguard)
- 完全缺失：2 种 (block 缺少 adapter)
- **总计：19 种出站中，10 种完全可用 (53%)，较前次 +2 种（+11%）**

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
