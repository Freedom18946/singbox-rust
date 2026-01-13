# singbox-rust 项目规范文档

> **Rust 版本**: 1.92  
> **许可证**: Apache-2.0  
> **对标**: sing-box Go 1.12.14

---

## 1. 项目概述

singbox-rust 是 sing-box 代理平台的 Rust 实现版本，旨在提供与 Go 版本功能对等的高性能网络代理工具。项目采用 Cargo workspace 架构，模块化设计，使用 feature flags 进行细粒度功能控制。

### 1.1 核心特性

- **协议支持**: SOCKS5, HTTP, Shadowsocks, VMess, VLESS, Trojan, Hysteria, Hysteria2, TUIC, WireGuard, SSH, ShadowTLS, AnyTLS, Naive
- **透明代理**: TUN 设备、redirect、tproxy
- **智能路由**: 基于规则的流量分流，支持 GeoIP、GeoSite、进程匹配
- **DNS 管理**: 多策略 DNS、FakeIP、hosts、缓存
- **传输层**: WebSocket, gRPC, HTTP/2, QUIC, 多路复用 (smux/yamux)
- **TLS**: REALITY, ECH, uTLS 指纹模拟
- **可观测性**: Prometheus metrics、诊断 HTTP 服务
- **企业特性**: 认证、限流、热重载

### 1.2 架构概览

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              app (主入口)                                │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌──────────────┐    │
│  │    CLI      │  │  Bootstrap  │  │   Logging   │  │   Telemetry  │    │
│  └─────────────┘  └─────────────┘  └─────────────┘  └──────────────┘    │
├─────────────────────────────────────────────────────────────────────────┤
│                              sb-core (核心引擎)                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌──────────────┐    │
│  │   Router    │  │    DNS      │  │   Inbound   │  │   Outbound   │    │
│  │   引擎      │  │   系统      │  │   管理器    │  │   管理器     │    │
│  └─────────────┘  └─────────────┘  └─────────────┘  └──────────────┘    │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌──────────────┐    │
│  │  Services   │  │  Endpoints  │  │  Metrics    │  │  Diagnostics │    │
│  │  后台服务   │  │   端点      │  │  监控指标   │  │   诊断       │    │
│  └─────────────┘  └─────────────┘  └─────────────┘  └──────────────┘    │
├─────────────────────────────────────────────────────────────────────────┤
│                           sb-adapters (协议适配器)                       │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │  Inbound: HTTP, SOCKS, Shadowsocks, VMess, VLESS, Trojan, TUN...  │  │
│  │  Outbound: Direct, Block, SOCKS, HTTP, SS, VMess, VLESS, Trojan...│  │
│  │  Endpoint: WireGuard, Tailscale                                   │  │
│  │  Service: Resolved, DERP, SSM-API                                 │  │
│  └───────────────────────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────────────────────┤
│                            sb-transport (传输层)                         │
│  ┌────────┐┌────────┐┌────────┐┌────────┐┌────────┐┌────────┐          │
│  │  TLS   ││WebSocket│ gRPC   ││HTTP/2  ││  QUIC  ││Multiplex│         │
│  └────────┘└────────┘└────────┘└────────┘└────────┘└────────┘          │
├─────────────────────────────────────────────────────────────────────────┤
│  sb-config │ sb-tls │ sb-metrics │ sb-runtime │ sb-api │ sb-subscribe  │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Workspace 成员

| Crate | 文件数 | 描述 |
|-------|--------|------|
| `app` | 341 | 主入口，CLI 命令，服务启动 |
| `sb-core` | 439 | 核心引擎：路由、DNS、入站/出站管理 |
| `sb-adapters` | 110 | 协议适配器：入站/出站/端点/服务实现 |
| `sb-config` | 54 | 配置解析、验证、IR 转换 |
| `sb-transport` | 57 | 传输层：TLS、WebSocket、gRPC、QUIC、多路复用 |
| `sb-tls` | 20 | TLS 实现：REALITY、ECH |
| `sb-runtime` | 17 | 运行时辅助：握手、场景测试 |
| `sb-metrics` | 9 | Prometheus 指标 |
| `sb-api` | 29 | Clash API、V2Ray API |
| `sb-subscribe` | 24 | 订阅解析（Clash、SingBox 格式） |
| `sb-platform` | 22 | 平台适配 |
| `sb-proto` | 9 | 协议定义 |
| `sb-types` | 2 | 共享类型 |
| `sb-common` | 10 | 通用工具 |
| `sb-security` | 5 | 安全工具 |
| `sb-test-utils` | 3 | 测试工具 |
| `sb-admin-contract` | 2 | 管理接口契约 |
| `benches` | 12 | 性能基准测试 |
| `xtask` | 3 | 构建任务 |
| `xtests` | 17 | 扩展测试 |

---

## 3. Feature Flags 体系

### 3.1 聚合特性

| Feature | 含义 |
|---------|------|
| `acceptance` | 验收构建：router + tools + observe + admin_debug + auth 等 |
| `adapters` | 所有协议适配器 |
| `full` | 完整功能 |

### 3.2 核心特性

| Feature | 描述 |
|---------|------|
| `router` | 路由引擎 |
| `observe` | 可观测性 (metrics) |
| `admin_debug` | 管理调试接口 |
| `tools` | 工具命令 |
| `explain` | 路由解释 |

### 3.3 协议特性

| Feature | 协议 |
|---------|------|
| `adapter-socks` | SOCKS5 |
| `adapter-http` | HTTP |
| `adapter-shadowsocks` | Shadowsocks |
| `adapter-vmess` | VMess |
| `adapter-vless` | VLESS |
| `adapter-trojan` | Trojan |
| `adapter-hysteria` | Hysteria |
| `adapter-hysteria2` | Hysteria2 |
| `adapter-tuic` | TUIC |
| `adapter-wireguard` | WireGuard |
| `adapter-tun` | TUN |
| `adapter-tor` | Tor |
| `adapter-naive` | NaiveProxy |
| `adapter-shadowtls` | ShadowTLS |
| `adapter-anytls` | AnyTLS |

### 3.4 传输特性

| Feature | 传输 |
|---------|------|
| `transport_tls` | TLS |
| `tls_reality` | REALITY |
| `tls_ech` | ECH |
| `transport_mux` | 多路复用 |
| `transport_ws` | WebSocket |
| `transport_grpc` | gRPC |
| `v2ray_transport` | V2Ray 传输 |

---

## 4. 文档索引

- [01-architecture.md](./01-architecture.md) - 架构设计详解
- [02-app-crate.md](./02-app-crate.md) - 主入口 crate
- [03-sb-core.md](./03-sb-core.md) - 核心引擎 crate
- [04-sb-adapters.md](./04-sb-adapters.md) - 协议适配器 crate
- [05-sb-transport.md](./05-sb-transport.md) - 传输层 crate
- [06-sb-config.md](./06-sb-config.md) - 配置系统
- [07-router-engine.md](./07-router-engine.md) - 路由引擎详解
- [08-dns-system.md](./08-dns-system.md) - DNS 系统详解
- [09-supporting-crates.md](./09-supporting-crates.md) - 辅助 crate
- [10-build-testing.md](./10-build-testing.md) - 构建与测试
