# sing-box Go 项目规范文档

> **版本**: 1.12.14  
> **语言**: Go 1.23.1  
> **许可证**: GPLv3  
> **官方文档**: https://sing-box.sagernet.org

---

## 1. 项目概述

sing-box 是一个通用代理平台（The Universal Proxy Platform），由 nekohasekai 开发，属于 SagerNet 生态系统的核心组件。它是一个功能完整的网络代理工具，支持多种代理协议、透明代理、TUN 设备、DNS 解析、流量路由等功能。

### 1.1 核心特性

- **多协议支持**: Shadowsocks, VMess, VLESS, Trojan, Hysteria, Hysteria2, TUIC, WireGuard, SSH, HTTP, SOCKS5 等
- **透明代理**: TUN 设备、redirect、tproxy
- **智能路由**: 基于规则的流量分流，支持 GeoIP、GeoSite、进程匹配等
- **DNS 管理**: 多 DNS 服务器、FakeIP、DNS 规则
- **跨平台**: Linux, macOS, Windows, Android, iOS
- **扩展性**: 支持 Clash API、V2Ray API

### 1.2 架构概览

```
┌─────────────────────────────────────────────────────────────┐
│                         Box (主引擎)                         │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │  Inbound    │  │  Outbound   │  │    Router           │  │
│  │  Manager    │──│  Manager    │──│  (路由规则引擎)     │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
│         │                │                    │              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   DNS       │  │  Network    │  │   Connection        │  │
│  │   Router    │──│  Manager    │──│   Manager           │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                    Protocol Layer                            │
│  ┌────────┐┌────────┐┌────────┐┌────────┐┌────────┐        │
│  │  SS    ││ VMess  ││ VLESS  ││Trojan  ││Hysteria│  ...   │
│  └────────┘└────────┘└────────┘└────────┘└────────┘        │
├─────────────────────────────────────────────────────────────┤
│                    Transport Layer                           │
│  ┌────────┐┌────────┐┌────────┐┌────────┐┌────────┐        │
│  │WebSocket│ gRPC   ││  H2    ││ QUIC   ││  TCP   │  ...   │
│  └────────┘└────────┘└────────┘└────────┘└────────┘        │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. 目录结构

```
sing-box-1.12.14/
├── box.go                    # 主引擎，Box 结构体和生命周期管理
├── adapter/                  # 核心接口定义层
├── protocol/                 # 协议实现层 (23种协议)
├── transport/                # 传输层实现 (11种传输)
├── route/                    # 路由引擎
├── dns/                      # DNS 解析系统
├── option/                   # 配置选项定义
├── common/                   # 通用工具库 (24个模块)
├── log/                      # 日志系统
├── constant/                 # 常量定义
├── experimental/             # 实验性功能
├── include/                  # 条件编译注册
├── service/                  # 服务层
├── cmd/                      # 命令行工具
├── clients/                  # 客户端实现
├── test/                     # 测试套件
├── docs/                     # 文档
└── release/                  # 发布配置
```

---

## 3. 核心依赖

| 依赖 | 版本 | 用途 |
|------|------|------|
| `github.com/sagernet/sing` | v0.7.14 | 核心网络库 |
| `github.com/sagernet/sing-tun` | v0.7.3 | TUN 设备支持 |
| `github.com/sagernet/sing-vmess` | v0.2.7 | VMess 协议 |
| `github.com/sagernet/sing-shadowsocks2` | v0.2.1 | Shadowsocks 协议 |
| `github.com/sagernet/quic-go` | v0.52.0-mod | QUIC 传输 |
| `github.com/sagernet/gvisor` | - | 用户态网络栈 |
| `github.com/sagernet/wireguard-go` | v0.0.1-beta.7 | WireGuard 协议 |
| `github.com/sagernet/tailscale` | v1.80.3-mod | Tailscale 集成 |
| `github.com/miekg/dns` | v1.1.67 | DNS 解析 |
| `github.com/metacubex/utls` | v1.8.3 | uTLS 指纹模拟 |

---

## 4. 生命周期管理

sing-box 采用四阶段启动机制：

```go
type StartStage uint8

const (
    StartStateInitialize StartStage = iota  // 初始化阶段
    StartStateStart                          // 启动阶段
    StartStatePostStart                      // 启动后阶段
    StartStateStarted                        // 完成启动
)
```

每个组件都实现 `Lifecycle` 接口：

```go
type Lifecycle interface {
    Start(stage StartStage) error
    Close() error
}
```

---

## 5. 文档索引

- [01-architecture.md](./01-architecture.md) - 架构设计详解
- [02-adapter-layer.md](./02-adapter-layer.md) - 适配器层接口
- [03-protocol-layer.md](./03-protocol-layer.md) - 协议实现层
- [04-transport-layer.md](./04-transport-layer.md) - 传输层实现
- [05-route-engine.md](./05-route-engine.md) - 路由引擎
- [06-dns-system.md](./06-dns-system.md) - DNS 系统
- [07-common-utilities.md](./07-common-utilities.md) - 通用工具库
- [08-option-config.md](./08-option-config.md) - 配置选项
- [09-experimental.md](./09-experimental.md) - 实验性功能
- [10-cmd-tools.md](./10-cmd-tools.md) - 命令行工具
- [11-constants-logging.md](./11-constants-logging.md) - 常量与日志系统
