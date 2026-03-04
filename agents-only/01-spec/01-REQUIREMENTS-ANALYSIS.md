# 需求分析（Requirements Analysis）

> **整体目标**：实现与 Go sing-box 1.12.14 的功能对等，同时满足 Rust 工程化的长期可维护性/可演进性/可测试性要求。

---

## 1. 功能需求（Functional Requirements）

### 1.1 协议支持

#### Inbound 协议（18/18 已对齐，含 accepted limitations）
| 协议 | 状态 | 备注 |
|------|------|------|
| SOCKS5, HTTP, Mixed | ✅ | 完整支持 |
| Direct, DNS | ✅ | 完整支持 |
| TUN (`tun.macos.tun2socks`) | ◐ | scaffold 模式默认；能力状态见 `docs/capabilities.md` |
| Redirect (`inbound.redirect`) | ◐ | Linux 代码存在，当前构建未接线，运行时报 clear error |
| TProxy (`inbound.tproxy`) | ◐ | Linux 代码存在，当前构建未接线，运行时报 clear error |
| Shadowsocks, VMess, VLESS, Trojan | ✅ | 多用户支持 |
| Naive, ShadowTLS, AnyTLS | ✅ | 完整支持 |
| Hysteria v1, Hysteria2, TUIC | ✅ | QUIC 支持 |

#### Outbound 协议（19/19 已对齐）
| 协议 | 状态 | 备注 |
|------|------|------|
| Direct, Block, HTTP, SOCKS5, DNS | ✅ | 完整支持 |
| Shadowsocks, VMess, VLESS, Trojan | ✅ | Stream conversion |
| SSH, ShadowTLS, Tor, AnyTLS | ✅ | 完整支持 |
| Hysteria v1, Hysteria2, TUIC | ✅ | QUIC 支持 |
| WireGuard | ✅ | 用户空间 |
| Selector, URLTest | ✅ | 组选择器 |

### 1.2 DNS 传输（11/11 已对齐）
- ✅ TCP, UDP, DoT, DoH, DoH3, DoQ
- ✅ system, local, DHCP
- ✅ resolved, tailscale (feature-gated)

### 1.3 路由规则（38/38 已对齐）
所有规则项完整支持：domain, cidr, port, process_name, geoip, geosite, clash_mode 等。

### 1.4 服务（Services）
| 服务 | 状态 | 备注 |
|------|------|------|
| DERP | ✅ | Relay/STUN/Mesh |
| Clash API | ✅ | Router/cache wiring |
| V2Ray API | ✅ | gRPC StatsService |
| Cache File | ✅ | Sled persistence |
| Resolved | ✅ | Linux feature-gated |
| SSMAPI | ✅ | Feature-gated |

---

## 2. 非功能需求（Non-Functional Requirements）

### 2.1 性能要求

| 指标 | 要求 | 当前状态 |
|------|------|---------|
| 原生进程匹配 | 149x faster than Go | ✅ macOS 验证 |
| 零拷贝解析 | 热路径最小化分配 | ✅ 实现 |
| 内存安全 | 无 GC 暂停 | ✅ Rust 保证 |

### 2.2 安全要求

- **密钥管理**：支持环境变量、文件、内联三种方式
- **凭证脱敏**：自动 redact tokens/keys/credentials
- **TLS 要求**：TLS 1.2+ 强制
- **依赖安全**：cargo-deny 检查所有 HIGH/CRITICAL 漏洞

### 2.3 可测试性要求

- sb-core 单元测试不需要真实网络栈（通过 mock ports）
- 协议适配器通过 integration tests 单独测试
- CI 强制执行依赖边界检查

---

## 3. 当前缺口分析（Gap Analysis）

### 3.1 Critical Gaps（需要行动）

| Gap | 严重度 | 描述 | 当前处理 |
|-----|--------|------|---------|
| Parity feature gates | 🔴 High | 默认构建注册 stub，需要 `--features parity` | 已定义 parity feature set |
| TLS fragmentation | 🟡 Medium | Windows ACK best-effort | 已记录限制 |
| WireGuard endpoint | 🟡 Medium | 用户空间不支持 UDP listen/reserved | 已记录限制 |
| TLS uTLS/ECH | 🟡 Medium | rustls 无法完全复制 ClientHello | 已接受限制 |

### 3.2 De-scoped（已移除）

| 项目 | 原因 |
|------|------|
| Tailscale endpoint | tsnet/gVisor 复杂度高 |
| ShadowsocksR | Go 已移除 |
| libbox/mobile | 移动客户端不在范围 |
| locale/release | 国际化/打包不在范围 |

---

## 4. 约束条件（Constraints）

### 4.1 技术约束

- **Rust 版本**：1.92+
- **Async Runtime**：tokio multi-thread
- **TLS 库**：rustls（无法完全模拟 uTLS）
- **QUIC 库**：quinn

### 4.2 架构约束（依赖宪法）

```
sb-types   <- sb-config
   ^            ^
   |            |
sb-core   <- sb-adapters  <- sb-transport / sb-tls / sb-platform
   ^
   |
sb-api / sb-metrics / sb-runtime
   ^
   |
  app (composition root)
```

**禁止违规**：
- sb-core 不能依赖 axum/tonic/tower/hyper/rustls/quinn
- sb-types 不能依赖 tokio/网络库
- sb-api 不能直接依赖 sb-adapters

---

*下一步：阅读 [02-ACCEPTANCE-CRITERIA.md](./02-ACCEPTANCE-CRITERIA.md) 了解验收标准*
