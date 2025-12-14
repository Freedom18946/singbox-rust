# Next Steps (2025-12-14 Execution Plan)

Parity Status: **~86% Aligned** with Go `go_fork_source/sing-box-1.12.12` (79 aligned / 92 core items; 2 not aligned; 6 feature-gated/de-scoped). See [GO_PARITY_MATRIX.md](GO_PARITY_MATRIX.md) for details.

## Working Method (Strict)

All work is accepted **only** when the following three layers are satisfied and recorded:
1. **Source parity**: Rust implementation matches the Go reference behavior/API/types (cite the Go file + Rust file(s)).
2. **Test parity**: tests exist and are runnable locally (unit/integration), and they validate the behavior (not just compilation).
3. **Config/effect parity**: the config parameter(s) are demonstrated to change runtime behavior (via tests or reproducible config fixtures).

After each acceptance:
- Update `GO_PARITY_MATRIX.md` (status + notes + totals if applicable)
- Append a timestamped QA entry to `VERIFICATION_RECORD.md` (commands + evidence + conclusion)

---

## Execution Timeline & Roadmap

```
本周                        下周                        后续
┌────────────────────────┐  ┌────────────────────────┐  ┌────────────────────────┐
│ 🔥 P1: 高优先级         │→│ 📦 P2: 平台完善         │→│ 🔬 P3: 长期评估         │
│ 1. SSMAPI 收尾 (1-2天)  │  │ 3. Resolved 完善 (1-2天)│  │ 5. Tailscale 评估 (2-4周)│
│ 2. 测试覆盖补全 (1天)   │  │ 4. DHCP INFORM (可选)   │  │ 6. ECH/uTLS 决策       │
└────────────────────────┘  └────────────────────────┘  └────────────────────────┘
```

### 推荐执行顺序

| # | 任务 | 优先级 | 工作量 | 对齐影响 | 依赖 |
|---|------|--------|--------|----------|------|
| 1 | SSMAPI 服务收尾 | 🔥 高 | 1-2天 | 服务对齐 ◐→✅ | 无 |
| 2 | 测试覆盖补全 | 🔥 高 | 1天 | 验收证据 | P1.1 |
| 3 | Resolved 服务完善 | 📦 中 | 1-2天 | Linux 平台 | 无 |
| 4 | DHCP INFORM | 📦 低 | 1-2天 | DNS 发现 | 无 |
| 5 | Tailscale 栈评估 | 🔬 研究 | 2-4周 | Endpoint 对齐 | 决策文档 |
| 6 | ECH/uTLS 路线决策 | 🔬 研究 | 取决于方案 | TLS 完整性 | 无 |

---

## P0: 决策项 ✅ 已完成 (2025-12-14)

### 0. 协议分歧清理
**状态**: ✅ 已完成 | **决策**: 选项B（保留代码，feature 默认关闭）

**已实施**:
1. **ShadowsocksR**: 
   - Feature gate: `legacy_shadowsocksr` (默认 OFF)
   - 文件: `crates/sb-adapters/Cargo.toml`, `crates/sb-adapters/src/outbound/mod.rs`, `crates/sb-adapters/src/register.rs`

2. **Tailscale Outbound**: 
   - Feature gate: `legacy_tailscale_outbound` (默认 OFF)
   - 文件: `crates/sb-adapters/Cargo.toml`, `crates/sb-adapters/src/outbound/mod.rs`

**启用方式**: 在 `Cargo.toml` 中添加 feature 依赖：
```toml
[dependencies]
sb-adapters = { path = "crates/sb-adapters", features = ["legacy_shadowsocksr", "legacy_tailscale_outbound"] }
```

---

## P1: 高优先级 - 服务对齐 (本周)

### 1. SSMAPI 服务收尾 ✅ 核心对齐完成 (2025-12-14)
**状态**: ✅ 核心完成 | **剩余**: per-endpoint 状态管理 + 缓存格式优化（可选）

**已实现**:
- [x] `ManagedSSMServer::update_users()` trait 方法
- [x] `ShadowsocksInboundAdapter` 实现 `update_users()`
- [x] `UserManager` 重构：`with_server()` + `post_update()` 自动推送用户变更
- [x] `TrafficManager::update_users()` 用户列表同步
- [x] 编译验证 ✅ sb-core + sb-adapters
- [x] 测试验证 ✅ `cargo test -p sb-core --features service_ssmapi -- ssmapi`

**Go 对齐点**:
| Go | Rust | 状态 |
|----|------|-----|
| `UserManager.postUpdate()` | `UserManager::post_update()` | ✅ |
| `server.UpdateUsers(users, uPSKs)` | `ManagedSSMServer::update_users()` | ✅ |
| `TrafficManager.UpdateUsers()` | `TrafficManager::update_users()` | ✅ |

**后续优化** (可选):
- [ ] per-endpoint 状态管理
- [ ] per-endpoint 缓存格式

**Go 参考文件**:
- [`service/ssmapi/server.go`](file:///Users/bob/Desktop/Projects/ING/sing/singbox-rust/go_fork_source/sing-box-1.12.12/service/ssmapi/server.go)
- [`service/ssmapi/api.go`](file:///Users/bob/Desktop/Projects/ING/sing/singbox-rust/go_fork_source/sing-box-1.12.12/service/ssmapi/api.go)
- [`service/ssmapi/cache.go`](file:///Users/bob/Desktop/Projects/ING/sing/singbox-rust/go_fork_source/sing-box-1.12.12/service/ssmapi/cache.go)

**验收标准**:
```bash
# 编译验证
cargo check -p sb-core --features service_ssmapi

# 单元测试
cargo test -p sb-core --features service_ssmapi -- ssmapi

# 集成测试 (待补充)
cargo test -p sb-adapters --features "adapter-shadowsocks service_ssmapi" -- ssmapi_integration
```

---

### 2. 测试覆盖补全 ✅ 核心完成 (2025-12-14)
**状态**: ✅ SSMAPI 测试完成 | **剩余**: 可选 E2E 测试

**已完成测试** (13 tests):
| 测试文件 | 测试数 | 测试内容 |
|---------|--------|---------|
| `user.rs` | 5 | `with_server()`, `post_update()`, CRUD, 批量设置 |
| `traffic.rs` | 2 | 流量跟踪、清除 |
| `server.rs` | 3 | Service 创建、builder、生命周期 |
| `api.rs` | 3 | Server info、stats、user lifecycle |

**验证命令**:
```bash
cargo test -p sb-core --features service_ssmapi -- ssmapi  # ✅ 13 tests passed
```

**后续可选**:
- [ ] SS inbound 端到端绑定测试
- [ ] DERP 协议互操作测试

**测试文件位置**:
```
crates/sb-core/src/services/ssmapi/tests/
crates/sb-core/src/services/derp/tests/
crates/sb-adapters/tests/integration/
```

---

## P2: 平台完善 (下周)

### 3. Resolved 服务完善 (Linux)
**状态**: ◐ 部分完成 | **工作量**: 1-2天 | **平台**: Linux only

**已完成**:
- [x] D-Bus server `org.freedesktop.resolve1.Manager` (615 行)
- [x] Per-link DNS routing + domain matching
- [x] `update_link()` / `delete_link()` 方法
- [x] DNS stub listener

**待完成**:
| 缺口 | Go 参考 | 描述 |
|------|---------|------|
| DNSRouter 路由 | `service.go:L180-200` | 查询转发走配置的路由器，而非系统 resolver |
| NetworkMonitor 回调 | `service.go:L85-95` | 网络变化时更新 DNS 配置 |
| netlink 监听 | `netmon/netmon_linux.go` | Linux 网络接口变化监听 |

**Go 参考文件**:
- [`service/resolved/service.go`](file:///Users/bob/Desktop/Projects/ING/sing/singbox-rust/go_fork_source/sing-box-1.12.12/service/resolved/service.go)

**Rust 文件**:
- `crates/sb-adapters/src/service/resolved_impl.rs`
- `crates/sb-core/src/dns/transport/resolved.rs`

---

### 4. DNS DHCP 主动探测
**状态**: ⏳ 待评估 | **工作量**: 1-2天 | **优先级**: 低

**现状**:
- Rust: 仅 passive `resolv.conf` 监控
- Go: 主动 DHCP INFORM 探测 + 接口发现

**任务**:
- [ ] 评估是否需要 DHCP INFORM
- [ ] 添加接口发现
- [ ] 服务器超时和刷新处理

**Go 参考**: `dns/transport/dhcp/`

---

## P3: 长期评估

### 5. Tailscale 栈完全对齐
**状态**: ⏳ 需评估 | **工作量**: 2-4周 | **风险**: 高

**现状差距**:
| 方面 | Go | Rust |
|------|----|----|
| 控制平面 | `tsnet.Server` 内置 | 依赖外部 `tailscaled` daemon |
| 数据平面 | gVisor netstack | 主机网络栈 |
| DNS Hook | `LookupHook` 集成 | 无 |
| 路由/过滤 | `wgengine.ReconfigListener` | 无 |

**评估任务**:
- [ ] 研究 tsnet CGO → Rust FFI 可行性
- [ ] 评估 `tailscale-control` 纯 Rust 替代
- [ ] 编写决策文档 (`docs/tailscale_alignment_decision.md`)

**如可行的实现任务**:
- [ ] 控制平面认证集成
- [ ] netstack TCP/UDP 数据平面
- [ ] DNS hook
- [ ] 路由/过滤器集成

---

### 6. ECH / uTLS 深度对齐
**状态**: ⏳ 待决策 | **阻塞**: rustls 库限制

**uTLS 现状**:
| 方面 | 状态 | 说明 |
|------|------|------|
| 指纹名称 | ✅ | 所有 Go 指纹名称已对齐 |
| 配置解析 | ✅ | `UtlsFingerprint` 枚举完整 |
| 实际 ClientHello | ◐ | rustls 无法完全复刻扩展顺序 |

**ECH 现状**:
| 方面 | 状态 | 说明 |
|------|------|------|
| 配置解析 | ✅ | ECHConfigList 解析存在 |
| HPKE 原语 | ✅ | CLI keygen 可用 |
| 运行时握手 | ❌ | rustls 0.23 无 ECH 支持 |
| Go 状态 | ◐ | `go1.24+` build tag gated |

**可选路径**:
- **A) 接受限制**: 标注当前状态为 de-scope，记录理由
- **B) 替代 TLS 库**: 评估 boringssl FFI 或 openssl-rs
- **C) 等待 rustls**: 跟踪 rustls ECH 进展

---

### 7. Go `experimental/` 对齐决策
**状态**: ⊘ 已 De-scope | **影响**: 仅影响 ClashAPI/V2rayAPI 用户

**Go `experimental/` 内容**:
- `cachefile/` - 规则集持久缓存
- `clashapi/` - Clash API 兼容
- `v2rayapi/` - V2Ray 统计 API
- `libbox/` - 移动平台绑定
- `locale/` - 本地化
- `deprecated/` - 废弃特性警告

**决策**: 这些是 Go 特有的实验性功能，**不纳入 Rust 复刻范围**。Rust 实现专注于核心代理功能。

---

## 已完成项 (Completed)

0. **验收硬化：TLS CryptoProvider + sb-core 公共 API 稳定性** ✅ (2025-12-13)
   - `ensure_rustls_crypto_provider()` 在所有 TLS 构建前执行
   - workspace rustls 统一 ring-only

1. **Service schema/type parity** ✅ (2025-12-13)
   - `ssm-api` type string + `servers` map + Listen Fields 对齐

2. **DERP: TLS-required + wire protocol parity** ✅ (2025-12-13)
   - TLS-required + `config_path` + NaCl box ClientInfo/ServerInfo 对齐

3. **DERP: Mesh parity** ✅ (2025-12-13)
   - `meshKey` in ClientInfo 验证对齐

4. **uTLS 指纹接入** ◐ (2025-12-13)
   - 所有指纹名称对齐；完整 ClientHello 形状受 rustls 限制

5. **TLS CryptoProvider 收敛** ✅ (2025-12-13)

6. **协议分歧清理** ✅ (2025-12-14)
   - `legacy_shadowsocksr` + `legacy_tailscale_outbound` feature gates

---

## 验证要求

每个任务完成后（必须按三层验收记录）:
1. **Source**：列出对应 Go 文件与 Rust 文件、关键对齐点
2. **Tests**：新增/更新测试文件，并给出 `cargo test ...` 命令与结果
3. **Config/Effect**：列出关键配置参数 + 预期效果
4. 更新 `GO_PARITY_MATRIX.md`
5. 追加 `VERIFICATION_RECORD.md`

---

## Quick Reference: Go vs Rust Type Mapping

| Go Type | Rust Type | Location |
|---------|-----------|----------|
| `constant.TypeSSMAPI = "ssm-api"` | `ServiceType::Ssmapi` | `crates/sb-config/src/ir/mod.rs` |
| `constant.TypeDERP = "derp"` | `ServiceType::Derp` | `crates/sb-config/src/ir/mod.rs` |
| `constant.TypeResolved = "resolved"` | `ServiceType::Resolved` | `crates/sb-config/src/ir/mod.rs` |
| `option.SSMAPIServiceOptions` | `ServiceIR` with servers/cache_path | `crates/sb-config/src/ir/mod.rs` |
| `option.DERPServiceOptions` | `ServiceIR` with derp fields | `crates/sb-config/src/ir/mod.rs` |
| `option.ListenOptions` | `ServiceIR` listen/listen_port/etc | `crates/sb-config/src/ir/mod.rs` |
| `option.InboundTLSOptions` | `InboundTlsOptionsIR` | `crates/sb-config/src/ir/mod.rs` |

---

## Quick Reference: Feature Flags

| Feature | Purpose | Default |
|---------|---------|---------|
| `legacy_shadowsocksr` | Enable ShadowsocksR outbound (Go removed) | OFF |
| `legacy_tailscale_outbound` | Enable Tailscale outbound (Go has no outbound) | OFF |
| `service_ssmapi` | Enable SSMAPI service | ON (when used) |
| `service_derp` | Enable DERP service | ON (when used) |
| `service_resolved` | Enable Resolved service (Linux) | ON (when used) |
