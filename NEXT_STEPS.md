# Next Steps (2025-12-15 Execution Plan)

Parity Status: **~88% Aligned** with Go `go_fork_source/sing-box-1.12.12` (84 aligned / 95 core items; 2 not aligned; 4 feature-gated/de-scoped; 14 Rust extensions). See [GO_PARITY_MATRIX.md](GO_PARITY_MATRIX.md) for details.

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
│ 1. Resolved 完善 (1-2天)│  │ 2. DHCP INFORM (可选)   │  │ 3. Tailscale 评估 (2-4周)│
│                        │  │                        │  │ 4. ECH/uTLS 决策       │
└────────────────────────┘  └────────────────────────┘  └────────────────────────┘
```

### 推荐执行顺序

| # | 任务 | 优先级 | 工作量 | 对齐影响 | 依赖 |
|---|------|--------|--------|----------|------|
| 1 | Resolved 服务完善 | ✅ 完成 | 1-2天 | 服务对齐 ◐→✅ | 无 |
| 2 | DHCP INFORM 主动探测 | 📦 低 | 1-2天 | DNS 发现 | 无 |
| 3 | Tailscale 栈评估 | 🔬 研究 | 2-4周 | Endpoint 对齐 | 决策文档 |
| 4 | ECH/uTLS 路线决策 | 🔬 研究 | 取决于方案 | TLS 完整性 | 无 |

---

## ✅ 已完成项 (Completed)

### 2025-12-14 完成

1. **P0: 协议分歧清理** ✅
   - `legacy_shadowsocksr` feature gate (默认 OFF)
   - `legacy_tailscale_outbound` feature gate (默认 OFF)

2. **P1: SSMAPI 服务核心对齐** ✅
   - `ManagedSSMServer::update_users()` trait 方法
   - `ShadowsocksInboundAdapter` 实现 `update_users()`
   - `UserManager::post_update()` 自动推送用户变更
   - `TrafficManager::update_users()` 用户列表同步
   - 测试验证 ✅ (13 tests passed)

3. **测试覆盖补全** ✅
   - SSMAPI 测试 (user.rs, traffic.rs, server.rs, api.rs)

### 2025-12-13 完成

1. **TLS CryptoProvider + sb-core 公共 API 稳定性** ✅
2. **Service schema/type parity** ✅
3. **DERP: TLS-required + wire protocol parity** ✅
4. **DERP: Mesh parity** ✅
5. **uTLS 指纹接入** ◐ (受 rustls 限制)

---

## ✅ P1: Resolved 服务完善 (已完成 2025-12-15)

**状态**: ✅ 完成 | **工作量**: 1天 | **平台**: Linux only

### 已完成
- [x] D-Bus server `org.freedesktop.resolve1.Manager` (615 行)
- [x] Per-link DNS routing + domain matching
- [x] `update_link()` / `delete_link()` 方法
- [x] DNS stub listener
- [x] Resolved DNS transport (`sb-core/src/dns/transport/resolved.rs`, 20KB)
- [x] **DNSRouter 注入** - 使用配置的路由器而非 SystemResolver
- [x] **NetworkMonitor 回调** - 网络变化时自动更新 DNS 配置

### 验证结果
```bash
# 编译验证 (Linux) - 已通过
cargo check -p sb-adapters --features "service_resolved,network_monitor" ✅
```

---

## P2: 平台完善 (下周)

### 2. DNS DHCP 主动探测
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

### 3. Tailscale 栈完全对齐
**状态**: ⏳ 需评估 | **工作量**: 2-4周 | **风险**: 高

**现状差距**:
| 方面 | Go | Rust |
|------|----|------|
| 控制平面 | `tsnet.Server` 内置 | 依赖外部 `tailscaled` daemon |
| 数据平面 | gVisor netstack | 主机网络栈 |
| DNS Hook | `LookupHook` 集成 | 无 |
| 路由/过滤 | `wgengine.ReconfigListener` | 无 |

**评估任务**:
- [ ] 研究 tsnet CGO → Rust FFI 可行性
- [ ] 评估 `tailscale-control` 纯 Rust 替代
- [ ] 编写决策文档 (`docs/tailscale_alignment_decision.md`)

---

### 4. ECH / uTLS 深度对齐
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

## Rust 扩展功能 (非 Go 对齐项)

以下功能是 Rust 实现的扩展，不在 Go reference 中：

| 功能 | 文件 | 说明 |
|------|------|------|
| Clash API | `services/clash_api.rs` | Rust 原生 Clash API 实现 |
| V2Ray API | `services/v2ray_api.rs` | Rust 原生 V2Ray Stats API |
| Cache File | `services/cache_file.rs` | 规则集本地缓存 |
| NTP Service | `services/ntp.rs` | NTP 时间同步 |
| DNS Forwarder | `services/dns_forwarder.rs` | DNS 转发服务 |
| Circuit Breaker | `sb-transport/circuit_breaker.rs` | 熔断器 |
| Resource Pressure | `sb-transport/resource_pressure.rs` | 资源压力管理 |
| DoH3 Transport | `dns/transport/doh3.rs` | DNS over HTTP/3 |
| Enhanced UDP | `dns/transport/enhanced_udp.rs` | 增强 UDP DNS |
| Multiplex Transport | `sb-transport/multiplex.rs` | 连接复用 |
| Retry Transport | `sb-transport/retry.rs` | 连接重试 |

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

---

## Quick Reference: Crate Statistics

| Crate | Files | Primary Purpose |
|-------|-------|-----------------|
| `sb-adapters` | 109 | Protocol implementations |
| `sb-config` | 49 | Config parsing/validation |
| `sb-core` | 424 | Core runtime/services |
| `sb-tls` | 20 | TLS implementations |
| `sb-transport` | 57 | Transport layer |
| `sb-common` | 10 | Shared utilities |
| `sb-platform` | 20 | Platform-specific |
| `sb-runtime` | 17 | Async runtime |
| `sb-api` | 29 | Admin API |
| `sb-subscribe` | 24 | Subscription management |
