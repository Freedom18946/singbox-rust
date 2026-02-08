# L2 功能对齐 — 缺口分析（L2 Parity Gap Analysis）

> **分析日期**：2026-02-08
> **数据来源**：`GO_PARITY_MATRIX.md`（2026-01-31 校准）+ L1 后回归验证
> **分析 Agent**：Claude Code (Opus 4.6)

---

## 总体状态

| 指标 | 值 |
|------|-----|
| **总对标项** | 209 |
| **完全对齐 (✅)** | 183 (88%) |
| **部分对齐 (◐)** | 15 (7%) |
| **未对齐 (❌)** | 3 (1%) |
| **已排除 (⊘)** | 4 (2%) |
| **Rust 独有 (➕)** | 4 (2%) |
| **L1 后回归** | 4 处（已修复） |

---

## L1 后回归验证结果

| 回归 | 根因 | 修复状态 |
|------|------|---------|
| `xtests/out_trojan_smoke.rs` 编译失败 | 引用已删除的 `sb_core::outbound::trojan` | ✅ 已修复（删除测试文件） |
| `xtests/out_ss_smoke.rs` 编译失败 | 引用已删除的 `sb_core::outbound::shadowsocks` | ✅ 已修复（删除测试文件） |
| `shutdown_lifecycle` 2 个测试 panic | CryptoProvider 未初始化（L1.3 移除协议代码后暴露） | ✅ 已修复（Supervisor::start 添加初始化） |
| `telemetry.rs` OutboundKind 枚举不匹配 | L1.3 移除协议后 telemetry 仍引用旧 variant | ✅ 已修复（移除 dead arms） |
| `app --features router` maxminddb 错误 | **pre-existing**，maxminddb API 变更 | ⬜ 不是 L1 回归 |

**结论**：4 处 L1 回归全部已修复。`cargo test --workspace` 1431 passed, 0 failed。

---

## 15 个 Partial (◐) 项分类

### 1. 可忽略 / 已接受限制（6 项）

| 项 | 领域 | 说明 | 建议 |
|----|------|------|------|
| uTLS fingerprint | TLS | rustls 无法完全复制 ClientHello 排序 | 接受限制，已文档化 |
| REALITY client | TLS | 证书验证 permissive | 接受限制 |
| REALITY server | TLS | leaf cloning 不完整 | 接受限制 |
| ECH | TLS | QUIC/server-side pending | 接受限制 |
| TLS fragment | Utility | Windows ACK best-effort | 接受限制 |
| WireGuard endpoint | Endpoint | UDP listen/reserved 不支持 | 接受限制 |

### 2. 架构/集成层缺口（6 项 — L2 核心工作）

| PX ID | 领域 | 当前状态 | 缺口核心 | 工作量 |
|-------|------|---------|---------|--------|
| PX-004 | DNS 栈 | env-gated/minimal | 无 Go-style DNSRouter/TransportManager/RuleAction 流程; 无 EDNS0 subnet/TTL rewrite/RDRC | 大 |
| PX-006 | Adapter 管理器 | registry-only | lifecycle stages/dependency ordering/default outbound 缺失 | 大 |
| PX-007 | Adapter 接口 | IR/registry-based | 缺 Go handler/upstream wrappers, Router/RuleSet interfaces | 大 |
| PX-008 | DNS/FakeIP | env-only LRU | 缺 DNSRouter/DNSClient/TransportManager/RDRC | 大 |
| PX-009 | 时间/证书/缓存服务 | global-only | 缺 adapter-level surfaces, cache_file 缺 mode/selection/rule_set | 中 |
| PX-010 | Clash API | mostly stubbed | 未 wire 到 router/dns/cache/history | 大 |

### 3. 服务实现缺口（3 项）

| PX ID | 服务 | 缺口 | 工作量 |
|-------|------|------|--------|
| PX-011 | SSMAPI | per-endpoint binding/tracker/API 偏差 | 中 |
| PX-012 | V2Ray API | router-wide ConnectionTracker + HTTP JSON | 中 |
| PX-013 | Cache File | BoltDB buckets/cache_id/FakeIP metadata/RDRC | 大 |
| PX-014 | DERP | config/behavior 偏差 | 中 |
| PX-015 | Resolved | UDP-only, 缺 resolve1 D-Bus methods | 中 |

---

## 3 个 Not Aligned (❌) 项

| 领域 | 问题 | 对应 PX |
|------|------|--------|
| Repository Structure | 缺 `clients/`, `include/`, `release/` | ⊘ 已排除 |
| Config schema | `schema_version` vs `$schema` 偏差 | PX-002 |
| Route/rules | 部分 rule actions/logical rules 偏差 | PX-003 (大部分已修复) |

---

## L2 工作分层建议

### Tier 1: 用户直接可感知功能（优先）

这些直接影响 GUI.for SingBox 兼容性和实际可用性：

| 工作项 | 对应 PX | 影响 | 说明 |
|--------|---------|------|------|
| **app maxminddb 修复** | — | GeoIP CLI 不可用 | pre-existing 但阻塞 router build |
| **Config schema 兼容** | PX-002 | 配置文件不兼容 | schema_version vs $schema |
| **Clash API 完整化** | PX-010 | GUI 无法获取代理列表/切换 | GUI.for 核心交互点 |
| **CLI 参数对齐** | M2.3 | GUI 启动/检查/版本命令 | `-c`/`-C`/`-D` 等 |

### Tier 2: 运行时核心引擎（功能正确性）

| 工作项 | 对应 PX | 影响 | 说明 |
|--------|---------|------|------|
| **Adapter 生命周期** | PX-006 | 启动顺序/依赖解析 | Go 4-stage lifecycle |
| **DNS 栈对齐** | PX-004, PX-008 | DNS 解析行为不一致 | DNSRouter/RDRC/FakeIP |
| **Cache File 完整化** | PX-013 | 重启后状态丢失 | mode/selection/FakeIP/RDRC |
| **ConnectionTracker** | PX-005, PX-012 | V2Ray API 统计不完整 | router-wide tracking |

### Tier 3: 服务补全（边缘功能）

| 工作项 | 对应 PX | 影响 | 说明 |
|--------|---------|------|------|
| **SSMAPI 对齐** | PX-011 | SS 管理面 | per-endpoint binding |
| **DERP 配置对齐** | PX-014 | mesh 网络 | config schema |
| **Resolved 完整化** | PX-015 | Linux DNS 集成 | resolve1 API |

### Tier 4: 已接受限制（不动）

- TLS uTLS/ECH/REALITY — rustls 库限制
- WireGuard endpoint UDP — userspace 限制
- TLS fragment Windows — 平台限制
- Tailscale endpoint — de-scoped
- ShadowsocksR — Go 已移除
- libbox/mobile/locale — de-scoped

---

## 编译状态矩阵

| 构建配置 | 状态 | 说明 |
|---------|------|------|
| `cargo check --workspace` | ✅ | 默认构建 |
| `cargo check -p sb-core` | ✅ | 默认 features |
| `cargo check -p sb-core --all-features` | ✅ | 所有 features |
| `cargo check -p app` | ✅ | 最小构建 |
| `cargo check -p app --features router` | ❌ | maxminddb API (pre-existing) |
| `cargo check -p app --features parity` | ❌ | 依赖 router → 同上 |
| `cargo test --workspace` | ✅ | 1431 passed, 0 failed |

**关键阻塞**：`app --features router` 的 `maxminddb` 编译错误阻塞 parity build。这是 L2 的第一个修复点。

---

## 功能对齐率预测

| 完成 Tier | 预计对齐率 | 增量 |
|-----------|-----------|------|
| 当前 | 88% (183/209) | — |
| Tier 1 完成 | ~92% | +4% (Clash API + Config + CLI) |
| Tier 2 完成 | ~96% | +4% (DNS + Lifecycle + Cache) |
| Tier 3 完成 | ~98% | +2% (服务补全) |
| Tier 4 (已接受) | 98% 封顶 | 剩余 2% 为库/平台限制 |

---

## L2 前置依赖

1. ✅ L1 架构整固完成（check-boundaries.sh exit 0）
2. ✅ L1 回归验证通过（1431 tests passed）
3. ⬜ `maxminddb` API 修复（阻塞 parity build）
4. ⬜ B3 feature flag 互斥分析（不严格阻塞但影响 feature 组合测试）

---

*分析日期：2026-02-08 | Agent：Claude Code (Opus 4.6)*
