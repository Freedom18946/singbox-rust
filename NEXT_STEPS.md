# Next Steps (2025-12-13 Execution Plan)

Parity Status: **~89% Aligned** with Go `go_fork_source/sing-box-1.12.12` (63 aligned / 71 total; 5 partial, 3 not aligned). See [GO_PARITY_MATRIX.md](GO_PARITY_MATRIX.md) for details.

## Working Method (Strict)

All work is accepted **only** when the following three layers are satisfied and recorded:
1. **Source parity**: Rust implementation matches the Go reference behavior/API/types (cite the Go file + Rust file(s)).
2. **Test parity**: tests exist and are runnable locally (unit/integration), and they validate the behavior (not just compilation).
3. **Config/effect parity**: the config parameter(s) are demonstrated to change runtime behavior (via tests or reproducible config fixtures).

After each acceptance:
- Update `GO_PARITY_MATRIX.md` (status + notes + totals if applicable)
- Append a timestamped QA entry to `VERIFICATION_RECORD.md` (commands + evidence + conclusion)

## Execution Timeline

```
P0 快速收益 (1-2天)    → P1 核心对齐 (1周)    → P2 平台完善 (2周)    → P3 评估
├─ 0. 验收阻塞清理     ├─ 3. DERP H2/WS端点  ├─ 5. Resolved动态    ├─ 7. Tailscale评估
├─ 1. 测试漂移修复     ├─ 4. SSMAPI收尾      ├─ 6. DHCP INFORM
└─ 2. uTLS接入握手
```

---

## Current Work Queue (Ordered)

All items below must satisfy the **three-layer acceptance** (Source + Tests + Config/Effect) and be recorded in `VERIFICATION_RECORD.md`.

1. **DERP: Wire protocol parity (blocker)**
   - Align Rust DERP framing to sagernet/tailscale `derp` (`ProtocolVersion=2`, naclbox ClientInfo/ServerInfo, frame IDs, ping/pong, etc.)
   - Target files: Go `github.com/sagernet/tailscale/derp/*` vs Rust `crates/sb-transport/src/derp/protocol.rs` + `crates/sb-core/src/services/derp/*`

2. **DERP: Mesh parity migration**
   - Remove Rust-only `/derp/mesh` + `x-derp-mesh-psk` divergence
   - Align to Go mesh model: `SetMeshKey` + meshKey in encrypted ClientInfo + `derphttp.NewClient(...).MeshKey`
   - Add/enable mesh E2E tests (currently `mesh_test.rs` is ignored)

3. **DERP: `verify_client_endpoint` enforcement**
   - Match Go `SetVerifyClientLocalClient(endpoints)` behavior (requires Tailscale endpoint integration)
   - Add tests proving handshake rejects unauthorized clients when configured

4. **SSMAPI: Inbound binding + TLS**
   - Bind service to managed Shadowsocks inbounds (per-server routing prefixes)
   - Add optional TLS (and HTTP/2 when TLS is enabled)

5. **Resolved: netmon + netlink callbacks**
   - Register NetworkMonitor callbacks
   - Implement Linux netlink change tracking (scoped + tested)

6. **DHCP INFORM**
   - Add active DHCP INFORM probe + interface discovery

## P0: 快速收益 (1-2天)

### 0. 验收阻塞清理（让全套测试可用）
**状态**: ✅ 已完成 (2025-12-12) | **工作量**: 2-4小时 | **影响**: QA/CI 全套测试可全绿

**阻塞已解决**（来自 `VERIFICATION_RECORD.md` 2025-12-12 QA Session）:
- `sb-config`：`real_subscription_test` 缺少订阅 fixture 文件
- `app`：`report_health` 依赖 `report` bin（`dev-cli` 下编译失败，缺 `toml` 依赖）

**任务**:
- [x] 为 `crates/sb-config/tests/real_subscription_test.rs` 增加 fixture 或显式 gate
- [x] 修复 `dev-cli` feature 的 `report` bin 依赖/编译；并将 `report_health` 测试按 feature gate
- [x] 对齐 `version`/`sb-version` JSON 合约（RC tooling 所需字段）
- [x] 运行 `cargo test -p sb-config` 与 `cargo test -p app` 验证全绿

**文件**: `crates/sb-config/tests/real_subscription_test.rs`, `app/tests/report_health.rs`, `app/Cargo.toml`

---

### 1. 修复测试漂移 - InboundParam 字段
**状态**: ✅ 已完成 (2025-12-12) | **工作量**: 2-4小时 | **影响**: app 级测试漂移已清零

**问题**: `InboundParam` 添加了 7 个新字段，测试初始化未更新
- 缺失字段: `uuid`, `method`, `security`, `flow`, `masquerade`, `tun_options`, `users_shadowsocks`

**任务**:
- [x] 为 `InboundParam` 实现 `Default` trait
- [x] 更新 `app/tests/direct_inbound_test.rs` 使用 `..Default::default()`
- [x] 检查并修复其他有同样问题的测试文件（当前仅 direct_inbound 覆盖）
- [x] 运行 `cargo test -p app` 验证

**文件**: `crates/sb-core/src/adapter/mod.rs`, `app/tests/direct_inbound_test.rs`

---

### 2. uTLS 指纹接入 TLS 握手
**状态**: ✅ 已完成 (2025-12-12) | **工作量**: 1天 | **影响**: uTLS 指纹已接入标准/REALITY/ShadowTLS

**现状**:
- `utls_fingerprint` 已在标准 TLS（v2ray transport mapper）、REALITY client、ShadowTLS outbound 中实际生效
- Go `uTLSClientHelloID` 的 alias 名称已补齐（`chrome_psk*`, `chrome_pq*`, `ios`, `android`, `randomized` 等）

**任务**:
- [x] 在标准 TLS builder 路径中根据 `utls_fingerprint` 调用 `UtlsConfig`
- [x] 让 Standard/Reality/ShadowTLS 的 client 路径可选使用 uTLS config
- [x] 补齐与 Go `uTLSClientHelloID` 对应的 name→fingerprint 映射
- [x] 添加合约/回归测试覆盖（unknown fingerprint 拒绝、Reality config 校验等）

**文件**: `crates/sb-tls/src/utls.rs`, `crates/sb-tls/src/reality/`, `crates/sb-core/src/outbound/`, `crates/sb-adapters/src/register.rs`

---

## P1: 核心功能对齐 (1周)

### 3. DERP 服务对齐（H2/WS/端点）
**状态**: 🔄 进行中 | **工作量**: 3-5天 | **影响**: 支持完整 Tailscale 中继

**Go 参考**: `go_fork_source/sing-box-1.12.12/service/derp/service.go`

**已完成**:
- [x] `verify_client_urls` + `verify_client_endpoints` 字段
- [x] `from_ir` 读取配置
- [x] `verify_client_via_urls()` HTTP 验证函数
- [x] 现有: STUN, TLS acceptor, HTTP 路由 + Upgrade/WS + endpoints（已对齐 `derphttp`/`tsweb`）

**待完成（推荐推进顺序）**:
- [ ] **DERP wire protocol**：对齐 sagernet/tailscale `derp`（`ProtocolVersion=2`、naclbox ClientInfo/ServerInfo、frame IDs、ping/pong、meshKey 等），替换/升级当前 Rust-only framing
- [x] 用 hyper 替换当前 HTTP stub（支持 HTTP/1.1 + HTTP/2；保留现有 DERP 原始帧探测作为兼容路径）
- [x] `/derp`：实现 HTTP Upgrade DERP handler（`Upgrade: derp|websocket`；支持 `Derp-Fast-Start: 1`）；对齐 `derphttp.Handler(server)`
- [x] `/derp`：实现 WebSocket upgrade（仅当 `Upgrade: websocket` 且 `Sec-WebSocket-Protocol` 包含 `derp`；对齐 `addWebSocketSupport`）
- [x] 握手期 verify_client：`verify_client_url`（已在 ClientInfo 后、注册前强制拒绝）
- [ ] 握手期 verify_client：`verify_client_endpoint`（需要 Tailscale LocalClient / 等价能力）
- [x] 端点对齐：`/derp/probe`, `/derp/latency-check`（已对齐 Go `derphttp.ProbeHandler`）
- [x] 端点对齐：`/bootstrap-dns`（对齐 `handleBootstrapDNS`；使用全局 DNS resolver）
- [x] 端点对齐：`/` home（default/blank/redirect）、`/robots.txt`（`tsweb.AddBrowserHeaders`）、`/generate_204`（`derphttp.ServeNoContent` challenge/response）
- [ ] Mesh 行为对齐：移除 `/derp/mesh` + `x-derp-mesh-psk`，迁移到 Go mesh 机制（`SetMeshKey` + ClientInfo `meshKey` + `derphttp.NewClient(...).MeshKey`）

**验收标准（P1-3 关闭条件）**:
- Rust DERP 服务可被标准 DERP client（包含 WS 与非 WS 路径）成功握手并收发 DERP frame
- `verify_client_url` 配置开启时：验证失败会在握手期拒绝连接（可测）
- `/generate_204` 返回 204（含 `X-Tailscale-Challenge/Response`）；`/robots.txt` 文本一致且含 browser headers；`/bootstrap-dns?q=` 返回 JSON 映射；`/derp/probe` 行为与 Go 一致

**文件**: `crates/sb-core/src/services/derp/server.rs`

---

### 4. SSMAPI 服务收尾（Inbound 绑定 + TLS）
**状态**: ◐ 部分完成 | **工作量**: 0.5-1天 | **影响**: 支持多用户 SS 动态管理

**已实现**:
- [x] `TrafficManager` / `UserManager` 与 Go 字段对齐
- [x] `TrafficTracker` / `ManagedSSMServer` traits
- [x] `load_cache()`/`save_cache()` 持久化
- [x] Axum REST 路由对齐

**待完成**:
- [ ] 绑定到 `InboundManager`，按 server 前缀路由（Go: chi `entry.Key`）
- [ ] 让 Shadowsocks inbounds 实现并注册 `ManagedSSMServer`
- [ ] 可选 TLS + 自动启用 HTTP/2（Go 行为）

**文件**: `crates/sb-core/src/services/ssmapi/`, `crates/sb-adapters/src/inbound/shadowsocks.rs`

---

## P2: 平台完善 (2周)

### 5. Resolved 服务完善
**状态**: ✅ 大部分完成 | **工作量**: 0.5天 | **影响**: Linux systemd-resolved 集成

**已完成**:
- [x] ResolvedService (615 行) - D-Bus server, DNS stub listener
- [x] ResolvedTransport (702 行) - per-link DNS routing
- [x] `update_link()` / `delete_link()` 方法
- [x] LinkServers / LinkDomain 结构
- [x] Domain matching 和 search domains

**待完成** (平台特定):
- [ ] NetworkMonitor 回调注册 (当前 stub 33 行)
- [ ] Linux netlink 网络变化监听

**文件**: `crates/sb-adapters/src/service/resolved_impl.rs`, `crates/sb-core/src/dns/transport/resolved.rs`

---

### 6. DNS DHCP 主动探测
**状态**: ⏳ 待评估 | **工作量**: 1-2天 | **影响**: DHCP DNS 发现

**任务**:
- [ ] 评估现有 DNS 传输是否需要 DHCP INFORM
- [ ] 添加接口发现
- [ ] 服务器超时和刷新处理

**文件**: `crates/sb-core/src/dns/upstream.rs`, `crates/sb-core/src/dns/transport/`

---

## P3: 长期评估

### 7. Tailscale 栈完全对齐
**状态**: ⏳ 需评估 | **工作量**: 2-4周 | **风险**: 高

**评估任务**:
- [ ] 研究 tsnet CGO → Rust FFI 可行性
- [ ] 评估 `tailscale-control` 纯 Rust 替代
- [ ] 编写决策文档

**如可行的实现任务**:
- [ ] 控制平面认证集成
- [ ] netstack TCP/UDP 数据平面
- [ ] DNS hook (`LookupHook`)
- [ ] 路由/过滤器集成

---

### 8. ECH / Go experimental 取舍与对齐
**状态**: ⏳ 待决策 | **工作量**: 1-2天 | **风险**: 中

**任务**:
- [ ] 明确 Go `experimental/` 与 ECH 是否纳入 100% 复刻范围
- [ ] 如纳入：拆解模块 + 设计 Rust 实现路径
- [ ] 如不纳入：在 `GO_PARITY_MATRIX.md` 标注 de-scope 与理由

---

## 验证要求

每个任务完成后（必须按三层验收记录）:
1. **Source**：列出对应 Go 文件与 Rust 文件、关键对齐点
2. **Tests**：新增/更新测试文件，并给出 `cargo test ...` 命令与结果
3. **Config/Effect**：列出关键配置参数 + 预期效果（通过测试或可复现实例验证）
4. 更新 `GO_PARITY_MATRIX.md`
5. 追加 `VERIFICATION_RECORD.md`（带时间戳的 QA Session 记录）
