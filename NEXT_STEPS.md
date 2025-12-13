# Next Steps (2025-12-13 Execution Plan)

Parity Status: **~86% Aligned** with Go `go_fork_source/sing-box-1.12.12` (61 aligned / 71 total; 7 partial, 3 not aligned). See [GO_PARITY_MATRIX.md](GO_PARITY_MATRIX.md) for details.

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
├─ 2. uTLS接入握手
└─ 2b. TLS CryptoProvider收敛
```

---

## Current Work Queue (Ordered)

All items below must satisfy the **three-layer acceptance** (Source + Tests + Config/Effect) and be recorded in `VERIFICATION_RECORD.md`.

0. **验收硬化：TLS CryptoProvider + sb-core 公共 API/文档稳定性** ✅ 已完成 (2025-12-13)
   - Sweep all `sb-core` rustls config builder call sites and ensure `ensure_rustls_crypto_provider()` is executed before any `ClientConfig::builder()` / `ServerConfig::builder()`.
   - Consolidate scattered `install_default()` into a single source of truth (avoid per-module “best-effort” installs).
   - Converge workspace rustls provider features (prefer ring-only): eliminate dual-provider graphs (ring + aws-lc-rs) where possible via `default-features = false` + explicit provider feature selection.
   - Stabilize `sb-core` runtime public API import paths (e.g. `sb_core::runtime::Supervisor`) and keep crate doctests aligned to avoid future doc/test regressions.
   - Acceptance: `cargo test -p sb-core --features router` and core crates suites stay green; `shutdown_lifecycle` remains non-panicking.

1. **Service schema/type parity (blocker)** ✅ 已完成 (2025-12-13)
   - Service Listen Fields + shared `tls` object aligned to Go
   - `ssm-api` type string + `servers` endpoint→inbound map supported (legacy alias `ssmapi` accepted temporarily)
   - Acceptance: `cargo test -p sb-config`, `cargo test -p sb-core --features "service_derp service_ssmapi service_resolved"`, `cargo test -p sb-adapters`, `cargo test -p app`

2. **DERP: TLS-required + wire protocol parity (blocker)** ✅ 已完成 (2025-12-13)
   - ✅ Enforce TLS-required + `config_path` required behavior (Go rejects DERP without TLS; config_path required)
   - ✅ Align DERP framing to sagernet/tailscale `derp` (`ProtocolVersion=2`, NaCl box ClientInfo/ServerInfo, frame IDs/ping/pong; `config_path` key JSON `{"PrivateKey":"privkey:<hex>"}`)
   - Target files: Go `github.com/sagernet/tailscale/derp/*`, `go_fork_source/sing-box-1.12.12/service/derp/service.go` vs Rust `crates/sb-transport/src/derp/protocol.rs` + `crates/sb-core/src/services/derp/*`
   - Acceptance: `cargo test -p sb-core --features "service_derp" --lib`, `cargo test -p sb-core --features "service_derp service_ssmapi service_resolved"`, `cargo test -p sb-adapters --features "service_derp"`, `cargo test -p app`

3. **DERP: Mesh + `verify_client_endpoint` parity** ✅ 已完成 (2025-12-13)
   - ✅ Mesh 对齐 Go 模型：`meshKey` in ClientInfo 验证已实现（server.rs L1654-1665）
   - ✅ `/derp/mesh` endpoint 保留作向后兼容，已标记 DEPRECATED
   - ⊘ De-scoped: `verify_client_endpoint` 需要 Tailscale LocalClient daemon，当前为 warn-only

4. **SSMAPI: `ssm-api` parity (config + runtime)** 🔄 进行中
   - ✅ `type="ssm-api"` + `servers` parsing + `{endpoint}/server/v1/...` routing + TLS options are implemented
   - ✅ API response contract aligned: `GET /server/v1/users` returns `{"users":[UserObject...]}`
   - Remaining: Go `servers` mapping enforcement + per-endpoint cache format + `UpdateUsers` binding

5. **Protocol divergence cleanup**
   - Decide fate of Rust `tailscale` outbound (Go is endpoint-only)
   - Decide fate of Rust `shadowsocksr` outbound (Go registry rejects; removed upstream)

6. **Resolved: DNSRouter + netmon/netlink**
   - Route DNS via configured router (Go `adapter.DNSRouter` equivalent), not system resolver
   - Register NetworkMonitor callbacks + implement Linux netlink change tracking (scoped + tested)

7. **TLS fidelity (uTLS + ECH)**
   - Decide approach for full uTLS ClientHello parity and ECH runtime parity (blocked by rustls limitations)

8. **DHCP INFORM**
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
**状态**: ◐ 部分完成 (2025-12-12) | **工作量**: 1天 | **影响**: uTLS 指纹已接入，但与 Go/uTLS 的 on-wire ClientHello 仍不一致（extension order/shape 等）

**现状**:
- `utls_fingerprint` 已在标准 TLS（v2ray transport mapper）、REALITY client、ShadowTLS outbound 中实际生效
- Go `uTLSClientHelloID` 的 alias 名称已补齐（`chrome_psk*`, `chrome_pq*`, `ios`, `android`, `randomized` 等）
- 仍缺：完整 uTLS 指纹一致性（rustls 限制导致无法完全复刻 Go/uTLS 扩展顺序与 ClientHello 形状）

**任务**:
- [x] 在标准 TLS builder 路径中根据 `utls_fingerprint` 调用 `UtlsConfig`
- [x] 让 Standard/Reality/ShadowTLS 的 client 路径可选使用 uTLS config
- [x] 补齐与 Go `uTLSClientHelloID` 对应的 name→fingerprint 映射
- [x] 添加合约/回归测试覆盖（unknown fingerprint 拒绝、Reality config 校验等）

**文件**: `crates/sb-tls/src/utls.rs`, `crates/sb-tls/src/reality/`, `crates/sb-core/src/outbound/`, `crates/sb-adapters/src/register.rs`

---

### 2b. TLS CryptoProvider 收敛（全路径无 panic）
**状态**: ✅ 已完成 (2025-12-13) | **工作量**: 0.5-1天 | **影响**: 避免 rustls 0.23 在双 provider 依赖图下的运行时 panic；为后续 service/schema 对齐提供稳定测试基线

**现状**:
- 已修复：`sb-core` 在构建全局 TLS client config 时会触发的 CryptoProvider panic（`shutdown_lifecycle` 现已全绿）。
- 仍存在：`sb-core`/workspace 内部仍有多处散落的 `install_default()`；且依赖图可能仍同时启用 `ring` 与 `aws-lc-rs`（长期应收敛为单 provider）。

**任务**:
- [x] 在 `sb-core` TLS 全局配置构建前确保 provider 已安装（`tls::ensure_rustls_crypto_provider()`）。
- [x] 修复 `sb-core` crate-level doctest 代码片段，保证 `cargo test -p sb-core --doc` 可编译通过。
- [x] 为外部调用方提供稳定导入路径（在 `sb-core` 的 `runtime` 模块 re-export `Supervisor`），并同步更新文档片段与 doctest。
- [x] 扫描 `sb-core` 内所有 rustls builder 入口（`ClientConfig::builder()` / `ServerConfig::builder()`），统一在入口处调用 `ensure_rustls_crypto_provider()`。
- [x] 替换/移除散落的 `install_default()`（改为调用统一的 `ensure_rustls_crypto_provider()`），避免“局部修补”导致未来回归。
- [x] 收敛 workspace 依赖特性：rustls/tokio-rustls 统一 ring-only，并对 `anytls-rs` 进行本地 patch 以移除 aws-lc provider 源。
- [x] 验收回归：`cargo test -p sb-core --features router` + `cargo test -p sb-tls` + `cargo test -p sb-transport` + `cargo test -p sb-adapters` + `cargo test -p app`。

**文件**: `crates/sb-core/src/tls/mod.rs`, `crates/sb-core/src/tls/global.rs`, `crates/sb-core/src/*`（所有 rustls builder 调用点）, `crates/*/Cargo.toml`

## P1: 核心功能对齐 (1周)

### 3. DERP 服务对齐（H2/WS/端点）
**状态**: ✅ 已完成 (2025-12-13) | **工作量**: 3-5天 | **影响**: 支持完整 Tailscale 中继

**Go 参考**: `go_fork_source/sing-box-1.12.12/service/derp/service.go`

**已完成**:
- [x] `verify_client_urls` + `verify_client_endpoints` 字段
- [x] `from_ir` 读取配置
- [x] `verify_client_via_urls()` HTTP 验证函数
- [x] 现有: STUN, TLS acceptor, HTTP 路由 + Upgrade/WS + endpoints（已对齐 `derphttp`/`tsweb`）
- [x] **DERP wire protocol**：对齐 sagernet/tailscale `derp`（`ProtocolVersion=2`、NaCl box ClientInfo/ServerInfo、frame IDs、ping/pong、meshKey 等）
- [x] 用 hyper 替换当前 HTTP stub（支持 HTTP/1.1 + HTTP/2）
- [x] `/derp`：实现 HTTP Upgrade DERP handler（`Upgrade: derp|websocket`；支持 `Derp-Fast-Start: 1`）
- [x] `/derp`：实现 WebSocket upgrade（仅当 `Upgrade: websocket` 且 `Sec-WebSocket-Protocol` 包含 `derp`）
- [x] 握手期 verify_client：`verify_client_url`（已在 ClientInfo 后、注册前强制拒绝）
- [x] 端点对齐：`/derp/probe`, `/derp/latency-check`, `/bootstrap-dns`, `/`, `/robots.txt`, `/generate_204`
- [x] **Mesh 行为对齐**：`meshKey` in ClientInfo 验证已实现；`/derp/mesh` 保留作向后兼容

**已 De-scope**:
- ⊘ `verify_client_endpoint`：需要 Tailscale LocalClient daemon (Unix socket) 集成，当前为 warn-only

**验收标准（已满足）**:
- Rust DERP 服务可被标准 DERP client（包含 WS 与非 WS 路径）成功握手并收发 DERP frame ✅
- `verify_client_url` 配置开启时：验证失败会在握手期拒绝连接 ✅
- mesh peer 通过 `meshKey` in ClientInfo 认证 ✅

**文件**: `crates/sb-core/src/services/derp/server.rs`

---

### 4. SSMAPI 服务收尾（Inbound 绑定 + TLS）
**状态**: ❌ 未对齐 | **工作量**: 1-2天（不含测试） | **影响**: 当前实现无法作为 Go `ssm-api` 的 drop-in 替代

**已实现**:
- [x] HTTP server 基础骨架 + 部分 API handlers
- [x] `TrafficTracker` / `ManagedSSMServer` traits（用于后续绑定）
- [x] TLS server 能力（axum-server）

**关键缺口（按 Go 参考定义）**:
- [ ] **type/配置**：Go `type="ssm-api"` + Listen Fields + `servers`(endpoint→inbound tag)，Rust 当前 schema/type 不兼容
- [ ] **绑定**：按 `servers` 绑定 managed Shadowsocks inbound，并将用户变更推送到 `ManagedSSMServer.UpdateUsers`
- [ ] **路由**：路径必须是 `{endpoint}/server/v1/...`（Go chi `entry.Key` + `APIServer.Route`），而不是 Rust-only 全局 `/server/v1`
- [ ] **API 合约**：`GET /server/v1/users` 返回 `{"users":[UserObject...]}`；并对齐错误返回/状态码细节
- [ ] **缓存**：对齐 Go cache JSON（按 endpoint 保存 users + traffic 计数）

**文件**: `crates/sb-core/src/services/ssmapi/`, `crates/sb-adapters/src/inbound/shadowsocks.rs`

---

## P2: 平台完善 (2周)

### 5. Resolved 服务完善
**状态**: ◐ 部分完成 | **工作量**: 1-2天（Linux 相关） | **影响**: Linux systemd-resolved 集成仍非 drop-in

**已完成**:
- [x] ResolvedService (615 行) - D-Bus server, DNS stub listener
- [x] ResolvedTransport (702 行) - per-link DNS routing
- [x] `update_link()` / `delete_link()` 方法
- [x] LinkServers / LinkDomain 结构
- [x] Domain matching 和 search domains

**待完成** (平台特定/行为对齐):
- [ ] **行为**：查询转发应走配置的 DNSRouter（Go `adapter.DNSRouter`），而不是系统 resolver
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
