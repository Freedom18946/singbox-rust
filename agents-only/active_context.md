<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: **L23 — TUN / Sniff 运行时补全**
**历史阶段**: L1-L22 + 后 L22 补丁 全部 Closed
**工作区状态**: Tier 1 全部完成，Tier 2 全部完成

## L23 Tier 2 完成摘要（2026-03-16）

### T4: Provider 后台更新循环 ✅
- `ProviderManager::start_background_updates()` — 可配置 tick interval 定时扫描 stale providers
- `tick_updates()` 收集过期 proxy/rule providers → `fetch_and_update()` 获取最新内容
- `watch::Receiver<bool>` shutdown 信号优雅退出
- **DIV-H-003 → CLOSED**

### T5: Provider 健康检查探针 ✅
- `ProviderManager::health_check_provider()` — 通过 `OutboundRegistryHandle::connect_tcp()` 执行真实 TCP 探测
- 5 秒超时，无 registry 时优雅降级为 healthy
- **DIV-H-004 → CLOSED**

### T6: SV 域 7 BHV — Provider 连接 + 偏差关闭 ✅
- `ApiState::new()` / `with_monitoring()` → `provider_manager: Some(Arc::new(ProviderManager::default()))`
- Provider endpoints 不再返回 503；空 ProviderManager 返回正确的空响应
- 3 个新 e2e 测试: `test_get_proxy_providers_with_data`, `test_healthcheck_proxy_provider_with_data`, `test_get_rule_providers_with_data`
- DIV-H-003/004 CLOSED, DIV-H-005 STRUCTURAL 新增（Go provider endpoints 全部 stub）
- **BHV-SV-005/006/007 现有 Rust-only e2e 覆盖**

## 构建基线（2026-03-16）

| 构建 | 状态 |
|------|------|
| `cargo check --workspace --all-features --all-targets` | ✅ pass |
| `cargo clippy -p sb-api --all-features --all-targets -- -D warnings` | ✅ pass |
| `cargo test -p sb-api --lib` | ✅ 28 passed |
| `cargo test -p sb-api --test clash_http_e2e` | ✅ 47 passed |
| `cargo test -p sb-core --lib` | ✅ 504 passed |

## 下一步：L23 Tier 3

| 任务 | 描述 | 状态 |
|------|------|------|
| L23-T7 | Redirect IPv6 (DIV-H-002) — 平台限制，有限影响 | deferred |

## 关键文件速查

| 内容 | 路径 |
|------|------|
| ProviderManager | `crates/sb-api/src/managers.rs` |
| Clash API server | `crates/sb-api/src/clash/server.rs` |
| Provider handlers | `crates/sb-api/src/clash/handlers.rs` |
| Provider e2e tests | `crates/sb-api/tests/clash_http_e2e.rs` |
| Golden spec | `labs/interop-lab/docs/dual_kernel_golden_spec.md` |
