<!-- tier: S -->
# 当前上下文（Active Context）
> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。
---
## 战略状态
**当前阶段**: 维护模式，L1-L25 全部 Closed
**Parity**: 92.9% (52/56)，以 `labs/interop-lab/docs/dual_kernel_golden_spec.md` 为准
**当前维护线**: `MT-CONTRACT-02` transport/session contract convergence — 已完成

## 最近完成（2026-04-04）

### MT-CONTRACT-02：transport/session contract convergence — 已完成
- 性质：maintenance / protocol-quality work，不是 parity completion
- ShadowTLS typed wrapper contract：
  - 引入 `StreamCapability` enum (BareTcp/TlsRecordFramed/AuthenticatedTlsRecordFramed)
  - 引入 `WrapperContract` struct 组合 endpoint + capability
  - 新增 `wrapper_contract()` accessor
  - 更新 `connect_detour_stream` doc 引用 `StreamCapability`
  - 更新 `ShadowTlsDetourBridge` doc 明确契约代理语义
  - 新增 4 个 typed contract 测试 (v1/v2/v3/unsupported)
- TUN TCP detached/draining session policy：
  - 引入 `CleanupMode` enum (ClientRst/ClientFin/ServerEof/DrainTimeout/OwnerDrop) + Display
  - 新增 `remove_with_reason()` 方法
  - `DrainPolicy` 新增 `simultaneous_close_grace` 字段
  - 新增 `drain_policy()` accessor
  - `tun_enhanced.rs` RST 分支集成 `CleanupMode::ClientRst`
  - 新增 4 个 typed policy 测试
- 验证：clippy 0 warnings；sb-adapters --lib 216/216 pass

### MT-CONTRACT-01：transport-wrapper + detached-session contract hardening — 已完成
- ShadowTLS：`WrapperEndpoint`、`DetourStreamResult`、`wrapper_endpoint()`
- TUN TCP：`SessionPhase`、`DrainPolicy`、`run_eviction_sweep()`

## 当前验证事实
- 已通过最小充分验证：
  - `cargo clippy -p sb-adapters --all-features --all-targets -- -D warnings` ✅
  - `cargo test -p sb-adapters --all-features shadowtls -- --test-threads=1` ✅
  - `cargo test -p sb-adapters --all-features tun_session -- --test-threads=1` ✅
  - `cargo test -p sb-adapters --all-features tun_enhanced -- --test-threads=1` ✅
  - `cargo test -p sb-adapters --all-features register -- --test-threads=1` ✅
  - `cargo test -p sb-adapters --all-features --lib -- --test-threads=1` ✅ (216 pass)

## 当前阶段结论
- 当前没有新的基线阻塞或必须立即开卡的质量问题
- ShadowTLS wrapper contract 已从雏形推进到 typed contract (endpoint + capability + accessor)
- TUN TCP session policy 已从雏形推进到 typed cleanup mode (reason + grace period + accessor)
- 剩余未来工作只应按跨线高层 boundary regroup

## 暂停事项
- 不再恢复细碎 maintenance 排程
- 不把 maintenance work 写成 parity completion
- 不把 `future boundary` 自动等同于"下一卡默认继续做"
