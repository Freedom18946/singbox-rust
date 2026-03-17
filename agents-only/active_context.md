<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: **L24 — 性能 / 安全 / 质量 / 功能补全**（B1+B2+B3+B4 全部完成）
**历史阶段**: L1-L23 全部 Closed
**Parity**: 92.9% (52/56) — SV.1 (4 BHVs) 已重分类为 harness-only 并移出分母

## L24 进度（2026-03-17）

**目标**: 从"功能完整"推向"生产就绪"
**详细工作包**: `agents-only/planning/L24-workpackage.md`

### B1 批次：安全修复 + Fuzz 基础设施 — ✅ 全部完成

- ✅ T1-01~06: 安全修复 + sniff/协议 fuzz targets 真实化
- ✅ T2-08: Fuzz corpus 114 seeds (19 dirs) + regression framework (`fuzz/run_regression.sh`)

### B2 批次：性能热路径 + Benchmark — ✅ 核心已交付

- ✅ T1-08: `suffix_match()` format!() 消除 → 零分配后缀检查
- ✅ T1-09: `matches_host()` to_string() 消除 → 快路径零分配
- ✅ T1-12: TCP relay e2e benchmark (基线: 2.4-3.0 GiB/s) + domain_match benchmark

### B3 批次：功能补全 + 错误处理 — ✅ 全部完成

- ✅ T1-10: SOCKS5 outbound IPv6 — ATYP=0x04 + 16 字节地址 (`socks5.rs:138`)
- ✅ T1-11: TUN IPv6 UDP 响应包 — `build_ipv6_udp()` + `ipv6_udp_checksum()` (`tun/udp.rs`)
- ✅ T2-01: DNS cache `std::sync::Mutex` → `parking_lot::Mutex` — 7 处 match poison 模式消除
- ✅ T2-02: `register.rs` 12x `.lock().unwrap()` → `.unwrap_or_else(|e| e.into_inner())`
- ✅ T2-03: `log/mod.rs` RwLock poison-tolerant (`read`/`write` 均已修复)
- ✅ T2-04: 5x `NonZeroUsize::new_unchecked()` unsafe → `NonZeroUsize::new(N).unwrap()`
- ✅ 附带: `benches/tcp_relay_e2e.rs` 2x `unit_arg` clippy 错误修复

### B2 — ✅ 全部完成

- ✅ T2-05: SS AEAD `encrypt_in_place`/`decrypt_in_place` + reusable `enc_buf`/`chunk_buf`
  - 消除每个 chunk 4-6 次 Vec 分配；UDP 路径同步升级
- ✅ T2-07: `docs/benchmark-baseline.md` + `reports/benchmarks/baseline.json` 数据填充
  - domain_match 12 条目基线；CI gate 已在 `bench-regression.yml`
- ✅ T2-09: `metered.rs` pump() 16KB→64KB，全局 `RELAY_BUF_POOL`（128 entry cap）
  - RAII `RelayBuf` drop 自动归还；Deref/DerefMut → `[u8]` 透明兼容

### B4 批次：T3 tier — ✅ 全部完成（2026-03-17）

- ✅ T3-05: endpoint sniff host mutation — `override_destination` 现在真正更新 `endpoint` 为 sniffed domain
- ✅ T3-08: `getpwuid`/`getgrgid` → `getpwuid_r`/`getgrgid_r` 线程安全版本 (context_pop.rs, Linux only)
- ✅ T3-07: tailscale.rs `state: AtomicU8` → `Arc<AtomicU8>`，消除 2 个 unsafe raw pointer cast
- ✅ T3-06: ShadowTLS v1 inbound 实现 — `handle_v1` + `relay_server_to_client_passthrough` + `copy_until_v1_handshake_finished`
- ✅ T3-04: macOS 系统代理 — `MacOsSystemProxyGuard` Drop guard via networksetup (HTTP+HTTPS)
- ✅ T3-03: Switchboard direct UDP — `ConnectedUdpStream` AsyncRead/AsyncWrite wrapper for connected UdpSocket
- ✅ T3-01 (partial): 删除 4 个确认死亡的空 feature flag (labels, minijson, obs, preview)；`http_exporter` 保留（app 依赖）
- ✅ T3-02: sb-types doc comments 已完整 (`cargo doc --no-deps` 零警告)

## 构建基线（2026-03-17，B4 交付后）

| 构建 | 状态 |
|------|------|
| `cargo check --workspace --all-features --all-targets` | ✅ pass |
| `cargo clippy --workspace --all-features --all-targets -- -D warnings` | ✅ pass |
| `cargo test -p sb-core --lib` | ✅ pass (509 tests) |
| `cargo test -p sb-adapters` | ✅ pass |
| `cargo +nightly fuzz build` | ✅ pass (20 targets) |

## L24 状态

**L24 全部 Closed**（B1+B2+B3+B4，30 任务）。项目进入维护状态。
