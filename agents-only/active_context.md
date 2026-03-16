<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: **L24 — 性能 / 安全 / 质量 / 功能补全**（B1 完成，T2-08 + B2 核心已交付）
**历史阶段**: L1-L23 全部 Closed
**Parity**: 92.9% (52/56) — SV.1 (4 BHVs) 已重分类为 harness-only 并移出分母

## L24 进度（2026-03-17）

**目标**: 从"功能完整"推向"生产就绪"
**详细工作包**: `agents-only/planning/L24-workpackage.md`

### B1 批次：安全修复 + Fuzz 基础设施 — ✅ 全部完成

- ✅ T1-01~06: 安全修复 + sniff/协议 fuzz targets 真实化
- ✅ T2-08: Fuzz corpus 114 seeds (19 dirs) + regression framework (`fuzz/run_regression.sh`)

### B2 批次：性能热路径 + Benchmark — ✅ 核心已交付

- ✅ T1-08: `suffix_match()` format!() 消除 → 零分配后缀检查 (`domain_matches_suffix()`)
  - 同时修复 `router/ruleset/matcher.rs` (L153, L395) + `routing/matcher.rs` (L85) 的 format!()
- ✅ T1-09: `matches_host()` to_string() 消除 → 快路径零分配（仅 uppercase 时 fallback 分配）
  - `router/matcher.rs` 现已加入模块树 (`pub mod matcher` in router/mod.rs)
  - `routing/matcher.rs` 域名预 lowercase 移至构建时
- ✅ T1-12: 端到端 TCP relay benchmark (`benches/benches/tcp_relay_e2e.rs`)
  - 基线: 16KB buf → 2.4 GiB/s, 64KB buf → 3.0 GiB/s (1MB payload, loopback)
  - 额外: domain_match benchmark 验证优化效果

### B2 待做（依赖 T1-12 已满足）

- T2-05: SS AEAD per-chunk aead_in_place 优化
- T2-07: Benchmark 基线文档 + CI 集成
- T2-09: TCP relay pump buffer 池化

### 下一批次：B3（功能补全 + 错误处理）

无前置依赖，可直接并行：
- T1-10: SOCKS5 outbound IPv6 (ATYP=0x04) [S]
- T1-11: TUN IPv6 UDP 响应包构建 [M]
- T2-01: DNS cache Mutex async 化 [M]
- T2-02: register.rs 12x unwrap defensive 化 [S]
- T2-03: RwLock poison-tolerant 化 [S]
- T2-04: NonZeroUsize unsafe 消除 [S]

## 构建基线（2026-03-17）

| 构建 | 状态 |
|------|------|
| `cargo check --workspace --all-features --all-targets` | ✅ pass |
| `cargo test -p sb-core --lib` | ✅ pass (509 tests) |
| `cargo bench -p sb-benches --bench domain_match` | ✅ meaningful data |
| `cargo bench -p sb-benches --bench tcp_relay_e2e` | ✅ meaningful data |
| `cargo +nightly fuzz build` | ✅ pass (20 targets) |
