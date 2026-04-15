<!-- tier: S -->
# 当前上下文（Active Context）
> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。
---
## 战略状态
**当前阶段**: 最高目标实验态 — 用户显式要求继续追求“可直接替换 Go sing-box 的 Rust 二进制”；`MT-REAL-02` 已重开
**Parity**: 52/56 BHV (92.9%)；`ARCH-LIMIT-REALITY` 仍保留为当前 parity 账面口径，直到出现 live 成功样本
**当前焦点**: 用 Go `uTLS` ↔ Rust REALITY `ClientHello` 基线 harness 驱动后续突破，不再盲补指纹

## 最新闭环（2026-04-16）

### MT-REAL-02: Go uTLS vs Rust REALITY ClientHello 基线 harness

- 已新增：
  - `scripts/tools/reality_go_utls_dump.sh`
  - `crates/sb-tls/examples/reality_clienthello_dump.rs`
  - `scripts/tools/reality_clienthello_diff.py`
  - `scripts/tools/reality_clienthello_diff.sh`
- 已生成证据：
  - `agents-only/mt_real_01_evidence/clienthello_baseline/go_reality_utls_clienthello.hex`
  - `agents-only/mt_real_01_evidence/clienthello_baseline/rust_reality_clienthello.hex`
  - `agents-only/mt_real_01_evidence/clienthello_baseline/go_vs_rust_clienthello_diff.json`
  - `agents-only/mt_real_01_evidence/clienthello_baseline/go_utls_run1_vs_run2.json`
- 首次基线结论：
  - Go ↔ Rust 基线有稳定大差距
  - Rust record length: `241`
  - Go 明显多出：
    - `GREASE` cipher suite
    - 额外 TLS 1.2 cipher suites
    - `0x0012` / `0x001b` / `0x44cd` / `0xfe0d` / `0x0023` / `0xff01` / 尾部 GREASE
  - Go/Rust 的扩展顺序、`supported_versions`、`supported_groups`、`key_share`、`signature_algorithms` 仍显著不同
  - 新发现：Go `uTLS` 自身也不是单一静态模板，两次 dump 的 record length 与 extension order 都会变化
- 报告：
  - `agents-only/mt_real_02_baseline.md`

## 仍然有效的历史结论

- `FIX-03/04/05` 的 live 结果没有反转：
  - Phase 3 真实节点矩阵仍是 `0/21`
  - 主失败形态仍是 `REALITY handshake failed ... tls handshake eof`
- 但此前 `ARCH-LIMIT-REALITY` 的结论，现在只作为：
  - parity bookkeeping / 维护口径
  - 不再作为停止实验推进的理由

## 当前权威入口

- 最高目标原文：
  - `agents-only/archive/L12-L17/06-STRATEGIC-ROADMAP.md`
  - `agents-only/archive/L01-L04/05-USER-ABSTRACT-REQUIREMENTS.md`
- 当前实验报告：
  - `agents-only/mt_real_02_baseline.md`
- parity / divergence 账面口径：
  - `labs/interop-lab/docs/dual_kernel_golden_spec.md`
  - `agents-only/reference/GO_PARITY_MATRIX.md`

## 当前默认准则

- 后续 REALITY 改动必须先对齐 `go_vs_rust_clienthello_diff.json`
- 每轮只消减一组真实差异，然后立刻做：
  - baseline diff 复跑
  - live chrome 样本复测
- 暂不跳到 FFI/BoringSSL/自建 TLS 栈；除非基线收敛后 live 仍无成功样本
