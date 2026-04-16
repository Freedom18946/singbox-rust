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

### MT-REAL-02: baseline-driven REALITY ClientHello rounds 1-6

- baseline / family harness 仍有效：
  - `reality_go_utls_dump.sh` / `reality_clienthello_dump.rs` / `reality_clienthello_diff.{py,sh}` / `reality_clienthello_family.{py,sh}`
- 当前证据：
  - `agents-only/mt_real_01_evidence/clienthello_baseline/go_vs_rust_clienthello_family.json`
- Round 1（缺失扩展族 + 额外 cipher suites）：
  - Rust 已补入：`GREASE` cipher suite、额外 TLS 1.2 cipher suites、`0x0012/0x001b/0x44cd/0xfe0d/0x0023/0xff01`、尾部 GREASE
  - baseline diff：Rust record length `241 -> 519`
  - live chrome 3 样本复测：`0/3`，仍统一 `tls handshake eof`
- Round 2（typed 子结构）：
  - Rust 已补齐：`supported_versions` / `supported_groups` / `key_share` / `signature_algorithms` typed payload
  - baseline diff：Go / Rust `record_len` 现均为 `528`
  - 剩余显著差异已主要收敛到 Go `uTLS` 动态 extension order / 模板族波动
  - live chrome 3 样本复测：`0/3`，仍统一 `tls handshake eof`
- Round 3（dynamic order family）：
  - Rust 不再固定中段 extension order；改为头部 GREASE 固定、尾部 GREASE 固定、中段扩展随机化
  - family 证据显示：
    - Go: `12 runs -> 12` 个不同 order families
    - Rust: `12 runs -> 12` 个不同 order families
    - Go `record_len`: `{496, 528, 560, 592}`
    - Rust `record_len`: 目前固定 `528`
    - Go `fe0d` len: `{186, 218, 250, 282}`
    - Rust `fe0d` len: 目前固定 `218`
  - live chrome 3 样本复测：`0/3`，仍统一 `tls handshake eof`
- Round 4（dynamic `BoringGREASEECH` family）：
  - Rust 已移除静态 `0xfe0d` baseline blob，改为按 Go `uTLS` `BoringGREASEECH` 模板动态生成：
    - `outer_type=0x00` / `kdf=0x0001` / `aead=0x0001` / `config_id=random` / `encapsulated_key_len=32` / `payload_len ∈ {144, 176, 208, 240}`
  - 新测试：
    - `test_chrome_baseline_ech_outer_matches_utls_boring_grease_family`
  - family 证据（`40 runs`）显示：
    - Go `record_len`: `{496, 528, 560, 592}`
    - Rust `record_len`: `{496, 528, 560, 592}`
    - Go `fe0d` len: `{186, 218, 250, 282}`
    - Rust `fe0d` len: `{186, 218, 250, 282}`
    - Go / Rust extension presence 均一致，头尾 extension 均固定为 GREASE
  - 单次 diff 现在主要表现为“同族不同抽样”，不再是静态缺口
  - live chrome 3 样本复测仍为 `0/3`，仍统一 `tls handshake eof`
- Round 5（opaque middle-order family）：
  - vendored `rustls` 已改为让 `opaque_extensions` 参与中段随机排序，不再总被追加到尾部
  - 新测试：`test_chrome_baseline_opaque_extensions_are_not_pinned_to_tail_block`
  - family 证据（`40 runs`）显示：
    - Rust 的 `0x0012/0x001b/0x44cd/0xfe0d` 已进入中段随机族，不再形成固定尾部块
    - Go / Rust `order_family_count` 仍均为 `40`
    - `record_len` / `fe0d` family 仍保持覆盖
  - live chrome 3 样本复测仍为 `0/3`，仍统一 `tls handshake eof`
- Round 6（seeded shuffle semantics）：
  - vendored `rustls` 中段顺序已从“基于扩展号哈希排序”改为真正的 seeded Fisher-Yates shuffle
  - 语义上已更接近 Go `ShuffleChromeTLSExtensions(...)`
  - `record_len` / `fe0d` family 仍保持完整覆盖，opaque extensions 仍在中段随机族
  - live chrome 3 样本复测仍为 `0/3`，仍统一 `tls handshake eof`
- 当前报告：`agents-only/mt_real_02_baseline.md`

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
- 现在已进入“静态字节几乎收敛但 live 仍失败”的阶段：
  - 优先研究 `HelloChrome_Auto` 的动态 extension order / payload family
  - `fe0d` / record-length 动态族、opaque middle-order 族、seeded shuffle 语义都已被覆盖，下一焦点转向更深层运行时行为：
    - Go `HelloChrome_Auto` 的 joint-distribution / 相关性
    - 更深层的 TLS / socket 发包 shaping
  - 暂不回到盲补单个固定报文
