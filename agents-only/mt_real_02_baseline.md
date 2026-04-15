# MT-REAL-02: Go uTLS vs Rust REALITY ClientHello Baseline Harness

日期：2026-04-16

## 目标

- 在 `FIX-03/04/05` 连续证伪后，不再继续“盲补指纹”。
- 建立一个可重复执行的 Go `uTLS` ↔ Rust REALITY `ClientHello` 基线对照工具链，把后续所有突破都约束到真实字节基线。

## 新增工具

- `scripts/tools/reality_go_utls_dump.sh`
  - 使用本地 `go_fork_source/sing-box-1.12.14`
  - 调用 Go `NewRealityClient(... with_utls ...)`
  - 捕获首个 TLS record 并输出 hex
- `crates/sb-tls/examples/reality_clienthello_dump.rs`
  - 通过 `sb_tls::reality::debug_emit_client_hello_record(...)`
  - 输出 Rust REALITY 首个 TLS record 的 hex
- `scripts/tools/reality_clienthello_diff.py`
  - 解析 Go/Rust 两侧原始 TLS record
  - 规范化为结构摘要（GREASE、cipher suites、扩展顺序、typed 子结构）
- `scripts/tools/reality_clienthello_diff.sh`
  - 串起 Go dump、Rust dump、统一 diff

## 证据产物

- `agents-only/mt_real_01_evidence/clienthello_baseline/go_reality_utls_clienthello.hex`
- `agents-only/mt_real_01_evidence/clienthello_baseline/rust_reality_clienthello.hex`
- `agents-only/mt_real_01_evidence/clienthello_baseline/go_vs_rust_clienthello_diff.json`
- `agents-only/mt_real_01_evidence/clienthello_baseline/go_utls_run1_vs_run2.json`

## 首次基线结果

### 0. 先确认一个关键事实：Go `uTLS` 本身存在动态模板波动

- 两次独立 Go dump 的结果并不完全相同：
  - run1 record length: `592`
  - run2 record length: `560`
  - 扩展顺序也发生变化
- 这说明后续目标不应被理解为“对齐某一个固定 Chrome 报文”，而是：
  - 需要覆盖 Go `HelloChrome_Auto` / REALITY 路径实际发出的动态模板族
  - 当前 harness 不只是拿来对齐 Rust ↔ Go，也可以先拿来度量 Go 自己的变化范围

### 1. Go ↔ Rust 长度差异

- Go record length: `528`
- Rust record length: `241`

### 2. 结构化关键差异

1. Cipher suites
- Go:
  - 以 `GREASE` 开头
  - 含额外 `0xcca9/0xcca8/0xc013/0xc014/0x009c/0x009d/0x002f/0x0035`
- Rust:
  - 只有基础 rustls/ring 列表

2. Extension order
- Go 顺序：
  - `GREASE, 0xff01, 0x0010, 0x0012, 0x002b, 0x001b, 0x000b, 0x000d, 0x44cd, 0x000a, 0x0033, 0x0017, 0xfe0d, 0x0000, 0x002d, 0x0023, 0x0005, GREASE`
- Rust 顺序：
  - `0x0005, 0x002b, 0x000a, 0x0010, 0x0017, 0x0000, 0x000d, 0x000b, 0x002d, 0x0033`

3. Typed 子结构
- Go `supported_versions`:
  - `[GREASE, 0x0304, 0x0303]`
- Rust `supported_versions`:
  - `[0x0304]`
- Go `supported_groups`:
  - `[GREASE, 0x001d, 0x0017, 0x0018]`
- Rust `supported_groups`:
  - `[0x001d, 0x0017, 0x0018]`
- Go `key_share`:
  - `[{group: GREASE, len: 1}, {group: 0x001d, len: 32}]`
- Rust `key_share`:
  - `[{group: 0x001d, len: 32}]`

4. 额外扩展族
- Go 存在但 Rust 缺失：
  - `0x0012` (`signed_certificate_timestamp`)
  - `0x001b`
  - `0x44cd`
  - `0xfe0d`（大 payload，当前基线长度 `218`）
  - 尾部 `GREASE`
  - `0x0023` (`session_ticket`)
  - `0xff01` (`renegotiation_info`)

5. SignatureAlgorithms
- Go:
  - `[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]`
- Rust:
  - `[0x0503, 0x0403, 0x0807, 0x0806, 0x0805, 0x0804, 0x0601, 0x0501, 0x0401]`

## 当前结论

- 这套基线 harness 已经证明：
  - 真实差异面远大于 `FIX-04/05` 当时肉眼整理出来的列表
  - Go REALITY `uTLS` Chrome_Auto 当前还包含若干此前未进入 Rust 补丁范围的扩展族与顺序约束
- 因此下一步继续推进的正确方式是：
  - 以 `go_vs_rust_clienthello_diff.json` 为单一输入
  - 每次只消减一组真实差异
  - live 验证与基线 diff 同步推进

## 下一步建议

1. 先把 Rust 侧补到与当前 Go 基线同阶：
- `0x0012`
- `0x001b`
- `0x44cd`
- `0xfe0d`
- `0x0023`
- `0xff01`
- 尾部 GREASE

2. 再复跑：
- `scripts/tools/reality_clienthello_diff.sh`
- live Phase 3 chrome 配置样本复测

3. 只有当：
- 结构 diff 显著收敛
- live 仍然 `0/x`
  时，才考虑重新评估更重的技术路线
