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

## 2026-04-16 进展更新：baseline rounds 1/2

### Round 1: 缺失扩展族 + 额外 cipher suites

- 实现：
  - 在 vendored `rustls` 中新增 opt-in `ClientHelloFingerprint`
  - 支持：
    - prepend GREASE cipher suite
    - append raw extra cipher suites
    - 注入 opaque extensions
    - empty `session_ticket`
    - `renegotiation_info`
    - explicit extension ordering
  - REALITY chrome-like 路径先补入：
    - `0x0012`
    - `0x001b`
    - `0x44cd`
    - `0xfe0d`（当时先使用 baseline sample payload；后续已在 Round 4 替换为动态 `BoringGREASEECH` family）
    - `0x0023`
    - `0xff01`
    - 尾部 GREASE
    - 额外 TLS 1.2 cipher suites
- 验证：
  - `cargo test -p sb-tls` → PASS
  - `cargo check --workspace` → PASS
  - `bash scripts/tools/reality_clienthello_diff.sh`
    - Rust record length: `241 -> 519`
    - 缺失扩展族与额外 cipher suites 已进入 Rust ClientHello
- live 复测：
  - 临时配置：`/tmp/phase3_ip_direct_mt_real02_round1_chrome.json`
  - 样本：
    - `HK-A-BGP-0.3倍率`
    - `HK-A-BGP-1.0倍率`
    - `HK-A-BGP-2.0倍率`
  - 结果：`0/3`
    - 三个样本均为 `curl: (97) Can't complete SOCKS5 connection`
    - app 日志仍统一为 `REALITY handshake failed ... tls handshake eof`

### Round 2: typed 子结构

- 实现：
  - `supported_versions = [GREASE, 0x0304, 0x0303]`
  - `supported_groups = [GREASE, 0x001d, 0x0017, 0x0018]`
  - `key_share = [GREASE(1B), x25519(32B)]`
  - `signature_algorithms = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]`
  - `parse_client_key_share()` 改为扫描列表提取 `x25519`，不再假设第一个 share 就是目标
- 验证：
  - `cargo test -p sb-tls` → PASS
  - `cargo check --workspace` → PASS
  - `bash scripts/tools/reality_clienthello_diff.sh`
    - Go / Rust `record_len` 现均为 `528`
    - cipher suites、缺失扩展族、typed payload 已对齐
    - 剩余差异已主要收敛到 Go `uTLS` 自身的动态 extension order / 模板族
- live 复测：
  - 继续复用 `/tmp/phase3_ip_direct_mt_real02_round1_chrome.json`
  - 同样 3 个 HK 样本结果仍为 `0/3`
  - 日志再次统一为 `REALITY handshake failed ... tls handshake eof`

## 更新后的工程结论

- 这轮结果比 `FIX-04/05` 更强，因为它不是“靠肉眼猜一组 Chrome 参数”，而是：
  - 先用 baseline harness 锁定真实字节差异
  - 再逐轮消减
  - 每轮都同步做 live 复测
- 当前已能确认：
  - Rust REALITY `ClientHello` 的静态结构差异已大幅收敛
  - 但 live failure **没有**随之反转
- 因而当前 blocker 已进一步收敛为：
  - 并非单纯缺某几个静态扩展 / cipher / typed payload
  - 更可能是 `HelloChrome_Auto` 的动态模板族、extension order 运行时变化、或更深层 I/O shaping 行为

## 2026-04-16 进展更新：dynamic order family

### 新增工具

- `scripts/tools/reality_clienthello_family.py`
  - 读取一批 Go / Rust `*.hex`
  - 汇总：
    - `record_len` 分布
    - `fe0d` 长度分布
    - extension presence
    - order family 数量与样本
- `scripts/tools/reality_clienthello_family.sh`
  - 自动各跑多次 Go / Rust dump
  - 直接输出 family 级比较 JSON

### 新增证据

- `agents-only/mt_real_01_evidence/clienthello_baseline/go_vs_rust_clienthello_family.json`

### 实现

- Rust REALITY chrome-like 指纹不再强制固定完整 extension order
- 改为：
  - 头部 GREASE 固定
  - 尾部 GREASE 固定
  - 中段扩展保留随机化
- 目的：
  - 不再只逼近 Go 的某一个单次样本
  - 转而覆盖 `HelloChrome_Auto` 的动态顺序族

### family 结果

- Go（12 runs）：
  - `record_len` 分布：`496 x2`, `528 x3`, `560 x4`, `592 x3`
  - `fe0d` len 分布：`186 x2`, `218 x3`, `250 x4`, `282 x3`
  - `order_family_count = 12`
  - 头部 extension 始终是 GREASE，尾部 extension 始终是 GREASE
- Rust（12 runs）：
  - `record_len` 分布：`528 x12`
  - `fe0d` len 分布：`218 x12`
  - `order_family_count = 12`
  - 头部 extension 始终是 GREASE，尾部 extension 始终是 GREASE

### 这轮能确认什么

- Rust 现在已经在 **顺序族层面** 逼近 Go：
  - 不再是固定顺序
  - 头尾 GREASE 的整体骨架也一致
- 但 Rust 仍未覆盖 Go 的：
  - `record_len` 动态族
  - `fe0d` payload 长度动态族

### live 复测

- 继续使用：
  - `/tmp/phase3_ip_direct_mt_real02_round1_chrome.json`
- 样本：
  - `HK-A-BGP-0.3倍率`
  - `HK-A-BGP-1.0倍率`
  - `HK-A-BGP-2.0倍率`
- 结果仍为 `0/3`
  - 三个样本均 `curl: (97) Can't complete SOCKS5 connection`
  - app 日志仍统一落在：
    - `REALITY handshake failed ... tls handshake eof`

## 下一步建议（更新）

1. 不要回退到再补单个固定 Chrome 报文
2. 下一轮优先研究 `fe0d` / `record_len` 的动态 family，而不是再只盯 extension order
3. 如果 `fe0d` family 也被逼近后 live 仍然 `0/x`，再正式评估更重路线：
   - `uTLS` 等价层
   - FFI / BoringSSL
   - 更激进的 TLS 发包控制

## 2026-04-16 进展更新：dynamic `BoringGREASEECH` family

### 实现

- Rust REALITY chrome-like 路径已移除静态 `0xfe0d` baseline blob
- 改为直接复刻 Go `uTLS` `BoringGREASEECH` family：
  - `outer_type = 0x00`
  - `kdf_id = 0x0001`
  - `aead_id = 0x0001`
  - `config_id = random u8`
  - `encapsulated_key_len = 32`
  - `payload_len ∈ {144, 176, 208, 240}`
  - 因而：
    - `0xfe0d` len family = `{186, 218, 250, 282}`
    - `record_len` family = `{496, 528, 560, 592}`
- 新增测试：
  - `test_chrome_baseline_ech_outer_matches_utls_boring_grease_family`
  - 原 `test_chrome_baseline_extensions_are_injected` 也已改为验证 family 结构，而不是固定 `218`

### 验证

- `cargo test -p sb-tls` → PASS
- `cargo check --workspace` → PASS
- `bash scripts/tools/reality_clienthello_diff.sh`
  - 当前单次 diff 主要表现为“同一动态 family 内的不同抽样”
  - 本轮固化证据样本中：
    - Go `record_len = 592`, `fe0d len = 282`
    - Rust `record_len = 528`, `fe0d len = 218`
  - 这已不再表示 Rust 缺结构，而是两侧各自抽到了 family 的不同 member
- `SB_REALITY_FAMILY_RUNS=40 bash scripts/tools/reality_clienthello_family.sh`
  - Go（40 runs）：
    - `record_len` 分布：`496 x8`, `528 x12`, `560 x11`, `592 x9`
    - `fe0d` len 分布：`186 x8`, `218 x12`, `250 x11`, `282 x9`
    - `order_family_count = 40`
  - Rust（40 runs）：
    - `record_len` 分布：`496 x9`, `528 x13`, `560 x11`, `592 x7`
    - `fe0d` len 分布：`186 x9`, `218 x13`, `250 x11`, `282 x7`
    - `order_family_count = 40`
  - 额外可确认：
    - Go / Rust extension presence 全量一致
    - 头部 extension 始终是 GREASE
    - 尾部 extension 始终是 GREASE

### live 复测

- 临时配置：
  - `/tmp/phase3_ip_direct_mt_real02_round2_chrome.json`
- 样本：
  - `HK-A-BGP-0.3倍率`
  - `HK-A-BGP-1.0倍率`
  - `HK-A-BGP-2.0倍率`
- 结果仍为 `0/3`
  - 三个样本均 `curl: (97) Can't complete SOCKS5 connection`
  - app 日志仍统一落在：
    - `REALITY handshake failed ... tls handshake eof`

## 更新后的结论（再次收敛）

- `fe0d` / `record_len` 动态 family 本身已不再是主 blocker
- 这意味着当前更深一层的未知数已经收敛到：
  - `HelloChrome_Auto` 运行时更细的相关性，而不只是“是否出现某个 family member”
  - extension order 与 `fe0d` 档位是否存在 Go 特有耦合
  - 更深层的 TLS / socket 发包 shaping

## 下一步建议（再次更新）

1. 保持 baseline harness 驱动，不回到盲补固定报文
2. 下一轮优先研究：
   - extension order 与 `fe0d` 档位的联动
   - Go `HelloChrome_Auto` family 的更细粒度相关性，而不只看边际分布
3. 如果相关性也被覆盖后 live 仍然 `0/x`，再正式进入更重路线评估：
   - `uTLS` 等价层
   - FFI / BoringSSL
   - 更激进的 TLS 发包控制
