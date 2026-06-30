<!-- tier: B -->
# MT-REAL-02: Go uTLS vs Rust REALITY ClientHello Baseline Harness

> **Superseded-governance pointer (2026-06-06).** Current closure governance is
> superseded by `labs/interop-lab/docs/dual_kernel_golden_spec.md` S4 and
> `agents-only/active_context.md`. This file is retained as a historical audit
> record; fresh09 identity is not an active closure obligation.

日期：2026-04-16

## 目标

- 在 `FIX-03/04/05` 连续证伪后，不再继续“盲补指纹”。
- 建立一个可重复执行的 Go `uTLS` ↔ Rust REALITY `ClientHello` 基线对照工具链，把后续所有突破都约束到真实字节基线。

## 新增工具

- `scripts/tools/reality_go_utls_dump.sh`
  - 使用本地 `go_fork_source/sing-box-1.13.13`
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

## 2026-04-16 进展更新：opaque middle-order family

### 实现

- vendored `rustls` 的 extension ordering 逻辑已调整：
  - `opaque_extensions` 不再被默认追加到尾部
  - 现在会参与中段随机排序
  - 但真正的结构化 `ECH` / `ECH outer extensions` / `PSK` 仍保留原本的尾部约束
- 这使得 REALITY chrome-like 路径里的：
  - `0x0012`
  - `0x001b`
  - `0x44cd`
  - `0xfe0d`
  不再构成固定尾部块，而是会像 Go `HelloChrome_Auto` 一样进入中段 joint-order family
- 新增测试：
  - `test_chrome_baseline_opaque_extensions_are_not_pinned_to_tail_block`

### 验证

- `cargo test -p sb-tls` → PASS
- `cargo check --workspace` → PASS
- `bash scripts/tools/reality_clienthello_diff.sh`
  - 当前单次样本里，Rust 的 `0xfe0d` 已可出现在中段，而不再固定为倒数第二个扩展
  - 本轮固化样本中：
    - Go order：
      - `GREASE, 0x0012, 0x0017, 0x000d, 0x0000, 0x001b, 0x0023, 0x002d, 0x0010, 0x0033, 0x44cd, 0xff01, 0x0005, 0xfe0d, 0x002b, 0x000a, 0x000b, GREASE`
    - Rust order：
      - `GREASE, 0x0000, 0x0023, 0x0017, 0x0005, 0x002d, 0xff01, 0x0012, 0x001b, 0x000b, 0x44cd, 0x0010, 0x002b, 0x0033, 0xfe0d, 0x000a, 0x000d, GREASE`
  - 这轮的差异已更接近“joint family 内不同样本”，而不是“Rust 把 opaque 扩展固定钉在尾部”
- `SB_REALITY_FAMILY_RUNS=40 bash scripts/tools/reality_clienthello_family.sh`
  - Go（40 runs）：
    - `record_len` 分布：`496 x7`, `528 x8`, `560 x13`, `592 x12`
    - `fe0d` len 分布：`186 x7`, `218 x8`, `250 x13`, `282 x12`
    - `order_family_count = 40`
  - Rust（40 runs）：
    - `record_len` 分布：`496 x13`, `528 x13`, `560 x8`, `592 x6`
    - `fe0d` len 分布：`186 x13`, `218 x13`, `250 x8`, `282 x6`
    - `order_family_count = 40`
  - 能确认：
    - Rust 仍覆盖完整 `record_len` / `fe0d` family
    - Rust 的 opaque 扩展已进入中段随机族，而不是固定尾部块

### live 复测

- 临时配置：
  - `/tmp/phase3_ip_direct_mt_real02_round3_chrome.json`
- 样本：
  - `HK-A-BGP-0.3倍率`
  - `HK-A-BGP-1.0倍率`
  - `HK-A-BGP-2.0倍率`
- 结果仍为 `0/3`
  - 三个样本均 `curl: (97) Can't complete SOCKS5 connection`
  - app 日志仍统一落在：
    - `REALITY handshake failed ... tls handshake eof`

## 更新后的结论（再次收敛）

- `opaque tail block` 也已不再是主 blocker
- 到这一轮为止，可以明确排除的层级已经包括：
  - 缺失扩展族
  - 额外 TLS 1.2 cipher suites
  - typed payload 差异
  - `fe0d` / `record_len` family 缺失
  - `opaque_extensions` 固定尾部排序
- 因而下一焦点进一步收敛为：
  - Go `HelloChrome_Auto` 的更细粒度 joint-distribution / 相关性，而不只是“会不会随机”
  - 更深层的 TLS / socket 发包 shaping

## 下一步建议（再次更新）

1. 保持 baseline harness 驱动，不回到盲补固定报文
2. 下一轮优先研究：
   - Go `HelloChrome_Auto` joint-distribution，而不是只看单维分布
   - 是否存在 `fe0d` 档位、extension order、首尾之外位置的联合约束
3. 如果 joint-distribution 也被覆盖后 live 仍然 `0/x`，再正式进入更重路线评估：
   - `uTLS` 等价层
   - FFI / BoringSSL
   - 更激进的 TLS 发包控制

## 2026-04-16 进展更新：seeded shuffle semantics

### 实现

- vendored `rustls` 的中段 extension 排序逻辑已进一步从：
  - “按 `order_seed + ext_type` 做哈希后排序”
  变为：
  - “按 `order_seed` 驱动的 seeded Fisher-Yates shuffle”
- 这使得 Rust 侧顺序机制在语义上更接近 Go `uTLS` 的：
  - `ShuffleChromeTLSExtensions(...)`
  - 即真正的 shuffle，而不只是一个 deterministic hash-based permutation
- 仍保留的约束：
  - 头部 GREASE 固定
  - 尾部 GREASE 固定
  - 结构化 `ECH` / `PSK` 的尾部约束不被打破

### 验证

- `cargo test -p sb-tls` → PASS
- `cargo check --workspace` → PASS
- `bash scripts/tools/reality_clienthello_diff.sh`
  - 本轮固化样本中：
    - Go `record_len = 592`
    - Rust `record_len = 560`
  - 单次 order 继续表现为“同一动态族内不同抽样”，而不是明显的固定机制差异
- `SB_REALITY_FAMILY_RUNS=40 bash scripts/tools/reality_clienthello_family.sh`
  - Go（40 runs）：
    - `record_len` 分布：`496 x12`, `528 x8`, `560 x12`, `592 x8`
    - `fe0d` len 分布：`186 x12`, `218 x8`, `250 x12`, `282 x8`
    - `order_family_count = 40`
  - Rust（40 runs）：
    - `record_len` 分布：`496 x4`, `528 x7`, `560 x15`, `592 x14`
    - `fe0d` len 分布：`186 x4`, `218 x7`, `250 x15`, `282 x14`
    - `order_family_count = 40`
  - 可确认：
    - Rust 仍覆盖完整 `record_len` / `fe0d` family
    - Rust 仍保有中段 shuffle 行为
    - 但 Go / Rust 的联合分布并未自然收敛成“同一个抽样器”

### live 复测

- 临时配置：
  - `/tmp/phase3_ip_direct_mt_real02_round4_chrome.json`
- 样本：
  - `HK-A-BGP-0.3倍率`
  - `HK-A-BGP-1.0倍率`
  - `HK-A-BGP-2.0倍率`
- 结果仍为 `0/3`
  - 三个样本均 `curl: (97) Can't complete SOCKS5 connection`
  - app 日志仍统一落在：
    - `REALITY handshake failed ... tls handshake eof`

## 更新后的结论（再次收敛）

- 到这一轮为止，已经可以明确排除的层级进一步扩大到：
  - 缺失扩展族
  - typed payload 差异
  - `fe0d` / `record_len` family 缺失
  - `opaque tail block`
  - “Rust 只是 hash 排序，不是真 shuffle”
- 当前更可能的 blocker 已进一步收敛为：
  - Go `HelloChrome_Auto` 的更细粒度 joint-distribution / 条件分布
  - 或更深层的 TLS / socket 发包 shaping

## 下一步建议（再次更新）

1. 保持 baseline harness 驱动，不回到盲补固定报文
2. 下一轮优先研究：
   - joint-distribution，而不是只看单维 family
   - 具体看 `fe0d` 档位与 extension order 是否有条件耦合
3. 如果 joint-distribution 也被逼近后 live 仍然 `0/x`，再正式进入更重路线评估：
   - `uTLS` 等价层
   - FFI / BoringSSL
   - 更激进的 TLS 发包控制

## 2026-04-16 进展更新：joint harness + shared randomization seed

### 背景

- rounds 1-6 已经证明：
  - 缺失扩展族、typed payload、`fe0d` / `record_len` family、opaque middle-order、hash-sort vs shuffle 语义都不足以单独解释 live failure
- 当前下一焦点因此转向：
  - `HelloChrome_Auto` 的 joint-distribution / 条件分布
  - 更深层的 TLS / socket 发包 shaping

### 新增实现

- `scripts/tools/reality_clienthello_family.py`
  - 在原有 family 汇总之上新增：
    - `record_len_to_fe0d_len`
    - `fe0d_position_counts`
    - `fe0d_len_to_position`
    - `extension_position_counts`
    - `fe0d_len_to_prefix4`
    - `fe0d_len_to_suffix4`
  - 目的：
    - 不再只看边际 family
    - 直接观测 `fe0d` 档位与 extension 位置/局部顺序的条件分布
- vendored `rustls` + `sb-tls`
  - 新增 `ClientHelloFingerprint.randomization_seed`
  - `vendor/rustls/src/client/hs.rs`
    - `extension_order_seed` 现在可复用该 handshake-scoped seed，而不再必然走独立 `secure_random`
  - `crates/sb-tls/src/reality/handshake.rs`
    - REALITY chrome-like 指纹现在先生成一个握手级 `randomization_seed`
    - `0xfe0d` 的 `BoringGREASEECH` family member 也改为由该 seed 选档
  - 本轮目的不是宣称已经复刻 Go 的联合抽样器，而是先把 Rust 当前“完全独立 RNG 岛”收敛为“可继续建模的统一随机化入口”

### 新增测试

- `reality::handshake::tests::test_chrome_baseline_randomization_seed_selects_ech_family_bucket`
- `reality::handshake::tests::test_chrome_baseline_randomization_seed_preserves_family_constraints`

### 验证

- `cargo test -p sb-tls` → PASS (`105 passed`)
- `cargo check --workspace` → PASS
- `bash scripts/tools/reality_clienthello_diff.sh`
  - 本轮固化样本中：
    - Go `record_len = 528`, `fe0d len = 218`
    - Rust `record_len = 560`, `fe0d len = 250`
  - 差异仍然主要表现为“同一 family 内不同抽样”，未出现新的静态结构缺口
- `SB_REALITY_FAMILY_RUNS=40 bash scripts/tools/reality_clienthello_family.sh`
  - Go（40 runs）：
    - `record_len`: `496 x10`, `528 x10`, `560 x13`, `592 x7`
    - `fe0d len`: `186 x10`, `218 x10`, `250 x13`, `282 x7`
    - `record_len_to_fe0d_len` 仍严格一一对应：
      - `496 -> 186`
      - `528 -> 218`
      - `560 -> 250`
      - `592 -> 282`
    - `fe0d_position_counts` 仍覆盖很宽的位置族：`1..16`
  - Rust（40 runs）：
    - `record_len`: `496 x11`, `528 x10`, `560 x11`, `592 x8`
    - `fe0d len`: `186 x11`, `218 x10`, `250 x11`, `282 x8`
    - `record_len_to_fe0d_len` 同样继续严格一一对应：
      - `496 -> 186`
      - `528 -> 218`
      - `560 -> 250`
      - `592 -> 282`
    - `fe0d_position_counts` 仍覆盖宽位置族，但分布形态与 Go 还不是同一个抽样器

### Go 源码核对结果

- 本机 Go 依赖为：
  - `github.com/metacubex/utls v1.8.3`
- 核对 `uTLS` 代码可确认：
  - `ShuffleChromeTLSExtensions(...)` 本身每次握手使用 `crypto/rand`
  - `BoringGREASEECH()` 内部的 `config_id` / cipher suite / payload length 选择也使用 `crypto/rand`
- 因而当前还不能从源码推出一个“简单固定的 `fe0d 档位 -> extension order` 条件律”
- 这轮的 shared-seed 改动更像是：
  - 为 Rust 侧继续建模 joint-distribution 提供一个可控入口
  - 而不是已经证明这就是 Go 的真实抽样机制

### live 复测

- 临时配置：
  - `/tmp/phase3_ip_direct_mt_real02_round4_chrome.json`
- 样本：
  - `HK-A-BGP-0.3倍率`
  - `HK-A-BGP-1.0倍率`
  - `HK-A-BGP-2.0倍率`
- 结果仍为 `0/3`
  - 三个样本均 `curl: (97) Can't complete SOCKS5 connection`
  - app 日志仍统一落在：
    - `REALITY handshake failed ... tls handshake eof`

### 更新后的结论

- 本轮取得的不是 live reversal，而是：
  - joint-distribution 观测工具链补齐
  - Rust 指纹随机化新增了 handshake-scoped shared-seed 入口
- 但 live 结果没有反转，说明当前更可能的 blocker 继续收敛到：
  - joint-distribution 还需更细化建模
  - 或更深层的首 flight TLS / socket 发包 shaping

### 下一步建议（再次更新）

1. 继续保留 baseline / family / joint harness，不回到盲补固定报文
2. 后续若继续做 joint-distribution 建模，应从新的 shared-seed 入口继续推进，而不是再新增独立随机分支
3. 下一优先级开始上移到：
   - 首 flight record shaping
   - socket write chunk / 时序 / flush 行为
4. 在拿到 live 成功样本前，`ARCH-LIMIT-REALITY` 仍只保留为 parity bookkeeping，不作为停止实验的理由

---

## 2026-04-16 Round 8: first-flight trace harness（Go/Rust 首次 write/record 观测）

### 本轮目标

- 不再继续补静态字段，先验证当前 live blocker 是否可能来自：
  - 首次 `ClientHello` 被拆成多次 `write`
  - 首个 TLS record type / legacy version 不同
  - 连接一开始的最外层 write-path 形态偏离 Go

### 本轮实现

- 新增 Rust 侧 trace 能力：
  - `crates/sb-tls/src/reality/handshake.rs`
    - `RecordingAsyncIo`
    - `trace_client_hello_writes()`
    - `trace_client_hello_writes_async()`
  - `crates/sb-tls/src/reality/mod.rs`
    - `debug_trace_client_hello_writes(...)`
  - `crates/sb-tls/examples/reality_clienthello_trace.rs`
- 新增 Go/Rust 对照脚本：
  - `scripts/tools/reality_go_utls_trace.sh`
  - `scripts/tools/reality_clienthello_trace.sh`

### 新增测试

- `reality::handshake::tests::test_trace_client_hello_writes_form_single_tls_record`

### 验证

- `cargo test -p sb-tls` → PASS
- `cargo check --workspace` → PASS
- `bash scripts/tools/reality_clienthello_diff.sh` → PASS
- `bash scripts/tools/reality_clienthello_trace.sh` → PASS

### 关键结果

- Go trace：
  - `write_count = 1`
  - `record_type = 0x16`
  - `record_version = 0x0301`
- Rust trace：
  - `write_count = 1`
  - `record_type = 0x16`
  - `record_version = 0x0301`

### 本轮结论

- 在当前 probe 粒度下，Go / Rust 的最外层首 flight 形态是一致的：
  - 单次 write
  - 单个 `Handshake` record
  - legacy record version `0x0301`
- 因而“明显的首包多 write / record header 偏差”暂时不像主 blocker
- 下一步仍需继续向：
  - 更细的 joint-distribution
  - 更深的 TLS / socket shaping
 继续下钻

---

## 2026-04-16 Round 9: `fe0d` 条件落点建模（payload bucket -> extension position family）

### 本轮目标

- 不再把主要精力放在“还缺哪个静态扩展/字段”
- 正面推进用户指定的下一焦点之一：
  - `HelloChrome_Auto` 的 joint-distribution / 条件分布
- 当前选择先建模：
  - `fe0d` payload bucket 与 extension order 的耦合

### 本轮实现

- `crates/sb-tls/src/reality/handshake.rs`
  - chrome-like 指纹不再只把 extension order 委托给 vendored `rustls`
  - 改为显式生成 full `extension_order`
  - 生成逻辑为：
    - 先根据 `randomization_seed` 选出 `0xfe0d` payload bucket（仍对应 Go family：`186/218/250/282`）
    - 再按 bucket 选择一个经验 position profile
    - 对其余中段扩展继续做 seeded shuffle
    - 最终生成完整的 `GREASE ... GREASE` order
- 这不是 fixed-template 回退：
  - 中段扩展仍是随机族
  - 只是把 `fe0d` 的落点从“完全均匀洗牌产物”收敛到“按 bucket 条件分布采样”

### 新增测试

- `reality::handshake::tests::test_chrome_baseline_randomization_seed_conditions_fe0d_position_family`

### 验证

- `cargo test -p sb-tls` → PASS (`107 passed`)
- `cargo check --workspace` → PASS
- `bash scripts/tools/reality_clienthello_diff.sh`
  - 本轮固化样本中，Go / Rust 直接命中同档：
    - `record_len = 592`
    - `fe0d len = 282`
  - 但 extension order 仍明显不同，说明“同档位”不等于“同抽样器”
- `SB_REALITY_FAMILY_RUNS=40 bash scripts/tools/reality_clienthello_family.sh`
  - Go（40 runs）：
    - `record_len`: `496 x7`, `528 x9`, `560 x11`, `592 x13`
    - `fe0d len`: `186 x7`, `218 x9`, `250 x11`, `282 x13`
    - `fe0d_position_counts` mean ≈ `7.7`
  - Rust（40 runs）：
    - `record_len`: `496 x13`, `528 x9`, `560 x12`, `592 x6`
    - `fe0d len`: `186 x13`, `218 x9`, `250 x12`, `282 x6`
    - `fe0d_position_counts` mean ≈ `8.8`
  - 说明：
    - Rust 现在已经不是“纯均匀乱序”
    - 但 Go / Rust 的 `fe0d` 位置云团仍不是同一个条件抽样器

### live 复测

- 运行入口：
  - `cargo run -q -p app --features parity --bin run -- -c /tmp/phase3_ip_direct_mt_real02_round4_chrome.json`
- 临时配置：
  - `/tmp/phase3_ip_direct_mt_real02_round4_chrome.json`
- 样本：
  - `HK-A-BGP-0.3倍率`
  - `HK-A-BGP-1.0倍率`
  - `HK-A-BGP-2.0倍率`
- 结果仍为 `0/3`
  - 三个样本均 `curl: (97) Can't complete SOCKS5 connection`
  - app 日志继续统一落在：
    - `REALITY handshake failed ... tls handshake eof`

### 本轮结论

- 这轮的实质收敛是：
  - Rust 已开始显式建模 `fe0d bucket -> position family`
  - 单次样本可以直接命中与 Go 同档的 `record_len` / `fe0d len`
- 但 live 结果仍未翻转，说明当前 blocker 继续收敛到：
  - 条件分布建模还不够深
  - 或更深层的 TLS / socket 发包 shaping

### 下一步建议（再次更新）

1. 不回退到 fixed-template / hash-sort / 静态补字段
2. 若继续做 `HelloChrome_Auto` joint-distribution 建模，下一跳应扩大到：
   - 不只 `fe0d` 的位置
   - 还包括与 `0x0017/0x002b/0xff01/0x0012` 等关键扩展的相对顺序族
3. 继续把一部分精力放在更深层运行时行为：
   - 首 flight 之后的 read/write 时序
   - socket-level shaping / flush / 可能的 TFO 相关差异

---

## 2026-04-16 Round 10: bucket-conditioned extension bias + TFO/socket reality check

### 本轮目标

- 在 `fe0d` 条件落点之外，继续推进更深一层的 joint-distribution：
  - 把 `0x002b/0xff01/0x0017/0x0000` 等关键扩展也纳入 bucket-conditioned 建模视野
- 同时验证“更深层 TLS / socket 发包 shaping”里一个最值得排查的分支：
  - Go 是否在 REALITY 客户端路径上具备 slow-open / TFO 的首次写入语义

### 本轮实现

- `scripts/tools/reality_clienthello_family.py`
  - 新增：
    - `fe0d_len_to_extension_position_counts`
    - `fe0d_len_to_extension_mean_positions`
  - 现在 family 输出可直接观测指定 `fe0d` bucket 下关键扩展的条件位置均值
- `crates/sb-tls/src/reality/handshake.rs`
  - Rust chrome-like 指纹继续推进 bucket-conditioned ordering：
    - 保留 `fe0d` family / target-position 入口
    - 对 `0x002b/0xff01/0x0017/0x0000` 等关键扩展增加 bucket-conditioned bias
    - 又把 score 从“强分箱”放松成“可重叠分箱”，避免云团被压塌到极端位置
- `scripts/tools/reality_go_utls_dump.sh`
- `scripts/tools/reality_go_utls_trace.sh`
  - 修复 macOS 下 `mktemp` 模板问题，避免 Go probe / trace 脚本因临时文件名而间歇失败

### 新增测试

- `reality::handshake::tests::test_chrome_bucket_targets_bias_key_extensions_by_payload_family`

### 验证

- `cargo test -p sb-tls` → PASS (`108 passed`)
- `cargo check --workspace` → PASS
- `bash scripts/tools/reality_clienthello_diff.sh` → PASS
- `SB_REALITY_FAMILY_RUNS=40 bash scripts/tools/reality_clienthello_family.sh` → PASS

## 2026-04-24 进展更新：Round 33 Vision REALITY write-boundary bridge

### 目标

- 在 Round 32 已恢复 Go-like first DIRECT record boundary 后，继续处理 app live dataplane residual。
- 不改变 REALITY ClientHello sampler；不引入固定 bucket、固定 position、固定 precedence 或 position->mode 规则。
- 本轮聚焦 app-facing Vision REALITY 写侧：保留上游 write chunk 边界，避免 `DuplexStream` reader-side byte stream 把 Go `VisionWriter.WriteMultiBuffer` 语义压平。

### 实现

- 文件：
  - `crates/sb-adapters/src/outbound/vless.rs`
- 新增 `VisionWriteBridge`：
  - `AsyncWrite::poll_write` 将每个非空 `buf` 作为一个独立 `Vec<u8>` 发送给 IO task。
  - `poll_shutdown` drop sender，使 IO task 能按 channel close 关闭 REALITY raw/tls write side。
- `VisionRealityClientStream`：
  - writer 字段从 `DuplexStream` 改为 `VisionWriteBridge`。
  - IO task 使用 `write_rx.recv()` 获取 write chunk。
  - 现有 TLS application-data record 补齐逻辑仍保留：
    - 只补齐当前 TLS record；
    - 当前 record 之外的 overflow 继续作为 delayed raw remainder；
    - DIRECT 后 `VISION_DIRECT_SPLIT_DELAY=5ms` 保持。

### 新增测试

- `test_vision_write_bridge_preserves_write_chunks`
  - 连续两次 `write_all` 必须在 receiver 端保持两个独立 chunk。
  - `shutdown` 后 receiver 必须结束。

### A/B 结果

- `VISION_DIRECT_SPLIT_DELAY=0ms` 被 live 证伪：
  - `HK-A-BGP-0.3倍率` default HTTPS：`5/12`
  - `HK-A-BGP-1.0倍率` default HTTPS：`4/12`
  - 已恢复 `5ms`。
- bounded `futures::mpsc` / Sink bridge 被 live 证伪：
  - `HK-A-BGP-0.3倍率` default HTTPS：`6/12`
  - `HK-A-BGP-1.0倍率` default HTTPS：`1/12`
  - 最终保留低延迟 tokio unbounded bridge；背压问题后续需要在不改变写侧调度的前提下单独处理。

### live 复测

#### Rust full app

- 构建：
  - `cargo build -p app --bin run --features 'acceptance,parity,clash_api'`
- 配置：
  - `/tmp/phase3_ip_direct_mt_real02_round4_chrome.json`
- 首次 unbounded bridge + 5ms info run：
  - `HK-A-BGP-0.3倍率` default HTTPS：`10/12` HTTP `200`
  - `HK-A-BGP-1.0倍率` default HTTPS：`7/12` HTTP `200`
- 最终代码复测：
  - `HK-A-BGP-0.3倍率` default HTTPS：`6/12` HTTP `200`
  - `HK-A-BGP-1.0倍率` default HTTPS：`8/12` HTTP `200`
- debug 小样本：
  - 失败连接已发送 `DIRECT(content_len=86)` 与后续 `raw_write_len=59`，但未进入 server raw-read。
  - 成功连接会继续出现 `Vision REALITY enabling raw reads`，并看到后续 raw writes。

### 当前判定

- Round 33 是 live dataplane 的实质推进：
  - 相比 Round 32 baseline `0.3=6/12, 1.0=5/12`，本轮出现 `0.3=10/12` 与 `1.0=8/12` 档位。
  - write-boundary preservation 是有效方向。
- 但 live residual 仍存在：
  - 主要失败仍是 `curl (16) Error in the HTTP2 framing layer`。
  - 少量样本仍可见 REALITY handshake EOF / SOCKS 97。
- 下一轮继续聚焦：
  - DIRECT 后 raw write/read 时序；
  - server rawInput drain 与本地 raw read enable 的差异；
  - 不改 ClientHello sampler，除非后续 family × no-raw-read 样本出现强收敛。

### 验证

- `python3 -m unittest scripts/tools/test_reality_clienthello_family.py` → PASS
- `cargo test -p sb-adapters --features adapter-vless,tls_reality test_vision` → PASS
  - `14 passed`
- `cargo test -p sb-tls`：
  - 初次并发 run 触发 `global::tests::test_chrome_mode_non_empty` root-store 状态波动；
  - `cargo test -p sb-tls global::tests::test_chrome_mode_non_empty -- --nocapture` → PASS
  - `cargo test -p sb-tls -- --test-threads=1` → PASS (`117 passed`, doctest `1 passed`)
  - 普通 `cargo test -p sb-tls` 复跑 → PASS (`117 passed`, doctest `1 passed`)
- `cargo check --workspace` → PASS
- `bash scripts/tools/reality_clienthello_diff.sh` → PASS / exit 0
  - sample remains `match=false` because Go/Rust single samples landed in different dynamic order families
- `SB_REALITY_FAMILY_RUNS=40 bash scripts/tools/reality_clienthello_family.sh` → PASS

- `bash scripts/tools/reality_clienthello_trace.sh` → PASS

## 2026-04-25 进展更新：Round 34 REALITY read-loop partial-record drain

### 目标

- 继续 Round 33 后的 live dataplane residual，不修改 REALITY ClientHello sampler。
- 按用户提醒调整 live 口径：真实节点没有 usability guarantee，节点更新后仍断流可能是节点自身问题；本轮把 live 大样本降级为机会性 sanity，不再对易失节点过拟合。

### 根因收缩

- Round 33 的失败样本常见：
  - client 已发 `DIRECT(content_len=86)`
  - DIRECT 后 raw remainder 已写出
  - 但没有进入 `Vision REALITY enabling raw reads`
- 本轮检查 vendored rustls / tokio-rustls 后确认：
  - 普通 `tokio_rustls::TlsStream::read()` 会调用 rustls `process_new_packets()`；
  - rustls 会继续处理 deframer 中的后续完整消息；
  - 如果一次 socket read 同时包含外层 DIRECT plaintext 与随后的 inner raw TLS bytes，外层 rustls 可能在 Vision 看到 DIRECT 前继续消费后续 bytes。
- 第一版短路修复后又暴露 partial-record 问题：
  - 如果 rustls 已缓冲 partial TLS record，但还没有足够 bytes 产出 plaintext；
  - REALITY custom `read_tls` 会在 `buffered_raw_tls_len()>0` 时反复处理同一 partial buffer；
  - 由于没有 await 底层 IO，Vision IO task 的写侧会被饿死。
  - 中途 live 表现为 `HK-A-BGP-0.3倍率/1.0倍率` `0/12` timeout；debug 显示 REALITY/VLESS dial ok，但没有 raw write 日志。

### 实现

- `vendor/rustls/src/conn.rs`
  - 新增 `ConnectionCommon::process_new_packets_until_plaintext()`。
  - 内部拆出 `process_new_packets_inner(..., stop_after_plaintext)`。
  - 当本轮处理从 `0` pending plaintext 变为有 pending plaintext 时停止，保留后续 deframer bytes 给 REALITY/Vision drain。
- `vendor/rustls/src/client/client_conn.rs`
  - 为 `ClientConnection` 暴露 `process_new_packets_until_plaintext()`。
- `crates/sb-tls/src/reality/client.rs`
  - `RealityClientTlsStream::read_tls` 改为 REALITY 专用读循环：
    - 先 drain rustls plaintext reader；
    - 再处理已缓冲 TLS bytes 到第一段 plaintext；
    - 如果已有 buffered bytes 但仍无 plaintext，继续 await 底层 socket read；
    - 底层 read 使用 4KiB chunk，避免一次读取过多 inner raw bytes。
  - 这样同时覆盖：
    - `DIRECT plaintext + raw bytes` coalesced；
    - 大 TLS record 被分片成多个底层 read 的 partial-record 场景。

### 新增测试

- `reality::client::tests::test_read_tls_stops_before_coalesced_raw_bytes`
  - 本地 TLS server 先写 outer TLS plaintext，再直接写底层 raw bytes。
  - client `read_tls` 必须返回 outer plaintext，并让 `take_buffered_raw_tls()` 取到 raw bytes。
- `reality::client::tests::test_read_tls_waits_for_fragmented_tls_record`
  - 本地 TLS server 写大于 `REALITY_TLS_READ_CHUNK` 的 application-data record。
  - client `read_tls` 必须在 timeout 内继续 await 后续网络 bytes，不得 partial-buffer 自旋。

### live sanity

- 构建：
  - `cargo build -p app --bin run --features 'acceptance,parity,clash_api'`
- 启动：
  - `RUST_LOG=sb_adapters::outbound::vless=debug,sb_tls::reality=debug,sb_core::outbound=debug,app=info,sb_api=info,sb_core=info ./target/debug/run -c /tmp/phase3_ip_direct_mt_real02_round4_chrome.json`
- preflight：
  - `GET /version` → `200`
  - SOCKS greeting → `[5, 0]`
- 短 sanity（不作为节点稳定性 oracle）：
  - `HK-A-BGP-1.0倍率` forced `--http1.1` HTTPS → HTTP `200`, time `~0.95s`
  - `HK-A-BGP-1.0倍率` default HTTPS → HTTP `200`, time `~0.89s`
- debug 观察：
  - forced HTTP/1.1 样本：`Vision REALITY enabling raw reads pending_plaintext_len=0 buffered_raw_tls_len=0`
  - default HTTPS 样本：`Vision REALITY enabling raw reads pending_plaintext_len=0 buffered_raw_tls_len=31`，随后继续 raw writes
  - 这确认本轮 read-loop 能把 coalesced raw bytes 留给 Vision，而不是被外层 rustls 抢先吞掉。

### 当前判定

- Round 34 是 live dataplane 读侧 ownership 的实质修复，不是 sampler 改动。
- 本轮不再追着易失节点做大样本定论：
  - 中途的 `0/12` timeout 被用来定位实现 bug；
  - 最终只保留短 sanity 作为“新 binary 没有把已知可用路径打坏”的证据。
- 下一步如果继续 live，应优先选近期确认可用的节点/Go 对照样本，并把失败样本按：
  - node outage
  - dial-time REALITY EOF
  - post-DIRECT no raw-read
  - HTTP2 framing residual
  分开归因。

### 验证

- `cargo test -p sb-tls reality::client::tests::test_read_tls -- --nocapture` → PASS
  - `2 passed`
- `cargo test -p sb-tls` → PASS
  - `119 passed`
  - doctest `1 passed`
- `cargo test -p sb-adapters --features adapter-vless,tls_reality test_vision -- --nocapture` → PASS
  - `14 passed`
- `python3 -m unittest scripts/tools/test_reality_clienthello_family.py` → PASS
- `cargo check --workspace` → PASS
- `bash scripts/tools/reality_clienthello_diff.sh` → PASS / exit 0
  - sample remains `match=false` because Go/Rust single samples landed in different dynamic order families
- `SB_REALITY_FAMILY_RUNS=40 bash scripts/tools/reality_clienthello_family.sh` → PASS

- `cargo build -p app --bin run --features 'acceptance,parity,clash_api'` → PASS

## 2026-04-25 进展更新：Round 35 probe-outbound live failure classification

### 目标

- 继续 Round 34 后的 live dataplane 工作，但本轮只推进诊断面，不修改 REALITY ClientHello sampler。
- 按用户提醒调整 live 口径：
  - 节点没有 usability guarantee；
  - 节点拉取更新后仍断流可能是节点侧易失；
  - probe 必须优先把失败按类型分桶，而不是把所有失败都当成 sampler 或 bridge 回归。

### 实现

- `app/src/bin/probe-outbound.rs`
  - post-dial `write_all` / `read` 均包上 `tokio::time::timeout(Duration::from_secs(args.timeout), ...)`。
  - `read == 0` 改为显式失败：
    - `ERR stream_mode=... stage=read class=post_dial_eof ...`
    - 避免把空响应误报为 `OK response_bytes=0`。
  - 新增 probe 输出 helpers：
    - `print_probe_error(...)`
    - `classify_probe_error_text(...)`
    - `sanitize_probe_detail(...)`
  - 当前 failure classes：
    - `reality_dial_eof`
    - `post_dial_eof`
    - `http2_framing`
    - `timeout`
    - `socks_connect`
    - `connection_refused`
    - `connection_reset`
    - `broken_pipe`
    - `other`
  - post-dial read/write error 不再统一成 generic IO；会复用 classifier 保留 EOF/reset/broken-pipe 等归因。
  - `direct_reality` / `direct_vless_dial` 的 err/timeout 输出带 `class=...`，方便 pre-bridge 与 post-bridge 对照。
  - app-facing direct `VlessConfig` 构造改为：
    - 先使用 `..VlessConfig::default()`；
    - 再按 `#[cfg(feature = "tls_reality")]` 填 `reality`。
    - 这样在 app dev-feature unification 带入 `transport_ech` 字段时，probe 仍能稳定编译。

### 新增测试

- `classify_probe_error_text_covers_reality_live_failures`
  - 覆盖：
    - `tls handshake eof`
    - HTTP2 framing
    - timeout
    - early EOF
    - SOCKS5 connect
    - connection reset
    - broken pipe
- `sanitize_probe_detail_collapses_and_truncates`
  - 确认多空白折叠；
  - 长 detail 限制在 240 chars + `...`。

### live sanity

- 命令：
  - `cargo run -q -p app --bin probe-outbound --features 'sb-core,sb-adapters,sb-transport,adapter-vless,tls_reality' -- --config /tmp/phase3_ip_direct_mt_real02_round4_chrome.json --outbound 'HK-A-BGP-1.0倍率' --target example.com:80 --timeout 10`
- 结果：
  - `direct_reality phase=pre_bridge result=ok`
  - `direct_vless_dial phase=pre_bridge result=ok`
  - `direct_reality phase=post_bridge result=ok`
  - `direct_vless_dial phase=post_bridge result=ok`
  - `OK stream_mode=connect_io connect_time_ms=264 response_bytes=838 first_line=HTTP/1.1 200 OK`
- 该样本仅作为“当前 probe/app feature 面没有被诊断补丁打坏”的短 sanity，不作为节点稳定性 oracle。

### 当前判定

- Round 35 是 live dataplane 诊断工具面的实质推进：
  - 后续 app `probe-outbound` 可以直接把 failure class 打出来；
  - 易失节点的断流不再把 MT-REAL-02 引回无基线 sampler patch；
  - pre-bridge/post-bridge direct probes 能更快定位 app feature surface、registry/bridge surface 与节点侧问题的分界。
- 本轮没有改变 wire sampler、Vision write-boundary 或 REALITY read-loop 行为。

### 验证

- `cargo fmt --all` → PASS
- `cargo test -p app --bin probe-outbound --features 'sb-core,sb-adapters,sb-transport,adapter-vless,tls_reality' -- --nocapture` → PASS
  - `2 passed`
- `python3 -m unittest scripts/tools/test_reality_clienthello_family.py` → PASS
- `cargo test -p sb-tls` → observed known global-state fluctuation
  - first full parallel run failed only at `global::tests::test_none_mode_empty`
  - `cargo test -p sb-tls global::tests::test_none_mode_empty -- --nocapture` → PASS
  - `cargo test -p sb-tls -- --test-threads=1` → PASS
    - `119 passed`
    - doctest `1 passed`
- `cargo test -p sb-adapters --features adapter-vless,tls_reality test_vision -- --nocapture` → PASS
  - `14 passed`
- `cargo check --workspace` → PASS
- `bash scripts/tools/reality_clienthello_diff.sh` → PASS / exit 0
  - sample remains `match=false` because Go/Rust single samples landed in different dynamic order families
- `SB_REALITY_FAMILY_RUNS=40 bash scripts/tools/reality_clienthello_family.sh` → PASS
- `cargo build -p app --bin run --features 'acceptance,parity,clash_api'` → PASS

## 2026-04-25 进展更新：Round 36 minimal VLESS REALITY phase probe failure classification

### 目标

- 继续 Round 35 的 live 诊断面推进。
- 不修改 REALITY ClientHello sampler、Vision write-boundary、REALITY read-loop。
- 先确认 app-facing VLESS bridge regression 当前仍被 cargo 发现，再把最小 `sb-adapters` phase probe 升级到和 app `probe-outbound` 同一套 failure class 口径。

### test discovery / bridge guard

- `cargo test -p sb-adapters --features adapter-vless,tls_reality -- --list`
  - 已列出：
    - `register::tests::test_vless_outbound_bridge_connect_io_defers_vision_response_until_first_read`
- 结论：
  - 该 regression test 当前没有被 cfg / module gate 隐藏。
  - app-facing bridge 仍覆盖 `connect_io()` 不等待 VLESS response 的行为。

### 实现

- `crates/sb-adapters/examples/vless_reality_phase_probe.rs`
  - `PhaseResult` 新增 `class: Option<String>`。
  - JSON 顶层新增：
    - `phase_timeout_ms`
    - `probe_io_timeout_ms`
  - `direct_reality` / `transport_reality` / `vless_dial` / `vless_probe_io` 均加整体 phase-level timeout。
  - 新增 `SB_VLESS_PHASE_TIMEOUT_MS`：
    - 用于控制前三个 phase 和整体 phase timeout；
    - 默认沿用 `SB_VLESS_PROBE_IO_TIMEOUT_MS`，保持旧环境变量兼容。
  - failure classifier 与 app `probe-outbound` 对齐：
    - `reality_dial_eof`
    - `post_dial_eof`
    - `http2_framing`
    - `timeout`
    - `socks_connect`
    - `connection_refused`
    - `connection_reset`
    - `broken_pipe`
    - `other`
  - error detail 会折叠空白并截断到 240 chars + `...`。
  - 分类在 detail 截断前完成，避免长链路错误里的关键字被截断后误分到 `other`。

### 新增测试

- `classify_probe_error_text_covers_reality_live_failures`
  - 覆盖 REALITY handshake EOF、HTTP2 framing、early/unexpected EOF、timeout、SOCKS5、reset、broken pipe。
- `phase_result_error_classifies_and_sanitizes_details`
  - 确认 `PhaseResult::error` 同时设置 `class` 并折叠多空白。
- `sanitize_probe_detail_truncates_long_errors`
  - 确认长错误被限制在 240 chars + `...`。
- `phase_result_classifies_before_truncating_details`
  - 确认超长错误仍先按原始字符串分类，再截断 detail。

### 当前判定

- Round 36 是 live phase 诊断工具面的实质推进。
- 后续可把：
  - app `probe-outbound`
  - minimal `vless_reality_phase_probe`
  的输出按同一 `class` 字段直接比较，减少把节点易失、post-dial EOF、dial-time REALITY EOF、HTTP2 framing 和 feature-surface 分叉混在一起的概率。
- 本轮没有改变任何 wire sampler 或 dataplane 行为。

### 验证

- `cargo test -p sb-adapters --features adapter-vless,tls_reality -- --list` → PASS
  - confirmed `register::tests::test_vless_outbound_bridge_connect_io_defers_vision_response_until_first_read` is listed
- `cargo test -p sb-adapters --example vless_reality_phase_probe --features adapter-vless,tls_reality -- --nocapture` → PASS
  - `4 passed`
- `cargo test -p sb-adapters --features adapter-vless,tls_reality register::tests::test_vless_outbound_bridge_connect_io_defers_vision_response_until_first_read -- --nocapture` → PASS outside sandbox
  - sandbox run was blocked by local TCP listener `PermissionDenied`
- `cargo test -p sb-adapters --features adapter-vless,tls_reality test_vision -- --nocapture` → PASS
  - `14 passed`
- `python3 -m unittest scripts/tools/test_reality_clienthello_family.py` → PASS
- `cargo test -p sb-tls` → PASS outside sandbox
  - `119 passed`
  - doctest `1 passed`
  - sandbox run was blocked by local socket trace tests, not by assertions
- `cargo check --workspace` → PASS
- `bash scripts/tools/reality_clienthello_diff.sh` → PASS / exit 0
  - sample remains `match=false` because Go/Rust single samples landed in different dynamic order families
- `SB_REALITY_FAMILY_RUNS=40 bash scripts/tools/reality_clienthello_family.sh` → PASS
- `cargo build -p app --bin run --features 'acceptance,parity,clash_api'` → PASS

## 2026-04-25 进展更新：Round 37 app probe structured phase JSON

### 目标

- 继续 Round 35/36 的 live dataplane 诊断面。
- 不修改 REALITY ClientHello sampler、Vision write-boundary、REALITY read-loop。
- 把 app `probe-outbound` 的结果结构化，使它能和 minimal `vless_reality_phase_probe` 按同一 `class` 口径做同节点、同目标、同超时对比。

### 实现

- `app/src/bin/probe-outbound.rs`
  - 新增 `--json`：
    - 默认文本输出保持兼容；
    - 启用后 stdout 输出可直接解析的 pretty JSON；
    - `OK/ERR` 人类可读 bridge 行在 JSON 模式下改走 stderr。
  - JSON 顶层包含：
    - `tool`
    - `config`
    - `outbound`
    - `outbound_type`
    - `target`
    - `timeout_secs`
    - `pre_bridge`
    - `post_bridge`
    - `bridge_probe`
  - `pre_bridge` / `post_bridge` 保留 app 直接 VLESS probe 的两个 phase：
    - `direct_reality`
    - `direct_vless_dial`
  - 每个 phase result 包含：
    - `ok`
    - `status` (`ok` / `err` / `timeout` / `skip`)
    - `elapsed_micros`
    - `class`
    - `error`
    - `reason`
  - `bridge_probe` 覆盖 app bridge 的 end-to-end probe：
    - 成功时记录 `stream_mode` / `connect_time_ms` / `response_bytes` / `first_line`；
    - `connect` / `connect_io` / `write` / `read` failure 均记录 `stage` / `class` / sanitized `error`；
    - `connect_io` fallback 时保留 sanitized `raw_connect_error`，方便区分“raw connect 不支持”与真正 bridge failure。
  - 长错误仍按 Round 35/36 规则：
    - 先按原始错误分类；
    - 再折叠空白并截断到 240 chars + `...`。

### 新增测试

- `probe_phase_result_classifies_before_truncating_details`
  - 确认超长错误仍先分类为 `reality_dial_eof`，再截断 detail。
- `probe_phase_result_skip_keeps_failure_class_empty`
  - 确认跳过 phase 不伪造 failure class。
- `probe_json_output_serializes_phase_classes`
  - 确认 JSON 中 `pre_bridge` 与 `bridge_probe` 的 class 字段可直接读取。

### 当前判定

- Round 37 是诊断工具面的实质推进：
  - 后续可把 app `probe-outbound --json` 与 minimal `vless_reality_phase_probe` JSON 直接放到同一个 sample 表里比较；
  - app bridge 的拨号阶段失败现在也不会绕过 class 分桶；
  - 仍不把易失节点 outage 当 sampler 回归。
- 本轮没有改变 wire sampler 或 dataplane 行为。

### 验证

- `cargo fmt --all` → PASS
- `cargo test -p app --bin probe-outbound --features 'sb-core,sb-adapters,sb-transport,adapter-vless,tls_reality' -- --nocapture` → PASS
  - `5 passed`
- `cargo test -p app --bin probe-outbound --no-default-features --features 'sb-core,sb-adapters,sb-transport' -- --nocapture` → PASS
  - `5 passed`
- `cargo test -p sb-adapters --example vless_reality_phase_probe --features adapter-vless,tls_reality -- --nocapture` → PASS
  - `4 passed`
- `python3 -m unittest scripts/tools/test_reality_clienthello_family.py` → PASS
- `cargo check --workspace` → PASS
- `cargo build -p app --bin run --features 'acceptance,parity,clash_api'` → PASS

## 2026-04-25 进展更新：Round 38 app/minimal REALITY probe matrix

### 目标

- 继续 Round 35-37 的 live dataplane 诊断面，并把“两个 probe 都能输出 class”推进成“能批量生成、归档、对比同节点样本”。
- 不修改 REALITY ClientHello sampler、Vision write-boundary、REALITY read-loop。
- 避免后续手工拼 minimal probe 环境变量、人工读两份日志，从而把节点易失、sandbox 权限、app feature surface 分叉混在一起。

### 实现

- `crates/sb-adapters/examples/vless_reality_phase_probe.rs`
  - 新增 `SB_VLESS_ALPN`：
    - 逗号分隔；
    - 自动 trim；
    - 空项丢弃；
    - 写入 `RealityClientConfig.alpn`。
  - JSON 顶层新增 `alpn`，让样本里能直接看到 minimal probe 的 ALPN surface。
  - classifier 与 app `probe-outbound` 同步新增：
    - `permission_denied`
    - 覆盖 `Operation not permitted` / `permission denied`，用于 sandbox/local socket blocked 样本。

- `scripts/tools/reality_vless_env_from_config.py`
  - 从 raw sing-box/app config 中提取 minimal phase probe 所需环境变量。
  - 支持：
    - outbound name: `tag` / `name`
    - port: `server_port` / `port`
    - REALITY: `tls.reality.public_key` / `reality_public_key`
    - SNI: `tls.reality.server_name` / `tls.server_name` / `reality_server_name` / `tls_sni` / fallback server
    - uTLS: `tls.utls.fingerprint` / `utls_fingerprint`
    - ALPN: `tls.alpn` / `tls_alpn`
  - 输出格式：
    - JSON
    - shell `export ...`（用于 wrapper）
  - 明确拒绝非 VLESS 或非 plain TCP transport，避免拿 transport 节点跑错 minimal probe。

- `scripts/tools/reality_probe_compare.py`
  - 输入：
    - app `probe-outbound --json`
    - minimal `vless_reality_phase_probe` JSON
  - 输出：
    - `classes`
      - `app.pre.direct_reality`
      - `app.pre.direct_vless_dial`
      - `app.post.direct_reality`
      - `app.post.direct_vless_dial`
      - `app.bridge`
      - `minimal.direct_reality`
      - `minimal.transport_reality`
      - `minimal.vless_dial`
      - `minimal.vless_probe_io`
    - 6 组 comparison：
      - app pre/post REALITY
      - app pre/post VLESS dial
      - minimal direct/transport REALITY
      - app post vs minimal direct REALITY
      - app post vs minimal VLESS dial
      - app bridge vs minimal probe I/O
    - summary labels：
      - `app_pre_post_diverged`
      - `minimal_transport_diverged`
      - `app_minimal_diverged`
      - `bridge_io_diverged`
      - `all_ok`
      - `reality_all_<class>`

- `scripts/tools/reality_vless_probe_matrix.sh`
  - 一键串起：
    - app `probe-outbound --json`
    - env extraction
    - minimal `vless_reality_phase_probe`
    - compare report
  - 输出目录包含：
    - `run.json`
    - `app.json`
    - `app.stderr`
    - `phase.json`
    - `phase.stderr`
    - `compare.json`
  - app probe 非零退出不视为 wrapper 失败；只要能写出 JSON，就继续生成 compare report。

- `scripts/tools/test_reality_probe_tools.py`
  - 新增 6 个 Python 单测，覆盖：
    - raw sing-box REALITY config 提取；
    - IR-like REALITY config 提取；
    - JSON config load；
    - all-ok compare；
    - app/minimal + bridge divergence label；
    - all REALITY phases 同 failure class label。

- `scripts/tools/README.md`
  - 增加 REALITY Probe Matrix 用法和 supporting tools。

### smoke

- 命令：
  - `bash scripts/tools/reality_vless_probe_matrix.sh --config agents-only/mt_real_01_evidence/phase3_ip_direct.json --outbound '__phase3_invalid_vless' --target example.com:80 --timeout 1 --phase-timeout-ms 1000 --probe-io-timeout-ms 1000 --output-dir /tmp/reality-vless-probe-matrix-smoke`
- 结果：
  - wrapper exit `0`
  - `app_status=1`（预期：probe 失败，但 JSON 已生成）
  - `phase_status=0`
  - `run.json` 生成成功
  - `compare.json` 生成成功
  - sandbox local socket blocked 环境下所有 phase class 均为 `permission_denied`
  - summary labels：
    - `reality_all_permission_denied`

### 当前判定

- Round 38 是 live 证据采集面的实质推进：
  - 下一次真实节点复测可以直接生成三份可归档 JSON；
  - 如果 app 与 minimal 在同节点同目标出现稳定 class 分叉，`compare.json` 会直接给出 divergence label；
  - 如果所有 REALITY phase 同 class 失败，则优先按节点/环境 bucket 处理，而不是回退到 sampler patch。
- 本轮没有改变 wire sampler 或 dataplane 行为。

### 验证

- `cargo fmt --all` → PASS
- `bash -n scripts/tools/reality_vless_probe_matrix.sh` → PASS
- `python3 -B -m unittest scripts/tools/test_reality_probe_tools.py scripts/tools/test_reality_clienthello_family.py` → PASS
  - `9 tests`
- `python3 scripts/tools/reality_vless_env_from_config.py --config agents-only/mt_real_01_evidence/phase3_ip_direct.json --outbound 'HK-A-BGP-0.3倍率' --target example.com:80 --phase-timeout-ms 9000 --probe-io-timeout-ms 11000 --format json` → PASS
- `python3 scripts/tools/reality_probe_compare.py --app-json <tmp>/app.json --phase-json <tmp>/phase.json` with an ad-hoc fixture → PASS
- `cargo test -p app --bin probe-outbound --features 'sb-core,sb-adapters,sb-transport,adapter-vless,tls_reality' -- --nocapture` → PASS
  - `5 passed`
- `cargo test -p app --bin probe-outbound --no-default-features --features 'sb-core,sb-adapters,sb-transport' -- --nocapture` → PASS
  - `5 passed`
- `cargo test -p sb-adapters --example vless_reality_phase_probe --features adapter-vless,tls_reality -- --nocapture` → PASS
  - `5 passed`
- `cargo check --workspace` → PASS
- `cargo build -p app --bin run --features 'acceptance,parity,clash_api'` → PASS

## 2026-04-29 进展更新：Round 57 per-run health rollup and HK targeted repeat

### 目标

- Round 56 showed `HK-A-BGP-2.0` as the only latest divergence bucket, but the latest aggregate labels mixed one divergent sample and one same-failure sample.
- Add per-run health to the rollup so we can distinguish:
  - stable divergence across runs;
  - mixed node/path instability;
  - pure same-class failures.
- Use the new run-health filter to target only HK and repeat it.
- 本轮不修改 REALITY ClientHello sampler、Vision raw/direct dataplane、REALITY concrete read-loop。

### 工具实现

- `scripts/tools/reality_vless_evidence_rollup.py`
  - Parses sanitized evidence `runs[]`.
  - Adds per-run health:
    - `run_all_ok`
    - `run_same_failure`
    - `run_divergence`
    - `run_unknown`
  - Per outbound:
    - `run_health_counts`
    - `latest_run_health_counts`
    - latest history entries now keep compact `runs`.
  - Top-level:
    - `latest_run_health_counts`
    - `latest_stable_divergence_outbounds`
    - `latest_stable_divergence_outbound_count`
    - `latest_mixed_run_health_outbounds`
    - `latest_mixed_run_health_outbound_count`
- `scripts/tools/reality_vless_probe_plan.py`
  - Adds `--latest-run-health`.
  - Can combine `--latest-health latest_divergence` with `--latest-run-health run_divergence` or `run_same_failure`.
  - Plan output now includes `latest_run_health_counts`.
- `scripts/tools/README.md`
  - Documents latest run-health filtering and mixed run-health interpretation.
- `scripts/tools/test_reality_probe_tools.py`
  - Adds tests for:
    - mixed latest run-health counts;
    - stable latest divergence run-health;
    - planner latest-run-health filtering;
    - combined outbound/latest-run filters.

### Round 57 live execution

- Planner command:
  - `python3 scripts/tools/reality_vless_probe_plan.py --config agents-only/mt_real_01_evidence/phase3_ip_direct.json --rollup-json agents-only/mt_real_02_evidence/live_rollup.json --latest-health latest_divergence --latest-run-health run_divergence --output-json /tmp/reality-vless-hk-divergence-plan-r57.json`
- Selected:
  - `HK-A-BGP-2.0`
  - `latest_health = latest_divergence`
  - prior `latest_run_health_counts = {"run_divergence": 1, "run_same_failure": 1}`
- Batch command:
  - `python3 scripts/tools/reality_vless_probe_batch.py --config agents-only/mt_real_01_evidence/phase3_ip_direct.json --plan-json /tmp/reality-vless-hk-divergence-plan-r57.json --target example.com:80 --runs 4 --timeout 8 --phase-timeout-ms 8000 --probe-io-timeout-ms 8000 --output-dir /tmp/reality-vless-probe-batch-live-r57-hk-repeat`
- Batch result:
  - `selected_count = 1`
  - `executed_runs = 4`
  - `status_counts.completed = 4`

### Round 57 evidence

- Committed evidence:
  - `agents-only/mt_real_02_evidence/round57_hk_mixed_divergence_repeat_summary.json`
- Summary:
  - `total = 4`
  - `executed_runs = 4`
  - `app_minimal_diverged = 2`
  - `app_pre_post_diverged = 1`
  - `minimal_transport_diverged = 2`
  - `probe_io_all_timeout = 4`
  - `reality_all_timeout = 1`
  - `class_counts.connection_reset = 2`
  - `class_counts.reality_dial_eof = 1`
  - `class_counts.timeout = 33`

### Per-run observations

- Run 1:
  - app pre/post direct REALITY split: timeout vs connection_reset.
  - app post direct REALITY vs minimal direct REALITY split: connection_reset vs timeout.
  - bridge/probe IO: same timeout.
- Run 2:
  - minimal direct REALITY vs transport REALITY split: reality_dial_eof vs timeout.
  - app post direct REALITY vs minimal direct REALITY split: timeout vs reality_dial_eof.
  - bridge/probe IO: same timeout.
- Run 3:
  - uniform timeout across app/minimal phases.
- Run 4:
  - minimal direct REALITY vs transport REALITY split: timeout vs connection_reset.
  - bridge/probe IO: same timeout.

### Rollup after Round 57

- Updated:
  - `agents-only/mt_real_02_evidence/live_rollup.json`
  - `agents-only/mt_real_02_evidence/live_rollup.md`
- Summary:
  - `total_rounds = 10`
  - `total_executed_runs = 54`
  - `total_all_ok_runs = 21`
  - `total_non_all_ok_runs = 33`
  - `latest_non_all_ok_outbound_count = 5`
  - `latest_health_counts.latest_all_ok = 16`
  - `latest_health_counts.latest_same_failure = 4`
  - `latest_health_counts.latest_divergence = 1`
  - `latest_run_health_counts.run_all_ok = 15`
  - `latest_run_health_counts.run_same_failure = 9`
  - `latest_run_health_counts.run_divergence = 3`
- Latest stable divergence:
  - none (`0`)
- Latest mixed run-health:
  - `HK-A-BGP-2.0`
- Latest same-failure remains:
  - `JP-A-BGP-0.3`
  - `JP-A-BGP-1.0`
  - `UK-A-BGP-0.5`
  - `US-A-BGP-0.5`

### 当前判定

- HK is confirmed as an unstable mixed diagnostic-phase divergence bucket, not a stable dataplane/sampler structural split.
- Across 4 targeted samples, bridge/probe IO remained same-class timeout every time.
- Divergence did not repeat at a single stable phase boundary:
  - app pre/post direct REALITY once;
  - minimal direct/transport twice with different failure classes;
  - one uniform timeout.
- No ClientHello sampler or Vision dataplane patch is justified by Round 57.
- Next useful work should either:
  - keep HK isolated as node/path instability and focus same-failure buckets separately;
  - or add a dedicated “stable divergence only” planner mode before any sampler/dataplane attempt.

### 验证

- `python3 -B -m unittest scripts/tools/test_reality_probe_tools.py scripts/tools/test_reality_clienthello_family.py` → PASS
  - `34 tests`
- JSON validation:
  - `agents-only/mt_real_02_evidence/round57_hk_mixed_divergence_repeat_summary.json` → PASS
  - `agents-only/mt_real_02_evidence/live_rollup.json` → PASS
  - `/tmp/reality-vless-hk-divergence-plan-after-r57.json` → PASS
  - `/tmp/reality-vless-hk-mixed-plan-after-r57.json` → PASS
  - `/tmp/reality-vless-same-failure-plan-after-r57.json` → PASS
- ASCII scan:
  - `agents-only/mt_real_02_evidence/round57_hk_mixed_divergence_repeat_summary.json` → PASS
  - `agents-only/mt_real_02_evidence/live_rollup.json` → PASS
  - `agents-only/mt_real_02_evidence/live_rollup.md` → PASS
- `cargo check --workspace` → PASS

## 2026-04-29 进展更新：Round 56 health-aware live recheck and batch hard timeout

### 目标

- 把 Round 55 的 `latest_health` rollup 直接接入 planner 选择逻辑。
- 用 planner JSON 驱动一次真实 live recheck，而不是手工复制 outbounds。
- 修掉 live batch 暴露出的工具可靠性问题：minimal phase probe 偶尔超过内部 timeout，可能卡住整个 batch。
- 本轮不修改 REALITY ClientHello sampler、Vision raw/direct dataplane、REALITY concrete read-loop。

### 工具实现

- `scripts/tools/reality_vless_probe_plan.py`
  - 新增 `--latest-health`，可重复传入。
  - 支持直接选择：
    - `latest_divergence`
    - `latest_same_failure`
    - `latest_all_ok`
    - `latest_unknown`
  - 输出每个 selected item 的 `latest_health`。
  - 顶层输出：
    - `latest_health_filter`
    - `latest_health_counts`
- `scripts/tools/reality_vless_probe_batch.py`
  - 新增 matrix-level process-group hard timeout。
  - 默认 hard timeout 由 app/phase/probe IO timeouts 推导，且不低于 `180s`。
  - 超时时杀掉整个 matrix process group，返回 status `124`，batch result 标记 `matrix_timeout`。
  - `plan.json` / `summary.json` / stdout 均记录 `matrix_timeout_secs`。
- `scripts/tools/README.md`
  - 记录 `--latest-health` planner 用法。
  - 记录 `--matrix-timeout` 用法。
- `scripts/tools/test_reality_probe_tools.py`
  - 增加 latest-health planner 单测。
  - 增加 matrix default timeout 单测。
  - 增加 wedged shell script 触发 `MATRIX_TIMEOUT_STATUS` 的 subprocess 单测。

### live 执行

- Planner command:
  - `python3 scripts/tools/reality_vless_probe_plan.py --config agents-only/mt_real_01_evidence/phase3_ip_direct.json --rollup-json agents-only/mt_real_02_evidence/live_rollup.json --latest-health latest_divergence --latest-health latest_same_failure --output-json /tmp/reality-vless-latest-health-plan-r56.json`
- Planner selected:
  - `6`
  - `HK-A-BGP-2.0` as `latest_divergence`
  - `JP-A-BGP-0.3`, `JP-A-BGP-1.0`, `US-A-BGP-0.5`, `US-A-BGP-0.8`, `UK-A-BGP-0.5` as `latest_same_failure`
- Batch command:
  - `python3 scripts/tools/reality_vless_probe_batch.py --config agents-only/mt_real_01_evidence/phase3_ip_direct.json --plan-json /tmp/reality-vless-latest-health-plan-r56.json --target example.com:80 --runs 2 --timeout 8 --phase-timeout-ms 8000 --probe-io-timeout-ms 8000 --output-dir /tmp/reality-vless-probe-batch-live-r56-health-recheck`
- Batch result:
  - `selected_count = 6`
  - `executed_runs = 12`
  - `status_counts.completed = 12`

### Round 56 evidence

- Committed evidence:
  - `agents-only/mt_real_02_evidence/round56_latest_health_recheck_summary.json`
- Summary:
  - `total = 12`
  - `executed_runs = 12`
  - `all_ok = 2`
  - `app_minimal_diverged = 1`
  - `app_pre_post_diverged = 1`
  - `bridge_io_diverged = 1`
  - `probe_io_all_connection_reset = 4`
  - `probe_io_all_reality_dial_eof = 2`
  - `probe_io_all_timeout = 3`
  - `reality_all_connection_reset = 4`
  - `reality_all_reality_dial_eof = 2`
  - `reality_all_timeout = 3`

### Per-outbound observations

- `HK-A-BGP-2.0`
  - two completed runs.
  - one run had app/minimal + bridge IO divergence:
    - labels `app_minimal_diverged`, `app_pre_post_diverged`, `bridge_io_diverged`.
  - paired run was uniform timeout.
  - Judgment: still the only latest divergence bucket; timeout/connection-reset dominated, not a ClientHello sampler signal.
- `JP-A-BGP-0.3`
  - two runs same-class `reality_dial_eof`.
- `JP-A-BGP-1.0`
  - two runs same-class timeout.
- `US-A-BGP-0.5`
  - two runs same-class connection_reset.
- `UK-A-BGP-0.5`
  - two runs same-class connection_reset.
- `US-A-BGP-0.8`
  - two runs `all_ok`.
  - This node moves from latest same-failure to recovered.

### Rollup after Round 56

- Updated:
  - `agents-only/mt_real_02_evidence/live_rollup.json`
  - `agents-only/mt_real_02_evidence/live_rollup.md`
- Summary:
  - `total_rounds = 9`
  - `total_executed_runs = 50`
  - `total_all_ok_runs = 21`
  - `total_non_all_ok_runs = 29`
  - `latest_non_all_ok_outbound_count = 5`
  - `latest_health_counts.latest_all_ok = 16`
  - `latest_health_counts.latest_same_failure = 4`
  - `latest_health_counts.latest_divergence = 1`
- Latest divergence:
  - `HK-A-BGP-2.0`
- Latest same-failure:
  - `JP-A-BGP-0.3`
  - `JP-A-BGP-1.0`
  - `UK-A-BGP-0.5`
  - `US-A-BGP-0.5`
- Recovered:
  - `TW-A-BGP-1.0`
  - `US-A-BGP-0.8`

### Next plan smoke

- Command:
  - `python3 scripts/tools/reality_vless_probe_plan.py --config agents-only/mt_real_01_evidence/phase3_ip_direct.json --rollup-json agents-only/mt_real_02_evidence/live_rollup.json --latest-health latest_divergence --latest-health latest_same_failure --output-json /tmp/reality-vless-latest-health-plan-after-r56.json`
- Selected:
  - `5`
  - `HK-A-BGP-2.0`
  - `JP-A-BGP-0.3`
  - `JP-A-BGP-1.0`
  - `US-A-BGP-0.5`
  - `UK-A-BGP-0.5`
- Batch dry-run from that plan:
  - selected `5`
  - `matrix_timeout_secs = 180`

### 当前判定

- Round 56 materially shrinks the latest non-all-ok live set from `6` to `5`.
- `US-A-BGP-0.8` should no longer be treated as current failure evidence; it is now a recovered historical bucket.
- `HK-A-BGP-2.0` is the only latest divergence bucket and should be isolated from the four same-class node/path failures in future analysis.
- No sampler/dataplane patch is justified by Round 56. The evidence still says classify first, then only touch sampler/dataplane if a stable structural divergence appears.

### 验证

- `python3 -B -m unittest scripts/tools/test_reality_probe_tools.py scripts/tools/test_reality_clienthello_family.py` → PASS
  - `30 tests`
- JSON validation:
  - `agents-only/mt_real_02_evidence/round56_latest_health_recheck_summary.json` → PASS
  - `agents-only/mt_real_02_evidence/live_rollup.json` → PASS
  - `/tmp/reality-vless-latest-health-plan-r56.json` → PASS
  - `/tmp/reality-vless-latest-health-plan-after-r56.json` → PASS
  - `/tmp/reality-vless-plan-json-dry-after-r56/plan.json` → PASS
  - `/tmp/reality-vless-plan-json-dry-after-r56/summary.json` → PASS
- ASCII scan:
  - `agents-only/mt_real_02_evidence/round56_latest_health_recheck_summary.json` → PASS
  - `agents-only/mt_real_02_evidence/live_rollup.json` → PASS
  - `agents-only/mt_real_02_evidence/live_rollup.md` → PASS
- `cargo check --workspace` → PASS

## 2026-04-26 进展更新：Round 55 plan-json batch consumption and latest health rollup

### 目标

- 把 Round 53 planner 与 Round 54 batch runner 接成可重复流水线，避免手工复制 latest non-all-ok outbound names。
- 让 live rollup 不只记录“latest non-all-ok”，还直接区分：
  - latest 已恢复；
  - latest 仍是 app/minimal divergence；
  - latest 是 same-class node/path failure。
- 本轮不修改 REALITY ClientHello sampler、Vision raw/direct dataplane、REALITY concrete read-loop。

### 实现

- `scripts/tools/reality_vless_probe_batch.py`
  - 新增 `--plan-json`，读取 planner JSON 的 `selected[].name`。
  - 支持多个 `--plan-json`，并与显式 `--outbound` 按输入顺序合并去重。
  - batch `plan.json` 与 `summary.json` 记录 `plan_json` provenance。
- `scripts/tools/reality_vless_evidence_rollup.py`
  - 新增 `latest_health(labels)`：
    - `latest_all_ok`
    - `latest_same_failure`
    - `latest_divergence`
    - `latest_unknown`
  - 顶层新增：
    - `latest_health_counts`
    - `latest_divergence_outbounds`
    - `latest_same_failure_outbounds`
    - `recovered_outbounds`
  - 每个 outbound 新增 `latest_health` 字段。
- `scripts/tools/test_reality_probe_tools.py`
  - 覆盖 planner JSON name extraction。
  - 覆盖顺序去重。
  - 覆盖 latest divergence outbounds。
  - 覆盖 recovered outbound latest health。
- `scripts/tools/README.md`
  - 记录 `--plan-json` 使用方式。
  - 记录 rollup latest health 语义。

### 重新生成的 live rollup

- Updated:
  - `agents-only/mt_real_02_evidence/live_rollup.json`
  - `agents-only/mt_real_02_evidence/live_rollup.md`
- Summary:
  - `total_rounds = 8`
  - `total_executed_runs = 38`
  - `total_all_ok_runs = 19`
  - `total_non_all_ok_runs = 19`
  - `latest_non_all_ok_outbound_count = 6`
  - `latest_health_counts.latest_all_ok = 15`
  - `latest_health_counts.latest_same_failure = 5`
  - `latest_health_counts.latest_divergence = 1`
- Latest divergence:
  - `HK-A-BGP-2.0`
- Latest same-failure:
  - `JP-A-BGP-0.3`
  - `JP-A-BGP-1.0`
  - `UK-A-BGP-0.5`
  - `US-A-BGP-0.5`
  - `US-A-BGP-0.8`
- Recovered:
  - `TW-A-BGP-1.0`

### Planner-to-batch smoke

- Planner command:
  - `python3 scripts/tools/reality_vless_probe_plan.py --config agents-only/mt_real_01_evidence/phase3_ip_direct.json --rollup-json agents-only/mt_real_02_evidence/live_rollup.json --include-failure-rechecks --limit 20 --output-json /tmp/reality-vless-latest-non-all-ok-plan-r55.json`
- Planner selected:
  - `6`
- Batch dry-run command:
  - `python3 scripts/tools/reality_vless_probe_batch.py --config agents-only/mt_real_01_evidence/phase3_ip_direct.json --plan-json /tmp/reality-vless-latest-non-all-ok-plan-r55.json --target example.com:80 --runs 2 --dry-run --output-dir /tmp/reality-vless-plan-json-dry-r55`
- Batch dry-run selected:
  - `6`
- Selected names:
  - `HK-A-BGP-2.0`
  - `JP-A-BGP-0.3`
  - `JP-A-BGP-1.0`
  - `US-A-BGP-0.5`
  - `US-A-BGP-0.8`
  - `UK-A-BGP-0.5`

### 当前判定

- Round 55 turns the latest non-all-ok loop into a reproducible planner JSON -> batch input path.
- The current live state is sharper than Round 54:
  - one latest divergence bucket (`HK-A-BGP-2.0`);
  - five latest same-class failure buckets;
  - one recovered historical failure bucket (`TW-A-BGP-1.0`).
- No sampler/dataplane change is justified by this tooling-only round.

### 验证

- `python3 -B -m unittest scripts/tools/test_reality_probe_tools.py scripts/tools/test_reality_clienthello_family.py` → PASS
  - `27 tests`
- JSON validation:
  - `agents-only/mt_real_02_evidence/live_rollup.json` → PASS
  - `/tmp/reality-vless-latest-non-all-ok-plan-r55.json` → PASS
  - `/tmp/reality-vless-plan-json-dry-r55/plan.json` → PASS
  - `/tmp/reality-vless-plan-json-dry-r55/summary.json` → PASS
- ASCII scan:
  - `agents-only/mt_real_02_evidence/live_rollup.json` → PASS
  - `agents-only/mt_real_02_evidence/live_rollup.md` → PASS
- `cargo check --workspace` → PASS

## 2026-04-26 进展更新：Round 54 latest non-all-ok repeat recheck

### 目标

- 使用 Round 53 latest-aware planner 选择当前 latest non-all-ok outbounds。
- 对每个节点 repeat 2 次，确认哪些 failure buckets 稳定，哪些可能恢复。
- 仍然不修改 REALITY ClientHello sampler、Vision write-boundary、REALITY read-loop。

### 执行

- Command:
  - `python3 scripts/tools/reality_vless_probe_batch.py --config agents-only/mt_real_01_evidence/phase3_ip_direct.json --target example.com:80 --outbound 'HK-A-BGP-2.0倍率' --outbound 'JP-A-BGP-0.3倍率' --outbound 'JP-A-BGP-1.0倍率' --outbound 'US-A-BGP-0.5倍率' --outbound 'US-A-BGP-0.8倍率' --outbound 'UK-A-BGP-0.5倍率' --runs 2 --timeout 8 --phase-timeout-ms 8000 --probe-io-timeout-ms 8000 --output-dir /tmp/reality-vless-probe-batch-live-r54-recheck`
- Selection:
  - `HK-A-BGP-2.0`
  - `JP-A-BGP-0.3`
  - `JP-A-BGP-1.0`
  - `US-A-BGP-0.5`
  - `US-A-BGP-0.8`
  - `UK-A-BGP-0.5`
- Runs:
  - `2` per outbound
  - `12` total executed runs

### 结果

- Summary:
  - `total = 12`
  - `executed_runs = 12`
  - `status_counts.completed = 12`
  - `label_counts.app_pre_post_diverged = 1`
  - `label_counts.reality_all_timeout = 3`
  - `label_counts.reality_all_reality_dial_eof = 2`
  - `label_counts.reality_all_connection_reset = 4`
  - `label_counts.probe_io_all_timeout = 4`
  - `label_counts.probe_io_all_reality_dial_eof = 2`
  - `label_counts.probe_io_all_connection_reset = 4`
  - `label_counts.probe_io_all_post_dial_eof = 2`
  - `class_counts.ok = 15`
  - `class_counts.timeout = 35`
  - `class_counts.reality_dial_eof = 18`
  - `class_counts.connection_reset = 36`
  - `class_counts.post_dial_eof = 4`

### Per-outbound observations

- `HK-A-BGP-2.0`
  - run 1:
    - one app pre/post direct REALITY mismatch (`app.pre.direct_reality=ok`, post/minimal mostly timeout)
    - label `app_pre_post_diverged`
    - probe IO same timeout
  - run 2:
    - uniform timeout across app/minimal phases
  - Judgment: unstable node/path timeout bucket; not a sampler-change signal.
- `JP-A-BGP-0.3`
  - both runs `reality_dial_eof`
  - probe IO same failure labels present
- `JP-A-BGP-1.0`
  - both runs timeout
  - probe IO same timeout labels present
- `US-A-BGP-0.5`
  - both runs connection_reset
- `US-A-BGP-0.8`
  - both runs direct phases ok
  - app bridge and minimal VLESS probe IO `post_dial_eof`
  - label `probe_io_all_post_dial_eof`
  - no app/minimal divergence
- `UK-A-BGP-0.5`
  - both runs connection_reset

### Evidence

- Generated by:
  - `scripts/tools/reality_vless_probe_evidence.py`
- Committed sanitized summary:
  - `agents-only/mt_real_02_evidence/round54_latest_non_all_ok_recheck_summary.json`
- Updated rollup:
  - `agents-only/mt_real_02_evidence/live_rollup.json`
  - `agents-only/mt_real_02_evidence/live_rollup.md`
- Raw local output remains outside the repo:
  - `/tmp/reality-vless-probe-batch-live-r54-recheck`

### Rollup after Round 54

- Summary:
  - `total_rounds = 8`
  - `total_executed_runs = 38`
  - `total_all_ok_runs = 19`
  - `total_non_all_ok_runs = 19`
  - `latest_non_all_ok_outbound_count = 6`
- Latest non-all-ok outbounds:
  - `HK-A-BGP-2.0`
  - `JP-A-BGP-0.3`
  - `JP-A-BGP-1.0`
  - `UK-A-BGP-0.5`
  - `US-A-BGP-0.5`
  - `US-A-BGP-0.8`

### 当前判定

- Round 54 confirms the six latest non-all-ok outbounds are stable live failure buckets under current network/node conditions.
- The one HK app pre/post mismatch is not stable across repeat and appears in a timeout-dominated node/path bucket.
- No ClientHello sampler change is justified.

### 验证

- `python3 -B -m unittest scripts/tools/test_reality_probe_tools.py scripts/tools/test_reality_clienthello_family.py` → PASS
  - `25 tests`
- JSON validation:
  - `agents-only/mt_real_02_evidence/round54_latest_non_all_ok_recheck_summary.json` → PASS
  - `agents-only/mt_real_02_evidence/live_rollup.json` → PASS
- ASCII scan for Round 54 evidence and live rollup → PASS
- `cargo check --workspace` → PASS

## 2026-04-26 进展更新：Round 53 latest-aware live rollup and recheck planner

### 目标

- 改进 rollup/planner 的 recheck 语义。
- 旧逻辑按 historical aggregate label counts 判断 `prior_non_all_ok`，导致已经被后续 repeat 恢复的节点仍会永远进入 recheck queue。
- 典型样本：
  - `TW-A-BGP-1.0` Round 47 有 one-shot divergence；
  - Round 48 targeted repeat 是 `all_ok=3`；
  - 旧 planner 仍把它计入 `prior_non_all_ok`。

### 实现

- 更新 `scripts/tools/reality_vless_evidence_rollup.py`
  - 为每个 outbound 记录 `history`。
  - 记录 latest state：
    - `latest_round`
    - `latest_status_counts`
    - `latest_label_counts`
    - `latest_class_counts`
    - `latest_has_non_all_ok`
  - 保留 historical state：
    - aggregate `status_counts`
    - aggregate `label_counts`
    - aggregate `class_counts`
    - `historical_has_non_all_ok`
  - 顶层新增：
    - `latest_non_all_ok_outbounds`
    - `latest_non_all_ok_outbound_count`

- 更新 `scripts/tools/reality_vless_probe_plan.py`
  - `has_non_all_ok` 现在优先看 `latest_label_counts`。
  - 如果旧 rollup 没有 latest 字段，则回退到 aggregate `label_counts`。

- 扩展 `scripts/tools/test_reality_probe_tools.py`
  - 新增 latest recovered outbound rollup 覆盖：
    - round 7 failure
    - round 8 all_ok
    - latest state 应是 recovered
  - 新增 planner 使用 latest all_ok 覆盖 historical failure 的覆盖。

- 更新 `scripts/tools/README.md`
  - 记录 rollup latest state 与 planner latest-aware behavior。

### 结果

- Regenerated:
  - `agents-only/mt_real_02_evidence/live_rollup.json`
  - `agents-only/mt_real_02_evidence/live_rollup.md`
- Current rollup:
  - `total_rounds = 7`
  - `total_executed_runs = 26`
  - `total_all_ok_runs = 19`
  - `latest_non_all_ok_outbound_count = 6`
- Latest non-all-ok outbounds:
  - `HK-A-BGP-2.0`
  - `JP-A-BGP-0.3`
  - `JP-A-BGP-1.0`
  - `UK-A-BGP-0.5`
  - `US-A-BGP-0.5`
  - `US-A-BGP-0.8`
- `TW-A-BGP-1.0`:
  - latest labels: `all_ok = 3`
  - removed from latest recheck queue
  - historical one-shot divergence remains in rollup

### 当前判定

- Recheck planning now reflects latest observed state while preserving historical evidence.
- Next live work should repeat the six latest non-all-ok outbounds, not TW.

### 验证

- `python3 -B -m unittest scripts/tools/test_reality_probe_tools.py scripts/tools/test_reality_clienthello_family.py` → PASS
  - `25 tests`
- `python3 -m json.tool agents-only/mt_real_02_evidence/live_rollup.json` → PASS
- ASCII scan for `agents-only/mt_real_02_evidence/live_rollup.json` and `agents-only/mt_real_02_evidence/live_rollup.md` → PASS
- Latest-aware planner smoke:
  - `python3 scripts/tools/reality_vless_probe_plan.py --config agents-only/mt_real_01_evidence/phase3_ip_direct.json --rollup-json agents-only/mt_real_02_evidence/live_rollup.json --include-failure-rechecks --limit 20 --output-json /tmp/reality-vless-latest-non-all-ok-plan-r53.json` → PASS
  - `prior_non_all_ok = 6`
- `cargo check --workspace` → PASS

## 2026-04-26 进展更新：Round 52 final non-internal uncovered live evidence

### 目标

- 使用 Round 51 修复后的 planner，跑最后一个默认 non-internal uncovered ready node。
- 仍然不修改 REALITY ClientHello sampler、Vision write-boundary、REALITY read-loop。

### 执行

- Command:
  - `python3 scripts/tools/reality_vless_probe_batch.py --config agents-only/mt_real_01_evidence/phase3_ip_direct.json --target example.com:80 --outbound 'US-A-BGP-1.5倍率' --runs 1 --timeout 8 --phase-timeout-ms 8000 --probe-io-timeout-ms 8000 --output-dir /tmp/reality-vless-probe-batch-live-r52`
- Selection:
  - `US-A-BGP-1.5`

### 结果

- Summary:
  - `total = 1`
  - `executed_runs = 1`
  - `status_counts.completed = 1`
  - `label_counts.all_ok = 1`
  - `class_counts.ok = 9`
  - `matrix_health.has_divergence = false`
- Per outbound:
  - `US-A-BGP-1.5`
    - app/minimal matrix all class `ok`
    - label `all_ok`

### Evidence

- Generated by:
  - `scripts/tools/reality_vless_probe_evidence.py`
- Committed sanitized summary:
  - `agents-only/mt_real_02_evidence/round52_final_uncovered_live_summary.json`
- Updated rollup:
  - `agents-only/mt_real_02_evidence/live_rollup.json`
  - `agents-only/mt_real_02_evidence/live_rollup.md`
- Raw local output remains outside the repo:
  - `/tmp/reality-vless-probe-batch-live-r52`

### Rollup after Round 52

- Covered rounds:
  - Round 41
  - Round 42
  - Round 44
  - Round 47
  - Round 48
  - Round 50
  - Round 52
- Summary:
  - `total_rounds = 7`
  - `total_executed_runs = 26`
  - `total_all_ok_runs = 19`
  - `total_non_all_ok_runs = 7`
  - `has_any_divergence = true`
- Labels:
  - `all_ok = 19`
  - `app_minimal_diverged = 1`
  - `minimal_transport_diverged = 1`
  - `probe_io_all_connection_reset = 1`
  - `probe_io_all_post_dial_eof = 1`
  - `reality_all_connection_reset = 2`
  - `reality_all_reality_dial_eof = 1`
  - `reality_all_timeout = 2`
- Classes:
  - `ok = 186`
  - `timeout = 18`
  - `connection_reset = 18`
  - `reality_dial_eof = 10`
  - `post_dial_eof = 2`

### Planner after Round 52

- Default planner:
  - `uncovered = 0`
  - `prior_non_all_ok = 7`
  - `covered_all_ok = 14`
  - selected: `[]`
- This means non-internal ready-node coverage is complete for the current config/rollup.

### 当前判定

- The current live evidence rollup covers all non-internal ready nodes in `phase3_ip_direct.json`.
- The only committed divergence is the one-shot Round 47 TW direct REALITY EOF; Round 48 targeted repeat did not reproduce it.
- Remaining work should prioritize repeat checks for prior non-all_ok buckets, not sampler modification.

### 验证

- `python3 -B -m unittest scripts/tools/test_reality_probe_tools.py scripts/tools/test_reality_clienthello_family.py` → PASS
  - `24 tests`
- JSON validation:
  - `agents-only/mt_real_02_evidence/round52_final_uncovered_live_summary.json` → PASS
  - `agents-only/mt_real_02_evidence/live_rollup.json` → PASS
- ASCII scan for Round 52 evidence and live rollup → PASS
- `cargo check --workspace` → PASS

## 2026-04-26 进展更新：Round 51 planner internal sentinel exclusion

### 目标

- 修复 coverage planner 在接近覆盖完成时默认选择 `__phase3_invalid_vless` 的问题。
- 该 outbound 是 internal/sentinel negative sample，不应作为普通 live coverage candidate。
- 仍然不修改 REALITY ClientHello sampler、Vision write-boundary、REALITY read-loop。

### 实现

- 更新 `scripts/tools/reality_vless_probe_plan.py`
  - 默认跳过 name 以 `__` 开头的 ready outbounds。
  - 新增 `--include-internal`。
  - 只有显式传入 `--include-internal` 时，才把 sentinel/internal outbounds 纳入 plan。

- 扩展 `scripts/tools/test_reality_probe_tools.py`
  - sample config 增加 `__phase3_invalid_vless`。
  - 默认 plan 验证不会选 internal sentinel。
  - 显式 `include_internal=True` 时验证会选 sentinel。

- 更新 `scripts/tools/README.md`
  - 记录 planner 默认排除 `__*`。

### smoke

- Default:
  - `python3 scripts/tools/reality_vless_probe_plan.py --config agents-only/mt_real_01_evidence/phase3_ip_direct.json --rollup-json agents-only/mt_real_02_evidence/live_rollup.json --limit 5 --output-json /tmp/reality-vless-next-plan-after-r50-no-internal.json`
  - Result:
    - `uncovered = 1`
    - selected: `US-A-BGP-1.5`
- With internal:
  - `python3 scripts/tools/reality_vless_probe_plan.py --config agents-only/mt_real_01_evidence/phase3_ip_direct.json --rollup-json agents-only/mt_real_02_evidence/live_rollup.json --limit 5 --include-internal --output-json /tmp/reality-vless-next-plan-after-r50-with-internal.json`
  - Result:
    - `uncovered = 2`
    - selected: `US-A-BGP-1.5`, `__phase3_invalid_vless`

### 当前判定

- Planner now points the next real live sample at the only remaining non-internal uncovered node: `US-A-BGP-1.5`.
- Internal negative samples remain available for explicit smoke runs.

### 验证

- `python3 -B -m unittest scripts/tools/test_reality_probe_tools.py` → PASS
  - `21 tests`
- `python3 -B -m unittest scripts/tools/test_reality_probe_tools.py scripts/tools/test_reality_clienthello_family.py` → PASS
  - `24 tests`
- `python3 scripts/tools/reality_vless_probe_plan.py --help` → PASS
- `cargo check --workspace` → PASS

## 2026-04-26 进展更新：Round 50 probe IO labeled live evidence

### 目标

- 使用 Round 49 compare label fix 后的工具重新跑 planner-selected JP/US live batch。
- 确认 probe IO same-failure 不再作为无标签 non-all_ok 进入 rollup。
- 仍然不修改 REALITY ClientHello sampler、Vision write-boundary、REALITY read-loop。

### 执行

- Command:
  - `python3 scripts/tools/reality_vless_probe_batch.py --config agents-only/mt_real_01_evidence/phase3_ip_direct.json --target example.com:80 --outbound 'JP-A-BGP-5倍率' --outbound 'JP-A-BGP-4.0倍率' --outbound 'US-A-BGP-0倍率' --outbound 'US-A-BGP-0.5倍率' --outbound 'US-A-BGP-0.8倍率' --runs 1 --timeout 8 --phase-timeout-ms 8000 --probe-io-timeout-ms 8000 --output-dir /tmp/reality-vless-probe-batch-live-r50`
- Selection:
  - `JP-A-BGP-5`
  - `JP-A-BGP-4.0`
  - `US-A-BGP-0`
  - `US-A-BGP-0.5`
  - `US-A-BGP-0.8`

### 结果

- Summary:
  - `total = 5`
  - `executed_runs = 5`
  - `status_counts.completed = 5`
  - `label_counts.all_ok = 3`
  - `label_counts.reality_all_connection_reset = 1`
  - `label_counts.probe_io_all_connection_reset = 1`
  - `label_counts.probe_io_all_post_dial_eof = 1`
  - `class_counts.ok = 34`
  - `class_counts.connection_reset = 9`
  - `class_counts.post_dial_eof = 2`
- Per outbound:
  - `JP-A-BGP-5`
    - app/minimal matrix all class `ok`
    - label `all_ok`
  - `JP-A-BGP-4.0`
    - app/minimal matrix all class `ok`
    - label `all_ok`
  - `US-A-BGP-0`
    - app/minimal matrix all class `ok`
    - label `all_ok`
  - `US-A-BGP-0.5`
    - all REALITY phases class `connection_reset`
    - app bridge / minimal VLESS probe IO also class `connection_reset`
    - labels `reality_all_connection_reset` and `probe_io_all_connection_reset`
  - `US-A-BGP-0.8`
    - app/minimal direct phases class `ok`
    - app bridge and minimal VLESS probe IO class `post_dial_eof`
    - label `probe_io_all_post_dial_eof`
    - no divergence

### Evidence

- Generated by:
  - `scripts/tools/reality_vless_probe_evidence.py`
- Committed sanitized summary:
  - `agents-only/mt_real_02_evidence/round50_probe_io_labeled_live_summary.json`
- Updated rollup:
  - `agents-only/mt_real_02_evidence/live_rollup.json`
  - `agents-only/mt_real_02_evidence/live_rollup.md`
- Raw local output remains outside the repo:
  - `/tmp/reality-vless-probe-batch-live-r50`

### Rollup after Round 50

- Summary:
  - `total_rounds = 6`
  - `total_executed_runs = 25`
  - `total_all_ok_runs = 18`
  - `total_non_all_ok_runs = 7`
  - `has_any_divergence = true`
- Labels:
  - `all_ok = 18`
  - `app_minimal_diverged = 1`
  - `minimal_transport_diverged = 1`
  - `probe_io_all_connection_reset = 1`
  - `probe_io_all_post_dial_eof = 1`
  - `reality_all_connection_reset = 2`
  - `reality_all_reality_dial_eof = 1`
  - `reality_all_timeout = 2`
- Classes:
  - `ok = 177`
  - `timeout = 18`
  - `connection_reset = 18`
  - `reality_dial_eof = 10`
  - `post_dial_eof = 2`

### 当前判定

- Round 50 confirms the Round 49 label fix under live conditions.
- US-0.8 is a matched probe-IO failure, not app/minimal divergence.
- The only committed divergence remains the single Round 47 TW sample, and Round 48 targeted repeat did not reproduce it.
- No sampler change is justified.

### 下一批 planner 状态

- After updated rollup:
  - `uncovered = 2`
  - `prior_non_all_ok = 7`
  - `covered_all_ok = 13`
- Default planner-selected nodes:
  - `US-A-BGP-1.5`
  - `__phase3_invalid_vless`
- Follow-up tooling issue:
  - planner should default-exclude internal `__*` sentinel outbounds from live coverage planning.

### 验证

- `python3 -B -m unittest scripts/tools/test_reality_probe_tools.py scripts/tools/test_reality_clienthello_family.py` → PASS
  - `23 tests`
- JSON validation:
  - `agents-only/mt_real_02_evidence/round50_probe_io_labeled_live_summary.json` → PASS
  - `agents-only/mt_real_02_evidence/live_rollup.json` → PASS
- ASCII scan for Round 50 evidence and live rollup → PASS
- `cargo check --workspace` → PASS

## 2026-04-26 进展更新：Round 49 probe IO same-failure labeling

### 目标

- 修补 compare label coverage。
- Round 49 planner 下一批 live run 里出现一个重要边界：
  - app bridge 与 minimal VLESS probe IO 同时 `post_dial_eof`；
  - direct REALITY / VLESS dial phases 都是 `ok`；
  - compare mismatches 为 `0`；
  - 但旧 compare labels 为空。
- 这个不是 divergence，但不能进入 rollup 后成为“无标签 non-all_ok”。

### 实现

- 更新 `scripts/tools/reality_probe_compare.py`
  - 新增 probe IO same-failure label 规则：
    - 如果 `app.bridge == minimal.vless_probe_io`
    - 且 class 不是 `ok` / `missing`
    - 则添加 `probe_io_all_<class>`
  - 对触发样本输出：
    - `probe_io_all_post_dial_eof`

- 扩展 `scripts/tools/test_reality_probe_tools.py`
  - 新增 `test_report_labels_same_probe_io_failure_without_divergence`
  - 覆盖：
    - mismatches 仍为 `0`
    - labels 包含 `probe_io_all_post_dial_eof`

### smoke

- Command:
  - `python3 scripts/tools/reality_probe_compare.py --app-json /tmp/reality-vless-probe-batch-live-r49/005-US-A-BGP-0.8/app.json --phase-json /tmp/reality-vless-probe-batch-live-r49/005-US-A-BGP-0.8/phase.json`
- Result:
  - `mismatches = 0`
  - `labels = ["probe_io_all_post_dial_eof"]`

### 当前判定

- `probe_io_all_post_dial_eof` 是 class-first evidence label，不是 divergence。
- 该修复避免 rollup 出现 no-label non-all_ok 样本。
- 本轮没有修改 REALITY sampler/read-loop/adapter behavior。

### 验证

- `python3 -B -m unittest scripts/tools/test_reality_probe_tools.py` → PASS
  - `20 tests`
- `python3 -B -m unittest scripts/tools/test_reality_probe_tools.py scripts/tools/test_reality_clienthello_family.py` → PASS
  - `23 tests`
- `python3 scripts/tools/reality_probe_compare.py --app-json /tmp/reality-vless-probe-batch-live-r49/005-US-A-BGP-0.8/app.json --phase-json /tmp/reality-vless-probe-batch-live-r49/005-US-A-BGP-0.8/phase.json` → PASS
- JSON validation for regenerated US-0.8 compare → PASS
- `cargo check --workspace` → PASS

## 2026-04-26 进展更新：Round 47/48 planner-selected live batch and targeted repeat

### 目标

- 使用 Round 46 planner 选择未覆盖 ready nodes 做下一组 live batch。
- 对任何 divergence 先做 targeted repeat，不立即改 sampler。
- 仍然不修改 REALITY ClientHello sampler、Vision write-boundary、REALITY read-loop。

### Round 47 执行

- Command:
  - `python3 scripts/tools/reality_vless_probe_batch.py --config agents-only/mt_real_01_evidence/phase3_ip_direct.json --target example.com:80 --outbound 'HK-A-BGP-2.0倍率' --outbound 'HK-A-BGP-2.5倍率' --outbound 'TW-A-BGP-1.0倍率' --outbound 'JP-A-BGP-0.3倍率' --outbound 'JP-A-BGP-1.1倍率' --runs 1 --timeout 8 --phase-timeout-ms 8000 --probe-io-timeout-ms 8000 --output-dir /tmp/reality-vless-probe-batch-live-r47`
- Selection:
  - planner-selected uncovered nodes from Round 46:
    - `HK-A-BGP-2.0`
    - `HK-A-BGP-2.5`
    - `TW-A-BGP-1.0`
    - `JP-A-BGP-0.3`
    - `JP-A-BGP-1.1`

### Round 47 结果

- Summary:
  - `total = 5`
  - `executed_runs = 5`
  - `status_counts.completed = 5`
  - `label_counts.all_ok = 2`
  - `label_counts.reality_all_timeout = 1`
  - `label_counts.reality_all_reality_dial_eof = 1`
  - `label_counts.app_minimal_diverged = 1`
  - `label_counts.minimal_transport_diverged = 1`
  - `class_counts.ok = 26`
  - `class_counts.timeout = 9`
  - `class_counts.reality_dial_eof = 10`
- Per outbound:
  - `HK-A-BGP-2.0`
    - all app/minimal phases class `timeout`
    - label `reality_all_timeout`
  - `HK-A-BGP-2.5`
    - app/minimal matrix all class `ok`
    - label `all_ok`
  - `TW-A-BGP-1.0`
    - app pre/post direct REALITY: `ok`
    - app pre/post VLESS dial: `ok`
    - app bridge: `ok`
    - minimal direct REALITY: `reality_dial_eof`
    - minimal transport REALITY: `ok`
    - minimal VLESS dial/probe IO: `ok`
    - labels `app_minimal_diverged` and `minimal_transport_diverged`
  - `JP-A-BGP-0.3`
    - all REALITY phases class `reality_dial_eof`
    - label `reality_all_reality_dial_eof`
  - `JP-A-BGP-1.1`
    - app/minimal matrix all class `ok`
    - label `all_ok`

### Round 48 targeted repeat

- Command:
  - `python3 scripts/tools/reality_vless_probe_batch.py --config agents-only/mt_real_01_evidence/phase3_ip_direct.json --target example.com:80 --outbound 'TW-A-BGP-1.0倍率' --runs 3 --timeout 8 --phase-timeout-ms 8000 --probe-io-timeout-ms 8000 --output-dir /tmp/reality-vless-probe-batch-live-r48-tw-repeat`
- Summary:
  - `total = 3`
  - `executed_runs = 3`
  - `status_counts.completed = 3`
  - `label_counts.all_ok = 3`
  - `class_counts.ok = 27`
  - `matrix_health.has_divergence = false`

### Evidence

- Generated by:
  - `scripts/tools/reality_vless_probe_evidence.py`
- Committed sanitized summaries:
  - `agents-only/mt_real_02_evidence/round47_planner_uncovered_live_summary.json`
  - `agents-only/mt_real_02_evidence/round48_tw_divergence_repeat_summary.json`
- Updated rollup:
  - `agents-only/mt_real_02_evidence/live_rollup.json`
  - `agents-only/mt_real_02_evidence/live_rollup.md`
- Raw local output remains outside the repo:
  - `/tmp/reality-vless-probe-batch-live-r47`
  - `/tmp/reality-vless-probe-batch-live-r48-tw-repeat`

### Rollup after Round 48

- Covered rounds:
  - Round 41
  - Round 42
  - Round 44
  - Round 47
  - Round 48
- Summary:
  - `total_rounds = 5`
  - `total_executed_runs = 20`
  - `total_all_ok_runs = 15`
  - `total_non_all_ok_runs = 5`
  - `has_any_divergence = true`
- Labels:
  - `all_ok = 15`
  - `reality_all_timeout = 2`
  - `reality_all_connection_reset = 1`
  - `reality_all_reality_dial_eof = 1`
  - `app_minimal_diverged = 1`
  - `minimal_transport_diverged = 1`
- Classes:
  - `ok = 143`
  - `timeout = 18`
  - `connection_reset = 9`
  - `reality_dial_eof = 10`

### 当前判定

- Round 47 found the first committed app/minimal divergence label.
- The only divergent phase was `minimal.direct_reality`; app direct REALITY, app bridge, minimal transport REALITY, and VLESS paths were `ok`.
- Round 48 targeted repeat ran 3 more samples against the same TW node and all 3 were `all_ok`.
- Therefore this is not yet a stable sampler/dataplane regression signal.
- Keep collecting class-first evidence; do not change ClientHello sampler based on this isolated one-shot divergence.

### 下一批 planner 状态

- After updated rollup:
  - `uncovered = 7`
  - `prior_non_all_ok = 5`
  - `covered_all_ok = 10`
- Next default planner-selected nodes:
  - `JP-A-BGP-5`
  - `JP-A-BGP-4.0`
  - `US-A-BGP-0`
  - `US-A-BGP-0.5`
  - `US-A-BGP-0.8`

### 验证

- `python3 -B -m unittest scripts/tools/test_reality_probe_tools.py scripts/tools/test_reality_clienthello_family.py` → PASS
  - `22 tests`
- JSON validation:
  - `agents-only/mt_real_02_evidence/round47_planner_uncovered_live_summary.json` → PASS
  - `agents-only/mt_real_02_evidence/round48_tw_divergence_repeat_summary.json` → PASS
  - `agents-only/mt_real_02_evidence/live_rollup.json` → PASS
- ASCII scan for Round 47 / Round 48 evidence and live rollup → PASS
- `cargo check --workspace` → PASS

## 2026-04-26 进展更新：Round 46 coverage-aware live batch planner

### 目标

- 将“下一批 live 节点该跑谁”工具化。
- 输入当前 config 和 committed live rollup，优先找还没有 evidence 覆盖的 ready REALITY VLESS 节点。
- 仍然不修改 REALITY ClientHello sampler、Vision write-boundary、REALITY read-loop。

### 实现

- 新增 `scripts/tools/reality_vless_probe_plan.py`
  - 输入：
    - `--config`
    - `--rollup-json`
    - `--limit`
  - 可选：
    - `--include-failure-rechecks`
    - `--include-covered`
    - `--output-json`
  - 使用 `safe_slug` 对齐 config outbound name 和 rollup `by_outbound` key。
  - 分桶：
    - `uncovered`
    - `prior_non_all_ok`
    - `covered_all_ok`
  - 默认只选择 uncovered ready nodes。

- 扩展 `scripts/tools/test_reality_probe_tools.py`
  - 新增 `RealityProbePlanTests`。
  - 覆盖：
    - 默认优先 uncovered；
    - 可加入 prior non-all_ok / covered nodes；
    - node classification。

- 更新 `scripts/tools/README.md`
  - 增加 planner 用法。

### smoke

- Command:
  - `python3 scripts/tools/reality_vless_probe_plan.py --config agents-only/mt_real_01_evidence/phase3_ip_direct.json --rollup-json agents-only/mt_real_02_evidence/live_rollup.json --limit 5 --output-json /tmp/reality-vless-next-plan-r46.json`
- Output:
  - `uncovered = 12`
  - `prior_non_all_ok = 2`
  - `covered_all_ok = 8`
  - selected:
    - `HK-A-BGP-2.0`
    - `HK-A-BGP-2.5`
    - `TW-A-BGP-1.0`
    - `JP-A-BGP-0.3`
    - `JP-A-BGP-1.1`

### 当前判定

- Live sampling now has a repeatable coverage planner.
- Next live round can use the planner-selected uncovered nodes instead of manually choosing candidates.
- This reinforces class-first evidence expansion and keeps sampler changes gated on actual app/minimal divergence.

### 验证

- `python3 -B -m unittest scripts/tools/test_reality_probe_tools.py` → PASS
  - `19 tests`
- `python3 -B -m unittest scripts/tools/test_reality_probe_tools.py scripts/tools/test_reality_clienthello_family.py` → PASS
  - `22 tests`
- `python3 scripts/tools/reality_vless_probe_plan.py --config agents-only/mt_real_01_evidence/phase3_ip_direct.json --rollup-json agents-only/mt_real_02_evidence/live_rollup.json --limit 5 --output-json /tmp/reality-vless-next-plan-r46.json` → PASS
- `python3 scripts/tools/reality_vless_probe_plan.py --help` → PASS
- `cargo check --workspace` → PASS

## 2026-04-26 进展更新：Round 45 live evidence rollup

### 目标

- 将已经 committed 的 live evidence 汇总成机器可读 JSON 和人工可读 Markdown。
- 避免后续判断散落在多个 round 文档中。
- 仍然不修改 REALITY ClientHello sampler、Vision write-boundary、REALITY read-loop。

### 实现

- 新增 `scripts/tools/reality_vless_evidence_rollup.py`
  - 输入多个 evidence JSON。
  - 输出 rollup JSON / Markdown。
  - 聚合：
    - total rounds
    - total executed runs
    - all_ok / non-all_ok runs
    - divergence flag
    - status counts
    - label counts
    - class counts
    - per-outbound counts

- 扩展 `scripts/tools/test_reality_probe_tools.py`
  - 新增 `RealityEvidenceRollupTests`。
  - 覆盖：
    - multi-evidence aggregation；
    - per-outbound aggregation；
    - markdown table row generation。

- 更新 `scripts/tools/README.md`
  - 增加 rollup 用法。

### 生成

- Command:
  - `python3 scripts/tools/reality_vless_evidence_rollup.py --evidence agents-only/mt_real_02_evidence/round41_live_batch_summary.json agents-only/mt_real_02_evidence/round42_cross_region_live_summary.json agents-only/mt_real_02_evidence/round44_wide_region_live_summary.json --output-json agents-only/mt_real_02_evidence/live_rollup.json --output-md agents-only/mt_real_02_evidence/live_rollup.md`
- Generated:
  - `agents-only/mt_real_02_evidence/live_rollup.json`
  - `agents-only/mt_real_02_evidence/live_rollup.md`

### 当前 rollup

- Covered rounds:
  - Round 41
  - Round 42
  - Round 44
- Summary:
  - `total_rounds = 3`
  - `total_executed_runs = 12`
  - `total_all_ok_runs = 10`
  - `total_non_all_ok_runs = 2`
  - `has_any_divergence = false`
- Labels:
  - `all_ok = 10`
  - `reality_all_timeout = 1`
  - `reality_all_connection_reset = 1`
- Classes:
  - `ok = 90`
  - `timeout = 9`
  - `connection_reset = 9`

### 当前判定

- Committed live evidence currently shows no app/minimal divergence.
- Non-all_ok samples are uniform node/path classes:
  - JP timeout in Round 42
  - UK connection_reset in Round 44
- No sampler change is justified by the committed live evidence rollup.

### 验证

- `python3 -B -m unittest scripts/tools/test_reality_probe_tools.py scripts/tools/test_reality_clienthello_family.py` → PASS
  - `19 tests`
- `python3 -m json.tool agents-only/mt_real_02_evidence/live_rollup.json` → PASS
- ASCII scan for `agents-only/mt_real_02_evidence/live_rollup.json` and `agents-only/mt_real_02_evidence/live_rollup.md` → PASS
- `cargo check --workspace` → PASS

## 2026-04-26 进展更新：Round 44 wide-region live batch evidence

### 目标

- 在 Round 41/42 基础上继续扩大 live sample 面。
- 使用 Round 43 evidence builder 生成 sanitized evidence。
- 仍然不修改 REALITY ClientHello sampler、Vision write-boundary、REALITY read-loop。

### 执行

- Command:
  - `python3 scripts/tools/reality_vless_probe_batch.py --config agents-only/mt_real_01_evidence/phase3_ip_direct.json --target example.com:80 --outbound 'SG-A-BGP-1.2倍率' --outbound 'ID-A-BGP-1.2倍率' --outbound 'TW-A-Hinet-1.1倍率' --outbound 'DE-A-BGP-1.0倍率' --outbound 'UK-A-BGP-0.5倍率' --runs 1 --timeout 8 --phase-timeout-ms 8000 --probe-io-timeout-ms 8000 --output-dir /tmp/reality-vless-probe-batch-live-r44`
- Selection:
  - config: `agents-only/mt_real_01_evidence/phase3_ip_direct.json`
  - target: `example.com:80`
  - outbounds: `SG-A-BGP-1.2`, `ID-A-BGP-1.2`, `TW-A-Hinet-1.1`, `DE-A-BGP-1.0`, `UK-A-BGP-0.5`
  - runs: `1`

### 结果

- Batch stdout:
  - `selected_count = 5`
  - `runs = 1`
  - `summary_json = /tmp/reality-vless-probe-batch-live-r44/summary.json`
- Summary:
  - `total = 5`
  - `executed_runs = 5`
  - `status_counts.completed = 5`
  - `label_counts.all_ok = 4`
  - `label_counts.reality_all_connection_reset = 1`
  - `class_counts.ok = 36`
  - `class_counts.connection_reset = 9`
  - `matrix_health.has_divergence = false`
- Per outbound:
  - `SG-A-BGP-1.2`
    - app/minimal matrix all class `ok`
    - label `all_ok`
  - `ID-A-BGP-1.2`
    - app/minimal matrix all class `ok`
    - label `all_ok`
  - `TW-A-Hinet-1.1`
    - app/minimal matrix all class `ok`
    - label `all_ok`
  - `DE-A-BGP-1.0`
    - app/minimal matrix all class `ok`
    - label `all_ok`
  - `UK-A-BGP-0.5`
    - app pre/post direct REALITY, app pre/post VLESS dial, app bridge, and all minimal probes class `connection_reset`
    - label `reality_all_connection_reset`

### Evidence

- Generated by:
  - `scripts/tools/reality_vless_probe_evidence.py`
- Committed sanitized summary:
  - `agents-only/mt_real_02_evidence/round44_wide_region_live_summary.json`
- Raw local output remains outside the repo:
  - `/tmp/reality-vless-probe-batch-live-r44`

### 当前判定

- Round 44 expands positive live dataplane evidence to SG/ID/TW/DE.
- UK is a consistent `connection_reset` across every app/minimal phase, so it is node/path evidence, not a Rust app/minimal divergence.
- No sampler change is justified by this sample.

### 验证

- `python3 -m json.tool agents-only/mt_real_02_evidence/round44_wide_region_live_summary.json` → PASS
- ASCII scan for `agents-only/mt_real_02_evidence/round44_wide_region_live_summary.json` → PASS
- `python3 -B -m unittest scripts/tools/test_reality_probe_tools.py scripts/tools/test_reality_clienthello_family.py` → PASS
  - `17 tests`
- `cargo check --workspace` → PASS

## 2026-04-26 进展更新：Round 43 sanitized live evidence builder

### 目标

- 将 Round 41/42 这种 live batch summary 的 evidence 归档步骤工具化。
- 避免每次手工摘录 `summary.json`，也避免把 provider raw tag / 大量 raw dump 直接塞进仓库。
- 仍然不修改 REALITY ClientHello sampler、Vision write-boundary、REALITY read-loop。

### 实现

- 新增 `scripts/tools/reality_vless_probe_evidence.py`
  - 输入 batch runner 的 `summary.json`。
  - 输出可提交的 sanitized evidence JSON。
  - 非 ASCII outbound name 会压成稳定 ASCII key。
  - 输出 compact `runs`，只保留：
    - `outbound`
    - `ordinal`
    - `run_index`
    - `status`
    - labels
    - compact class counts
  - 输出 `matrix_health`：
    - `has_divergence`
    - `divergence_labels`
    - `all_ok_runs`
    - `uniform_failure_labels`

- 扩展 `scripts/tools/test_reality_probe_tools.py`
  - 新增 `RealityProbeEvidenceTests`。
  - 覆盖：
    - sanitized outbound key；
    - `matrix_health`；
    - compact per-run class counts；
    - evidence JSON ASCII 输出。
  - 工具单测扩到 `14`。

- 更新 `scripts/tools/README.md`
  - 增加 evidence builder 用法。

### smoke

- 使用 Round 42 raw summary 生成 evidence：
  - `python3 scripts/tools/reality_vless_probe_evidence.py --summary-json /tmp/reality-vless-probe-batch-live-r42/summary.json --output-json /tmp/reality-vless-probe-evidence-r42.generated.json --round 42 --date 2026-04-26 --description 'generated cross-region live evidence' --command 'round42 smoke' --interpretation 'classification-first generated evidence smoke'`
- stdout:
  - `executed_runs = 3`
  - `has_divergence = false`
- JSON validation:
  - `python3 -m json.tool /tmp/reality-vless-probe-evidence-r42.generated.json` → PASS
- ASCII scan:
  - PASS

### 当前判定

- Round 43 把 live evidence 归档变成可重复工具链步骤。
- 下一轮 live 扩样可以直接：
  - batch runner 生成 raw `/tmp/.../summary.json`
  - evidence builder 生成 `agents-only/mt_real_02_evidence/roundNN_*.json`
  - docs 记录 class-first 结论
- 本轮仍没有任何 wire/dataplane 行为改动。

### 验证

- `python3 -B -m unittest scripts/tools/test_reality_probe_tools.py` → PASS
  - `14 tests`
- `python3 -B -m unittest scripts/tools/test_reality_probe_tools.py scripts/tools/test_reality_clienthello_family.py` → PASS
  - `17 tests`
- `python3 scripts/tools/reality_vless_probe_evidence.py --summary-json /tmp/reality-vless-probe-batch-live-r42/summary.json --output-json /tmp/reality-vless-probe-evidence-r42.generated.json --round 42 --date 2026-04-26 --description 'generated cross-region live evidence' --command 'round42 smoke' --interpretation 'classification-first generated evidence smoke'` → PASS
- `python3 -m json.tool /tmp/reality-vless-probe-evidence-r42.generated.json` → PASS
- `python3 scripts/tools/reality_vless_probe_evidence.py --help` → PASS
- `cargo check --workspace` → PASS

## 2026-04-26 进展更新：Round 42 cross-region live batch evidence

### 目标

- 在 Round 41 HK repeat all_ok 后，做一组小而有边界的跨区域 live sample。
- 仍然不修改 REALITY ClientHello sampler、Vision write-boundary、REALITY read-loop。
- 关注点：
  - SG/JP/US 是否出现 app/minimal 分叉；
  - timeout/eof 是否按 class 聚合，而不是被误判成 sampler 问题。

### 执行

- Command:
  - `python3 scripts/tools/reality_vless_probe_batch.py --config agents-only/mt_real_01_evidence/phase3_ip_direct.json --target example.com:80 --outbound 'SG-A-BGP-1.0倍率' --outbound 'JP-A-BGP-1.0倍率' --outbound 'US-A-BGP-0.1倍率' --runs 1 --timeout 8 --phase-timeout-ms 8000 --probe-io-timeout-ms 8000 --output-dir /tmp/reality-vless-probe-batch-live-r42`
- Selection:
  - config: `agents-only/mt_real_01_evidence/phase3_ip_direct.json`
  - target: `example.com:80`
  - outbounds: `SG-A-BGP-1.0`, `JP-A-BGP-1.0`, `US-A-BGP-0.1`
  - runs: `1`

### 结果

- Batch stdout:
  - `selected_count = 3`
  - `runs = 1`
  - `summary_json = /tmp/reality-vless-probe-batch-live-r42/summary.json`
- Summary:
  - `total = 3`
  - `executed_runs = 3`
  - `status_counts.completed = 3`
  - `label_counts.all_ok = 2`
  - `label_counts.reality_all_timeout = 1`
  - `class_counts.ok = 18`
  - `class_counts.timeout = 9`
- Per outbound:
  - `SG-A-BGP-1.0`
    - app/minimal matrix all class `ok`
    - label `all_ok`
  - `JP-A-BGP-1.0`
    - app pre/post direct REALITY, app pre/post VLESS dial, app bridge, and all minimal probes class `timeout`
    - label `reality_all_timeout`
  - `US-A-BGP-0.1`
    - app/minimal matrix all class `ok`
    - label `all_ok`

### Evidence

- Committed sanitized summary:
  - `agents-only/mt_real_02_evidence/round42_cross_region_live_summary.json`
- Raw local output remains outside the repo:
  - `/tmp/reality-vless-probe-batch-live-r42`

### 验证

- `python3 -m json.tool agents-only/mt_real_02_evidence/round42_cross_region_live_summary.json` → PASS
- `python3 -B -m unittest scripts/tools/test_reality_probe_tools.py scripts/tools/test_reality_clienthello_family.py` → PASS
  - `15 tests`
- `cargo check --workspace` → PASS

### 当前判定

- Cross-region live sample expanded positive evidence beyond HK:
  - SG and US are all_ok through app and minimal paths.
  - JP is a consistent timeout across every app/minimal phase, so it is node/path evidence, not a Rust app/minimal divergence.
- This reinforces the current class-first rule: do not touch sampler based on a uniformly timed-out node.

## 2026-04-26 进展更新：Round 41 small repeat live batch evidence

### 目标

- 使用 Round 40 repeat-aware batch runner 做小规模 live dataplane 复测。
- 仍然不修改 REALITY ClientHello sampler、Vision write-boundary、REALITY read-loop。
- 重点看同节点同目标 repeat samples 是否稳定同 class，以及 app/minimal 是否分叉。

### 执行

- Command:
  - `python3 scripts/tools/reality_vless_probe_batch.py --config agents-only/mt_real_01_evidence/phase3_ip_direct.json --target example.com:80 --include HK-A-BGP --limit 2 --runs 2 --timeout 8 --phase-timeout-ms 8000 --probe-io-timeout-ms 8000 --output-dir /tmp/reality-vless-probe-batch-live-r41`
- Selection:
  - config: `agents-only/mt_real_01_evidence/phase3_ip_direct.json`
  - target: `example.com:80`
  - include: `HK-A-BGP`
  - limit: `2`
  - runs: `2`

### 结果

- Batch stdout:
  - `selected_count = 2`
  - `runs = 2`
  - `summary_json = /tmp/reality-vless-probe-batch-live-r41/summary.json`
- Summary:
  - `total = 4`
  - `executed_runs = 4`
  - `status_counts.completed = 4`
  - `label_counts.all_ok = 4`
  - `class_counts.ok = 36`
- Per outbound:
  - `HK-A-BGP-0.3`
    - `completed = 2`
    - `all_ok = 2`
    - `ok = 18`
  - `HK-A-BGP-1.0`
    - `completed = 2`
    - `all_ok = 2`
    - `ok = 18`
- A representative app probe (`run-001`) showed:
  - pre-bridge direct REALITY: `ok`
  - pre-bridge direct VLESS dial: `ok`
  - post-bridge direct REALITY: `ok`
  - post-bridge direct VLESS dial: `ok`
  - bridge probe: `ok`, `HTTP/1.1 200 OK`, `response_bytes=837`
- A representative minimal phase probe (`run-001`) showed:
  - direct REALITY: `ok`
  - transport REALITY: `ok`
  - VLESS dial: `ok`
  - VLESS probe IO: `ok`

### Evidence

- Committed sanitized summary:
  - `agents-only/mt_real_02_evidence/round41_live_batch_summary.json`
- Raw local output remains outside the repo:
  - `/tmp/reality-vless-probe-batch-live-r41`

### 验证

- `python3 -m json.tool agents-only/mt_real_02_evidence/round41_live_batch_summary.json` → PASS
- `python3 -B -m unittest scripts/tools/test_reality_probe_tools.py scripts/tools/test_reality_clienthello_family.py` → PASS
  - `15 tests`
- `cargo check --workspace` → PASS

### 当前判定

- Round 41 is positive repeat live dataplane evidence:
  - current sampler/read-loop/adapter surface works for 2 ready HK REALITY VLESS nodes;
  - app pre/post, app bridge, and minimal phase probe all agree on class `ok`;
  - no stable app/minimal class fork appeared in these samples.
- This does not prove all nodes are healthy; it does reduce pressure to change sampler based on stale node failures.
- Next useful step is broader but still bounded sampling: e.g. one HK + one SG/JP/US sample set, still class-first.

## 2026-04-26 进展更新：Round 40 repeat-aware REALITY batch sampling

### 目标

- 在 Round 39 批量 runner 基础上继续推进重复采样能力。
- live dataplane 证据下一阶段需要确认：
  - 同节点同目标是否稳定同 class；
  - app/minimal/bridge 是否稳定分叉；
  - 失败是否只是节点易失，而不是 sampler/dataplane 回归。
- 因此本轮给 batch runner 增加 repeat samples，而不是改 ClientHello sampler。

### 实现

- `scripts/tools/reality_vless_probe_batch.py`
  - 新增 `--runs N`。
  - `runs == 1` 维持 Round 39 的 sample dir 形态：
    - `NNN-outbound/`
  - `runs > 1` 时输出：
    - `NNN-outbound/run-001/`
    - `NNN-outbound/run-002/`
    - ...
  - result 记录新增：
    - `ordinal`
    - `run_index`
  - `summary.json` 新增：
    - `executed_runs`
    - `by_outbound`
  - 非 dry-run 会先清理本轮 `results.jsonl`，避免复用同一个 output dir 时把旧结果混入新证据。
  - `--limit` 改为非负整数校验。
  - `--runs` 改为正整数校验。

- `scripts/tools/test_reality_probe_tools.py`
  - 新增/扩展覆盖：
    - repeat sample dir layout；
    - `--limit` / `--runs` 参数校验；
    - `summary.by_outbound`；
    - `summary.executed_runs`。
  - 本文件单测数扩到 `12`。

- `scripts/tools/README.md`
  - batch live 示例加入 `--runs 2`。
  - 记录 repeat sample dir 形态和 per-outbound summary。

### smoke

- Dry-run repeat:
  - `python3 scripts/tools/reality_vless_probe_batch.py --config agents-only/mt_real_01_evidence/phase3_ip_direct.json --target example.com:80 --limit 1 --runs 2 --dry-run --output-dir /tmp/reality-vless-probe-batch-repeat-dry`
  - PASS，stdout 显示 `selected_count=1` / `runs=2`。
- Executed repeat smoke:
  - `python3 scripts/tools/reality_vless_probe_batch.py --config agents-only/mt_real_01_evidence/phase3_ip_direct.json --target example.com:80 --outbound '__phase3_invalid_vless' --runs 2 --timeout 1 --phase-timeout-ms 1000 --probe-io-timeout-ms 1000 --output-dir /tmp/reality-vless-probe-batch-repeat-smoke`
  - PASS，生成：
    - `001-phase3_invalid_vless/run-001`
    - `001-phase3_invalid_vless/run-002`
  - summary:
    - `total = 2`
    - `executed_runs = 2`
    - `status_counts.completed = 2`
    - `label_counts.reality_all_connection_refused = 2`
    - `class_counts.connection_refused = 18`
    - `by_outbound.__phase3_invalid_vless.status_counts.completed = 2`

### 当前判定

- Round 40 把 Round 39 的“可控批量矩阵”推进到“可控重复采样矩阵”。
- 这让下一次真实节点复测可以小样本但有稳定性维度：例如 `--include 'HK-A-BGP' --limit 2 --runs 2`。
- 本轮仍没有修改 wire sampler 或 dataplane 行为。

### 验证

- `python3 -B -m unittest scripts/tools/test_reality_probe_tools.py` → PASS
  - `12 tests`
- `python3 -B -m unittest scripts/tools/test_reality_probe_tools.py scripts/tools/test_reality_clienthello_family.py` → PASS
  - `15 tests`
- `python3 scripts/tools/reality_vless_probe_batch.py --config agents-only/mt_real_01_evidence/phase3_ip_direct.json --target example.com:80 --limit 1 --runs 2 --dry-run --output-dir /tmp/reality-vless-probe-batch-repeat-dry` → PASS
- `python3 scripts/tools/reality_vless_probe_batch.py --config agents-only/mt_real_01_evidence/phase3_ip_direct.json --target example.com:80 --outbound '__phase3_invalid_vless' --runs 2 --timeout 1 --phase-timeout-ms 1000 --probe-io-timeout-ms 1000 --output-dir /tmp/reality-vless-probe-batch-repeat-smoke` → PASS
- `bash -n scripts/tools/reality_vless_probe_matrix.sh` → PASS
- `cargo check --workspace` → PASS

## 2026-04-26 进展更新：Round 39 batch REALITY probe matrix

### 目标

- 在 Round 38 单节点 app/minimal matrix 之上继续推进到批量采样层。
- 仍不修改 REALITY ClientHello sampler、Vision write-boundary、REALITY read-loop。
- 让下一次真实节点复测能够：
  - 先 dry-run 枚举候选节点；
  - 按 tag/include/limit 选择少量节点；
  - 每个节点生成完整 matrix 目录；
  - 统一汇总 labels/classes，减少人工读日志。

### 实现

- `scripts/tools/reality_vless_env_from_config.py`
  - 新增 `--list`。
  - 输出 config 中所有 VLESS outbound 的 metadata：
    - `name`
    - `server`
    - `port`
    - `server_name`
    - `fingerprint`
    - `flow`
    - `plain_tcp`
    - `has_uuid`
    - `has_reality_public_key`
    - `ready`
    - `skip_reason`
  - 新增 helpers：
    - `optional_port`
    - `is_plain_tcp_transport`
    - `reality_public_key`
    - `outbound_summary`
    - `reality_vless_ready_reason`
    - `list_reality_vless_outbounds`

- `scripts/tools/reality_vless_probe_batch.py`
  - 新增批量 runner。
  - 支持筛选：
    - `--outbound`（可重复）
    - `--include`
    - `--exclude`
    - `--include-skipped`
    - `--limit`
  - 支持执行控制：
    - `--dry-run`
    - `--timeout`
    - `--phase-timeout-ms`
    - `--probe-io-timeout-ms`
    - `--matrix-script`
  - 输出：
    - `plan.json`
    - `results.jsonl`（非 dry-run）
    - `summary.json`
    - 每个节点独立 sample dir，内含 Round 38 matrix 产物。
  - `summary.json` 聚合：
    - `status_counts`
    - `label_counts`
    - `class_counts`

- `scripts/tools/test_reality_probe_tools.py`
  - 新增 batch/discovery 单测：
    - `test_lists_ready_and_skipped_vless_reality_outbounds`
    - `test_safe_slug_keeps_paths_predictable`
    - `test_select_outbounds_filters_ready_names_and_limit`
    - `test_summarize_results_counts_labels_and_classes`
  - 本文件单测数扩到 `10`。

- `scripts/tools/README.md`
  - 增加 batch dry-run / live collection 示例。

### smoke

- Discovery:
  - `python3 scripts/tools/reality_vless_env_from_config.py --config agents-only/mt_real_01_evidence/phase3_ip_direct.json --list`
  - 成功枚举 REALITY VLESS 节点；`HK-A-BGP-*` 样本显示 `ready=true`。
- Dry-run:
  - `python3 scripts/tools/reality_vless_probe_batch.py --config agents-only/mt_real_01_evidence/phase3_ip_direct.json --target example.com:80 --limit 3 --dry-run --output-dir /tmp/reality-vless-probe-batch-dry`
  - 生成 `plan.json` / `summary.json`，`selected_count=3`。
- Executed smoke:
  - `python3 scripts/tools/reality_vless_probe_batch.py --config agents-only/mt_real_01_evidence/phase3_ip_direct.json --target example.com:80 --outbound '__phase3_invalid_vless' --timeout 1 --phase-timeout-ms 1000 --probe-io-timeout-ms 1000 --output-dir /tmp/reality-vless-probe-batch-smoke`
  - 生成：
    - `plan.json`
    - `results.jsonl`
    - `summary.json`
    - `001-phase3_invalid_vless/run.json`
    - `001-phase3_invalid_vless/app.json`
    - `001-phase3_invalid_vless/phase.json`
    - `001-phase3_invalid_vless/compare.json`
  - summary:
    - `status_counts.completed = 1`
    - `label_counts.reality_all_connection_refused = 1`
    - `class_counts.connection_refused = 9`

### 当前判定

- Round 39 把 live 证据采集从“单节点手工矩阵”推进到“可控批量矩阵”：
  - 可以先 dry-run 选节点；
  - 可以限制少量样本，避免把节点易失变成大样本噪声；
  - 可以按 class/label 汇总，直接看 app/minimal/bridge 分叉是否稳定。
- 本轮没有改变 wire sampler 或 dataplane 行为。

### 验证

- `python3 -B -m unittest scripts/tools/test_reality_probe_tools.py` → PASS
  - `10 tests`
- `python3 -B -m unittest scripts/tools/test_reality_probe_tools.py scripts/tools/test_reality_clienthello_family.py` → PASS
  - `13 tests`
- `python3 scripts/tools/reality_vless_env_from_config.py --config agents-only/mt_real_01_evidence/phase3_ip_direct.json --list` → PASS
- `python3 scripts/tools/reality_vless_probe_batch.py --config agents-only/mt_real_01_evidence/phase3_ip_direct.json --target example.com:80 --limit 3 --dry-run --output-dir /tmp/reality-vless-probe-batch-dry` → PASS
- `python3 scripts/tools/reality_vless_probe_batch.py --config agents-only/mt_real_01_evidence/phase3_ip_direct.json --target example.com:80 --limit 0 --dry-run --output-dir /tmp/reality-vless-probe-batch-limit0` → PASS
- `python3 scripts/tools/reality_vless_probe_batch.py --config agents-only/mt_real_01_evidence/phase3_ip_direct.json --target example.com:80 --outbound '__phase3_invalid_vless' --timeout 1 --phase-timeout-ms 1000 --probe-io-timeout-ms 1000 --output-dir /tmp/reality-vless-probe-batch-smoke` → PASS
- `bash -n scripts/tools/reality_vless_probe_matrix.sh` → PASS
- `cargo check --workspace` → PASS

### 结构观测

- 当前 round 的 single diff 仍然没有形成稳定收敛：
  - 某次 diff：Go `record_len=496` / Rust `record_len=592`
  - 说明当前 bucket-conditioned bias 还没有把 Rust 推到 Go 的同一 joint sampler
- 新 family 输出显示：
  - 现在已经能直接读到：
    - `186:0x002b`
    - `218:0xff01`
    - `282:0x0017`
    - `250:0x0000`
    - `...`
    这类 bucket-conditioned mean positions
  - 但 Rust 与 Go 在这些关键扩展上的条件均值仍明显偏离
  - 当前 round 说明：
    - “只建模 `fe0d` 档位和它自己的落点”仍然不够
    - 但“再硬一点的 bucket bias”也容易把位置云团压塌

### TFO / socket 线索核对

- Go 源码确认：
  - `go_fork_source/sing-box-1.13.13/common/dialer/tfo.go`
    - `slowOpenConn.Write(...)` 在首个 write 时会走：
      - `tfo.Dialer.DialContext(ctx, network, destination.String(), b)`
    - 也就是说，Go 确实具备“首次 ClientHello write 可以直接随 slow-open/TFO 发出”的能力
- 但当前 live 配置：
  - `/tmp/phase3_ip_direct_mt_real02_round4_chrome.json`
  - 各 REALITY outbound 均未显式设置 `tcp_fast_open`
  - 因而本轮还不能把 live 失败直接归因于“Rust 没有 TFO”
- `bash scripts/tools/reality_clienthello_trace.sh` 仍确认：
  - Go / Rust 当前 probe 都是：
    - 单次 write
    - 单个 `0x16` record
    - legacy record version `0x0301`

### 本轮结论

- 这轮取得的有效进展是：
  - joint-distribution 观测粒度继续上升到“按 `fe0d` bucket 分组的关键扩展位置统计”
  - Go 的 slow-open / TFO 语义已在源码层得到确认
  - baseline 脚本在 macOS 上的临时文件稳定性问题已清掉
- 但当前 Rust bucket-conditioned bias 还没有形成明确的结构收敛
- 因此本轮没有继续做 REALITY live 复测，避免把未收敛结构直接带去重复消耗 live 样本

### 下一步建议（再次更新）

1. 下一跳不要继续盲加更硬的 bucket 模板
2. 更合适的方向是：
   - 直接建模 bucket 下关键扩展的相对顺序关系，而不只是各自的绝对位置均值
   - 例如：`fe0d` 与 `0x002b/0xff01/0x0017/0x0000/0x0012` 的 pairwise precedence family
3. 另一条并行线可继续下钻：
   - 在不修改 live 配置语义的前提下，确认 Rust REALITY 真实运行路径在更细粒度上是否还存在 socket shaping 偏差
4. 只有当 family / joint 结果再次出现明确收敛趋势，再恢复 3 样本 live 复测

## 2026-04-17 Round 11: pairwise precedence harness + seed-gated pairwise bias

### 本轮目标

- 不再继续堆“更硬的 bucket 绝对位置模板”，而是直接把 bucket 内关键扩展的相对先后关系显式观测出来
- 用 Go baseline 驱动 Rust 的 key-extension 排序修正，但避免把 bucket 内云团压成固定子序列

### 本轮实现

- `scripts/tools/reality_clienthello_family.py`
  - 新增：
    - `fe0d_len_to_pairwise_precedence_counts`
    - `fe0d_len_to_pairwise_majority`
    - `fe0d_len_to_key_order_families`
  - family 输出现在不只看条件位置均值，也能直接看：
    - 每个 `fe0d` bucket 下关键扩展 pair 的“谁在前”统计
    - 关键扩展子序列 family 的离散程度
- `crates/sb-tls/src/reality/handshake.rs`
  - 新增 bucket pairwise rule tables，先把 Go family 中真正关心的 key-extension precedence 显式编码成“软约束”
  - 追加测试：
    - `reality::handshake::tests::test_chrome_bucket_pairwise_bias_tracks_go_majority_families`
    - `reality::handshake::tests::test_chrome_bucket_pairwise_bias_keeps_seed_variability`
  - 中途验证发现：
    - 若每条 pairwise rule 固定强度、每次都生效，Rust bucket 内 key-order cloud 会塌成过刚的 2-3 条子序列
  - 因而最终实现改成：
    - `randomization_seed` 驱动的 seed-gated pairwise bias
    - 同一 bucket 内不同 seed 只激活一部分 pairwise rule / 强度档位
    - 保留 pairwise 方向信息，但不把 key-order family 硬锁死

### 验证

- `cargo test -p sb-tls` → PASS (`110 passed`)
- `cargo check --workspace` → PASS
- `bash scripts/tools/reality_clienthello_diff.sh` → PASS
- `SB_REALITY_FAMILY_RUNS=40 bash scripts/tools/reality_clienthello_family.sh` → PASS

### 结构观测

- single diff 仍未稳定收敛：
  - 这一轮样本里，Go 仍可落到 `record_len=496 / fe0d len=186`
  - Rust 单样本仍常落在 `record_len=592 / fe0d len=282`
- 但 family 角度出现了一个“方向正确、尚未收敛”的变化：
  - 通过 `fe0d_len_to_key_order_families` 可以直接看到：
    - 固定强度 pairwise bias 会让 Rust top key-order family 过于集中
    - 改成 seed-gated 之后，Rust top key-order families 重新变散，离散度恢复到和 Go 同量级
  - 当前最终 `40 runs` family 中：
    - Go / Rust 的 `fe0d_len_to_key_order_families` 都出现了 16 组 top families
    - Rust 不再像中途那样塌成 2-3 条几乎固定的 bucket 子序列
- 但更关键的结论仍然是：
  - 多样性恢复了，不等于 joint sampler 已经对上
  - 选定 key pairs 的 majority 仍没有明显收敛到 Go
  - 例如当前 final `40 runs` 里：
    - bucket `186` 的 mismatch count 仍是 `9`
    - bucket `218` 的 mismatch count 仍是 `5`
    - bucket `250` 的 mismatch count 仍是 `8`
    - bucket `282` 的 mismatch count 仍是 `6`
  - 说明 Rust 现在比“固定强推 pairwise”更健康，但还没到可以恢复 live 的结构阶段

### 本轮结论

- 这轮最重要的不是“又多加了一层排序”，而是明确证伪了一个错误方向：
  - pairwise precedence 的确值得建模
  - 但不能以固定强度把 bucket 内 key-order cloud 压成少数刚性子序列
- 目前更合理的 Rust 方向已经收口到：
  - 保留 seed-level mixture
  - 让 pairwise precedence 成为条件分布的一部分，而不是固定模板
- 但截至 2026-04-17 这轮结束，结构仍未达到 clear convergence
- 因此本轮没有继续做 REALITY live 3 样本复测

### 下一步建议（再次更新）

1. 下一跳不要再增加新的固定 precedence 表
2. 更值得做的是：
   - 把 pairwise 约束从“静态规则表”继续推进到更接近 Go sampler 的 conditional activation
   - 特别关注 `fe0d` bucket 下：
     - `0x002b`
     - `0x0017`
     - `0x0012`
     - `0xfe0d`
     - `0xff01`
     之间的条件耦合，而不是单独拉某一个扩展
3. 另一条并行线仍然成立：
   - 更深层 TLS / socket shaping 仍值得继续核对
4. 只有当 family / joint 结果再次出现明确收敛趋势，再恢复 3 样本 live 复测

## 2026-04-17 Round 12: key-signature family + seed-selected signature modes

### 本轮目标

- 把 bucket 内 key-extension joint-distribution 再收紧一层：
  - 不只看 pairwise majority / key-order family
  - 直接看 5 组核心 key-pair 组成的 precedence signature family
- 在 Rust 侧把“独立 pair 随机开关”推进成更像 Go mixture 的 sampler：
  - 让一组相关 precedence 作为 mode 被 seed 一起选中

### 本轮实现

- `scripts/tools/reality_clienthello_family.py`
  - 新增：
    - `fe0d_len_to_key_signature_families`
  - 当前 signature 固定跟踪 5 组核心关系：
    - `0x0000 | 0x002b`
    - `0x0012 | 0xfe0d`
    - `0x0017 | 0xfe0d`
    - `0x002b | 0xfe0d`
    - `0xfe0d | 0xff01`
  - 这样 baseline harness 可以直接输出每个 `fe0d` bucket 下最常见的 precedence 组合，而不是把这些 pair 分散看
- `crates/sb-tls/src/reality/handshake.rs`
  - 新增 bucket-specific signature mode tables
  - Rust chrome-like 指纹当前做法改为：
    - `randomization_seed` 先选择一个 primary signature mode
    - 再选择一个 secondary signature mode 作为较轻扰动
    - mode 内 5 组 key-pair 的方向会一起影响 score
  - 这比上一轮“每个 pair 各自 seed-gated”更接近 Go bucket 内的相关翻转方式
- 新增测试：
  - `reality::handshake::tests::test_chrome_bucket_signature_modes_capture_go_top_signatures`
  - `reality::handshake::tests::test_chrome_bucket_signature_mode_selection_varies_by_seed`

### 验证

- `cargo test -p sb-tls` → PASS (`111 passed`)
- `cargo check --workspace` → PASS
- `bash scripts/tools/reality_clienthello_diff.sh` → PASS
- `SB_REALITY_FAMILY_RUNS=80 bash scripts/tools/reality_clienthello_family.sh` → PASS
- `SB_REALITY_FAMILY_RUNS=40 bash scripts/tools/reality_clienthello_family.sh` → PASS

### 结构观测

- 这轮新增的 `key_signature_families` 把 Go / Rust bucket 内的 joint sampler 看得更清楚了：
  - Go 的 top signature family 不是固定模板
  - 但确实存在若干重复出现的 precedence mode
  - Rust 现在已经能用 seed 选 mode，而不是只在单条 pair 上做独立偏置
- 最终 `40 runs` family 的 pairwise mismatch count 继续收敛到：
  - bucket `186` → `4`
  - bucket `218` → `5`
  - bucket `250` → `5`
  - bucket `282` → `1`
- 其中：
  - bucket `282` 已经接近 Go 的 key-signature family
  - 相比 Round 11，这轮 family 结构出现了实质继续收敛
- 但 single diff 仍未稳定收敛：
  - 当前 round 仍能看到 Go `record_len=560 / fe0d len=250`
  - Rust 单样本仍常落在 `record_len=592 / fe0d len=282`
  - 说明 bucket 内 precedence mode 已更接近 Go，但 `record_len <-> fe0d bucket` 与更深层 joint sampler 仍未完全同步

### live 复测

- 因为 structure/family 继续收敛，本轮恢复 3 样本 live 复测
- 运行入口：
  - `./target/debug/run -c /tmp/phase3_ip_direct_mt_real02_round4_chrome.json`
- Clash API / SOCKS preflight：
  - `GET /proxies` → `200`
  - `selector.now` 默认可见
  - `probe-socks.py 127.0.0.1:11080` → `SOCKS5 NO_AUTH accepted`
- 样本：
  - `HK-A-BGP-0.3倍率`
  - `HK-A-BGP-1.0倍率`
  - `HK-A-BGP-2.0倍率`
- 结果仍为 `0/3`
  - 三个样本均成功切组：`PUT /proxies/selector` → `204`
  - 三个样本均 `curl: (97) Can't complete SOCKS5 connection to example.com. (1)`
  - app 日志继续统一为：
    - `REALITY handshake failed: ... TLS handshake failed: tls handshake eof`

### 本轮结论

- 这轮取得的有效进展是：
  - baseline harness 已能直接输出 bucket 内 key-signature family
  - Rust sampler 已从“单条 pair 独立偏置”推进到“seed 选择一组相关 precedence mode”
  - family mismatch 确实继续下降，说明结构差异还在收敛
- 但 live 结果依然没有反转
- 这意味着当前 blocker 继续收敛到两条更深线索：
  - `record_len / fe0d bucket / key-signature mode` 之间更完整的 joint-distribution 仍未对齐
  - 或者结构之外，仍存在更深层的 TLS / socket 发包行为差异

### 下一步建议（再次更新）

1. 下一跳不要再加新的静态 signature mode
2. 更值得做的是：
   - 直接观测并建模 `record_len / fe0d bucket / key-signature mode` 的三元 joint-distribution
   - 不再把 `record_len family` 和 bucket 内 precedence sampler 分开近似
3. 与此同时：
   - 继续核对更深层 TLS / socket shaping
4. 只有当三元 joint 也出现明确收敛趋势，再继续 live 样本扩展

## 2026-04-17 Round 13: tri-joint harness + fe0d-position coupling falsification

### 本轮目标

- 把上一轮提出的“三元 joint”真正落成 baseline 输出，而不是只停留在建议里
- 验证一个自然但风险较高的 sampler 假设：
  - `fe0d_full_position` 是否可以直接拿来驱动 Rust 的 signature mode selection

### 本轮实现

- `scripts/tools/reality_clienthello_family.py`
  - 新增：
    - `record_len_to_key_signature_families`
    - `fe0d_len_pos_to_key_signature_families`
  - baseline harness 现在已能直接输出：
    - `record_len / key-signature family`
    - `fe0d bucket / fe0d position / key-signature family`
- `crates/sb-tls/src/reality/handshake.rs`
  - 本轮中途尝试：
    - 让 signature mode selection 显式吃进 `fe0d_full_position`
    - 用位置 quantile 去拉高/拉低 mode 的 “ECH-late” 倾向
  - 同时补过测试，确认代码本身可编可跑

### 验证

- 中途实验态验证：
  - `cargo test -p sb-tls` → PASS
  - `cargo check --workspace` → PASS
  - `bash scripts/tools/reality_clienthello_diff.sh` → PASS
  - `SB_REALITY_FAMILY_RUNS=40 bash scripts/tools/reality_clienthello_family.sh` → PASS
- 但结构结果显示实现方向不对，因此本轮最终回退到 Round 12 的稳定 sampler
- 回退后再次验证：
  - `cargo test -p sb-tls` → PASS (`111 passed`)
  - `cargo check --workspace` → PASS
  - `bash scripts/tools/reality_clienthello_diff.sh` → PASS
  - `SB_REALITY_FAMILY_RUNS=40 bash scripts/tools/reality_clienthello_family.sh` → PASS

### 结构观测

- 新增的 tri-joint 输出给了一个更清楚的图：
  - Go 的 `fe0d bucket / fe0d position / key-signature family` 不是任意漂移
  - 某些 bucket 下，高位 `fe0d` 与“更晚的 signature family”确实常一起出现
- 但本轮中途那条“直接用 `fe0d_full_position` 驱动 mode 选择”的实现方式，反而把结构拉坏了：
  - 中途实验态 `40 runs` family：
    - bucket `186` mismatch count 恶化到 `7`
    - bucket `282` mismatch count 恶化到 `8`
  - Rust 的 `fe0d position -> key-signature` 云团被过强地拉向错误位置族
  - single diff 也重新出现明显跨档漂移
- 这说明：
  - `fe0d position` 的确属于 joint-distribution 的一部分
  - 但不能用“位置直接决定 mode”的硬耦合方式去近似 Go sampler

### 本轮结论

- 这轮的有效产出不是新的 live 结果，而是两件更扎实的东西：
  - tri-joint baseline harness 已补齐
  - 一条看似自然的实现路径已被明确证伪
- 当前稳定状态在回退后重新确认：
  - reverted `40 runs` mismatch count 回到：
    - bucket `186` → `5`
    - bucket `218` → `4`
    - bucket `250` → `4`
    - bucket `282` → `4`
- 因为本轮实质属于“证伪后回退到上一稳定结构”，没有形成新的 clear convergence
- 因此本轮没有再继续做 live 复测

### 下一步建议（再次更新）

1. 下一跳不要把 `fe0d position` 直接硬接到 mode 选择上
2. 更值得做的是：
   - 把 tri-joint 继续用于“相关性观测”，而不是直接翻成强规则
   - 优先观察：
     - `record_len`
     - `fe0d bucket`
     - `fe0d position`
     - `key-signature family`
     之间哪些组合在 Go 侧真正形成稳定族
3. sampler 侧更合理的方向仍是：
   - 保持 seed-level mixture
   - 让 joint signal 以更弱、更间接的方式进入评分，而不是直接决定 mode
4. 只有当 tri-joint 也出现明确收敛趋势，再恢复 live 样本扩展

## 2026-04-17 Round 14: position-band tri-joint readout

### 本轮目标

- 不继续碰握手侧 sampler，而是把 tri-joint 再压成更可操作的“position band”层级
- 目标是回答一个更具体的问题：
  - Go / Rust 现在到底是哪个 bucket 的 `fe0d position band -> key-signature family` 还没有对齐

### 本轮实现

- `scripts/tools/reality_clienthello_family.py`
  - 新增：
    - `fe0d_len_to_position_band_counts`
    - `fe0d_len_band_to_key_signature_families`
  - 当前把每个 `fe0d` bucket 的 position 按 profile 分成：
    - `early`
    - `mid`
    - `late`
  - 然后直接统计：
    - 某 bucket 在各个 band 的出现次数
    - 某 bucket 的某个 band 下最常见的 key-signature family
- 新增测试：
  - `scripts/tools/test_reality_clienthello_family.py`
  - 覆盖：
    - `classify_fe0d_position_band(...)` 在 4 个 bucket 上的 band 划分
    - unknown profile 的兜底行为

### 验证

- `python3 -m unittest scripts/tools/test_reality_clienthello_family.py` → PASS
- `cargo test -p sb-tls` → PASS (`111 passed`)
- `cargo check --workspace` → PASS
- `bash scripts/tools/reality_clienthello_diff.sh` → PASS
- `SB_REALITY_FAMILY_RUNS=40 bash scripts/tools/reality_clienthello_family.sh` → PASS

### 结构观测

- 新的 band 级 tri-joint 输出把当前主偏差收得更具体了：
  - bucket `186`
    - Go `band_counts`：`late=5, mid=4, early=2`
    - Rust `band_counts`：`early=5, late=1, mid=1`
    - 这说明 Rust 在 `186` 桶里仍过度偏向早位 `fe0d`
  - bucket `250`
    - Go `band_counts`：`early=7, mid=1, late=1`
    - Rust `band_counts`：`mid=6, early=3, late=1`
    - 这说明 Rust 在 `250` 桶里仍明显偏中段，而 Go 更偏早段
  - bucket `218`
    - Go / Rust 都以 `late` 为主，虽然条件 family 还未完全一致，但 band 级别已经比较接近
  - bucket `282`
    - Go / Rust 都以 `late` 为主，结构上也相对接近
- 也就是说，截至这一轮：
  - 当前最值得继续盯的不是所有 bucket
  - 而是 `186` 与 `250` 这两个 bucket 的 band-level conditional distribution

### 本轮结论

- 这轮没有推进新的 sampler 改动，而是把 baseline 证据继续压成更能指导实现的形状
- 当前阶段已经非常明确：
  - 我们不再处于“缺静态字段/缺扩展族”的阶段
  - 也不再只是“bucket 内 key-signature mode 太粗”
  - 现在已经进入：
    - `fe0d bucket`
    - `fe0d position band`
    - `key-signature family`
    之间的条件分布对齐阶段
- 当前最核心的结构性偏差是：
  - `186` 桶：Go 晚、Rust 早
  - `250` 桶：Go 早、Rust 中
- 因为这轮只做观测增强，没有新的结构收敛，本轮没有继续做 live 复测

### 下一步建议（再次更新）

1. 下一跳优先只盯 `186` / `250` 两个 bucket
2. 更合适的方式是：
   - 不直接写死 position -> mode
   - 而是给现有 sampler 加更弱的 band-level bias
   - 且只在 `186/250` 两个 bucket 生效
3. `218/282` 先保持当前做法，不要一起动
4. 只有当 `186/250` 的 band 级 family 出现明确收敛，再恢复 live 复测

## 2026-04-17 Round 15: `186/250` weak band-level bias

### 本轮目标

- 严格沿用 Round 14 的权威结论，不回到：
  - 静态模板
  - 固定 precedence
  - `position -> mode` 硬耦合
- 只在当前主偏差最集中的两个 bucket 上做最小实验：
  - bucket `186`：让 Rust 的 `fe0d` 不再过度偏早
  - bucket `250`：让 Rust 的 `fe0d` 不再被中后段云团拖住

### 本轮实现

- `crates/sb-tls/src/reality/handshake.rs`
  - 新增 `ChromeFe0dPositionBand`
  - 先用与 baseline harness 一致的 profile quantile，把选中的 `fe0d_full_position` 分成：
    - `early`
    - `mid`
    - `late`
  - 然后只给 `fe0d target position` 一个更弱的、间接的 band-level bias：
    - bucket `186`
      - `early/mid` 轻推更晚
      - `late` 再轻推一档更晚
    - bucket `250`
      - `early/mid` 轻推更早
      - `late` 不额外加码，保留尾部多样性
  - `218/282` 保持 `0` bias，不跟着改
  - 这轮没有把 `position band` 直接接回 signature mode selection；它只影响 `fe0d` 自身的 target score
- 新增 Rust 单测：
  - `test_chrome_fe0d_position_band_classification_matches_profiles`
  - `test_chrome_fe0d_band_target_bias_only_adjusts_186_and_250_buckets`
  - `test_chrome_fe0d_band_bias_nudges_target_in_expected_direction`

### 验证

- `python3 -m unittest scripts/tools/test_reality_clienthello_family.py` → PASS
- `cargo test -p sb-tls` → PASS (`114 passed`)
- `cargo check --workspace` → PASS
- `bash scripts/tools/reality_clienthello_diff.sh` → PASS
- `SB_REALITY_FAMILY_RUNS=40 bash scripts/tools/reality_clienthello_family.sh` → PASS
- 额外诊断：
  - `SB_REALITY_FAMILY_RUNS=80 bash scripts/tools/reality_clienthello_family.sh` → PASS

### 结构观测

- `40 runs` gate 仍然能看到 bucket-level 抽样噪声，尤其是 `250` 的样本数在单轮里不稳定，因此这轮没有只凭 `40 runs` 的单次截图做结论
- 但 `80 runs` 诊断把趋势看得更清楚：
  - bucket `186`
    - Go：`early=4, mid=4, late=12`
    - Rust：`early=8, mid=0, late=12`
    - 对比 Round 14/当前改前那种“几乎全挤在 early” 的形态，这轮 Rust 已明显把 `late` band 拉回来
  - bucket `250`
    - Go：`early=12, mid=1, late=2`
    - Rust：`early=14, mid=2, late=5`
    - Rust 已从“后段/中段拖拽”转向明显的 `early` 主导，只剩一条偏厚的 `late` 尾巴
- `218/282` 没有被一起拉坏：
  - 本轮没有观察到新的 family 塌缩或 bucket 云团压平
- 这说明：
  - `position band` 确实能作为 joint signal 进入 sampler
  - 但更合理的入口是“弱 target bias”，不是 Round 13 那种“位置直接决定 mode”

### live 复测

- 因为 targeted buckets 已再次出现明确结构收敛，本轮恢复 live 3 样本复测
- 运行入口：
  - `./target/debug/run -c /tmp/phase3_ip_direct_mt_real02_round4_chrome.json`
- 控制面 preflight：
  - `GET /version`（Bearer `test123`）→ `200`
  - `GET /proxies`（Bearer `test123`）→ `200`
- 样本：
  - `HK-A-BGP-0.3倍率`
  - `HK-A-BGP-1.0倍率`
  - `HK-A-BGP-2.0倍率`
- 结果仍为 `0/3`
  - 三个样本均成功切组：`PUT /proxies/selector` → `204`
  - 三个样本均 `curl: (97) Can't complete SOCKS5 connection to example.com. (1)`
  - app 日志仍统一为：
    - `REALITY handshake failed: ... TLS handshake failed: tls handshake eof`

### 本轮结论

- 这轮不是 live reversal，但也不是新的证伪链：
  - family 云团没有被拉坏
  - `186/250` 的 band-level conditional distribution 已朝 Go 目标方向继续收敛
  - 当前稳定 sampler 现在可以保留这层 `186/250` weak band-level bias
- 但 live 仍未翻转，说明剩余 blocker 继续收敛到更深一层：
  - `position band -> key-signature family` 还不是全部；仍有更深 joint signal 尚未进入
  - 或者结构之外，仍有 TLS/socket 发包行为差异没有被当前 baseline 捕获

### 下一步建议（再次更新）

1. 保留本轮 `186/250` weak band-level bias，不要回退到 Round 14 前的更粗结构
2. 下一跳更值得看的不再是“再推大 band bias”，而是：
   - 在现有 weak band bias 之上补更间接的 joint signal
   - 例如 `record_len / bucket / band / key-signature family` 的更细 conditional weighting
3. 继续避免：
   - 固定 precedence
   - 固定 `position -> mode`
   - 一次性同时改 `218/282`
4. live 已再次确认仍为 `0/3`，因此下一轮在恢复更多 live 样本前，仍应先拿到新的结构收敛证据

## 2026-04-17 Round 16: band-scoped key-extension score bias falsification

### 本轮目标

- 在 Round 15 的稳定结构之上，再尝试一条更“间接”的 joint signal：
  - 不碰 `signature mode selection`
  - 不写死 `position -> mode`
  - 只在 extension-order score 里给少数 key extensions 一层很轻的 `bucket + raw band` bias
- 目标是：
  - bucket `186` 的 `late` band 里，让 `fe0d` 更常落到 `0x0017/0x002b/0xff01` 之后
  - bucket `250` 的 `early/mid` band 里，让 `fe0d` 更常领先这些 key extensions

### 本轮实现

- `crates/sb-tls/src/reality/handshake.rs`
  - 中途实验态新增过：
    - `chrome_band_key_extension_bias(payload_len, band, ext_type)`
  - 做法是：
    - `186 late` 给 `fe0d` 一个小的后推 bias，同时把 `0x0017/0x002b/0xff01` 轻推更早
    - `250 early/mid` 反向给 `fe0d` 小幅前推、给这些 key extensions 小幅后推
  - 这层 bias 直接叠在现有：
    - `target_position`
    - `pairwise_bias`
    - `jitter`
    之上，本意是避免新增独立 sampler 分支

### 验证

- 中途实验态验证：
  - `python3 -m unittest scripts/tools/test_reality_clienthello_family.py` → PASS
  - `cargo test -p sb-tls` → PASS (`116 passed`)
  - `cargo check --workspace` → PASS
  - `bash scripts/tools/reality_clienthello_diff.sh` → PASS
  - `SB_REALITY_FAMILY_RUNS=40 bash scripts/tools/reality_clienthello_family.sh` → PASS
  - 额外诊断：
    - `SB_REALITY_FAMILY_RUNS=80 bash scripts/tools/reality_clienthello_family.sh` → PASS

### 结构观测

- 这条路径的危险点在 `80 runs` 上被看得很清楚：
  - bucket `250` 的确明显变近：
    - 上一稳定结构：
      - Go：`early=0.800, mid=0.067, late=0.133`
      - Rust：`early=0.667, mid=0.095, late=0.238`
      - L1 = `0.267`
    - 本轮实验态：
      - Go：`early=0.458, mid=0.292, late=0.250`
      - Rust：`early=0.440, mid=0.280, late=0.280`
      - L1 = `0.060`
  - 但与此同时，其他 bucket 被带坏：
    - bucket `186`
      - 上一稳定结构 L1 = `0.400`
      - 本轮实验态 L1 = `0.533`
    - bucket `282`
      - 上一稳定结构 L1 = `0.242`
      - 本轮实验态 L1 = `0.500`
- 也就是说：
  - 这条 bias 确实能把某个目标 bucket 拉近
  - 但代价是把原本相对健康的 bucket 一起拉偏
  - 属于典型的“局部收益，整体结构损伤”

### 本轮结论

- 这轮应判定为**证伪链**，而不是新的稳定收敛：
  - `band-scoped key-extension score bias` 不适合作为当前 stable sampler 的组成部分
  - 它会让局部 bucket 的 key-family 更像 Go，但同时破坏其他 bucket 的云团
- 因此本轮已**回退到 Round 15 的稳定结构**

### 回退后验证

- 回退后再次执行：
  - `python3 -m unittest scripts/tools/test_reality_clienthello_family.py` → PASS
  - `cargo test -p sb-tls` → PASS (`114 passed`)
  - `cargo check --workspace` → PASS
  - `bash scripts/tools/reality_clienthello_diff.sh` → PASS
  - `SB_REALITY_FAMILY_RUNS=40 bash scripts/tools/reality_clienthello_family.sh` → PASS
- 因本轮属于“证伪并回退”，没有继续做新的 live 复测
- 当前 live 权威状态仍沿用 Round 15：
  - `/tmp/phase3_ip_direct_mt_real02_round4_chrome.json`
  - `HK-A-BGP-0.3倍率` / `HK-A-BGP-1.0倍率` / `HK-A-BGP-2.0倍率`
  - 结果 `0/3`
  - 统一 `tls handshake eof`

### 下一步建议（再次更新）

1. 当前稳定 sampler 仍是：
   - Round 12 seed-selected signature modes
   - Round 15 `186/250` weak band-level target bias
2. 不要再回到：
   - `band -> key-extension score bias`
   - `position -> mode`
   这两条已证伪路径
3. 下一跳更值得转向：
   - 继续做更高层、更稀疏的 joint readout
   - 或直接回到更深层 TLS/socket shaping 观测，而不是再往 extension-order 层加局部修正

## 2026-04-17 Round 17: four-way joint harness (`record_len + bucket + band + key-signature family`)

### 本轮目标

- 在 Round 16 已证伪 “band-scoped key-extension score bias” 之后，先不继续改 sampler
- 先回答一个更具体的问题：
  - `record_len` 在当前阶段是否仍提供独立于 `fe0d bucket` 的隐藏 joint signal？
  - 还是说 extension-order 层的剩余偏差，本质上还是那两个已知 bucket/band 问题？

### 本轮实现

- `scripts/tools/reality_clienthello_family.py`
  - 新增 helper：
    - `build_key_signature(positions)`
  - 新增输出：
    - `record_len_fe0d_len_band_counts`
    - `record_len_fe0d_len_band_to_key_signature_families`
- `scripts/tools/test_reality_clienthello_family.py`
  - 新增：
    - `test_build_key_signature_tracks_precedence_pairs`

### 验证

- `python3 -m unittest scripts/tools/test_reality_clienthello_family.py` → PASS (`3 tests`)
- `cargo test -p sb-tls` → PASS (`114 passed`)
- `cargo check --workspace` → PASS
- `bash scripts/tools/reality_clienthello_diff.sh` → PASS
- `SB_REALITY_FAMILY_RUNS=40 bash scripts/tools/reality_clienthello_family.sh` → PASS

### 结构观测

- 新的四元 joint 输出给了一个很重要的否定式结论：
  - `record_len <-> fe0d bucket` 的一一锁定仍然存在
  - 没有出现新的 “同一个 bucket 内再按 record_len 分裂出另一套独立 mode” 的迹象
- 也就是说：
  - 当前 extension-order 层的主偏差并没有被改写成新的 `record_len hidden mode`
  - 它只是被更精确地钉成：
    - Go 主组合：
      - `496 / 186 / late`
      - `560 / 250 / early`
    - Rust 主组合：
      - `496 / 186 / early`
      - `560 / 250 / mid`
- 换句话说，这轮四元 harness 没有暴露出新的独立条件轴；
  - 它强化的是现有结论，而不是把问题变复杂

### 本轮结论

- 这轮的价值不在于“新 sampler 收敛”，而在于把一个潜在岔路排除了：
  - 当前没有证据表明还存在一个 extension-order 层面的 `record_len` 隐藏维度，需要单独建模
  - 当前 extension-order 层可观测到的主偏差，仍然就是：
    - `496 / 186` 该晚却偏早
    - `560 / 250` 该早却偏中
- 因为：
  - Round 16 已证伪更强的局部 score bias
  - Round 17 又确认没有新的 record-length hidden mode
- 所以下一跳更合理的工程方向是：
  - 暂停继续给 extension-order 层加新的局部修正
  - 转向更深层的 TLS / socket shaping 观测

### 下一步建议（再次更新）

1. 当前稳定 sampler 仍维持：
   - Round 12 seed-selected signature modes
   - Round 15 `186/250` weak band-level target bias
2. 当前 extension-order 层面的新结论是：
   - 不再优先假设存在额外 `record_len` hidden mode
3. 下一跳更值得做的是：
   - 扩展 first-flight / socket shaping harness
   - 继续核对：
     - connect 后到首 write 的行为
     - 是否存在更细的 record / write / timing / socket option 差异
4. 本轮是观测增强，因此没有恢复 live 复测；当前 live 结论仍沿用 Round 15 的 `0/3`

## 2026-04-17 Round 18: local TCP socket trace harness

### 本轮目标

- 既然 Round 17 已经确认 extension-order 层没有新的 `record_len hidden mode`，这轮继续下探更深层运行时行为
- 目标从“编码出的 ClientHello bytes”推进到：
  - 在真实本地 TCP connect 上
  - 服务端到底观察到了什么首 flight socket 事件

### 本轮实现

- `crates/sb-tls/src/reality/handshake.rs`
  - 新增：
    - `SocketTraceChunk`
    - `LocalSocketTrace`
    - `trace_local_socket_handshake()`
  - 做法：
    - 在本地起一个 `127.0.0.1:0` TCP listener
    - Rust REALITY client 真实拨到这个 listener
    - 服务端按读事件记录：
      - 首读延迟
      - chunk 数量
      - 每个 chunk 的长度 / record type / hex
      - 首读后是否还出现第二段数据
- `crates/sb-tls/src/reality/mod.rs`
  - 新增公开 debug helper：
    - `debug_trace_local_socket_handshake(...)`
- `crates/sb-tls/examples/reality_clienthello_socket_trace.rs`
  - 新增 Rust trace example
- `scripts/tools/reality_go_utls_socket_trace.sh`
  - 新增 Go uTLS 对照 trace
- `scripts/tools/reality_clienthello_socket_trace.sh`
  - 新增统一对照入口
- 新增 Rust 单测：
  - `test_trace_local_socket_handshake_observes_first_flight_bytes`

### 验证

- `python3 -m unittest scripts/tools/test_reality_clienthello_family.py` → PASS (`3 tests`)
- `cargo test -p sb-tls` → PASS (`115 passed`)
- `cargo check --workspace` → PASS
- `bash scripts/tools/reality_clienthello_diff.sh` → PASS
- `SB_REALITY_FAMILY_RUNS=40 bash scripts/tools/reality_clienthello_family.sh` → PASS
- 新 trace：
  - `bash scripts/tools/reality_clienthello_socket_trace.sh` → PASS
  - 额外 `5 runs` local socket trace → PASS

### 结构观测

- 新 harness 的第一次对照已经说明：
  - Go：`read_count=1`, `chunk_lens=[597]`, `record_type=['0x16']`
  - Rust：`read_count=1`, `chunk_lens=[533]`, `record_type=['0x16']`
  - 两侧在本地 TCP 上都只发出单个 TLS record，之后等待服务端响应
- 额外 `5 runs` 稳定复现：
  - Go / Rust 都始终是：
    - `server_read_count = 1`
    - `server_timed_out_waiting_for_more = true`
    - `chunk_lens = [record_len + 5]`
  - 也就是说，在这个 probe 粒度上：
    - 没有看到多次 write / 多次 read
    - 没有看到首 flight 被切成多段 TCP payload
    - 没有看到新的 socket-level payload shaping 轴
- 当前 local socket trace 里看到的长度差异，仍然只是各自 ClientHello family 自身的长度族差异，而不是新的本地 socket 行为差异

### 本轮结论

- 这轮再次缩小了“运行时行为”这条搜索面：
  - 在“connect 后到首个 client payload 进入 socket”这一级，Go / Rust 现在都还是单段单 record
  - 因而当前还没有证据表明存在一个新的“首 flight socket 分片” blocker
- 下一步若继续下探 socket/runtime 行为，更值得看的已经不是：
  - 有没有第二个首 flight chunk
- 而是：
  - connect 后更细的时序
  - read/write/deadline/close 的调用序列
  - 或更底层的系统调用 / socket option 行为

### 下一步建议（再次更新）

1. 当前稳定 sampler 仍保持不变：
   - Round 12 seed-selected signature modes
   - Round 15 weak band-level target bias
2. 当前 socket shaping 新结论是：
   - “单次 connect 后马上分成多段首 flight” 不是现阶段已观测到的差异轴
3. 下一跳更值得做的是：
   - 扩展 trace 为更细的 call-sequence / timing probe
   - 特别关注：
     - `Read/Write` 之前和之后的 deadline / close 序列
     - 是否存在更细粒度但当前 listener trace 看不到的 runtime 行为差异
4. 本轮是观测增强，因此没有恢复 live 复测；当前 live 结论仍沿用 Round 15 的 `0/3`

## 2026-04-17 Round 19: socket trace timing probe

### 本轮目标

- Round 18 已经把“首 flight 是否被切成多段 TCP payload”基本排除了
- 这轮继续沿着运行时行为往下钻，但不回到 extension-order 层乱补：
  - 目标改成看更细的事件时序
  - 特别是：
    - connect 完成后到首个 TLS record 真正进入 socket 的延迟
    - 首读之后到 probe 结束的尾部时序
    - Go / Rust 是否在这些 runtime 轴上稳定分叉

### 本轮实现

- `crates/sb-tls/src/reality/handshake.rs`
  - 扩展 `SocketTraceChunk`：
    - 新增 `offset_micros`
  - 扩展 `LocalSocketTrace`：
    - `client_handshake_elapsed_micros`
    - `server_trace_elapsed_micros`
    - `server_first_read_to_end_micros`
    - `server_end_reason`
  - `trace_local_socket_handshake()` 现在除了保留首 flight bytes 外，还会输出：
    - 每个 server 读事件相对 `accept()` 的时间偏移
    - client handshake 从开始到报错/返回的总耗时
    - server 从 `accept()` 到 trace 结束的总耗时
    - 首读到结束之间的尾段耗时
    - 结束原因是 `eof` 还是 `timeout`
- `crates/sb-tls/examples/reality_clienthello_socket_trace.rs`
  - Rust example 同步输出上述 timing 字段
- `scripts/tools/reality_go_utls_socket_trace.sh`
  - Go uTLS 对照 trace 同步扩展相同字段
- `scripts/tools/reality_clienthello_socket_trace.sh`
  - 统一输出增加 `summary`
  - 直接把两侧 timing 关键字段并排摊开
- Rust 单测扩展：
  - `test_trace_local_socket_handshake_observes_first_flight_bytes`
    - 继续校验首 flight 是合法单 record
    - 也校验 timing 字段存在、offset 不越界、end reason 合法

### 验证

- `python3 -m unittest scripts/tools/test_reality_clienthello_family.py` → PASS (`3 tests`)
- `cargo test -p sb-tls` → PASS (`115 passed`)
- `cargo check --workspace` → PASS
- `bash scripts/tools/reality_clienthello_diff.sh` → PASS
- `SB_REALITY_FAMILY_RUNS=40 bash scripts/tools/reality_clienthello_family.sh` → PASS
- 新 timing trace：
  - `bash scripts/tools/reality_clienthello_socket_trace.sh` → PASS
  - 额外 `5 runs` timing trace 复验 → PASS

### 结构观测

- 先看 family gate：
  - 40 runs 没有看到 extension-order 层新的退化
  - 关键 bucket 仍保持此前稳定结构：
    - Go：
      - `186` 仍主要落在 `late`
      - `250` 仍主要落在 `early`
    - Rust：
      - `186` 仍是 `early/late` 混合
      - `250` 仍是 `early/mid` 混合
  - 也就是说，这轮 timing probe 没有把 family 云团拉坏
- 再看新的 socket timing probe：
  - 单次对照就已经出现一个值得跟的 runtime 轴：
    - Go：
      - `server_first_read_delay_micros = 1331`
      - `client_handshake_elapsed_micros = 27556`
      - `server_trace_elapsed_micros = 27399`
    - Rust：
      - `server_first_read_delay_micros = 9`
      - `client_handshake_elapsed_micros = 29130`
      - `server_trace_elapsed_micros = 27097`
  - 注意这里两侧同时仍然满足：
    - `server_read_count = 1`
    - `server_total_len = 533`
    - `server_end_reason = timeout`
    - `server_first_read_to_end_micros ≈ 26-27ms`
  - 也就是说：
    - 在“单 record / 单 read / 同长度”都一致的情况下
    - Go 仍然比 Rust 更晚把第一个 TLS record 送进 socket
- 额外 `5 runs` timing trace 的重复结果继续支持这个方向：
  - Go `server_first_read_delay_micros`：
    - 样本：`56, 1408, 1296, 1303, 1288`
    - 均值约 `1070us`
  - Rust `server_first_read_delay_micros`：
    - 样本：`5, 57, 14, 4, 13`
    - 均值约 `19us`
  - 而两侧 `client_handshake_elapsed_micros` 都仍在：
    - Go 约 `26.8-27.8ms`
    - Rust 约 `28.0-29.5ms`
- 当前最重要的新结论不是“哪边更快”，而是：
  - Go / Rust 的差异轴已经不只是 ClientHello 的 bytes / extension order
  - 更像是存在一个稳定的：
    - connect 完成之后
    - 首个 TLS payload 真正落到 socket 之前
    的 runtime timing 差异

### 本轮结论

- 这轮没有得到可以直接恢复 live 复测的结构收敛
- 但它把搜索面从“socket 是否分片”继续缩成了更具体的一条轴：
  - 首 write / flush 的时序
  - 或者握手驱动路径里的调度 / runtime 行为
- 因而下一步不应回到：
  - 固定 extension precedence
  - 固定 position -> mode
  - 静态模板补丁
- 更值得继续看的方向变成：
  - Go uTLS 与 Rust rustls/REALITY 之间：
    - connect 后是否有额外调度延迟
    - `write_tls` / `flush` / async connector 驱动的触发路径差异
    - 是否存在 deadline / readiness / task wakeup 相关分叉

### 下一步建议（再次更新）

1. 当前稳定 sampler 继续保持：
   - Round 12 seed-selected signature modes
   - Round 15 weak band-level target bias
2. 当前新增 runtime 信号是：
   - Go 首读常见在毫秒级
   - Rust 首读常见在几十微秒级
3. 下一跳更值得做的是：
   - 把 trace 再下探到：
     - client connect 完成时刻
     - `perform()` 内部首次 write 驱动时刻
     - close / EOF 传播时刻
   - 若需要，再做更细的 syscall / readiness 观测，而不是再改 extension sampler
4. 本轮仍属观测增强，因此不恢复 live 复测；当前 live 结论仍沿用 Round 15 的 `0/3`

## 2026-04-22 Round 20: client-side socket event trace

### 本轮目标

- Round 19 已经把搜索面压到“connect 后到首 write / EOF 之间的 runtime 时序”
- 但 Round 19 的结论仍然只基于 server 侧观测：
  - `server_first_read_delay_micros`
- 这轮的目标就是把 client 侧真实事件也拉进同一个 probe：
  - client 到底何时第一次 `write`
  - 之后有没有显式 `flush`
  - 何时收到 `read_eof`
- 只有把 client 侧事件链补上，才能判断：
  - Round 19 的“Go 首读更晚”到底是不是 client 首 write 真更晚
  - 还是 local harness 的 accept/read 调度差异

### 本轮实现

- `crates/sb-tls/src/reality/handshake.rs`
  - 新增：
    - `SocketTraceEvent`
  - `LocalSocketTrace` 新增：
    - `client_connect_elapsed_micros`
    - `client_first_write_after_connect_micros`
    - `client_first_read_after_connect_micros`
    - `client_event_trace`
  - 新增 `TracingAsyncIo<S>` + `ClientIoTraceRecorder`
    - 用真实 `TcpStream` 包装 `perform(...)`
    - 记录 client 侧：
      - `write`
      - `flush`
      - `shutdown`
      - `read`
      - `read_eof`
      - `*_error`
- `crates/sb-tls/examples/reality_clienthello_socket_trace.rs`
  - 同步输出 `SocketTraceEvent` 与新增 client-side summary 字段
- `scripts/tools/reality_go_utls_socket_trace.sh`
  - 新增 `tracedConn`
  - 包住真实 `net.Conn`
  - 记录 client 侧：
    - `Write`
    - `Read`
    - `Close`
    - `SetDeadline / SetReadDeadline / SetWriteDeadline`
- `scripts/tools/reality_clienthello_socket_trace.sh`
  - `summary` 同步增加：
    - `client_connect_elapsed_micros`
    - `client_first_write_after_connect_micros`
    - `client_first_read_after_connect_micros`
    - `client_event_kinds`
- Rust 单测扩展：
  - `test_trace_local_socket_handshake_observes_first_flight_bytes`
    - 继续校验单 record
    - 同时校验 `client_event_trace` 至少包含：
      - `write`
      - `read` 或 `read_eof`

### 验证

- `python3 -m unittest scripts/tools/test_reality_clienthello_family.py` → PASS (`3 tests`)
- `cargo test -p sb-tls` → PASS (`115 passed`)
- `cargo check --workspace` → PASS
- `bash scripts/tools/reality_clienthello_diff.sh` → PASS
- `SB_REALITY_FAMILY_RUNS=40 bash scripts/tools/reality_clienthello_family.sh` → PASS
- 新 trace：
  - `bash scripts/tools/reality_clienthello_socket_trace.sh` → PASS
  - 额外 `5 runs` client+server timing trace → PASS

### 结构观测

- 先看 family gate：
  - 本轮 probe 没有触碰 sampler，40 runs 也没有引入新的 family 退化
  - 当前仍保持：
    - Go `250` 以 `early` 为主
    - Rust `186` 仍是 `early/late` 混合
    - Rust `250` 仍没有塌成固定单 band
- 再看 client-side 事件链：
  - 单次 trace 就已经能看到：
    - Go：
      - `client_event_kinds = [write, read_eof]`
      - `client_first_write_after_connect_micros = 1223`
    - Rust：
      - `client_event_kinds = [write, flush, read_eof]`
      - `client_first_write_after_connect_micros = 773`
  - 额外 `5 runs` 的 client 首 write 结果：
    - Go：
      - 样本：`1130, 658, 877, 680, 856`
      - 均值约 `840us`
    - Rust：
      - 样本：`806, 913, 835, 798, 616`
      - 均值约 `794us`
  - 这说明：
    - Round 19 里“Go 首读更晚”并不能推出“Go 首 write 更晚”
    - 就 client 真正把首个 TLS record 交给 socket 的时刻而言，两侧其实已经很接近
- 再回看 server 侧首读：
  - Go `server_first_read_delay_micros`：
    - `18, 709, 608, 9, 891`
  - Rust `server_first_read_delay_micros`：
    - `7, 7, 9, 6, 5`
  - 结合 client 首 write 已接近，可以把 Round 19 的解释修正为：
    - 本地 harness 的 `server_first_read_delay_micros` 本身不是可靠 oracle
    - 它混入了 accept/read 调度差异
    - 特别是在 Rust 这条本地同 runtime probe 里，server accept/read 可能在 client write 已经入队之后才被调度
- 本轮更稳的新信号反而是：
  - Go client 事件链基本为：
    - `write -> read_eof`
  - Rust client 事件链稳定为：
    - `write -> flush -> read_eof`

### 本轮结论

- 这轮完成了一条重要证伪链：
  - Round 19 的“Go server 首读更晚”
  - 不等于
  - “Go client 首 write 更晚”
- 因而应明确回退的不是代码，而是解释口径：
  - `server_first_read_delay_micros` 不能再被当作 client 首 write 时序的直接代理
- 当前更值得继续盯的 runtime 差异变成：
  - Rust 特有的 `flush`
  - `write -> flush -> read_eof` 与 Go `write -> read_eof` 的调用链差别
  - 或者把 server 侧 probe 从同进程 / 同 runtime 调度耦合中隔离出去
- 同时，本轮再次确认：
  - extension-order / family 云团没有被这条 probe 拉坏

### 下一步建议（再次更新）

1. 当前稳定 sampler 继续保持：
   - Round 12 seed-selected signature modes
   - Round 15 weak band-level target bias
2. Round 19 的“首 write 更晚”解释现在应视为已证伪：
   - 需要以 Round 20 的 client-side 事件 trace 为准
3. 下一跳更值得做的是：
   - 继续追 `write -> flush -> read_eof` 这条 client-side 调用链
   - 或把 server 侧 probe 移到独立线程 / 独立进程，去掉 local scheduler artifact
   - 再决定是否需要更细的 syscall / readiness 观测
4. 本轮仍属观测增强，因此不恢复 live 复测；当前 live 结论仍沿用 Round 15 的 `0/3`

## 2026-04-22 Round 21: armed server barrier / blocking-thread listener probe

### 本轮目标

- Round 20 已经说明：
  - client-side 事件链比 server-side 首读时延更可信
- 但我们还没把 server-side 首读这条轴彻底证死：
  - 它到底是“可修正后还能用”
  - 还是“本地同机 harness 天然不可靠”
- 这轮就只做一件事：
  - 给 server 侧再加一层 armed barrier
  - 再看 `server_first_read_delay_micros` 会不会稳定下来

### 本轮实现

- `crates/sb-tls/src/reality/handshake.rs`
  - `trace_local_socket_handshake()` 的 server 侧从：
    - `tokio::TcpListener`
    - `tokio::spawn`
  - 改成：
    - `std::net::TcpListener`
    - 独立阻塞线程
    - `mpsc` ready barrier
  - 也就是：
    - server thread 先启动
    - 明确发出“ready”
    - client 收到 ready 之后才开始 `connect`
  - server 读循环也改成阻塞 `read + set_read_timeout`
- `scripts/tools/reality_go_utls_socket_trace.sh`
  - Go 侧对应也加上 `readyCh`
  - 保证 server goroutine 已进入 accept 路径后再 dial

### 验证

- `python3 -m unittest scripts/tools/test_reality_clienthello_family.py` → PASS (`3 tests`)
- `cargo test -p sb-tls` → PASS (`115 passed`)
- `cargo check --workspace` → PASS
- `bash scripts/tools/reality_clienthello_diff.sh` → PASS
- `SB_REALITY_FAMILY_RUNS=40 bash scripts/tools/reality_clienthello_family.sh` → PASS
- 新 trace：
  - `bash scripts/tools/reality_clienthello_socket_trace.sh` → PASS
  - 额外 `5 runs` armed socket trace → PASS
- 额外诊断：
  - `SB_REALITY_FAMILY_RUNS=80 bash scripts/tools/reality_clienthello_family.sh` → PASS

### 结构观测

- 先看 family gate：
  - 这轮只改 probe，不改 sampler
  - `40 runs` 有采样噪声，但额外 `80 runs` 诊断仍支持结构没被拉坏：
    - Go `250`：`early/mid/late = 13/5/3`
    - Rust `250`：`early/mid/late = 12/3/6`
  - 也就是说：
    - Round 12 + Round 15 的稳定 sampler 仍在
    - 这轮 probe 没把 family 云团压塌
- 再看 armed barrier 之后的 socket trace：
  - 单次样本已经出现一个新的对照形态：
    - Go：
      - `client_first_write_after_connect_micros = 693`
      - `server_first_read_delay_micros = 7`
    - Rust：
      - `client_first_write_after_connect_micros = 703`
      - `server_first_read_delay_micros = 742`
  - 这说明：
    - Rust 在独立阻塞线程后，server 首读开始更贴近 client 首 write
    - Round 20 之前的 current-thread artifact 确实被削弱了
- 但额外 `5 runs` 继续说明它仍然不是稳定 oracle：
  - Go：
    - `client_first_write_after_connect_micros`：
      - `529, 659, 536, 520, 1350`
    - `server_first_read_delay_micros`：
      - `562, 713, 5, 544, 6`
  - Rust：
    - `client_first_write_after_connect_micros`：
      - `930, 965, 723, 698, 1245`
    - `server_first_read_delay_micros`：
      - `940, 1017, 8736, 722, 1168`
- 关键点不在于均值，而在于模式：
  - Go 经常出现：
    - server goroutine 已经先阻塞在 `Read`
    - 所以 packet 一到，`server_first_read_delay_micros` 近乎 `0`
  - Rust 即使加了 ready barrier，仍可能出现：
    - server thread 已启动
    - 但 `accept/read` 或后续线程调度仍有尾部抖动
    - 导致像 `8736us` 这样的异常值
- 因而这轮新的证据链是：
  - ready barrier 能减少一部分 scheduler artifact
  - 但仍不能把 `server_first_read_delay_micros` 变成跨实现稳定可比的 oracle

### 本轮结论

- 这轮进一步收紧了 Round 20 的判断：
  - `server_first_read_delay_micros` 不是“有点 noisy 但还能用”
  - 而是即使加了 armed barrier，仍然会混入：
    - accept/read 调度
    - 本地线程 / goroutine 被调度到位的时机
    - 同机 harness 的运行时差异
- 所以如果后续还想继续沿 server-side 这条线下探：
  - 必须升级到独立进程级 probe
  - 或更外部的 syscall / packet 观测
- 在当前这套本地 harness 粒度上，更可靠的仍然是：
  - client-side `write/flush/read_eof` 事件链

### 下一步建议（再次更新）

1. 当前稳定 sampler 继续保持：
   - Round 12 seed-selected signature modes
   - Round 15 weak band-level target bias
2. 当前可保留的 runtime 结论是：
   - Go：`write -> read_eof`
   - Rust：`write -> flush -> read_eof`
3. 当前应明确放弃的 oracle 是：
   - 本地同机 harness 下的 `server_first_read_delay_micros`
4. 下一跳更值得做的是：
   - 继续沿 client-side 调用链追：
     - `write`
     - `flush`
     - `read_eof`
   - 或直接升级到独立进程 / syscall / packet 级 probe
5. 本轮仍属观测增强，因此不恢复 live 复测；当前 live 结论仍沿用 Round 15 的 `0/3`

## 2026-04-22 Round 22: external-process server probe

### 本轮目标

- Round 21 已经表明：
  - ready barrier 和阻塞线程能减少噪声
  - 但同机同进程 probe 里，server-side 首读仍然会混入运行时调度
- 所以这轮继续下探，但方向很明确：
  - 不再在同进程 listener 里兜圈子
  - 直接把 server 侧移到独立进程

### 本轮实现

- `crates/sb-tls/src/reality/handshake.rs`
  - 新增：
    - `ClientSocketTrace`
    - `trace_remote_socket_handshake(...)`
    - `trace_remote_socket_handshake_async(...)`
  - 把 client-side trace 从 local listener probe 中抽出来，做成可直接连任意 `SocketAddr` 的独立 helper
- `crates/sb-tls/src/reality/mod.rs`
  - 新增公开 helper：
    - `debug_trace_remote_socket_handshake(...)`
- `crates/sb-tls/examples/reality_clienthello_remote_socket_trace.rs`
  - 新增 Rust client-only remote trace example
- `scripts/tools/reality_go_utls_remote_socket_trace.sh`
  - 新增 Go uTLS client-only remote trace
- `scripts/tools/reality_socket_server_probe.py`
  - 新增独立进程 server probe：
    - 独立监听 `127.0.0.1:0`
    - 输出 port
    - 单连接读取首 flight
    - 记录：
      - `server_first_read_delay_micros`
      - `server_trace_elapsed_micros`
      - `server_chunks`
- `scripts/tools/reality_clienthello_external_socket_trace.sh`
  - 新增统一 orchestrator：
    - 分别为 Go / Rust 启一个独立 server 进程
    - 再跑对应 client trace
    - 最后把 client/server JSON 合并
- Rust 单测新增：
  - `test_trace_remote_socket_handshake_records_client_events`

### 验证

- `python3 -m unittest scripts/tools/test_reality_clienthello_family.py` → PASS (`3 tests`)
- `cargo test -p sb-tls` → PASS (`116 passed`)
- `cargo check --workspace` → PASS
- `bash scripts/tools/reality_clienthello_diff.sh` → PASS
- `SB_REALITY_FAMILY_RUNS=40 bash scripts/tools/reality_clienthello_family.sh` → PASS
- 新 external probe：
  - `bash scripts/tools/reality_clienthello_external_socket_trace.sh` → PASS
  - 额外 `5 runs` external-process probe → PASS

### 结构观测

- 先看 family gate：
  - 这轮仍然没有动 sampler
  - `40 runs` 下仍保持：
    - Go `250`：`early 7 / mid 3`
    - Rust `250`：`early 9 / mid 2`
  - 也就是说：
    - Round 12 + Round 15 的稳定 sampler 仍然在
    - 这轮新 probe 没有把 family 云团拉坏
- 再看 external-process server probe：
  - 单次样本已经很有力：
    - Go：
      - `client_first_write_after_connect_micros = 760`
      - `server_first_read_delay_micros = 652`
    - Rust：
      - `client_first_write_after_connect_micros = 811`
      - `server_first_read_delay_micros = 736`
  - 这和 Round 21 的 local listener probe 很不一样：
    - server-side 首读不再经常贴近 `0us`
    - 也不再出现那种明显失真的大幅漂移
  - 额外 `5 runs` external probe 继续压实：
    - Go：
      - `client_first_write_after_connect_micros`：
        - `733, 756, 745, 732, 746`
      - `server_first_read_delay_micros`：
        - `642, 734, 724, 731, 698`
      - 均值约：
        - `first_write = 742us`
        - `server_first_read = 706us`
    - Rust：
      - `client_first_write_after_connect_micros`：
        - `926, 1371, 933, 816, 809`
      - `server_first_read_delay_micros`：
        - `900, 1286, 905, 732, 717`
      - 均值约：
        - `first_write = 971us`
        - `server_first_read = 908us`
- 这轮最重要的结论是：
  - 一旦 server 侧换成独立进程，`server_first_read_delay_micros` 就重新变得可用
  - 它和 client 首 write 之间的关系开始稳定贴合
  - 因而 Round 21 中残余的 server-side 乱跳，确实主要来自：
    - 同进程 / 同机 harness 的调度 artifact
- 同时，外部 probe 也再次确认了当前最稳的 client-side 差异：
  - Go：
    - `write -> read_eof`
  - Rust：
    - `write -> flush -> read_eof`

### 本轮结论

- 这轮拿到了一个比较像“收敛点”的工具结论：
  - `external-process server probe` 可以替代本地 listener 的 server-side 首读观测
  - 以后如果还要看“server 什么时候看到首包”，这条轨道现在已经可信得多
- 同时，也把搜索面进一步收紧了：
  - 已经不必再继续调本地 listener/scheduler artifact
  - 现在真正值得盯的 runtime 差异，只剩下：
    - Rust 特有的 `flush`
    - 以及它是否对应真实 network-relevant 行为

### 下一步建议（再次更新）

1. 当前稳定 sampler 继续保持：
   - Round 12 seed-selected signature modes
   - Round 15 weak band-level target bias
2. 当前已经基本做完的事：
   - server-side 首读观测链已经从“不可信”推进到“external-process 下可用”
3. 当前最值得继续做的只剩两条：
   - 证明 Rust 的 `flush` 是否只是 `tokio-rustls` 的 API-level 事件
   - 或证明它确实映射到 live dataplane 上的真实差异
4. 如果 external-process probe 再没有发现新的 runtime 分叉，就应该准备恢复小规模 live gate，而不是无限继续本地 forensics
5. 本轮仍属观测增强，因此不恢复 live 复测；当前 live 结论仍沿用 Round 15 的 `0/3`

## 2026-04-22 Round 23: live gate restore + real-node remote trace split

### 本轮目标

- Round 22 已把 external-process server probe 收敛到可用状态
- 所以这轮不再继续本地 listener 取证，而是做两件更接近收尾的问题：
  - 恢复 live 3 样本复测，确认目前结构是否终于触发翻转
  - 直接对真实 HK 节点做 remote trace，判断低层 REALITY 本身到底能不能通

### 本轮实现

- `crates/sb-tls/src/reality/handshake.rs`
  - 新增：
    - `trace_remote_socket_handshake_with_timeout(...)`
  - 保留原来的：
    - `trace_remote_socket_handshake(...)`
    - 作为 `2s` 默认入口
- `crates/sb-tls/src/reality/mod.rs`
  - 新增：
    - `debug_trace_remote_socket_handshake_with_timeout(...)`
- `crates/sb-tls/examples/reality_clienthello_remote_socket_trace.rs`
  - 新增环境变量：
    - `SB_REALITY_TRACE_TIMEOUT_MS`
  - 使 remote trace example 可以继续保持默认 `2s`
  - 但对真实慢失败节点可显式放宽 timeout
- Rust 单测新增：
  - `test_trace_remote_socket_handshake_respects_timeout_override`

### 验证

- `python3 -m unittest scripts/tools/test_reality_clienthello_family.py` → PASS (`3 tests`)
- `cargo test -p sb-tls` → PASS (`117 passed`)
- `cargo check --workspace` → PASS
- `bash scripts/tools/reality_clienthello_diff.sh` → PASS
- `SB_REALITY_FAMILY_RUNS=40 bash scripts/tools/reality_clienthello_family.sh` → PASS

### live 复测

- 重新生成入口配置：
  - 以 `agents-only/mt_real_01_evidence/phase3_ip_direct.json` 为源
  - 对所有 `vless + tls.utls.enabled` 节点强制写成 `fingerprint = chrome`
  - 输出到：
    - `/tmp/phase3_ip_direct_mt_real02_round4_chrome.json`
- 运行入口：
  - `./target/debug/run -c /tmp/phase3_ip_direct_mt_real02_round4_chrome.json`
- 控制面 preflight：
  - `GET /version`（Bearer `test123`）→ `200`
  - `GET /proxies`（Bearer `test123`）→ `200`
  - `probe-socks.py 127.0.0.1:11080` → `SOCKS5 NO_AUTH accepted`
- 样本：
  - `HK-A-BGP-0.3倍率`
  - `HK-A-BGP-1.0倍率`
  - `HK-A-BGP-2.0倍率`
- 结果仍为 `0/3`
  - 三个样本均成功切组：`PUT /proxies/selector` → `204`
  - `HK-A-BGP-0.3倍率`：
    - `curl: (97) Can't complete SOCKS5 connection to example.com. (1)`
  - `HK-A-BGP-1.0倍率`：
    - `curl: (97) Can't complete SOCKS5 connection to example.com. (1)`
  - `HK-A-BGP-2.0倍率`：
    - 首轮 `curl: (28) Connection timed out after 10004 milliseconds`
    - 放宽到 `20s` 复验两次后：
      - 一次仍是 `curl: (28)`
      - 一次变成 `curl: (97)`
- app 日志最终仍统一落在：
  - `REALITY handshake failed ... tls handshake eof`
- 新变化不在“是否成功”，而在失败时延：
  - `HK-A-BGP-2.0倍率` 明显是更慢才落到 `EOF`

### 真实节点 remote trace

- 对 `/tmp/phase3_ip_direct_mt_real02_round4_chrome.json` 中真实 HK 节点直接跑：
  - Rust：
    - `cargo run -q -p sb-tls --example reality_clienthello_remote_socket_trace`
  - Go：
    - `bash scripts/tools/reality_go_utls_remote_socket_trace.sh`
- 关键观测如下：

- `HK-A-BGP-0.3倍率` (`87.83.106.217:10012`)
  - Rust：
    - `client_error = null`
    - `client_connect_elapsed_micros ≈ 17.8ms`
    - `client_handshake_elapsed_micros ≈ 966ms`
    - 事件链：
      - `write -> flush -> read -> write -> write -> flush`
  - Go：
    - `client_error = null`
    - `client_connect_elapsed_micros ≈ 19.9ms`
    - `client_handshake_elapsed_micros ≈ 900ms`
    - 事件链：
      - `write -> read -> read -> write`

- `HK-A-BGP-1.0倍率` (`131.143.242.78:10010`)
  - Rust：
    - `client_error = null`
    - `client_connect_elapsed_micros ≈ 10.6ms`
    - `client_handshake_elapsed_micros ≈ 187ms`
    - 事件链：
      - `write -> flush -> read -> write -> flush -> read -> read -> write -> flush`
  - Go：
    - `client_error = null`
    - `client_connect_elapsed_micros ≈ 17.8ms`
    - `client_handshake_elapsed_micros ≈ 136ms`
    - 事件链：
      - `write -> read -> read -> write`

- `HK-A-BGP-2.0倍率` (`103.73.220.182:10019`)
  - Rust：
    - 默认 `2s` probe 会先被本地工具 timeout 截断
    - 放宽 `SB_REALITY_TRACE_TIMEOUT_MS=60000` 之后：
      - `client_error = Handshake failed: TLS handshake failed: tls handshake eof`
      - `client_connect_elapsed_micros ≈ 14.6ms`
      - `client_handshake_elapsed_micros ≈ 31.2s`
      - 事件链：
        - `write -> flush -> read_eof`
  - Go：
    - `client_error = EOF`
    - `client_connect_elapsed_micros ≈ 15.2ms`
    - `client_handshake_elapsed_micros ≈ 49.4s`
    - 事件链：
      - `write -> read_eof`

### 本轮结论

- 这轮把问题边界大幅改写了：
  - 对 `HK-A-BGP-0.3倍率 / 1.0倍率` 而言：
    - 裸 `sb-tls` REALITY 握手在 Go / Rust 两边都能直接建立成功
    - 所以当前 live dataplane 的主 blocker，已经不再像 Round 1-22 那样继续收敛在：
      - ClientHello 静态字段
      - extension order sampler
      - 甚至低层 REALITY TLS 首次握手本身
  - 对 `HK-A-BGP-2.0倍率` 而言：
    - 它在低层 REALITY 上就会慢速 `EOF`
    - 所以它更像是“慢失败样本”，不适合继续作为主校准锚点
- Round 23 后新的主判断应当是：
  - `HK-A-BGP-0.3倍率 / 1.0倍率` 的真正 blocker 已经上移到：
    - VLESS outbound
    - `xtls-rprx-vision`
    - app / selector / adapter 真实拨号链
- 这也解释了为什么：
  - low-level remote trace 可以成功
  - 但 app live 仍在 `connect_io` 路径上报 `REALITY handshake failed ... tls handshake eof`
  - 当前最需要验证的已不再是“ClientHello 还差哪一位”，而是：
    - app 路径到底是不是在同一个低层 REALITY connector 之上走出了不同分支
    - 或者后续 VLESS / Vision 失败被错误归因到 REALITY 握手

### 下一步建议（再次更新）

1. 当前稳定 sampler 继续保持：
   - Round 12 seed-selected signature modes
   - Round 15 weak band-level target bias
2. `HK-A-BGP-2.0倍率` 暂时降级为慢失败样本：
   - 不再把它和 `0.3 / 1.0` 一起当作同权主锚点
3. 下一跳应显式上移到 app / adapter 路径：
   - VLESS outbound `RealityConnector::connect(...)` 真实调用链
   - `xtls-rprx-vision` 之前/之后的首个读写
   - 是否存在错误归因把上层失败包装成 `REALITY handshake failed`
4. 不再优先往 ClientHello sampler 上继续加新 bias，除非后续 app-path 证据再次把问题压回低层 REALITY

## 2026-04-23 Round 24: VLESS flow addon parity + response framing fix

### 本轮目标

- Round 23 已把问题边界抬到 app / adapter 路径。
- 所以这轮不再继续改 REALITY sampler，而是直接修补 Rust VLESS 与上游 Go `sing-vmess/vless` 的基础协议差距：
  - request addon 是否携带 `flow = xtls-rprx-vision`
  - response framing 是否正确读取 `version + additional_len + optional additional bytes`

### 上游锚点

- `github.com/sagernet/sing-vmess/vless/client.go`
  - `NewClient(options.UUID, options.Flow, logger)`
  - `prepareConn(...)` 在 `flow == xtls-rprx-vision` 时会进一步进入 `VisionConn`
- `github.com/sagernet/sing-vmess/vless/protocol.go`
  - `WriteRequest(...)` / `EncodeRequest(...)` 会在 addon 区编码：
    - protobuf header `0x0a`
    - flow string length 的 uvarint
    - flow string bytes
  - `ReadResponse(...)` 会读取：
    - `version`
    - `protobufLength`
    - 再跳过对应 addon bytes

### 本轮实现

- `crates/sb-adapters/src/outbound/vless.rs`
  - 新增：
    - `flow_addons()`
    - `push_uvarint()`
    - `uvarint_len()`
  - 修正：
    - `build_request_header()` 现在会为 `FlowControl::XtlsRprxVision` 编码 addon 区
    - `handshake()` 现在会读取完整 VLESS response header/addons，而不再把首字节误判成 “1 byte status”
- 新增 Rust 单测：
  - `test_build_request_header_omits_addons_without_flow`
  - `test_build_request_header_encodes_vision_flow_addon`
  - `test_handshake_consumes_vless_response_addons`

### 验证

- `cargo fmt --all` → PASS
- `cargo test -p sb-adapters --features adapter-vless,tls_reality,sb-transport vless::tests -- --nocapture` → PASS (`3 passed`)
- `cargo test -p sb-adapters --features adapter-vless,tls_reality,sb-transport --test vless_integration -- --nocapture` → PASS (`17 passed, 1 ignored`)
- `python3 -m unittest scripts/tools/test_reality_clienthello_family.py` → PASS (`3 tests`)
- `cargo test -p sb-tls` → PASS (`117 passed`)
- `cargo check --workspace` → PASS
- `bash scripts/tools/reality_clienthello_diff.sh` → PASS
- `SB_REALITY_FAMILY_RUNS=40 bash scripts/tools/reality_clienthello_family.sh` → PASS

### 外部验证现状

- 这轮试图用 `crates/sb-adapters/examples/vless_reality_phase_probe.rs` 重新验证 `HK-A-BGP-0.3倍率`
- 但验证窗口内外部节点明显漂移，未能形成新的稳定 live 验收：
  - `vless_reality_phase_probe`
    - `direct_reality = Authentication failed: reality verification failed`
    - `transport_reality = Authentication failed: reality verification failed`
    - `vless_dial = REALITY handshake failed: Authentication failed: reality verification failed`
  - 低层 `sb-tls` remote trace 随后又出现：
    - `Connection refused`
- 因而本轮不能把当前外部节点结果当作稳定 oracle 去评价这次 VLESS 修补是否已经翻转 live dataplane。

### 本轮结论

- 这轮已经把一个真实、明确、可单测的 app-path 协议缺口补上了：
  - Rust outbound 先前确实缺：
    - `flow addon`
    - 正确的 VLESS response framing
- 但上游 Go 的 `xtls-rprx-vision` 还会继续进入：
  - `VisionConn`
  - padding/direct-write 相关子协议包装
- 所以本轮最重要的新判断是：
  - VLESS request/response 的基础 framing 差距已经补齐
  - 当前最值得继续推进的真正 blocker，已经进一步收敛到：
    - `xtls-rprx-vision` 的 Vision 子协议包装
  - 而不是再回去继续调 REALITY ClientHello sampler

### 下一步建议（再次更新）

1. 保持当前稳定 REALITY sampler 不动：
   - Round 12 seed-selected signature modes
   - Round 15 weak band-level target bias
2. 继续沿 app / adapter 路径推进：
   - 在 Rust 侧实现最小可验证的 `VisionConn` / padding-direct 包装
   - 为 Vision 包装补可重复本地单测，而不是直接靠 live 节点调试
3. 当外部 HK 节点恢复稳定后，再恢复：
   - `vless_reality_phase_probe`
   - live 3 样本复测

## 2026-04-23 Round 25: Vision shared TLS state + direct split probe

### 本轮目标

- Round 24 已补齐 VLESS request/response 的基础 framing。
- 所以这轮继续沿 `xtls-rprx-vision` 推进，但仍不回到 REALITY ClientHello sampler。
- 目标是验证一个更具体的 Go 差距：
  - Go `VisionConn` 的 TLS 判别状态是读写共享的
  - 读侧看到 inner TLS 1.3 server hello 后，会驱动写侧把首个 inner appdata 从 `END` 切到 `DIRECT`
  - 且在 `DIRECT` 切换点会拆成两段写，并插入一个极短 delay

### 上游锚点

- `github.com/sagernet/sing-vmess/vless/vision.go`
  - `VisionConn` 持有一份共享状态：
    - `isTLS`
    - `numberOfPacketToFilter`
    - `isTLS12orAbove`
    - `remainingServerHello`
    - `cipher`
    - `enableXTLS`
  - 读侧 `filterTLS(...)` 会在 TLS 1.3 + 非 `TLS_AES_128_CCM_8_SHA256` 时打开 `enableXTLS`
  - 写侧命中 inner appdata 后：
    - 若 `enableXTLS == true`，改发 `commandPaddingDirect`
    - 并把首段带命令数据与后续裸流量拆开写
    - 两段之间插入约 `5ms` 延迟

### 本轮实现

- `crates/sb-adapters/src/outbound/vless.rs`
  - 新增 `VisionTlsState`
    - 用于共享 inner TLS 分类状态
    - 读写两侧共同更新 / 读取：
      - `is_tls`
      - `packets_to_filter`
      - `is_tls12_or_above`
      - `remaining_server_hello`
      - `cipher`
      - `enable_xtls`
  - `VisionEncoder` / `VisionDecoder`
    - 从原来的各自独立状态，改成共享 `VisionTlsState`
    - 这样写侧不再只能看到 client hello，而是能吃到读侧 server hello 的 TLS 1.3 / cipher 判别
  - 新增 `VisionWritePlan`
    - 让写侧不再只返回一个拼平的大 buffer
    - 在 `DIRECT` 切换点：
      - 首块发 `COMMAND_PADDING_DIRECT`
      - 后续 remainder 独立成后续 write chunk
      - 在首块与 remainder 之间插入 `5ms` split delay

### 新增 / 扩展测试

- `test_vision_encoder_roundtrips_continue_frame`
  - 更新为 shared-state 构造
- `test_vision_encoder_emits_end_when_padding_budget_is_exhausted`
  - 更新为通过共享 `VisionTlsState` 驱动终止条件
- `test_vision_encoder_emits_direct_after_tls13_server_hello`
  - 新增
  - 先在 decoder 侧喂入 fake TLS 1.3 server hello
  - 再验证 encoder 对首个 inner appdata 发出 `COMMAND_PADDING_DIRECT`
- `test_vision_encoder_splits_direct_write_plan`
  - 新增
  - 验证 `DIRECT` 路径会产出 split write plan，而不是单块拼平输出
- `test_vision_stream_roundtrips_bidirectional_payloads`
  - 更新为 shared-state 路径

### 验证

- `cargo fmt --all` → PASS
- `cargo test -p sb-adapters --features adapter-vless,tls_reality,sb-transport vision_ -- --nocapture` → PASS (`6 passed`)
- `cargo test -p sb-adapters --features adapter-vless,tls_reality,sb-transport --test vless_integration -- --nocapture` → PASS (`17 passed, 1 ignored`)
- `python3 -m unittest scripts/tools/test_reality_clienthello_family.py` → PASS (`3 tests`)
- `cargo test -p sb-tls` → PASS (`117 passed`)
- `cargo check --workspace` → PASS
- `bash scripts/tools/reality_clienthello_diff.sh` → PASS
- `SB_REALITY_FAMILY_RUNS=40 bash scripts/tools/reality_clienthello_family.sh` → PASS

### 外部 phase probe

- 使用：
  - `crates/sb-adapters/examples/vless_reality_phase_probe.rs`
  - 配置源：`/tmp/phase3_ip_direct_mt_real02_round4_chrome.json`

- `HK-A-BGP-0.3倍率`
  - `direct_reality = ok`
  - `transport_reality = ok`
  - `vless_dial = early eof`
  - 失败时延仍约 `17.25s - 17.42s`

- `HK-A-BGP-1.0倍率`
  - 复验稳定结果：
    - `direct_reality = ok`
    - `transport_reality = ok`
    - `vless_dial = early eof`
    - 失败时延仍约 `17.28s`
  - 首轮中曾出现一次：
    - `direct_reality = tls handshake eof`
    - 可视作外部节点漂移噪声；第二轮已恢复到 `direct_reality = ok`

### 本轮结论

- 这轮的价值，在于把一条 Vision 子协议路径明确证伪，而不是拿到新的 live 翻转：
  - `shared TLS state`
  - `DIRECT marker`
  - `DIRECT split + 5ms delay`
  - 这些都让 Rust Vision 更接近 Go `VisionConn` 的表层语义
  - 但真实节点 `vless_dial` 仍稳定停在 `~17s early eof`
- 因而结构判断进一步收敛为：
  - Round 24 已补齐：
    - VLESS `flow addon`
    - VLESS response framing
  - Round 25 已补齐：
    - Vision state-sharing
    - `DIRECT` 命令选择
    - split-write timing 语义
  - 剩余更像是 Go `VisionConn` 的深层旁路能力：
    - `directWrite`
    - `directRead`
    - `rawInput`
    - `netConn`
  - 也就是说，当前 blocker 已不太像“再补一层 Vision framing 小行为”就能翻转的级别

### 下一步建议（再次更新）

1. 保持当前稳定 REALITY sampler 不动：
   - Round 12 seed-selected signature modes
   - Round 15 weak band-level target bias
2. 保持 Round 24/25 的 Vision 代码与测试，作为最新 adapter 基线：
   - 这些改动没有污染 ClientHello family 云团
   - 也把表层 Vision 语义尽量推到了更接近 Go 的位置
3. 下一跳不要再叠表层 Vision 小修：
   - 应直接评估 Go `VisionConn` 的 `directWrite/directRead/rawInput/netConn` 深层旁路是否为真实主 blocker
4. 在没有新的更强结构证据前：
   - 暂不恢复 live 3 样本复测
   - 继续以 phase probe / 本地可重复验证为主

## 2026-04-23 Round 26: REALITY concrete stream + raw/tls dual-path Vision probe

### 本轮目标

- Round 25 已经把表层 Vision 语义推到：
  - shared TLS state
  - `DIRECT` marker
  - split-write + `5ms`
- 但真实节点仍停在 `~17s early eof`。
- 所以这轮不再只在 Vision framing 层做近似，而是第一次真正把：
  - REALITY concrete TLS stream
  - underlying raw transport
  - Vision read-side direct switch
  - Vision write-side raw remainder
  - 接到同一条运行链上。

### 本轮实现

#### 1. `sb-tls`：为 REALITY 暴露 concrete stream

- `crates/sb-tls/src/reality/client.rs`
  - 新增 `RealityClientTlsStream<S>`
  - 它包装 `tokio_rustls::client::TlsStream<S>`
  - 并对外提供：
    - `read_tls`
    - `write_tls_all`
    - `flush_tls`
    - `shutdown_tls`
    - `read_raw`
    - `write_raw_all`
    - `flush_raw`
    - `shutdown_raw`
  - `RealityConnector` 新增：
    - `connect_stream(...)`
  - 原 `connect(...)` 保持不变，但内部改为先走 concrete stream 再 boxed

- `crates/sb-tls/src/reality/handshake.rs`
  - 新增 `perform_stream(...)`
  - `perform(...)` 改为：
    - 先拿 concrete `RealityClientTlsStream<S>`
    - 再 boxed 回通用 `TlsIoStream`

- `crates/sb-tls/src/reality/mod.rs`
  - re-export `RealityClientTlsStream`

#### 2. `sb-adapters`：为 Vision 启用 raw/tls dual-path

- `crates/sb-adapters/src/outbound/vless.rs`
  - `handshake(...)` 改为 generic：
    - 不再只接受 `&mut BoxedStream`
    - 也能直接对 concrete REALITY stream 做 VLESS request/response
  - 新增 `VisionRealityClientStream`
    - 专用于：
      - `flow == xtls-rprx-vision`
      - `reality` 已启用
      - 且没有启用 ECH 叠层的路径
  - `dial(...)` 在上述条件满足时：
    - 不再先走 `RealityConnector::connect(...)` 再装进 trait object
    - 而是直接走：
      - `RealityConnector::connect_stream(...)`
      - `handshake(&mut concrete_tls_stream, ...)`
      - `VisionRealityClientStream::new(concrete_tls_stream, uuid)`

#### 3. Vision runtime 读写切换

- `VisionDecoder`
  - 新增 `raw_reads_enabled`
  - 当读侧遇到 `COMMAND_PADDING_DIRECT` 后：
    - 记录 raw-read switch
    - 后续 `VisionRealityClientStream` read task 改走 `read_raw`

- `VisionRealityClientStream`
  - read task：
    - 初始使用 `read_tls`
    - decoder 一旦触发 direct mode，后续改走 `read_raw`
  - write task：
    - 初始使用 `write_tls_all`
    - 当 `VisionWritePlan` 命中 `pause_after_first_chunk`：
      - 首块仍走 TLS path
      - remainder 改走 raw path
      - 期间保留 `5ms` split delay

### 新增测试

- `crates/sb-adapters/src/outbound/vless.rs`
  - `test_vision_decoder_enables_raw_reads_after_direct_frame`
    - 锁住读侧 `COMMAND_PADDING_DIRECT -> raw-read switch`
  - 既有 Vision tests 保持通过：
    - `test_vision_encoder_emits_direct_after_tls13_server_hello`
    - `test_vision_encoder_splits_direct_write_plan`
    - `test_vision_stream_roundtrips_bidirectional_payloads`

### 验证

- `cargo fmt --all` → PASS
- `cargo test -p sb-adapters --features adapter-vless,tls_reality,sb-transport vision_ -- --nocapture` → PASS (`7 passed`)
- `cargo test -p sb-adapters --features adapter-vless,tls_reality,sb-transport --test vless_integration -- --nocapture` → PASS (`17 passed, 1 ignored`)
- `python3 -m unittest scripts/tools/test_reality_clienthello_family.py` → PASS (`3 tests`)
- `cargo test -p sb-tls` → PASS (`117 passed`)
- `cargo check --workspace` → PASS
- `bash scripts/tools/reality_clienthello_diff.sh` → PASS
- `SB_REALITY_FAMILY_RUNS=40 bash scripts/tools/reality_clienthello_family.sh` → PASS

### 外部 phase probe

- 使用：
  - `crates/sb-adapters/examples/vless_reality_phase_probe.rs`
  - 配置源：`/tmp/phase3_ip_direct_mt_real02_round4_chrome.json`

#### 第一轮

- `HK-A-BGP-0.3倍率`
  - `direct_reality = ok`
  - `transport_reality = ok`
  - `vless_dial = early eof`
  - 失败时延约 `16.98s`

- `HK-A-BGP-1.0倍率`
  - `direct_reality = ok`
  - `transport_reality = tls handshake eof`
  - `vless_dial = early eof`
  - 失败时延约 `17.55s`

#### 第二轮复验

- `HK-A-BGP-0.3倍率`
  - `direct_reality = ok`
  - `transport_reality = ok`
  - `vless_dial = early eof`
  - 失败时延约 `16.97s`

- `HK-A-BGP-1.0倍率`
  - `direct_reality = ok`
  - `transport_reality = ok`
  - `vless_dial = early eof`
  - 失败时延约 `17.13s`

### 本轮结论

- 这轮的意义在于：
  - 它不再只是“Go `VisionConn` 表面行为近似”
  - 而是第一次真正把：
    - concrete REALITY TLS stream
    - raw transport
    - read-side raw switch
    - write-side raw remainder
    - 串进了同一条 Rust 运行链
- 但即便如此：
  - `HK-A-BGP-0.3倍率 / 1.0倍率` 仍稳定落在 `~17s early eof`
  - 没有出现新的成功相位
  - 且相比 Round 25 的 `~17.25s+`：
    - 本轮更像“略微更早失败”而不是继续后移
- 因而可以把这轮明确记成更强的证伪链：
  - 仅仅补齐 `directWrite/directRead` 的 raw/tls 双通道近似
  - 仍不足以翻转 live dataplane

### 结构判断（再次收敛）

1. 当前已补齐的层级：
   - Round 24：
     - VLESS `flow addon`
     - VLESS response framing
   - Round 25：
     - Vision shared TLS state
     - `DIRECT` marker
     - split-write timing
   - Round 26：
     - REALITY concrete stream
     - raw/tls dual-path wiring
     - read-side direct switch

2. 当前更像主 blocker 的层级：
   - Go `VisionConn` 中依赖：
     - `rawInput`
     - `input`
     - `netConn`
     - 更深内部缓冲/旁路的行为
   - 或者 app-path 更外层仍存在未识别包装差异

3. 当前不应再优先做的方向：
   - 再回 REALITY ClientHello sampler
   - 再叠表层 Vision framing / marker / split-write 小修
   - 在没有更强结构证据前恢复 live 3 样本复测

### 下一步建议（再次更新）

1. 保持当前稳定 REALITY sampler 不动：
   - Round 12 seed-selected signature modes
   - Round 15 weak band-level target bias
2. 保持 Round 24/25/26 代码与单测，作为最新 adapter/runtime 基线
3. 下一跳如果继续推进：
   - 优先评估能否更精确模拟 Go `rawInput/input` 的缓冲语义
   - 否则应把注意力重新扩大到 app-path 更外层差异，而不是继续在 Vision 表层打补丁

## 2026-04-23 Round 27: rustls read-buffer drain on DIRECT switch

### 背景

- Round 26 已经把：
  - REALITY concrete stream
  - raw/tls dual-path
  - read-side direct switch
  - write-side raw remainder
  - 接进同一条运行链
- 但真实节点仍稳定卡在：
  - `direct_reality = ok`
  - `transport_reality = ok`
  - `vless_dial ~= 17s early eof`
- 所以这轮不再补表层 Vision marker/timing，而是继续沿 Go `rawInput/input` 假设往下推一层：
  - 检查 Rust `DIRECT` 切换瞬间，`rustls` 内部是否还留着
    - 已解密但未吐出的 plaintext
    - 已从 socket 预读但未处理的 TLS bytes
  - 并把这两个缓存显式排空到 Vision read path

### 本轮改动

#### 1. vendored `rustls`：暴露读侧缓冲排空接口

- `vendor/rustls/src/conn.rs`
  - `ConnectionCommon` 新增：
    - `pending_plaintext_len()`
    - `take_pending_plaintext()`
    - `buffered_read_tls_len()`
    - `take_buffered_read_tls()`
- `vendor/rustls/src/client/client_conn.rs`
  - `ClientConnection` 对外转发上述接口

#### 2. `sb-tls`：把读侧缓冲排空能力挂到 REALITY concrete stream

- `crates/sb-tls/src/reality/client.rs`
  - `RealityClientTlsStream<S>` 新增：
    - `take_pending_tls_plaintext()`
    - `take_buffered_raw_tls()`
  - 用于在 `VisionRealityClientStream` 触发 `DIRECT` 时显式取出 `rustls` 内部残留读缓冲

#### 3. `sb-adapters`：在 `DIRECT` 切换点显式 drain rustls 内部残留

- `crates/sb-adapters/src/outbound/vless.rs`
  - 新增 helper：
    - `drain_vision_direct_read_buffers(...)`
  - `VisionRealityClientStream` read task 现在在首次命中 `decoder.raw_reads_enabled()` 时：
    - 先取出 `pending_plaintext`
    - 再取出 `buffered_raw_tls`
    - 先把 plaintext 继续过 `VisionDecoder`
    - 再把 raw TLS bytes 直接透传到 reader bridge
  - 目标是更接近 Go `VisionConn` 在 `DIRECT` 切换时对 `input/rawInput` 的排空语义

### 新增测试

- `crates/sb-adapters/src/outbound/vless.rs`
  - `test_drain_vision_direct_read_buffers_keeps_plaintext_before_raw_tls`
    - 锁住 `DIRECT` 切换时的顺序：
      - `pending plaintext`
      - 然后 `buffered raw tls`
  - 既有 Vision tests 继续保持通过：
    - `test_vision_decoder_enables_raw_reads_after_direct_frame`
    - `test_vision_encoder_emits_direct_after_tls13_server_hello`
    - `test_vision_encoder_splits_direct_write_plan`
    - `test_vision_stream_roundtrips_bidirectional_payloads`

### 验证

- `cargo fmt --all` → PASS
- `cargo test -p sb-adapters --features adapter-vless,tls_reality,sb-transport vision_ -- --nocapture` → PASS (`8 passed`)
- `cargo test -p sb-adapters --features adapter-vless,tls_reality,sb-transport --test vless_integration -- --nocapture` → PASS (`17 passed, 1 ignored`)
- `python3 -m unittest scripts/tools/test_reality_clienthello_family.py` → PASS (`3 tests`)
- `cargo test -p sb-tls` → PASS (`117 passed`)
- `cargo check --workspace` → PASS
- `bash scripts/tools/reality_clienthello_diff.sh` → PASS
- `SB_REALITY_FAMILY_RUNS=40 bash scripts/tools/reality_clienthello_family.sh` → PASS

### 真实节点 phase probe

- 使用：
  - `crates/sb-adapters/examples/vless_reality_phase_probe.rs`
  - 配置源：`/tmp/phase3_ip_direct_mt_real02_round4_chrome.json`

#### `HK-A-BGP-0.3倍率`

- `direct_reality = ok`
- `transport_reality = ok`
- `vless_dial = early eof`
- 失败时延约 `16.999s`

#### `HK-A-BGP-1.0倍率`

- `direct_reality = ok`
- `transport_reality = ok`
- `vless_dial = early eof`
- 失败时延约 `17.000s`

### Family gate 观察

- 这轮 dataplane/runtime 改动没有把 MT-REAL-02 结构面拉坏：
  - `order_family_count`
    - Go: `40`
    - Rust: `39`
  - `position_vector_family_count`
    - Go: `1`
    - Rust: `1`
- `40 runs` 摘要仍保持同一主偏差方向：
  - `186`
    - Go 仍偏 `late`
    - Rust 仍偏 `early`
  - `250`
    - Go 仍偏 `early`
    - Rust 仍是 `early/mid` 混合
- 也就是说：
  - 这轮更深的 runtime 补丁没有反向污染 ClientHello family 云团
  - 但也没有带来新的 live/phase 翻转

### 本轮结论

- 这轮把 Go `rawInput/input` 假设又往前推了一层：
  - 不只是 raw/tls dual-path
  - 还显式排空了 `rustls` 内部的两类残留读缓冲
- 但真实节点结果几乎钉死不变：
  - `HK-A-BGP-0.3倍率 / HK-A-BGP-1.0倍率`
  - 仍是 `~17.0s early eof`
  - 没有出现新的成功相位
  - 也没有继续把失败时延往后推
- 因而这条路径现在也可以纳入证伪链：
  - `DIRECT` 切换时补 drain rustls read buffers
  - 仍不足以翻转 dataplane

### 结构判断（再次更新）

1. 已证伪但保留为历史链的运行时近似：
   - Round 25：
     - shared TLS state
     - `DIRECT` marker
     - split-write timing
   - Round 26：
     - REALITY concrete stream
     - raw/tls dual-path
     - read-side direct switch
   - Round 27：
     - `DIRECT` 切换瞬间 drain rustls pending plaintext / buffered raw TLS

2. 当前更像主 blocker 的层级：
   - Go `VisionConn` 更强的读写所有权/旁路语义：
     - 不只是切换瞬间 drain buffer
     - 而是 `input/rawInput/netConn` 的长期 ownership 与流向
   - 或 app-path 更外层仍存在未识别包装差异

3. 当前不应再优先做的方向：
   - 回到 REALITY ClientHello sampler
   - 再叠表层 Vision framing 小修
   - 在没有新相位前恢复 live 3 样本 gate

## Round 28：证实 app 构建面与最小 probe 构建面分叉

### 本轮目标

- 这轮不是继续补 sampler，也不是继续堆 Vision 表层 patch。
- 目标改成先验证一件更基础的事：
  - 上一轮 `sb-adapters` 最小 phase probe 拿到的
    - `vless_dial = ok`
    - `vless_probe_io ~= 17s early eof`
  - 到底能不能在真正的 `app/run` 构建面里复现。
- 换句话说，这轮要先回答：
  - live 仍报 `vless dial failed ... tls handshake eof`
  - 是不是只是旧二进制/旧构建误导；
  - 还是 app 构建面本身就和最小 probe 面不一样。

### 代码改动

#### 1. `sb-adapters`：补一个 app-facing bridge regression test

- 文件：
  - `crates/sb-adapters/src/register.rs`
- 新增：
  - `test_vless_outbound_bridge_connect_io_defers_vision_response_until_first_read`
- 目的：
  - 不再只测 `VlessConnector` example
  - 而是直接测：
    - `build_vless_outbound(...)`
    - `AdapterIoBridge::connect_io(...)`
  - 锁住 app-facing 契约：
    - Vision 路径必须“先返回 layered stream”
    - VLESS response 必须延后到首次 read 再消费

#### 2. `app`：增强 `probe-outbound`，直接走 app 构建面诊断

- 文件：
  - `app/src/bin/probe-outbound.rs`
- 这轮把它从“只会 raw connect 的简单探针”扩成了 app-path 真诊断器：
  - 当 `connector.connect()` 不适用时：
    - 自动 fallback 到 `connector.connect_io()`
  - 启动时显式安装：
    - `sb_tls::ensure_crypto_provider()`
    - 避免 REALITY probe 因 rustls provider 未安装而 panic
  - 新增 `direct_vless_dial=...` 输出：
    - 在同一个 `app` 二进制里
    - 从同一份 `OutboundIR`
    - 手工重建一个 `VlessConnector`
    - 直接做一次 `dial()`
  - 因而现在 `probe-outbound` 可以给出两条同进程结论：
    - `direct_vless_dial`
    - bridge `connect_io`

### 先纠正一个 probe 误差源

- 这轮中途发现，手动复跑 `vless_reality_phase_probe` 时曾误把：
  - `SB_VLESS_PUBLIC_KEY`
  - 当成了正确变量名
- 但 example 实际读取的是：
  - `SB_VLESS_REALITY_PUBLIC_KEY`
- 所以那次出现的：
  - `Authentication failed: reality verification failed`
  - 不能继续当作结构证据
- 本轮后续所有外部 probe 结论都改为使用正确变量名重跑。

### live 复测：排除“旧二进制误导”

- 先重编：
  - `cargo build -p app --bin run --features 'acceptance,parity,clash_api'`
- 然后重新启动：
  - `./target/debug/run -c /tmp/phase3_ip_direct_mt_real02_round4_chrome.json`
- 预检查：
  - `GET /version` 正常
  - SOCKS5 greeting 正常返回 `[5, 0]`
- live 3 样本结果：
  - `HK-A-BGP-0.3倍率`
    - `PUT /proxies/selector = 204`
    - `curl: (97) Can't complete SOCKS5 connection to example.com. (1)`
  - `HK-A-BGP-1.0倍率`
    - `PUT /proxies/selector = 204`
    - `curl: (97) Can't complete SOCKS5 connection to example.com. (1)`
  - `HK-A-BGP-2.0倍率`
    - `PUT /proxies/selector = 204`
    - `curl: (97) Can't complete SOCKS5 connection to example.com. (1)`
- 新二进制下日志仍是旧相位：
  - `vless dial failed: Other error: REALITY handshake failed: Handshake failed: TLS handshake failed: tls handshake eof`
- 因而这一步已经排除了：
  - “live 只是用了旧二进制” 这个解释

### 外部 phase probe：最小 `sb-adapters` 构建面仍能推进到 post-dial 阶段

- 使用：
  - `crates/sb-adapters/examples/vless_reality_phase_probe.rs`
- 并把 target 改成与 live 对齐：
  - `example.com:443`

#### `HK-A-BGP-0.3倍率`

- `direct_reality = ok`
- `transport_reality = ok`
- `vless_dial = ok`
- `vless_probe_io = early eof`
- 失败时延约 `16.9s`

#### `HK-A-BGP-1.0倍率`

- `direct_reality = ok`
- `transport_reality = ok`
- `vless_dial = ok`
- `vless_probe_io = early eof`
- 失败时延约 `16.9s`

### app 构建面直探：同一份 `OutboundIR` 在 app 面上仍停在 dial-time EOF

- 使用新的：
  - `app/src/bin/probe-outbound.rs`
- 配置：
  - `/tmp/phase3_ip_direct_mt_real02_round4_chrome.json`
- target：
  - `example.com:443`

#### `HK-A-BGP-0.3倍率`

- `direct_vless_dial=err`
- 时延约 `957ms`
- 错误：
  - `Other error: REALITY handshake failed: Handshake failed: TLS handshake failed: tls handshake eof`
- bridge `connect_io()` 随后也落到同一错误

#### `HK-A-BGP-1.0倍率`

- `direct_vless_dial=err`
- 时延约 `944ms`
- 错误：
  - `Other error: REALITY handshake failed: Handshake failed: TLS handshake failed: tls handshake eof`
- bridge `connect_io()` 随后也落到同一错误

### 这轮最重要的结构结论

1. 新二进制 live 仍失败，不是旧构建误测：
   - `run` 已经重编
   - live 仍是 `dial-time tls handshake eof`

2. 分叉不在 selector / SOCKS inbound / bridge：
   - 因为在 `app` 同一进程里
   - 直接从同一份 `OutboundIR` 手工构 `VlessConnector`
   - 也会在 `~1s` 内 `tls handshake eof`
   - 说明 selector、Socks inbound、registry fallback 都只是把这个错误往外冒出来

3. 真正的分叉已经被压到“构建面 / 依赖面”：
   - 最小 `sb-adapters` example 构建面：
     - `vless_dial = ok`
     - `post-dial probe_io ~= 17s early eof`
   - `app/run` 构建面：
     - 同一目标、同一 `OutboundIR`
     - 仍停在 `dial-time tls handshake eof`
   - 所以当前最高优先级不再是：
     - sampler
     - Vision framing
     - selector 路径
   - 而是：
     - `app` 与最小 probe 之间的 feature/dependency surface 差异
     - 特别是 `sb-tls` / vendored `rustls` / adapter feature-unification 面

### 验证

- `python3 -m unittest scripts/tools/test_reality_clienthello_family.py` → PASS
- `cargo test -p sb-tls` → FAIL
  - 当前失败点：
    - `global::tests::test_none_mode_empty`
  - 表现为 root-store/global mode 相关波动
  - 与本轮 app/dataplane 主线无直接耦合
- `cargo check --workspace` → PASS
- `bash scripts/tools/reality_clienthello_diff.sh` → PASS
- `SB_REALITY_FAMILY_RUNS=40 bash scripts/tools/reality_clienthello_family.sh` → PASS

### Family gate 观察

- 这轮新增的是 app-path / 构建面诊断，不是新的 ClientHello sampler 变更：
  - `reality_clienthello_diff.sh` 仍保持通过
  - `40 runs family` 也没有出现新的云团塌陷
- 也就是说：
  - 这轮诊断增强没有把 MT-REAL-02 的结构面对齐链拉坏

### 下一跳

- 当前最值得继续推进的方向已经非常明确：
  - 不再优先追 sampler / Vision 小修
  - 直接比较：
    - `app` 构建面
    - 与最小 `sb-adapters` probe 构建面
  - 尤其是：
    - `sb-tls` feature set
    - vendored `rustls` feature/provider 面
    - 以及 app 侧依赖统一后是否把 REALITY runtime 拉回了旧相位

## Round 29 - app SNI lowering fix + live dataplane partial success

### 目标

- 继续接管 MT-REAL-02，不回到无基线 patch
- 按 Round 28 的下一步：
  1. 先确认 `register.rs` 新增的 VLESS bridge regression test 是否被 cargo 发现
  2. 对 app vs minimal `sb-adapters` surface 做二分
  3. 找出 app 面 `direct_vless_dial = tls handshake eof` 的真实触发条件
  4. 只有结构重新收敛后才恢复 live 复测

### VLESS bridge regression test 门控修复

- 原状态：
  - `test_vless_outbound_bridge_connect_io_defers_vision_response_until_first_read`
  - 被放在 `#[cfg(all(test, feature = "adapter-dns"))] mod tests`
  - 因而 `adapter-vless,tls_reality,sb-transport` 下 `--list` 看不到该 test
- 修复：
  - 外层 tests module 改成 `#[cfg(test)]`
  - `build_dns_outbound_accepts_doh` 单独加 `#[cfg(feature = "adapter-dns")]`
  - Hysteria2 专用 imports 移到对应 test 内
- 验证：
  - `cargo test -p sb-adapters --features adapter-vless,tls_reality,sb-transport --lib -- --list`
  - 现在能列出：
    - `register::tests::test_vless_outbound_bridge_connect_io_defers_vision_response_until_first_read`
  - 单测执行 PASS

### app probe surface 修正

- `app/src/bin/probe-outbound.rs`
  - 支持 `connect()` unsupported 后 fallback `connect_io()`
  - 安装 `sb_tls::ensure_crypto_provider()`
  - 不再必须启用 app 聚合 `adapters` 才能编译 VLESS direct diagnostic
  - 增加 pre/post bridge direct probes：
    - 脱敏 REALITY config
    - `direct_reality`
    - `direct_vless_dial`
- `app/src/util.rs`
  - `register_adapters_once()` 改为 `#[cfg(feature = "sb-adapters")]`
  - 具体 adapter feature（例如 `adapter-vless`）启用 optional dependency 时也会注册
- `app/Cargo.toml`
  - `probe-outbound` target required-features 从 `router` 缩为：
    - `sb-core`
    - `sb-adapters`
    - `sb-transport`
- minimal app feature 编译暴露两个小 cfg 漏洞并已修复：
  - `app/src/inbound_starter.rs` 的 `warn!` import
  - `app/src/router/mod.rs` no-router placeholder trace path

### 关键发现：不是 rustls provider / sampler，而是 sing-box `tls.server_name` lowering 丢失

- 修复前，用 minimal app feature：
  - `cargo run -q -p app --no-default-features --features 'sb-core,sb-transport,adapter-vless,tls_reality' --bin probe-outbound -- --config /tmp/phase3_ip_direct_mt_real02_round4_chrome.json --outbound 'HK-A-BGP-0.3倍率' --target example.com:443 --timeout 20`
- app probe 脱敏输出显示：
  - `server=87.83.106.217`
  - `sni=87.83.106.217`
  - `direct_reality = tls handshake eof`
  - `direct_vless_dial = tls handshake eof`
- 但最小 `sb-adapters` example 由 env 注入的成功基线使用：
  - `server_name = gamedownloads-rockstargames-com.akamaized.net`
  - `direct_reality = ok`
  - `transport_reality = ok`
  - `vless_dial = ok`
- 结论：
  - app 面不是因为 selector / SOCKS / bridge / feature surface 触发 EOF
  - `sb-config` v2 outbound lowering 只读取了 `tls.sni`
  - 没读取 sing-box 真实配置里的 `tls.server_name`
  - `tls.reality.server_name` 缺省时也没有 fallback 到 `tls.server_name`

### config lowering 修复

- 文件：
  - `crates/sb-config/src/validator/v2/outbound.rs`
- 修复内容：
  - `tls.server_name` 与 `tls.sni` 共同作为 `tls_sni` 来源
  - `tls.reality.server_name` 缺省时 fallback 到 `tls.server_name`
  - nested `tls.utls.fingerprint` 落到 `utls_fingerprint`
- 新增 test：
  - `test_parse_reality_uses_tls_server_name_fallback`
  - 覆盖 sing-box 风格：
    - `tls.server_name`
    - `tls.reality` 无 `server_name`
    - `tls.utls.fingerprint`

### app probe 翻转结果

#### `router,adapter-vless,tls_reality`

- `HK-A-BGP-0.3倍率`
  - pre bridge:
    - `sni=gamedownloads-rockstargames-com.akamaized.net`
    - `direct_reality = ok`
    - `direct_vless_dial = ok`
  - post bridge:
    - `direct_reality = ok`
    - `direct_vless_dial = ok`
- `HK-A-BGP-1.0倍率`
  - pre/post bridge:
    - `sni=d1--ov-gotcha07.bilivideo.com`
    - `direct_reality = ok`
    - `direct_vless_dial = ok`

#### `router,adapters`

- `HK-A-BGP-0.3倍率`
  - pre/post bridge:
    - `direct_reality = ok`
    - `direct_vless_dial = ok`

### Vision / REALITY live dataplane change

- SNI lowering 修复后，REALITY dial-time EOF 已消失
- 但 first live run 进入 post-dial 后仍出现：
  - default HTTPS：`curl (35)` / HTTP2 framing / timeout
  - HTTP80 在旧 concrete raw-bypass 路径上仍可出现 `Empty reply from server`
- 本轮做了保守 live dataplane 修正：
  - REALITY+Vision 路径先使用 TLS-only Vision framing
  - 即 `VisionEncoder::new_with_direct(..., allow_direct=false)`
  - TLS1.3 app-data 阶段发 `COMMAND_PADDING_END`，不发 `COMMAND_PADDING_DIRECT`
  - 避免当前 concrete `VisionRealityClientStream` 用单个 mutex 包住 read/write/raw 导致潜在写侧阻塞
  - raw direct bypass 代码保留，不作为本轮 live 默认路径
- 新增 test：
  - `test_vision_encoder_can_disable_direct_after_tls13_server_hello`

### live 复测

- 构建：
  - `cargo build -p app --bin run --features 'acceptance,parity,clash_api'`
- 启动：
  - `./target/debug/run -c /tmp/phase3_ip_direct_mt_real02_round4_chrome.json`
- preflight：
  - `GET /version`（Bearer `test123`）→ `200`
  - SOCKS5 greeting `127.0.0.1:11080` → `[5, 0]`

#### HTTP target

- 命令形态：
  - selector 切到样本
  - `curl -sS -m 20 --socks5-hostname 127.0.0.1:11080 http://example.com/`
- 结果：
  - `HK-A-BGP-0.3倍率`
    - `PUT /proxies/selector = 204`
    - `curl_exit=0`
    - `curl_http=200`
    - `time ~= 1.51s`
  - `HK-A-BGP-1.0倍率`
    - `PUT /proxies/selector = 204`
    - `curl_exit=0`
    - `curl_http=200`
    - `time ~= 0.44s`
  - `HK-A-BGP-2.0倍率`
    - `PUT /proxies/selector = 204`
    - `curl_exit=28`
    - `timeout 20s`

#### HTTPS target, forced HTTP/1.1

- 命令形态:
  - `curl --http1.1 -sS -m 20 --socks5-hostname 127.0.0.1:11080 https://example.com/`
- Results:
  - `HK-A-BGP-0.3倍率`
    - repeat 3/3 success
    - `curl_exit=0`
    - `curl_http=200`
    - `time ~= 1.77s` to `2.40s`
  - `HK-A-BGP-1.0倍率`
    - success
    - `curl_exit=0`
    - `curl_http=200`
    - `time ~= 0.63s` to `0.74s`
  - `HK-A-BGP-2.0倍率`
    - repeat timeout
    - `curl_exit=28`
    - `timeout 30s`

#### HTTPS default

- 不强制 `--http1.1` 时仍有残留：
  - `curl (16) Error in the HTTP2 framing layer`
  - 或 timeout
- 这说明：
  - dataplane 已翻过旧的 REALITY EOF blocker
  - HTTP2 / raw-bypass / Vision deep semantics 仍未完成

### 本轮结构结论

1. Round 28 的 `app direct_vless_dial = tls handshake eof` 已根因定位并修复：
   - 主因是 `tls.server_name` lowering 丢失
   - 不是 ClientHello sampler
   - 不是 app dependency surface

2. MT-REAL-02 live dataplane 已出现真实成功分支：
   - `HK-A-BGP-0.3倍率` and `HK-A-BGP-1.0倍率`
   - HTTP80 success
   - HTTPS/HTTP1.1 success

3. 不能宣称全量完成：
   - `HK-A-BGP-2.0倍率` 仍是慢 timeout
   - default HTTPS/HTTP2 仍有 framing residual
   - raw direct bypass 目前是保守禁用，后续还要按 Go `VisionConn` ownership 重新实现

4. 下一跳：
   - 继续从 live dataplane 出发
   - 不回到 ClientHello sampler
   - 重点处理：
     - Go `VisionConn` rawInput/input/directRead/directWrite ownership
     - HTTP2 framing residual
     - `2.0倍率` 慢 timeout 是否为节点质量还是 Vision/raw-bypass 残差

### 验证

- `python3 -m unittest scripts/tools/test_reality_clienthello_family.py` → PASS
- `cargo test -p sb-config test_parse_reality_uses_tls_server_name_fallback -- --nocapture` → PASS
- `cargo test -p sb-adapters --features 'adapter-vless,tls_reality,sb-transport' test_vision_encoder_can_disable_direct_after_tls13_server_hello -- --nocapture` → PASS
- `cargo test -p sb-adapters --features 'adapter-vless,tls_reality,sb-transport' test_vless_outbound_bridge_connect_io_defers_vision_response_until_first_read -- --nocapture` → PASS
- `cargo test -p sb-tls` → PASS
  - `117 passed`
  - previous `global::tests::test_none_mode_empty` fluctuation did not reproduce
- `cargo check --workspace` → PASS
- `bash scripts/tools/reality_clienthello_diff.sh` → PASS / exit 0
  - `match=false` remains the expected structural diff report, not a gate failure
- `SB_REALITY_FAMILY_RUNS=40 bash scripts/tools/reality_clienthello_family.sh` → PASS
  - concise snapshot saved to `/tmp/mt_real02_family_round29.json`
  - Go record/fe0d counts:
    - `496/186=5`
    - `528/218=11`
    - `560/250=15`
    - `592/282=9`
  - Rust record/fe0d counts:
    - `496/186=5`
    - `528/218=14`
    - `560/250=9`
    - `592/282=12`

## 2026-04-24 进展更新：Round 30 concrete Vision raw/direct pump

### Go VisionConn 对照

- 本轮对照 upstream `sing-vmess/vless/vision.go` 的真实语义：
  - `Write` 在 `enableXTLS` 后发 `commandPaddingDirect`
  - first DIRECT frame 仍写到 TLS conn
  - 随后切 `writer = netConn` 并 sleep `5ms`
  - `Read` 收到 `commandPaddingDirect` 后 drain TLS `input` 与 `rawInput`，然后切 `netConn.Read`
- 这确认 Round 29 的 TLS-only Vision path 只是保守 live workaround，不是最终 Go parity 结构。

### 实现

- 文件：
  - `crates/sb-adapters/src/outbound/vless.rs`
- 主要改动：
  - REALITY+Vision path 重新接入 `VisionRealityClientStream::new(...)`
  - `VisionRealityClientStream` 改为单 I/O pump，直接拥有 `RealityClientTlsStream<BoxedStream>`
  - 去掉旧的 `Arc<AsyncMutex<RealityClientTlsStream<_>>>` 双任务结构，避免读侧 await 时持锁阻塞写侧
  - pump 内用 `tokio::select!` 同时处理：
    - downstream client writes
    - upstream REALITY TLS/raw reads
  - 新增 `VlessResponsePeeler`：
    - VLESS response 可分片增量消费
    - response 与首个 Vision payload coalesced 时不会吞掉后续 payload
  - `VisionWritePlan` 新增 `enter_direct_after_first_chunk`：
    - 修复单个 DIRECT frame 没有 split remainder 时，后续写仍不切 raw 的问题
    - DIRECT frame 后固定 sleep `5ms`，与 Go `VisionConn` 语义一致
  - read side DIRECT 后继续使用 Round 27 的 rustls drain：
    - `take_pending_tls_plaintext()`
    - `take_buffered_raw_tls()`

### 新增/增强测试

- `test_vision_encoder_marks_single_chunk_direct_for_later_raw_writes`
- `test_vless_response_peeler_allows_coalesced_vision_payload`
- 既有 tests 增强：
  - `test_vision_encoder_emits_direct_after_tls13_server_hello`
  - `test_vision_encoder_can_disable_direct_after_tls13_server_hello`
  - `test_vision_encoder_splits_direct_write_plan`

### live 复测

#### app `probe-outbound` HTTP80

- 构建：
  - `cargo build -p app --bin probe-outbound --features 'router,adapter-vless,tls_reality'`
- 结果：
  - `HK-A-BGP-0.3倍率`
    - `direct_reality = ok`
    - `direct_vless_dial = ok`
    - `OK stream_mode=connect_io`
    - HTTP first line: `HTTP/1.1 200 OK`
  - `HK-A-BGP-1.0倍率`
    - `direct_reality = ok`
    - `direct_vless_dial = ok`
    - `OK stream_mode=connect_io`
    - HTTP first line: `HTTP/1.1 200 OK`

#### full app + SOCKS default HTTPS

- 构建：
  - `cargo build -p app --bin run --features 'acceptance,parity,clash_api'`
- 启动：
  - `./target/debug/run -c /tmp/phase3_ip_direct_mt_real02_round4_chrome.json`
- preflight：
  - `GET /version`（Bearer `test123`）→ `200`
  - SOCKS5 greeting `127.0.0.1:11080` → `[5, 0]`
- 首轮：
  - `HK-A-BGP-0.3倍率`
    - default HTTPS: `curl (16) Error in the HTTP2 framing layer`
    - forced `--http1.1`: HTTP `200`
  - `HK-A-BGP-1.0倍率`
    - default HTTPS: HTTP `200`
    - forced `--http1.1`: HTTP `200`
  - `HK-A-BGP-2.0倍率`
    - default HTTPS: `30s timeout`
    - forced `--http1.1`: `30s timeout`
- repeat default HTTPS after DIRECT sleep fix:
  - `HK-A-BGP-0.3倍率`: `2/5` success, remaining samples `curl (16)` HTTP2 framing
  - `HK-A-BGP-1.0倍率`: `2/5` success, remaining samples `curl (16)` HTTP2 framing
- diagnostic:
  - raising DIRECT delay to `20ms` did not improve stability
  - default remains Go-like `5ms`

### 当前判定

- Round 30 恢复了 Go-like REALITY concrete raw/direct dataplane：
  - 读写 ownership 不再通过整条 stream mutex 阻塞
  - VLESS response pending 不再阻塞客户端首包
  - DIRECT 后单 chunk raw-entry bug 已修复
- 但不能宣称 MT-REAL-02 完成：
  - default HTTPS/HTTP2 仍有 stochastic framing residual
  - `HK-A-BGP-2.0倍率` 仍是慢 timeout
- 下一轮优先级：
  - 继续做 HTTP2/raw-bypass 边界诊断
  - 重点观察 DIRECT 后首批 HTTP2 request bytes 是否与 Go 的 vectorised writer / rawInput drain 顺序仍有差异

### 验证

- `python3 -m unittest scripts/tools/test_reality_clienthello_family.py` → PASS
- `cargo test -p sb-adapters --features adapter-vless,tls_reality test_vision` → PASS (`9 passed`)
- `cargo test -p sb-adapters --features adapter-vless,tls_reality test_vless_response_peeler` → PASS
- `cargo test -p sb-tls` → PASS
  - `117 passed`
  - `global::tests::test_none_mode_empty` fluctuation did not reproduce
- `cargo check --workspace` → PASS
- `bash scripts/tools/reality_clienthello_diff.sh` → PASS / exit 0
  - sample: Go and Rust both `record_len=496` / `fe0d=186`; `match=false` remains expected order-family diff
- `SB_REALITY_FAMILY_RUNS=40 bash scripts/tools/reality_clienthello_family.sh` → PASS
  - concise snapshot saved to `/tmp/mt_real02_family_round30.json`
  - Go record/fe0d counts:
    - `496/186=8`
    - `528/218=8`
    - `560/250=12`
    - `592/282=12`
  - Rust record/fe0d counts:
    - `496/186=6`
    - `528/218=11`
    - `560/250=12`
    - `592/282=11`

## 2026-04-24 进展更新：Round 31 first DIRECT coalescing 与 live family 诊断

### 目标

- 延续 Round 30 的 concrete REALITY raw/direct pump，不回到 ClientHello 静态模板或固定 position/mode sampler。
- 处理 live 默认 HTTPS 仍随机落入 HTTP2 framing 的残差。
- 先确认 app-facing bridge regression test 已被 cargo 发现并实际执行。

### test discovery / bridge guard

- `cargo test -p sb-adapters --features adapter-vless,tls_reality -- --list`
  - 已列出 `register::tests::test_vless_outbound_bridge_connect_io_defers_vision_response_until_first_read`
- 单独执行：
  - `cargo test -p sb-adapters --features adapter-vless,tls_reality register::tests::test_vless_outbound_bridge_connect_io_defers_vision_response_until_first_read`
  - PASS
- 结论：
  - 该 regression test 当前没有被 cfg / module gate 隐藏。
  - app-facing bridge 仍覆盖 `connect_io()` 不等待 VLESS response 的行为。

### 实现

- 文件：
  - `crates/sb-adapters/src/outbound/vless.rs`
  - `crates/sb-tls/src/reality/handshake.rs`
- `VisionRealityClientStream` 写侧新增 `2ms` first-DIRECT coalesce：
  - 当 encoder 已确认 `is_tls && enable_xtls` 且本次输入是 TLS appdata 时，短暂再读一次 downstream client bytes
  - 目标是把 Rust 之前的 `direct_content_len=86` + 立即 `raw_write_len=59` 合并为首 DIRECT `direct_content_len=145`
  - live 观测中 coalesce 后 HTTP2 首 DIRECT 已稳定出现 `direct_content_len=145`
- 新增 `VisionDeferredRawWrites`：
  - DIRECT 后的 raw remainder 或空 guard 通过 `tokio::time::Instant` 延后释放
  - 保留 Round 30 的空 `5ms` guard；A/B 证伪显示移除该 guard 后 default HTTPS 从约 `6/8` 降为 `2/8`
- padding bytes 改为随机填充：
  - zero-padding A/B 降到 `5/8`
  - 随机填充更接近 Go `buf.Extend()` 不显式清零的实际形态
- `sb-tls` REALITY chrome path 新增 debug-only family log：
  - `randomization_seed`
  - `fe0d_len`
  - `fe0d_full_position`
  - `fe0d_position_band`
  - 仅用于 live 成功/失败关联，不改变 sampler。

### 新增/增强测试

- `test_deferred_raw_writes_hold_direct_remainder_until_deadline`
- `test_vision_padding_uses_random_padding_bytes`
- `test_vision_encoder_coalesces_only_first_direct_appdata`

### live 复测

#### Go 对照

- Go `sing-box` 使用 `with_utls,with_clash_api` 重新构建并运行在 `11180/19190`
- `HK-A-BGP-1.0倍率` default HTTPS：
  - `12/12` HTTP `200`
- 结论：
  - 当前 live 波动不是线路整体不可用。

#### Rust full app

- 构建：
  - `cargo build -p app --bin run --features 'acceptance,parity,clash_api'`
- 配置：
  - `/tmp/phase3_ip_direct_mt_real02_round4_chrome.json`
- 结果：
  - `HK-A-BGP-0.3倍率` default HTTPS：
    - debug run: `6/8` HTTP `200`
    - info run: `8/12` HTTP `200`
  - `HK-A-BGP-1.0倍率` default HTTPS：
    - debug run: `6/8` HTTP `200`
    - info run: `6/12` HTTP `200`
- 失败形态：
  - 主要是 `curl (16) Error in the HTTP2 framing layer`
  - family-debug run 中仍有少量 SOCKS `97` / timeout
- 关键改善：
  - 不再是 Round 28 的 app 面 `0/3` / `tls handshake eof` 统一失败
  - 首 DIRECT 后的 immediate `raw_write_len=59` race 已被 coalesce 消除

### live family 观察

- family-debug sample 中：
  - 成功样本常见 `186 late` / `218 late`
  - `282 early` 多次对应 post-DIRECT no raw-read failure
  - 但 `186/218 late` 也仍出现失败，样本不足以支持新的 deterministic sampler bias
- 当前结论：
  - 继续保留 Round 12 seed-selected signature modes 与 Round 15 弱 band bias
  - 不引入固定 bucket、固定 position、或 position->mode 硬耦合
  - 下一轮应继续扩大 ClientHello family × Vision DIRECT raw-read 关联样本，再决定是否需要 sampler 或 dataplane 进一步改动

### 验证

- `python3 -m unittest scripts/tools/test_reality_clienthello_family.py` → PASS
- `cargo test -p sb-adapters --features adapter-vless,tls_reality test_vision` → PASS
  - `11 passed`
- `cargo test -p sb-adapters --features adapter-vless,tls_reality register::tests::test_vless_outbound_bridge_connect_io_defers_vision_response_until_first_read` → PASS
- `cargo test -p sb-tls` → PASS
  - `117 passed`
  - `global::tests::test_none_mode_empty` fluctuation did not reproduce
- `cargo check --workspace` → PASS
- `bash scripts/tools/reality_clienthello_diff.sh` → PASS / exit 0
  - sample remains `match=false` because Go/Rust single samples landed in different dynamic order families
- `SB_REALITY_FAMILY_RUNS=40 bash scripts/tools/reality_clienthello_family.sh` → PASS

## 2026-04-24 进展更新：Round 32 Vision DIRECT record-boundary parity

### 目标

- 延续 Round 31 的 live dataplane 方向，但重新校准“首 DIRECT content_len=145”是否真是 Go parity。
- 不回到静态 ClientHello 模板、固定 bucket、固定 position、或 position->mode 规则。

### Go trace 发现

- 使用 `/tmp/sing-box-with-utls-clash` 与 trace log 跑真实 `HK-A-BGP-1.0倍率` default HTTPS：
  - `4/4` HTTP `200`
- Go `VisionConn` 在 curl 默认 HTTP/2 下的真实写侧形态：
  - `XtlsPadding 321 ... 0`：inner TLS ClientHello CONTINUE
  - `XtlsPadding 64 ... 0`：server hello 后一个 CONTINUE
  - `XtlsPadding 86 ... 2`：first DIRECT
- 结论：
  - Round 31 的 `direct_content_len=145` 是 Rust 侧局部改善形态，不是 Go parity 目标。
  - 正确下一步应把 Rust first DIRECT 重新约束到当前 TLS record 边界，再解释为什么同形态下仍有 no-raw-read 残差。

### 实现

- 文件：
  - `crates/sb-adapters/src/outbound/vless.rs`
- XTLS direct gate 修正：
  - Rust 之前在 TLS1.3 supported_versions 出现但 cipher 未解析时也启用 XTLS。
  - 现在要求 `cipher.is_some_and(|cipher| cipher != TLS13_AES_128_CCM_8_SHA256)`，对齐 Go `tls13CipherSuiteDic` lookup 成功后才启用 direct 的行为。
- first-DIRECT coalesce 改为 TLS record-boundary aware：
  - 新增 `tls_record_len(...)` 与 `split_direct_tls_record(...)`。
  - coalesce 只补齐当前 TLS application-data record。
  - 如果一次 downstream read 已经越过当前 TLS record，超出的 bytes 不再进入 DIRECT frame，而是作为 delayed raw chunk 排队。
  - 保留 Round 31 的 deferred raw write machinery 与 DIRECT 后 guard。

### 新增/增强测试

- `test_vision_encoder_does_not_direct_without_known_tls13_cipher`
- `test_vision_encoder_does_not_direct_for_tls13_ccm8_cipher`
- `test_split_direct_tls_record_keeps_overflow_for_raw_write`

### live 复测

#### Rust full app

- 构建：
  - `cargo build -p app --bin run --features 'acceptance,parity,clash_api'`
- 配置：
  - `/tmp/phase3_ip_direct_mt_real02_round4_chrome.json`
- info run:
  - `HK-A-BGP-0.3倍率` default HTTPS：`6/12` HTTP `200`
  - `HK-A-BGP-1.0倍率` default HTTPS：`5/12` HTTP `200`
- debug run:
  - `HK-A-BGP-1.0倍率` default HTTPS：`4/6` HTTP `200`
  - debug log 已显示 Rust 回到 Go-like `direct_content_len=86`，并可见 DIRECT 后 `raw_write_len=59`。

### 当前判定

- Round 32 是 parity/diagnostic 纠偏，不是最终 live 完成。
- HTTP2 residual 仍存在，失败仍主要是 `curl (16) Error in the HTTP2 framing layer`。
- 当前更精确的问题变成：
  - Go 的 `86 DIRECT + raw remainder` 稳定；
  - Rust 现在也能复现该 DIRECT 边界，但仍随机出现 client DIRECT 已发、server DIRECT raw-read 未进入。
- 下一轮应继续聚焦 raw/direct timing 与 remote server rawInput drain 的差异；不应基于本轮样本改 REALITY sampler。

### 验证

- `python3 -m unittest scripts/tools/test_reality_clienthello_family.py` → PASS
- `cargo test -p sb-adapters --features adapter-vless,tls_reality test_vision` → PASS
  - `13 passed`
- `cargo test -p sb-tls` → PASS
  - `117 passed`
  - doctest `1 passed`
- `cargo check --workspace` → PASS
- `bash scripts/tools/reality_clienthello_diff.sh` → PASS / exit 0
  - sample remains `match=false` because Go/Rust single samples landed in different dynamic order families
- `SB_REALITY_FAMILY_RUNS=40 bash scripts/tools/reality_clienthello_family.sh` → PASS

## 2026-04-30 进展更新：Round 58 stable same-failure bucket isolation

### 目标

- Round 57 isolated `HK-A-BGP-2.0` as the only latest mixed run-health bucket.
- Round 58 targets only pure latest same-failure buckets whose latest run-health is entirely `run_same_failure`.
- 本轮不打开新方向，不修改 REALITY ClientHello sampler、Vision raw/direct dataplane、REALITY concrete read-loop。

### 实现

- `scripts/tools/reality_vless_probe_plan.py`
  - Adds `--only-latest-run-health`.
  - This differs from `--latest-run-health`: the existing filter matches if at least one latest run has the requested health, while the new filter requires every present latest run-health kind to be inside the requested set.
  - This lets a plan choose stable same-failure buckets while excluding mixed buckets such as `HK-A-BGP-2.0`.
- `scripts/tools/reality_vless_evidence_rollup.py`
  - Adds `latest_stable_same_failure_outbounds`.
  - Adds `latest_stable_same_failure_outbound_count`.
  - Latest same-failure outbounds with more than one run-health kind are now kept in `latest_mixed_run_health_outbounds`.
- `scripts/tools/test_reality_probe_tools.py`
  - Adds stable same-failure rollup coverage.
  - Adds planner coverage for `--only-latest-run-health`.
  - Adds planner coverage proving mixed run-health is excluded by the only-run-health filter.
- `scripts/tools/README.md`
  - Documents latest run-health filtering and when to use the stricter only-run-health filter.

### live execution

- Planner command:
  - `python3 scripts/tools/reality_vless_probe_plan.py --config agents-only/mt_real_01_evidence/phase3_ip_direct.json --rollup-json agents-only/mt_real_02_evidence/live_rollup.json --latest-health latest_same_failure --only-latest-run-health run_same_failure --output-json /tmp/reality-vless-same-failure-plan-r58.json`
- Selected:
  - `JP-A-BGP-0.3`
  - `JP-A-BGP-1.0`
  - `US-A-BGP-0.5`
  - `UK-A-BGP-0.5`
- Batch command:
  - `python3 scripts/tools/reality_vless_probe_batch.py --config agents-only/mt_real_01_evidence/phase3_ip_direct.json --plan-json /tmp/reality-vless-same-failure-plan-r58.json --target example.com:80 --runs 2 --timeout 8 --phase-timeout-ms 8000 --probe-io-timeout-ms 8000 --output-dir /tmp/reality-vless-probe-batch-live-r58-same-failure`
- Batch result:
  - `selected_count = 4`
  - `executed_runs = 8`
  - `status_counts.completed = 8`
  - `has_divergence = false`
  - `all_ok_runs = 0`
- By outbound:
  - `JP-A-BGP-0.3`: `2/2` same-class `reality_dial_eof`
  - `JP-A-BGP-1.0`: `2/2` same-class `timeout`
  - `UK-A-BGP-0.5`: `2/2` same-class `connection_reset`
  - `US-A-BGP-0.5`: `2/2` same-class `connection_reset`

### evidence

- Committed evidence:
  - `agents-only/mt_real_02_evidence/round58_same_failure_recheck_summary.json`
- Updated rollup:
  - `agents-only/mt_real_02_evidence/live_rollup.json`
  - `agents-only/mt_real_02_evidence/live_rollup.md`

### Rollup after Round 58

- `total_rounds = 11`
- `total_executed_runs = 62`
- `total_all_ok_runs = 21`
- `total_non_all_ok_runs = 41`
- `latest_non_all_ok_outbound_count = 5`
- `latest_health_counts.latest_all_ok = 16`
- `latest_health_counts.latest_same_failure = 4`
- `latest_health_counts.latest_divergence = 1`
- `latest_run_health_counts.run_all_ok = 15`
- `latest_run_health_counts.run_same_failure = 9`
- `latest_run_health_counts.run_divergence = 3`
- Latest stable same-failure:
  - `JP-A-BGP-0.3`
  - `JP-A-BGP-1.0`
  - `UK-A-BGP-0.5`
  - `US-A-BGP-0.5`
- Latest mixed run-health:
  - `HK-A-BGP-2.0`
- Recovered:
  - `TW-A-BGP-1.0`
  - `US-A-BGP-0.8`

### 判定

- The four Round 58 outbounds remain stable node/path failure buckets:
  - no app/minimal divergence;
  - no bridge IO divergence;
  - no per-run class instability inside the latest sample set.
- `HK-A-BGP-2.0` remains a mixed run-health bucket and is intentionally excluded from pure same-failure selection.
- Round 58 provides no structural evidence for changing the ClientHello sampler, Vision raw/direct dataplane, or REALITY read-loop.
- The current evidence still says: classify and bucket first; only consider sampler/dataplane changes after stable structural divergence appears.

### 验证

- `PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest scripts/tools/test_reality_probe_tools.py scripts/tools/test_reality_clienthello_family.py` → PASS
  - `37 tests`
- JSON validation:
  - `agents-only/mt_real_02_evidence/round58_same_failure_recheck_summary.json` → PASS
  - `agents-only/mt_real_02_evidence/live_rollup.json` → PASS
- ASCII scan:
  - `agents-only/mt_real_02_evidence/round58_same_failure_recheck_summary.json` → PASS
  - `agents-only/mt_real_02_evidence/live_rollup.json` → PASS
  - `agents-only/mt_real_02_evidence/live_rollup.md` → PASS
- Planner smoke:
  - `latest_same_failure + only run_same_failure` selected `4`
  - `latest_divergence + only run_same_failure` selected `0`
  - `latest_divergence + latest-run-health run_divergence` selected `HK-A-BGP-2.0`
- `git diff --check` → PASS
- `cargo check --workspace` → PASS

## 2026-04-30 progress update: MT-REAL-02 Stage-2 Closure

### Decision

MT-REAL-02 stage-2 evidence-driven loop is closed. This is stage
closure, not project closure. The current evidence regime has
saturated: every latest non-all_ok candidate is mechanically classified
as node-level noise or cross-round mixed noise, with no stable
sampler/dataplane signal.

### Closure snapshot

- Node-level dead buckets: JP-A-BGP-0.3 (reality_dial_eof),
  JP-A-BGP-1.0 (timeout), UK-A-BGP-0.5 (connection_reset),
  US-A-BGP-0.5 (connection_reset).
- Mixed noise bucket: HK-A-BGP-2.0 (bi-modal plus phase-shifting).
- Recovered nodes: TW-A-BGP-1.0 and US-A-BGP-0.8.
- Latest all_ok baseline: 16 outbounds.

### Archive pointers

- Evidence timeline and falsified hypotheses:
  agents-only/archive/mt_real_02/round_45_60_evidence_framework.md
- Closure rationale and stage-3 options:
  agents-only/archive/mt_real_02/closure_report.md

### Framework fields

Per outbound: latest_health, latest_run_health_counts,
latest_divergence_phase_counts, latest_divergence_phase_dominance,
latest_divergence_run_ratio, is_bi_modal, dominant_phase_history,
is_phase_shifting.

Top-level/planner: latest_*_outbounds,
latest_phase_dominant/no_dominance/bi_modal/phase_shifting_outbounds,
--latest-health, --latest-run-health, --only-latest-run-health,
--latest-phase-dominance, --latest-bi-modal, --latest-phase-shifting.

### Stage-3 order

User-elected order: R62 path B framework abstraction, then R63 path C
next BHV gap via dual_kernel_golden_spec.md S5. Path A sample expansion
is on demand only.

Do not restart MT-REAL-02 sampler/dataplane patch work unless a new
sample regime first surfaces a stable structural signal.

## 2026-04-30 进展更新：Round 59-A divergence phase composition rollup

### 目标

- Keep the MT-REAL-02 evidence loop in classify-first mode.
- Add a rollup view that answers which divergence phases appear inside each mixed bucket's latest runs.
- This is tools-only: no live batch, no planner behavior change, no ClientHello sampler change, no Vision/REALITY dataplane change.

### 实现

- `scripts/tools/reality_vless_evidence_rollup.py`
  - Adds `DIVERGENCE_PHASE_LABELS` with fixed output order:
    - `app_pre_post_diverged`
    - `app_minimal_diverged`
    - `minimal_transport_diverged`
    - `bridge_io_diverged`
  - Counts phase labels from sanitized evidence `runs[].labels`.
  - One run can increment multiple phase counters if it carries multiple divergence labels.
  - Per outbound:
    - `divergence_phase_counts`
    - `latest_divergence_phase_counts`
  - Top-level:
    - `latest_divergence_phase_summary`
    - `latest_divergence_phase_total_counts`
  - Top-level phase summary only includes outbounds whose latest health is `latest_divergence`.
- `scripts/tools/reality_vless_probe_plan.py`
  - Unchanged.
- `scripts/tools/test_reality_probe_tools.py`
  - Adds tests for:
    - per-outbound divergence phase counts;
    - top-level latest divergence phase summary excluding same-failure outbounds;
    - outbounds without divergence labels staying empty in phase counts.
- `scripts/tools/README.md`
  - Documents the new phase composition fields.

### rollup regeneration

- Regenerated:
  - `agents-only/mt_real_02_evidence/live_rollup.json`
  - `agents-only/mt_real_02_evidence/live_rollup.md`
- Existing totals preserved:
  - `total_rounds = 11`
  - `total_executed_runs = 62`
  - `total_all_ok_runs = 21`
  - `latest_divergence_outbounds = ["HK-A-BGP-2.0"]`
- Latest divergence phase composition:
  - `app_pre_post_diverged = 1` (`HK-A-BGP-2.0`)
  - `app_minimal_diverged = 2` (`HK-A-BGP-2.0`)
  - `minimal_transport_diverged = 2` (`HK-A-BGP-2.0`)
  - `bridge_io_diverged = 0`
- Important interpretation:
  - Round 58 did not run `HK-A-BGP-2.0`.
  - `HK-A-BGP-2.0` therefore uses its own latest evidence round, Round 57, for latest divergence phase counts.

### 判定

- HK remains a mixed run-health bucket, not a stable sampler/dataplane signal.
- The phase view now makes the mixed shape explicit:
  - app/minimal divergence appears in `2` latest HK runs;
  - minimal direct vs transport divergence appears in `2` latest HK runs;
  - app pre/post divergence appears in `1` latest HK run;
  - bridge IO divergence does not appear in HK's latest round.
- This supports a Round 59-B longer repeat live batch focused on HK before considering any sampler/dataplane work.

### 验证

- `PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest scripts/tools/test_reality_probe_tools.py scripts/tools/test_reality_clienthello_family.py` → PASS
  - `40 tests`
- `jq empty agents-only/mt_real_02_evidence/live_rollup.json` → PASS
- ASCII scan:
  - `agents-only/mt_real_02_evidence/live_rollup.json` → PASS
  - `agents-only/mt_real_02_evidence/live_rollup.md` → PASS
- `git diff --check` → PASS
- `cargo check --workspace` → PASS

## 2026-04-30 进展更新：Round 59-B HK longer repeat and phase dominance metric

### 目标

- Add a stable phase dominance metric for mixed divergence buckets.
- Link planner selection to that metric without changing sampler/dataplane code.
- Run a 12-sample HK longer repeat to decide whether the Round 57 mixed phase shape is no-dominance, dominant, or mid-band.

### 实现

- `scripts/tools/reality_vless_evidence_rollup.py`
  - Adds per-outbound:
    - `latest_divergence_run_count`
    - `latest_divergence_phase_dominance`
  - The denominator is the count of latest runs with at least one divergence phase label.
  - Uniform timeout / same-failure runs are kept in run-health counts but do not enter the phase dominance denominator.
  - Thresholds:
    - `dominant_ratio >= 0.75` → dominant
    - `dominant_ratio < 0.50` → no-dominance
    - otherwise mid-band
  - Adds top-level:
    - `latest_phase_dominant_outbounds`
    - `latest_phase_no_dominance_outbounds`
- `scripts/tools/reality_vless_probe_plan.py`
  - Adds repeatable `--latest-phase-dominance {dominant,no_dominance,mid}`.
  - The filter composes with latest health, latest run health, and only-latest-run-health filters.
- `scripts/tools/test_reality_probe_tools.py`
  - Adds tests for dominance ratio, no-dominance tie-break, and planner phase dominance filtering.
  - Combined Python test count is now `43`.

### Pre-R59B snapshot

- Strict denominator corrected the earlier planning assumption:
  - R57 HK had `4` latest runs, but only `3` carried divergence phase labels.
  - Pre-R59B `HK-A-BGP-2.0` therefore had:
    - `latest_divergence_run_count = 3`
    - `dominant_phase = app_minimal_diverged`
    - `dominant_count = 2`
    - `dominant_ratio = 0.6667`
    - `is_dominant = false`
    - `is_no_dominance = false`
  - HK was mid-band, not no-dominance.
- Planner smoke:
  - `latest_divergence + run_divergence + phase no_dominance + mid` selected only `HK-A-BGP-2.0倍率`.
  - `latest_divergence + run_divergence + phase dominant` selected `0`.

### live execution

- Batch command:
  - `python3 scripts/tools/reality_vless_probe_batch.py --config agents-only/mt_real_01_evidence/phase3_ip_direct.json --plan-json /tmp/r59b-plan.json --target example.com:80 --runs 12 --timeout 8 --phase-timeout-ms 8000 --probe-io-timeout-ms 8000 --output-dir /tmp/reality-vless-probe-batch-live-r59b-hk-longer`
- Actual execution:
  - selected_count: `1`
  - executed_runs: `12`
  - by outbound: `HK-A-BGP-2.0倍率`
- Raw label counts:
  - `app_minimal_diverged=2`
  - `app_pre_post_diverged=4`
  - `bridge_io_diverged=1`
  - `minimal_transport_diverged=1`
  - `probe_io_all_timeout=11`
  - `reality_all_timeout=10`

### evidence

- New evidence:
  - `agents-only/mt_real_02_evidence/round59b_hk_longer_repeat_summary.json`
- Interpretation written:
  - `12 runs land in mid-band (max phase = app_pre_post_diverged at 0.6667). Tendency present but not dominant; defer sampler-related interpretation, mark for one more longer-repeat round.`

### Rollup after R59-B

- `total_rounds = 12`
- `total_executed_runs = 74`
- `total_all_ok_runs = 21`
- HK latest run health:
  - `run_divergence = 6`
  - `run_same_failure = 6`
- HK latest phase dominance:
  - `latest_divergence_run_count = 6`
  - `dominant_phase = app_pre_post_diverged`
  - `dominant_count = 4`
  - `dominant_ratio = 0.6667`
  - `is_dominant = false`
  - `is_no_dominance = false`
- Top-level dominance lists:
  - `latest_phase_dominant_outbounds = []`
  - `latest_phase_no_dominance_outbounds = []`

### 判定

- HK remains a mixed run-health, mid-band phase bucket.
- The 12-run repeat increases the denominator from `3` to `6`, but it still does not reach either no-dominance or dominant thresholds.
- This provides no structural evidence for changing the ClientHello sampler, Vision raw/direct dataplane, or REALITY read-loop.
- If this branch continues, HK should get one more longer-repeat round rather than sampler/dataplane work.

### 验证

- `PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest scripts/tools/test_reality_probe_tools.py scripts/tools/test_reality_clienthello_family.py` → PASS
  - `43 tests`
- `jq empty agents-only/mt_real_02_evidence/live_rollup.json` → PASS
- ASCII scan:
  - `agents-only/mt_real_02_evidence/live_rollup.json` → PASS
  - `agents-only/mt_real_02_evidence/live_rollup.md` → PASS
- `git diff --check` → PASS
- `cargo check --workspace` → PASS

## 2026-04-30 进展更新：Round 60 bi-modal and phase-shifting metrics

### 目标

- Make the HK two-mode behavior visible in rollup rather than hidden behind phase counts.
- Detect cross-round dominant-phase drift that single-round dominance thresholds cannot express.
- Recheck the four stable same-failure buckets with a 4-run live repeat after the HK bi-modal discovery.
- Keep the work strictly in Python tooling, evidence, and docs; no sampler/dataplane/Rust code change.

### 实现

- `scripts/tools/reality_vless_evidence_rollup.py`
  - Adds per-outbound:
    - `latest_round_run_count`
    - `latest_divergence_run_ratio`
    - `is_bi_modal`
    - `dominant_phase_history`
    - `is_phase_shifting`
  - Also adds `is_bi_modal` inside `latest_divergence_phase_dominance` when that block exists.
  - Adds top-level:
    - `latest_bi_modal_outbounds`
    - `latest_phase_shifting_outbounds`
  - Bi-modal definition:
    - `0.25 < latest_divergence_run_ratio < 0.75`
    - and `latest_round_run_count >= 6`
  - Phase-shifting definition:
    - inspect the last `3` dominant-phase history entries;
    - all 3 must be non-null;
    - at least 2 distinct dominant phases must appear.
- `scripts/tools/reality_vless_probe_plan.py`
  - Adds `--latest-bi-modal`.
  - Adds `--latest-phase-shifting`.
  - Both are intersection filters and compose with latest health, latest run health, only-latest-run-health, and phase-dominance filters.
- `scripts/tools/test_reality_probe_tools.py`
  - Adds tests for:
    - bi-modal ratio with minimum sample threshold;
    - phase shifting across 3 rounds;
    - dominant phase history without null padding;
    - planner bi-modal / phase-shifting intersection filtering.
  - Combined Python test count is now `47`.

### Pre-live rollup

- Existing 12-evidence rollup now exposes:
  - `HK-A-BGP-2.0.latest_divergence_run_ratio = 0.5`
  - `HK-A-BGP-2.0.is_bi_modal = true`
  - `HK-A-BGP-2.0.is_phase_shifting = true`
- Top-level:
  - `latest_bi_modal_outbounds = ["HK-A-BGP-2.0"]`
  - `latest_phase_shifting_outbounds = ["HK-A-BGP-2.0"]`
- Dominant phase history for HK:
  - R47: `null`
  - R54: `app_pre_post_diverged`
  - R56: `app_minimal_diverged`
  - R57: `app_minimal_diverged`
  - R59-B: `app_pre_post_diverged`

### live execution

- Planner command:
  - `python3 scripts/tools/reality_vless_probe_plan.py --config agents-only/mt_real_01_evidence/phase3_ip_direct.json --rollup-json agents-only/mt_real_02_evidence/live_rollup.json --latest-health latest_same_failure --only-latest-run-health run_same_failure --output-json /tmp/r60-stable-plan.json`
- Planner selected `4`:
  - `JP-A-BGP-0.3倍率`
  - `JP-A-BGP-1.0倍率`
  - `US-A-BGP-0.5倍率`
  - `UK-A-BGP-0.5倍率`
- Batch command:
  - `python3 scripts/tools/reality_vless_probe_batch.py --config agents-only/mt_real_01_evidence/phase3_ip_direct.json --plan-json /tmp/r60-stable-plan.json --target example.com:80 --runs 4 --timeout 8 --phase-timeout-ms 8000 --probe-io-timeout-ms 8000 --output-dir /tmp/reality-vless-probe-batch-live-r60-stable-longer`
- Actual execution:
  - `executed_runs = 16`
  - no divergence labels
  - no `all_ok` runs
- Per outbound:
  - `JP-A-BGP-0.3`: `4/4` same-class `reality_dial_eof`
  - `JP-A-BGP-1.0`: `4/4` same-class `timeout`
  - `US-A-BGP-0.5`: `4/4` same-class `connection_reset`
  - `UK-A-BGP-0.5`: `4/4` same-class `connection_reset`

### evidence

- New evidence:
  - `agents-only/mt_real_02_evidence/round60_stable_same_failure_longer_repeat_summary.json`
- Interpretation:
  - `JP-A-BGP-0.3: 4/4 still stable same-class node-level bucket (reality_dial_eof).`
  - `JP-A-BGP-1.0: 4/4 still stable same-class node-level bucket (timeout).`
  - `US-A-BGP-0.5: 4/4 still stable same-class node-level bucket (connection_reset).`
  - `UK-A-BGP-0.5: 4/4 still stable same-class node-level bucket (connection_reset).`

### Rollup after R60

- `total_rounds = 13`
- `total_executed_runs = 90`
- `total_all_ok_runs = 21`
- HK remains:
  - `latest_round = 59-B`
  - `latest_divergence_run_ratio = 0.5`
  - `is_bi_modal = true`
  - `is_phase_shifting = true`
- Four stable same-failure nodes:
  - latest round is `60`
  - `latest_health = latest_same_failure`
  - `latest_run_health_counts = {"run_same_failure": 4}`
  - `latest_divergence_run_ratio = 0.0`
  - `is_bi_modal = false`

### 判定

- HK is now explicitly classified as both bi-modal and phase-shifting.
- That combined shape supports exclusion from sampler-candidate reasoning rather than a new sampler/dataplane direction.
- The four stable same-failure buckets remain stable under a larger 4-run repeat; they did not reveal HK-like bi-modal behavior.

### 验证

- `PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest scripts/tools/test_reality_probe_tools.py scripts/tools/test_reality_clienthello_family.py` → PASS
  - `47 tests`
- `jq empty agents-only/mt_real_02_evidence/live_rollup.json` → PASS
- `jq empty agents-only/mt_real_02_evidence/round60_stable_same_failure_longer_repeat_summary.json` → PASS
- ASCII scan:
  - `agents-only/mt_real_02_evidence/live_rollup.json` → PASS
  - `agents-only/mt_real_02_evidence/live_rollup.md` → PASS
  - `agents-only/mt_real_02_evidence/round60_stable_same_failure_longer_repeat_summary.json` → PASS
- `git diff --check` → PASS
- `cargo check --workspace` → PASS

---

## Round 61 (R67 stage-3 path A sample-face recon)

### 日期

2026-05-04

### 目标

Cold-start re-check of the latest health buckets without touching
sampler or dataplane. Three independently-planned bounded batches.

### 三个批次结果

**Batch A — stable same-failure (`run_same_failure` filter, 4 outbounds × 2 runs):**
- JP-A-BGP-0.3倍率: 2/2 reality_dial_eof (still in node-level dead bucket)
- JP-A-BGP-1.0倍率: 2/2 all_ok (recovered)
- UK-A-BGP-0.5倍率: 2/2 connection_reset (still in node-level dead bucket)
- US-A-BGP-0.5倍率: 2/2 connection_reset (still in node-level dead bucket)

**Batch B — phase-shifting (HK-A-BGP-2.0倍率 × 4 runs):**
- 4/4 uniform `probe_io_all_connection_reset` + `reality_all_connection_reset`
- 单个均一同失败的 round 不能触发 closure_report 的 "is_phase_shifting=false stably across 3+ longer-repeat rounds" 重分类。

**Batch C — sanity (3 latest_all_ok outbounds × 1 run):**
- HK-A-BGP-0.3倍率: 1/1 all_ok
- HK-A-BGP-1.0倍率: 1/1 connection_reset (newly decayed)
- HK-A-BGP-2.5倍率: 1/1 connection_reset (newly decayed)

### 判定（R67 分类 A：no new signal）

- 所有失败 run 上 `probe_io` 与 `reality` 阶段同 class，无 transport-vs-app 偏差信号。
- recovered=3, latest stable same-failure=5；`is_phase_shifting` 在最新 3-round 窗口因 R61 单 round 暂时清空，但按 closure_report 规则尚未达到稳定重分类阈值。
- 最新 non-all_ok 仍是 node-level dead bucket + 衰减/恢复噪声，无 sampler/dataplane 信号。

### 验证

- `python3 -B -m unittest scripts/tools/test_reality_probe_tools.py scripts/tools/test_reality_clienthello_family.py scripts/tools/test_dual_kernel_verification.py` → 62 tests PASS
- `cargo build -p app --features acceptance,clash_api,service_ssmapi --bin app` → PASS
- 三个 batch summary 转 evidence + rollup 重建均通过；`live_rollup.json` 16 rounds, 105 runs, 24 all_ok。

---

## Round 68 (rollup round-ordering audit & rematerialization)

### 日期

2026-05-04

### 根因

`scripts/tools/reality_vless_evidence_rollup.py::round_sort_key` 旧实现：

```python
def round_sort_key(value):
    text = str(value)
    try:
        return (0, int(text))
    except ValueError:
        return (1, text)
```

任何纯整数 round 走 `(0, int)` 桶，任何含非数字字符的 round 走 `(1, str)` 桶。元组比较先比第一项：所有 `(0, ...)` 永远排在 `(1, ...)` 前面。结果：`"58", "60", "61"` 全部排在 `"59-B"` 之前——**`"59-B"` 反而排到了 `"61"` 后面**。`history` 取末尾作为 latest，于是 R67 之后 `HK-A-BGP-2.0.latest_round` 被记成 `"59-B"`，错误地把它停在 `latest_divergence_outbounds` 桶里。R67 live evidence 本身没问题，但 latest_* 指标全部受这一排序污染。

### 修复

1. 重写 `round_sort_key`：解析前导整数 + 后缀字符串，返回 `(major, suffix)`。`"58" → (58, "")`、`"59" → (59, "")`、`"59-B" → (59, "-B")`、`"60" → (60, "")`，元组比较自然得到 `58 < 59 < 59-B < 60 < 61`。无前导整数的字符串按 `(sys.maxsize, text)` 排末尾。
2. `build_rollup` 在迭代前用 `(round_sort_key, path.name)` 对输入路径做规范化排序，使同一 round 多个 evidence 文件的内部顺序由文件名决定，不再依赖 `--evidence` argv 顺序。

### 测试

- 新增 `RealityRoundSortKeyTests`（4 用例）：`58 < 59 < 59-B < 60 < 61` 排序；不可解析 token 排末尾。
- 新增 `RealityEvidenceRollupOrderingTests`（2 用例）：`HK-A-BGP-2.0` synthetic 在 `59-B` divergence + `61` same-failure 后必须 `latest_round=="61"` 且不在 `latest_divergence_outbounds`；同 round 多文件场景对 argv 顺序不敏感。
- 修复前 4 个用例失败，正好复现 R67 的污染症状。
- 修复后 6/6 全部通过；总计 `python3 -B -m unittest test_reality_probe_tools test_reality_clienthello_family test_dual_kernel_verification` → **68 PASS**（原 62 + 新 6）。

### 重建后的真实 latest_* 指标

- `total_rounds` = 16，`total_executed_runs` = 105，`total_all_ok_runs` = 24（与 R67 一致）。
- `HK-A-BGP-2.0.latest_round` = `61`，`latest_health` = `latest_same_failure`（之前错为 `59-B` / `latest_divergence`）。
- `latest_divergence_outbounds` = `[]`（之前错为 `["HK-A-BGP-2.0"]`）。
- `latest_stable_same_failure_outbounds` = `["HK-A-BGP-1.0", "HK-A-BGP-2.0", "HK-A-BGP-2.5", "JP-A-BGP-0.3", "UK-A-BGP-0.5", "US-A-BGP-0.5"]`（count 5→6，加入 HK-A-BGP-2.0）。
- `latest_bi_modal_outbounds` = `[]`，`latest_phase_shifting_outbounds` = `[]`：HK-A-BGP-2.0 的最新 round 是均一 connection_reset，机械指标当然不再标记 bi-modal 或 phase-shifting；这是 R67 单 round 的真实形状。**这并不构成 closure_report 的「3+ longer-repeat rounds 后稳定重分类」**——分析层仍需要 ≥3 个 longer-repeat round 一致才能在判断层把 HK-A-BGP-2.0 从 bi-modal/phase-shifting 名单上正式移除。
- `recovered_outbounds` = `["JP-A-BGP-1.0", "TW-A-BGP-1.0", "US-A-BGP-0.8"]`（不变）。

### 判定

- R67 的 classification A（no new signal）在重建后仍成立。
- 所有失败 run 仍是 `probe_io class == reality class`，无 transport-vs-app divergence。
- 没有新增 sampler/dataplane patch；BHV 账面 52/56 不变；`go_fork_source/*` 和 `.github/workflows/*` 未触碰。

---

## Round 69 (stage-3 current-sample closure + fresh-signal gate)

### 日期

2026-05-04

### 目标

在 R68 修复后的 rollup 基线上：
1. 给 HK-A-BGP-2.0 添加第二轮 longer-repeat confirmation，让 closure_report 的 `3+ longer-repeat rounds` 重分类规则向前推进；
2. 用 default planner 检查现有 `phase3_ip_direct.json` 还能否继续生成结构信号候选，建立 fresh sample face 的入口条件。

不寻找 patch 机会。

### HK-A-BGP-2.0 longer-repeat #2 结果

- 命令：`reality_vless_probe_batch.py --outbound 'HK-A-BGP-2.0倍率' --runs 4 --target example.com:80 --timeout 8 --phase-timeout-ms 8000 --probe-io-timeout-ms 8000`
- 4/4 runs 全部产出 `probe_io_all_connection_reset` + `reality_all_connection_reset`
- divergence run count: 0
- probe_io class == reality class on every run → 没有 transport-vs-app 偏差信号
- 这是 HK-A-BGP-2.0 第 2 轮 longer-repeat uniform same-failure（R61 是第 1 轮）。`closure_report.md` 的 "is_phase_shifting=false stably across 3+ longer-repeat rounds" 规则当前 2/3 满足，**仍需要再一轮才能正式重分类**。

### Fresh sample gate 结论

- `reality_vless_probe_plan.py --rollup-json …`（默认）选 0 个 outbound：所有 latest non-all_ok 已在 stable same-failure 桶里覆盖，没有 uncovered candidate。
- `--include-covered --limit 5` 仅返回 5 个 `latest_all_ok` recovery-watch 节点（HK-A-BGP-0.3、SG-A-BGP-1.0、SG-A-BGP-1.2、ID-A-BGP-1.2、TW-A-Hinet-1.1），全是已知健康节点的复测。
- 当前 committed `phase3_ip_direct.json` **样本面已饱和**。下一轮 signal hunting 必须由用户提供新 REALITY/VLESS 节点或新 config，否则只是在旧节点上反复刷掉线/恢复噪声。

### 重建后的 rollup

- `total_rounds` 16 → 17
- `total_executed_runs` 105 → 109
- `total_all_ok_runs` 24 → 24
- `latest_divergence_outbounds` 仍为 `[]`
- `latest_bi_modal_outbounds` 仍为 `[]`
- `latest_phase_shifting_outbounds` 仍为 `[]`
- `latest_stable_same_failure_outbounds` 仍为 `["HK-A-BGP-1.0", "HK-A-BGP-2.0", "HK-A-BGP-2.5", "JP-A-BGP-0.3", "UK-A-BGP-0.5", "US-A-BGP-0.5"]`
- HK-A-BGP-2.0：`latest_round=62`、`latest_health=latest_same_failure`、`is_bi_modal=False`、`is_phase_shifting=False`
- HK-A-BGP-2.0 dominant_phase_history 末尾 R59-B → R61 → R62 是「divergence → uniform → uniform」的两步 monotonic 静止；R57/R56/R54 仍是历史的 mixed phase pattern，所以纯历史聚合仍然记录 phase-shifting 痕迹

### 判定（R69 分类 A：current sample closed / no new signal）

- 没有 sampler/dataplane signal 出现。
- HK 重分类还差一轮 longer-repeat。
- 现有 sample face 已不再制造新候选；下一步只能依赖 fresh sample intake。
- 没有对 sampler/dataplane/`go_fork_source/*`/`.github/workflows/*` 做任何修改；BHV 账面 52/56 不变。

### 验证

- `python3 -B -m unittest scripts/tools/test_reality_probe_tools.py scripts/tools/test_reality_clienthello_family.py scripts/tools/test_dual_kernel_verification.py` → 68 PASS
- `cargo build -p app --features acceptance,clash_api,service_ssmapi --bin app` → PASS
- batch summary → evidence → rollup 重建均通过；jq empty pass。

---

## Round 70 (stage-3 final HK confirmation + current sample face closure)

### 日期

2026-05-04

### 目标

完成 HK-A-BGP-2.0 longer-repeat 序列的第 3 轮 confirmation。
若 4/4 继续 uniform same-failure 且 probe_io class == reality class，
按 `closure_report.md` 的「is_phase_shifting=false stably across 3+
longer-repeat rounds」规则正式把 HK-A-BGP-2.0 从 analyst-layer
bi-modal / phase-shifting suspect 名单中移除，并关闭当前 committed
sample face。同时 dry-run planner 验证 fresh sample gate 是否仍未
打开。本轮严格不修改 sampler/dataplane，不动 `go_fork_source/*`、
`.github/workflows/*`，不跑 broad live batch。

### HK-A-BGP-2.0 longer-repeat #3 结果

- 命令：`reality_vless_probe_batch.py --outbound 'HK-A-BGP-2.0倍率' --runs 4 --target example.com:80 --timeout 8 --phase-timeout-ms 8000 --probe-io-timeout-ms 8000 --output-dir /tmp/reality-vless-probe-batch-live-r70-hk-final`
- 4/4 runs 全部产出 `probe_io_all_connection_reset` +
  `reality_all_connection_reset`
- divergence run count: 0
- probe_io class == reality class on every run（每 run 9 个连接 class 全部 connection_reset，6/6 比较 match=true）
- 这是 HK-A-BGP-2.0 第 3 轮 longer-repeat uniform same-failure：
  R61 (1st) → R62 (2nd) → R63 (3rd)。`closure_report.md` 的 3/3
  规则现在正式满足。
- 重建后 rollup 中 `HK-A-BGP-2.0` 状态：`latest_round=63`、
  `latest_health=latest_same_failure`、`is_bi_modal=false`、
  `is_phase_shifting=false`、`latest_divergence_run_ratio=0.0`。
  dominant_phase_history 末尾 R59-B → R61 → R62 → R63 是
  `app_pre_post_diverged` → null → null → null 的稳定静止。
  历史聚合中 R54/R56/R57/R59-B 仍记录早期 mixed phase pattern，
  但现期 3 轮 longer-repeat 已稳定均一同失败。

### 判定（R70 分类 A：Current sample face formally closed / no new signal）

- 没有新的 sampler/dataplane signal 出现。
- HK-A-BGP-2.0 不再是当前样本面的 analyst-layer
  bi-modal / phase-shifting suspect。
- HK longer-repeat rule **3/3 satisfied** —— closure_report 的
  reclassification 路径已走完。
- 失败仍是 probe_io / reality 同 class 的统一连接重置，没有
  transport-vs-app 偏差信号。
- 节点掉线/衰减不写为 sampler regression。
- 不打 sampler/dataplane patch，不写 root-cause WP。

### Fresh sample gate dry-run 结论

- `reality_vless_probe_plan.py --rollup-json
  agents-only/mt_real_02_evidence/live_rollup.json --output-json
  /tmp/reality-vless-r70-default.json`（默认）：
  `selected_count=0`，`uncovered=0`，`prior_non_all_ok=6`，
  `covered_all_ok=15`。
- `reality_vless_probe_plan.py … --include-covered --limit 5
  --output-json /tmp/reality-vless-r70-include-covered.json`：
  `selected_count=5`，全部 reason=`covered_all_ok`、
  latest_health=`latest_all_ok`，仅 5 个 recovery-watch 节点
  (HK-A-BGP-0.3、SG-A-BGP-1.0、SG-A-BGP-1.2、ID-A-BGP-1.2、
  TW-A-Hinet-1.1)，无 uncovered/fresh candidate。
- 结论：当前 committed `phase3_ip_direct.json` sample face 已
  闭环；下一轮 signal hunting 必须由用户提供 fresh REALITY/VLESS
  节点或新 config，否则旧节点反复刷掉线/恢复噪声不会制造结构信号。

### 重建后的 rollup

- `total_rounds` 17 → 18
- `total_executed_runs` 109 → 113
- `total_all_ok_runs` 24 → 24（不变）
- `latest_divergence_outbounds` = `[]`
- `latest_bi_modal_outbounds` = `[]`
- `latest_phase_shifting_outbounds` = `[]`
- `latest_stable_same_failure_outbounds` =
  `["HK-A-BGP-1.0", "HK-A-BGP-2.0", "HK-A-BGP-2.5",
    "JP-A-BGP-0.3", "UK-A-BGP-0.5", "US-A-BGP-0.5"]`
- `recovered_outbounds` =
  `["JP-A-BGP-1.0", "TW-A-BGP-1.0", "US-A-BGP-0.8"]`

### 验证

- `python3 -B -m unittest scripts/tools/test_reality_probe_tools.py scripts/tools/test_reality_clienthello_family.py scripts/tools/test_dual_kernel_verification.py` → 68 PASS
- `cargo build -p app --features acceptance,clash_api,service_ssmapi --bin app` → PASS
- `reality_vless_probe_batch.py … --dry-run` → PASS（plan/runs/timeout 一致）
- `reality_vless_probe_batch.py …`（live）→ 4/4 completed
- `reality_vless_probe_evidence.py` → round63 evidence written
- `reality_vless_evidence_rollup.py` → 18 rounds / 113 runs
- BHV 账面 52/56 不变；`go_fork_source/*`、`.github/workflows/*` 未触碰；
  sampler/dataplane 无改动。

---

## Round 71 (fresh sample intake gate)

### 日期

2026-05-04

### 目标

R70 已正式关闭当前 committed `phase3_ip_direct.json` sample face。
继续在旧节点上跑 sampler 不会再制造结构信号。R71 不跑 live probe、
不修改 sampler/dataplane，专注建立干净的 fresh sample 入口：

1. 实现 redacted-by-default 的 candidate config 验证器，识别
   真正 fresh 的 REALITY/VLESS outbound、tag/指纹 duplicate、
   缺字段 not_ready、以及 rollup 已覆盖的 covered_existing。
2. 给 R72 live probe 准备「干净输入合同」：除非验证器输出
   `ready_for_r72=true`，否则 R72 不能启动。

### 工具

`scripts/tools/reality_vless_sample_intake.py`：

- 输入：
  - `--candidate-config PATH`
  - `--baseline-config`（默认 `agents-only/mt_real_01_evidence/phase3_ip_direct.json`）
  - `--rollup-json`（默认 `agents-only/mt_real_02_evidence/live_rollup.json`）
  - `--output-json PATH`（必填）
  - `--redacted-md PATH`（可选）
- 复用 `reality_vless_env_from_config.py` 的 `outbound_summary` /
  `reality_vless_ready_reason` 解析逻辑，**不重写** REALITY 字段判定。
- 分类规则（优先级从高到低）：
  1. `not_ready` —— `reality_vless_ready_reason()` 返回非 None
     （`missing_uuid` / `missing_reality_public_key` / `missing_server` /
     `missing_port` / `missing_name` / `non_tcp_transport` / `not_vless`）。
  2. `duplicate` —— ready 通过但 tag 与 baseline tag 集合冲突
     (`duplicate_kind=tag`)，或指纹 5-tuple
     (server_hash, port, server_name, public_key_hash, short_id_hash)
     与 baseline 中任一 outbound 完全一致 (`duplicate_kind=fingerprint`)；
     uuid 不参与指纹比较，因 uuid 是账户级的。
  3. `covered_existing` —— ready + 非 duplicate，但去掉 `倍率` 后缀的 tag
     已经存在于 `live_rollup.json` 的 `by_outbound` 索引里，等于复刷旧线。
  4. `fresh_ready` —— 以上都不是，进入 R72 候选池。
- 顶层 `summary.ready_for_r72 = (counts.fresh_ready > 0)`。R72 必须以此
  字段为 entry gate。
- Redaction：所有原文 UUID / public_key / short_id / server 一律替换为
  `{ "hash": SHA256[:12], "length": N }`，hash 决定性可比对但不可逆。
  `server_name` 与 `port` 是公开字段，按原文保留。markdown 报告由
  `render_redacted_md` 渲染，仅写 hash 和 region prefix。

### 测试

`scripts/tools/test_reality_probe_tools.py::RealityVlessSampleIntakeTests`，
7 个新用例：

1. `test_fresh_ready_outbound_is_identified` —— 候选 1 个全新 tag +
   全新指纹，应进入 fresh_ready，summary.ready_for_r72=True。
2. `test_baseline_tag_collision_is_duplicate` —— 候选 tag 与 baseline
   完全一致但 server/UUID 都不同，应判 duplicate (kind=tag)。
3. `test_fingerprint_collision_with_distinct_tag_is_duplicate` ——
   候选 tag 是新名字，但 server/port/server_name/public_key/short_id
   与 baseline 中某项完全一致，应判 duplicate (kind=fingerprint)，
   并记录 `duplicate_baseline_tags` 指回原 baseline tag。
4. `test_missing_reality_field_is_not_ready` —— 同时验证 3 个失败路径
   (missing_reality_public_key / missing_uuid / missing_server)，全部
   进入 not_ready 桶并带有正确 skip_reason。
5. `test_redacted_output_contains_no_raw_secrets` —— 候选含明文
   UUID/public_key/short_id/server，序列化 JSON 与 MD 中均不可
   出现这些原值；fingerprint hash 长度严格 12。
6. `test_no_candidate_fresh_when_all_overlap` —— 候选与 baseline
   完全相同 → fresh_ready=0、ready_for_r72=False。
7. `test_covered_existing_marks_known_rollup_keys` —— 候选 tag 不在
   baseline，但 stripped tag 已在 rollup 索引中，应进入 covered_existing
   桶并写 `detail.rollup_key`。

### 本轮验证

- `python3 -B -m unittest scripts/tools/test_reality_probe_tools.py
  scripts/tools/test_reality_clienthello_family.py
  scripts/tools/test_dual_kernel_verification.py` →
  **75 PASS**（原 68 + 新 7）。
- `cargo check --workspace` → PASS。
- `python3 scripts/tools/reality_vless_sample_intake.py --help` → 正常打印 CLI。

### Fresh config 状态

本轮**没有**用户提供的 fresh REALITY/VLESS config。`/tmp/mt_real_02_fresh_config.json`
不存在。因此：

- 没有跑 candidate 验证。
- 没有跑 `reality_vless_probe_batch.py --dry-run`。
- 没有 live probe。

新增 operator guide：`agents-only/mt_real_02_fresh_sample_intake.md`
（A-tier）。文档明确：

- 候选 config 必须放在 `/tmp/...`，不能进 `agents-only/` 下。
- 必填字段：type=vless / tag / server / server_port / uuid /
  reality.public_key / server_name / 纯 TCP transport。
- `short_id` 与 `utls.fingerprint` 不影响 ready，但影响 duplicate 检测。
- R72 启动门禁：`summary.ready_for_r72=true` + 一次成功的
  `reality_vless_probe_batch.py --dry-run`。
- 不允许把 raw secret 写进任何被 git 追踪的文件。

### 判定（R71 分类 A：intake gate ready, waiting for fresh config）

- 工具就绪并通过单测，redaction 完整，duplicate/not_ready/covered_existing
  三条边界都被测试覆盖。
- 当前没有可进入 R72 live probe 的 fresh candidates；R72 entry gate
  正式定义为「intake validator 输出 fresh_ready ≥ 1 且 dry-run 成功」。
- 没有 sampler/dataplane patch；未编辑 baseline config；BHV 账面 52/56
  不变；`go_fork_source/*`、`.github/workflows/*` 未触碰。

### 改动文件

- `scripts/tools/reality_vless_sample_intake.py`（新增）
- `scripts/tools/test_reality_probe_tools.py`（追加 7 用例 + 1 import）
- `agents-only/mt_real_02_fresh_sample_intake.md`（新增 A-tier 文档）
- `agents-only/active_context.md`（R71 状态、≤95 行）
- `agents-only/mt_real_02_baseline.md`（追加本节）

---

## Round 72 (fresh config intake validation + dry-run gate)

### 日期

2026-05-06

### 目标

验证用户放置在 `/tmp/mt_real_02_fresh_config.json` 的 fresh
REALITY/VLESS candidate 是否可进入下一轮 R73 bounded live probe。
本轮只允许 offline intake validator 和 dry-run gate；不跑 live probe，
不修改 sampler/dataplane，不修改 committed baseline config。

### 门禁

- `python3 -B -m unittest scripts/tools/test_reality_probe_tools.py scripts/tools/test_reality_clienthello_family.py scripts/tools/test_dual_kernel_verification.py`
  → **75 PASS**。
- `cargo check --workspace` → PASS。

### Intake validation

执行：

```bash
python3 scripts/tools/reality_vless_sample_intake.py \
  --candidate-config /tmp/mt_real_02_fresh_config.json \
  --baseline-config agents-only/mt_real_01_evidence/phase3_ip_direct.json \
  --rollup-json agents-only/mt_real_02_evidence/live_rollup.json \
  --output-json /tmp/mt_real_02_fresh_intake.json \
  --redacted-md /tmp/mt_real_02_fresh_intake.md
```

结果：validator 在生成 redacted summary 前拒绝输入，原因是 candidate
config root 不是 sing-box config object。`/tmp/mt_real_02_fresh_intake.json`
和 `/tmp/mt_real_02_fresh_intake.md` 均未生成。

Redacted summary counts 因输入被拒绝未产生：

- `fresh_ready`: not produced
- `duplicate`: not produced
- `not_ready`: not produced
- `covered_existing`: not produced
- `ready_for_r72`: not produced

### Dry-run gate

未执行。由于 intake validator 未产生 `summary.ready_for_r72=true`，
不得运行 `reality_vless_probe_batch.py`，也不得启动 live probe。

### 判定（R72 分类 D：invalid/unsafe input）

- Candidate config malformed for intake: root shape is not a sing-box
  config object.
- R73 live probe **不可启动**；需要重新提供符合 intake guide 的 fresh
  config 后再跑 R72 gate。
- 没有 sampler/dataplane patch；未编辑 baseline config；BHV 账面 52/56
  不变；`go_fork_source/*`、`.github/workflows/*` 未触碰。

### 改动文件

- `agents-only/active_context.md`（R72 状态、≤95 行）
- `agents-only/mt_real_02_baseline.md`（追加本节）

---

## Round 72b (fresh config root normalization + intake re-run)

### 日期

2026-05-06

### 目标

R72 发现 fresh candidate JSON 的 root 是 list，不是 sing-box config
object。R72b 只做安全 root normalization、重新跑 offline intake gate，
并按 `ready_for_r72` 决定是否允许 dry-run gate；仍不跑 live probe。

### 门禁

- `python3 -B -m unittest scripts/tools/test_reality_probe_tools.py scripts/tools/test_reality_clienthello_family.py scripts/tools/test_dual_kernel_verification.py`
  → **75 PASS**。
- `cargo check --workspace` → PASS。

### Root normalization

- Root type: list。
- 已生成 `/tmp/mt_real_02_fresh_config_wrapped.json`，结构为
  `{ "outbounds": <candidate-array> }`。
- `/tmp` normalized config 未提交。

### Intake validation

对 normalized config 重新执行 `reality_vless_sample_intake.py`，产出
redacted summary：

- `fresh_ready`: 0
- `duplicate`: 0
- `not_ready`: 0
- `covered_existing`: 0
- `ready_for_r72`: false

### Dry-run gate

未执行。`ready_for_r72=false`，没有 fresh candidates 可进入 dry-run
或 R73 live probe。

### 判定（R72b 分类 A：intake valid but no fresh candidates）

- Intake validator 正常完成，但 fresh_ready=0。
- R73 live probe **不可启动**。
- 没有 sampler/dataplane patch；未编辑 baseline config；BHV 账面 52/56
  不变；`go_fork_source/*`、`.github/workflows/*` 未触碰。

### 改动文件

- `agents-only/active_context.md`（R72b 状态、≤95 行）
- `agents-only/mt_real_02_baseline.md`（追加本节）

---

## Round 72c (fresh candidate type triage + operator feedback)

### 日期

2026-05-06

### 目标

R72b normalized config intake 得到 fresh_ready=0。R72c 只做安全字段计数
和协议族归因，确认该 candidate 是否属于 MT-REAL-02 的 REALITY/VLESS
fresh sample face；不跑 live probe，不修改 sampler/dataplane。

### 门禁

- `python3 -B -m unittest scripts/tools/test_reality_probe_tools.py scripts/tools/test_reality_clienthello_family.py scripts/tools/test_dual_kernel_verification.py`
  → **75 PASS**。
- `cargo check --workspace` → PASS。

### 安全类型摘要

只读取 `/tmp/mt_real_02_fresh_config_wrapped.json` 的字段计数，不输出
任何节点值：

- `outbounds_len`: 90
- `type_counts`: `trojan=90`
- VLESS candidates: 0
- REALITY candidates: 0
- UUID fields: 0
- `tls.reality` blocks: 0

### 判定（R72c 分类 D：invalid for MT-REAL-02 REALITY intake）

- Candidate 是合法 JSON，但协议族错误：本批是 Trojan-only，不是
  REALITY/VLESS sample face。
- 这不是 malformed JSON，也不是 validator bug。
- R73 REALITY live probe **不可启动**。
- 若继续 MT-REAL-02，需要重新提供 `type=vless` 且带 REALITY TLS
  字段与 UUID 的 fresh config。
- 若要利用这批 Trojan 节点，应另开新任务，不混入 REALITY 账。
- 没有 sampler/dataplane patch；未编辑 baseline config；BHV 账面 52/56
  不变；`go_fork_source/*`、`.github/workflows/*` 未触碰。

MT-TROJAN-FRESH-01 follow-up: REALITY remains blocked, and the Trojan-only config is moved to a separate Rust-only quality line that does not affect BHV 52/56 or dual-kernel parity status.
MT-TROJAN-FRESH-02 follow-up: REALITY remains blocked; Trojan quality-line dry-run planning is now ready for separate live authorization and still does not affect BHV 52/56 or dual-kernel parity status.

### 改动文件

- `agents-only/active_context.md`（R72c 状态、≤95 行）
- `agents-only/mt_real_02_baseline.md`（追加本节）

---

## R73 — MT-MIXED-FRESH-01 fresh REALITY/VLESS bounded live (2026-05-08)

### 触发

MT-MIXED-FRESH-01 在 2026-05-07 完成 no-live intake，15 个 fresh
REALITY/VLESS candidates 通过 fresh_ready=15、`ready_for_r73=true`
门禁；用户在 2026-05-08 显式授权 REALITY/VLESS live（不授权 Hys2
或 plain-VLESS）。本轮按既有 dry-run plan 执行 15×5=75 bounded
live runs。

### 门禁

- `python3 -B -m unittest test_reality_probe_tools test_reality_clienthello_family test_dual_kernel_verification`
  → **142 PASS**（运行时与 R72c 一致）
- `cargo check --workspace` → PASS
- secret scan 全清

### Pre-gate identity

- input_sha256_prefix: `f5681baf3ad4760c`
- candidate_count: 15
- runs_per_outbound: 5
- planned_total_runs: 75
- target: `example.com:80`
- timeout: 10s; phase-timeout-ms: 10000; probe-io-timeout-ms: 10000
- intake re-run on neutral subset: fresh_ready=15, duplicate=0,
  not_ready=0, covered_existing=0, ready_for_r73=true

### Config normalization

候选 config 的 `__id_in_gui` 私有字段被 validator 拒绝；通过既有
`scripts/tools/trojan_config_normalize.py::normalize_config`
（递归剥离 `__` 前缀字段）做 intake-time 标准化，写入
`/tmp/mt_mixed_fresh_subset_reality_clean.json`，**未触碰 sampler /
dataplane**；与 MT-TROJAN-FRESH-07 走的是同一条标准化路径。

### Live 数据

- executed_runs: 75 / 75
- status_counts: `{completed: 75}`
- run-level：run_all_ok=46, run_divergence=2, run_same_failure=27
- divergence_phase_label_count（occurrences）=5；
  distinct_divergence_phase_label_count=4（app_pre_post_diverged ×1,
  app_minimal_diverged ×2, bridge_io_diverged ×1,
  minimal_transport_diverged ×1）
- has_divergence: true（来自 2 个 divergence run，分别携带 2 / 3 个
  phase label）
- class_counts: `{ok: 417, other: 172, connection_reset: 47, timeout: 39}`

### Per-outbound 桶（run-level）

- 5/5 run_all_ok（9 个）：fresh01, fresh08, fresh09, fresh10,
  fresh11, fresh12, fresh13, fresh14, fresh15
- fresh06：1 run_all_ok + 1 run_divergence（同 1 个 run 携带 3 个
  phase labels：app_minimal + bridge_io + minimal_transport）+ 3
  run_same_failure（probe_io_all_other + reality_all_other）。
  MT-REAL-02 历史上首次出现单个 run 同时携带这 3 个 phase 的样本
- fresh02：1 run_divergence（同 1 个 run 携带 2 个 phase labels：
  app_pre_post + app_minimal，并同时被标 probe_io_all_other）+ 4
  run_same_failure（timeout）— node-health limited
- fresh03/04/05/07：5/5 run_same_failure（uniform other 或
  connection_reset）；fresh07 与 R61–R63 HK-A-BGP-2.0 同型
  connection_reset；fresh03/04/05 同型 probe_io_all_other +
  reality_all_other

### probe_io vs reality 一致性

| kind | probe_io_all_* | reality_all_* | delta |
| --- | ---: | ---: | ---: |
| connection_reset | 5 | 5 | 0 |
| timeout | 4 | 4 | 0 |
| other | 19 | 18 | +1 |

±1 的差距来自 fresh02 一个 run 同时被标 probe_io_all_other 与
app_pre_post_diverged，没有出现 transport-vs-app 跨 phase 的新型
divergence。

### 归因（按现有规则）

- 分类：**A**（actionable live signal；零新型 structural divergence）
- 9 个 fresh REALITY/VLESS 节点 5/5 端到端可用 — 这是 MT-REAL-02 自
  R45-R60 阶段以来第一次同时取得这么多 5/5 all_ok 的 fresh 节点
- fresh06 的 1 个 divergence run（携带 `app_minimal + bridge_io +
  minimal_transport` 3 个 phase label）是 R73 的关键 sample：第一次
  出现单 run 同时携带这三相位分歧的 fresh 节点；归因优先级照常按
  golden spec / S4 走，不下结论 sampler regression
- 同型 same-failure（fresh03/04/05/07）按 closure_report 规则属
  node-health limited，不写成 sampler regression
- run-level vs phase-label-level 区分：R73 共有 2 个 divergence
  run（fresh02、fresh06 各 1）但 5 个 phase-label occurrences；不要
  把 phase-label 计数当 divergence run 数。R74 已专门做账本纠偏。
- BHV 仍为 52/56；Rust-only quality 行为不写成 dual-kernel parity

### Rollup deltas

| 字段 | R72c 后 | R73 后 | delta |
| --- | ---: | ---: | ---: |
| total_rounds | 18 | 19 | +1 |
| total_executed_runs | 113 | 188 | +75 |
| total_all_ok_runs | 24 | 70 | +46 |
| by_outbound count | 21 | 36 | +15 |

### 改动文件

- `agents-only/mt_real_02_evidence/round73_mixed_fresh_live_summary.json`
- `agents-only/mt_real_02_evidence/round73_mixed_fresh_live_summary.md`
- `agents-only/mt_real_02_evidence/live_rollup.json` / `live_rollup.md`
- `agents-only/mt_mixed_fresh_intake.md`
- `agents-only/active_context.md`（≤95 行）
- `agents-only/mt_real_02_baseline.md`（本节）

### 授权范围确认

- Hys2 live: 0 runs（未授权）
- WS / plain VLESS live: 0 runs（未授权）
- 不扩大样本；不重选；不临场修改 sampler/dataplane
- 未触碰 `go_fork_source/*` 与 `.github/workflows/*`

---

## R74 — R73 evidence accounting audit & rematerialization (2026-05-08)

### 触发

R73 的几份 evidence/文案在「divergence run 数」与「divergence phase
label 出现次数」两个口径之间有混用：

- `round73_mixed_fresh_live_summary.md` 的 per-outbound 列
  `divergence_runs` 实际持有 phase-label per-occurrence 计数
  （fresh02=2、fresh06=3），不是 divergence-run 计数
- 「fresh06 4/5 mixed phase divergence」的措辞把 1 个 divergence
  run + 3 个 same-failure run 合并成「4/5 phase divergence」
- 「divergence runs: 5」实际指 5 个 phase-label occurrences，不是
  5 个 divergence run

### 性质判定

工具层正确：
`scripts/tools/dual_kernel_verification/health.py::classify_run_health`
对“一个 run 同时携带多个 phase label”仍返回单值
`run_divergence`，所以 `live_rollup.json.latest_run_health_counts`
的 `run_divergence=2` 是正确的，
`latest_divergence_outbounds=["fresh02","fresh06"]` 也正确。
账本错只在我们手写的 round73 派生文案里。

### 修正后的 R73 事实（per-run）

| outbound | 5 runs 的 run_health 序列 | divergence run 携带的 phase labels |
| --- | --- | --- |
| fresh02 | 4× run_same_failure（timeout）+ 1× run_divergence | app_minimal_diverged + app_pre_post_diverged（同 run 含 probe_io_all_other） |
| fresh06 | 3× run_same_failure（other）+ 1× run_divergence + 1× run_all_ok | app_minimal_diverged + bridge_io_diverged + minimal_transport_diverged |

R73 totals：
- run_all_ok = 46
- run_divergence = 2（fresh02、fresh06 各 1）
- run_same_failure = 27（fresh02 4 + fresh03 5 + fresh04 5 +
  fresh05 5 + fresh06 3 + fresh07 5）
- divergence_phase_label_count = 5（fresh02 贡献 2 + fresh06 贡献 3）
- distinct_divergence_phase_label_count = 4（app_pre_post,
  app_minimal, bridge_io, minimal_transport）

`live_rollup.json` 的 `latest_run_health_counts` 是跨所有 outbound
最近一轮的累计（含历史轮），所以 `run_same_failure=39`，比 R73 自身
的 27 大；这不是冲突，是聚合口径差异。

### 改动

- `agents-only/mt_real_02_evidence/round73_mixed_fresh_live_summary.json`
  - 在 summary 中新增 `divergence_run_count`、`divergence_phase_label_count`、
    `distinct_divergence_phase_label_count`、`divergence_phase_label_breakdown`、
    `same_failure_run_count`、`accounting_note`
  - 每个 by_outbound 条目新增 `run_health_counts`、
    `divergence_phase_label_count`、`divergence_phase_label_breakdown`
  - `interpretation` 重写，去掉「4/5 mixed phase divergence」
    「1/5 divergence sample」等口径混用
- `agents-only/mt_real_02_evidence/round73_mixed_fresh_live_summary.md`
  - 把 per-outbound 表拆成 `run_all_ok / run_divergence /
    run_same_failure / divergence_phase_labels (occurrences)` 4 列
  - 新增 fresh02 / fresh06 per-run facts 表
  - 把 classification block 改成 run-level 主语
- `agents-only/mt_mixed_fresh_intake.md`、`agents-only/active_context.md`、
  本文件 R73 节 — 同步纠偏

### 工具改动

- 没改 sampler / dataplane / runner
- 在 `scripts/tools/test_reality_probe_tools.py` 新增
  `RunDivergenceAccountingTests`（4 用例）：
  pin `classify_run_health` 在「一个 run 携带 2 / 3 个 phase label」
  时仍只返回 `run_divergence`、且 phase-label per-occurrence 计数
  与 run-level 计数不会被互相替换

### 门禁

- `python3 -B -m unittest test_reality_probe_tools test_reality_clienthello_family test_dual_kernel_verification`
  → **146 PASS**（+4 新用例）
- `cargo check --workspace` → PASS
- secret scan 全清
- BHV 52/56 不变

### 范围确认

- 没有 live probe；没有 node contact
- `live_rollup.json` 字段值没有变化（rollup 工具本身正确）
- `go_fork_source/*` 与 `.github/workflows/*` 未触碰
- Rust-only quality / 文档纠偏 ≠ dual-kernel parity 变化

---

## R75 — Fresh divergence attribution & run-health materialization (2026-05-08)

### 触发

R74 把 R73 evidence 的 `divergence_run_count` 与
`divergence_phase_label_count` 拆开后，仍留两个口径风险：

1. round-summary JSON 的 `runs[]` 里没有
   `run_health` 字段，下游必须从 `labels` 反推；R74
   纠偏的口径一直只活在 summary/by_outbound 层。
2. fresh02/fresh06 的 phase divergence 没有显式归因到 golden_spec
   S2/S3/S4，留下「Rust-only live evidence 是不是某个新 BHV 级别
   divergence」的歧义。

R75 把两件事都收口，no-live、no-node-contact、不动 sampler/dataplane。

### Per-run run_health 物化

新增 `scripts/tools/round_summary_run_health.py`：

- `classify_run(labels)` — 单 run 用既有
  `dual_kernel_verification.classify_run_health` 配
  `reality_vless_evidence_rollup.DIVERGENCE_PHASE_LABELS` 分桶
- `synthesize_round_totals(runs)` — 从 per-run 事实算
  `run_all_ok / run_divergence / run_same_failure / run_unknown`、
  `divergence_run_count`、`divergence_phase_label_count`、
  `distinct_divergence_phase_label_count`、
  `divergence_phase_label_breakdown`、`same_failure_run_count`
- `per_outbound_run_health_counts(runs)` /
  `per_outbound_phase_label_breakdown(runs)` — 同一套规则按 outbound
  分组
- `materialize_run_health(payload)` — 不就地修改输入；返回深拷贝，
  把 `run_health` 灌到每个 `runs[]` 条目，并按 per-run 事实重算
  `summary` 与 `by_outbound`

应用到 `agents-only/mt_real_02_evidence/round73_mixed_fresh_live_summary.json`：

- 75 个 `runs[]` 条目都带上 `run_health`
- summary `divergence_run_count=2`、
  `divergence_phase_label_count=5`、
  `distinct_divergence_phase_label_count=4`、
  `divergence_phase_label_breakdown={
    app_pre_post_diverged:1, app_minimal_diverged:2,
    bridge_io_diverged:1, minimal_transport_diverged:1
  }`、`same_failure_run_count=27`
- by_outbound 每条 `run_health_counts` + `divergence_phase_label_count`
  + `divergence_phase_label_breakdown` 全部由 per-run 事实重算

### Cross-check

- R73 round JSON: total=75, executed=75, run_all_ok=46,
  run_divergence=2, run_same_failure=27,
  divergence_phase_label_count=5, distinct=4
- live_rollup.json（rollup 工具确定性再生成 → 与 R74 提交完全一致）：
  - `latest_divergence_outbounds=["fresh02","fresh06"]`
  - `latest_divergence_phase_total_counts={app_pre_post_diverged:1,
    app_minimal_diverged:2, minimal_transport_diverged:1,
    bridge_io_diverged:1}`
  - `latest_run_health_counts.run_divergence=2`
- per-outbound：fresh02 `{run_all_ok:0, run_divergence:1,
  run_same_failure:4}` + 2 phase labels；fresh06
  `{run_all_ok:1, run_divergence:1, run_same_failure:3}` + 3 phase
  labels

### 归因审计（fresh02 / fresh06）

| outbound | divergence run 携带的 phase labels | golden_spec 归因 |
| --- | --- | --- |
| fresh02 | app_pre_post_diverged + app_minimal_diverged | DEV-REALITY-01 (ARCH-LIMIT) — no new S4 entry |
| fresh06 | app_minimal_diverged + bridge_io_diverged + minimal_transport_diverged | DEV-REALITY-01 (ARCH-LIMIT) — no new S4 entry |

证据：

- 这四个 phase 标签 (`app_pre_post_diverged`,
  `app_minimal_diverged`, `minimal_transport_diverged`,
  `bridge_io_diverged`) **不在** golden_spec S2 / S3 任何登记里；
  它们由
  `scripts/tools/reality_probe_compare.py:74-141` 在 6 个 phase
  比较 (`app_pre_post_*`, `minimal_direct_vs_transport_reality`,
  `app_post_vs_minimal_*`, `app_bridge_vs_minimal_probe_io`)
  mismatch 时合成，并由
  `scripts/tools/reality_vless_evidence_rollup.py:24-29`
  集中登记成 `DIVERGENCE_PHASE_LABEL_ORDER`
- 它们的 S4 容器是 **DEV-REALITY-01 (ARCH-LIMIT)**，即 Rust REALITY
  live dataplane 因为缺 `uTLS`-equivalent 暂时算 ARCH-LIMIT；R73 fresh
  数据是这条 ARCH-LIMIT 的 supporting evidence，**不是新 BHV-level
  divergence**
- 不需要在 golden_spec S4 新增条目；`DEV-REALITY-01` 已经覆盖整条
  REALITY live dataplane line

### Tests

- `python3 -B -m unittest test_reality_probe_tools test_reality_clienthello_family test_dual_kernel_verification`
  → **153 PASS**（+7 新用例）
- 新增 `RoundSummaryRunHealthMaterializationTests`（7 用例），固定：
  - 一个 run 携带 2 / 3 个 phase label 仍是单个 `run_divergence`
  - same-failure run 不会被误算成 `run_divergence`
  - all_ok run 永远不带 phase / bridge_io 标签
  - 75-run R73 合成 fixture 必得到
    run_all_ok=46, run_divergence=2, run_same_failure=27,
    divergence_phase_label_count=5, distinct=4
  - `materialize_run_health` 不会 mutate 输入
- `cargo check --workspace` → PASS
- `git diff --check` → clean
- secret scan 全清

### 改动文件

- `agents-only/mt_real_02_evidence/round73_mixed_fresh_live_summary.json`
  （per-run `run_health` 物化；summary 按 per-run 事实重算）
- `agents-only/mt_real_02_evidence/round73_mixed_fresh_live_summary.md`
  （加 R75 attribution audit；per-run 表用物化字段）
- `agents-only/mt_real_02_evidence/live_rollup.json` /
  `live_rollup.md` —— 工具确定性再生成，与 R74 提交无差
- `scripts/tools/round_summary_run_health.py`（新建）
- `scripts/tools/test_reality_probe_tools.py`（+7）
- `agents-only/active_context.md`（≤95 行）
- 本文件 R75 节

### 范围确认

- 没有 live probe；没有 node contact；没有动 sampler/dataplane
- `go_fork_source/*` / `.github/workflows/*` 未触碰
- `golden_spec` 未改：`DEV-REALITY-01` 已覆盖
- 不写成 dual-kernel parity 变化；BHV 52/56 不变

---

## R76 — Fresh REALITY/VLESS confirmation plan & authorization packet (2026-05-08)

### 触发

R75 把 R73 evidence 物化到 `run_health_counts` 后，下一步问题是
「下一轮 live 该跑谁、跑多深、按什么顺序授权」。R76 在 no-live 前提下
完成这个 planning + 授权 packet，不接触节点，不修改 sampler/dataplane。

### Cohort 划分（基于 R75 物化的 run_health_counts）

| Cohort | 节点 | runs/outbound | planned_total_runs |
| --- | --- | ---: | ---: |
| **A — divergence carrier** | fresh02, fresh06 | 5 | 10 |
| **B — same failure** | fresh03, fresh04, fresh05, fresh07 | 3 | 12 |
| **C — recovery watch (3 reps)** | fresh01, fresh09, fresh15 | 3 | 9 |
| Combined ceiling | all three | — | 31 |

C cohort 在 9 个 5/5 all_ok 节点中只挑 3 个代表（按 ordinal 跨度
fresh01 / fresh09 / fresh15），3 runs/node 满足 R59-B/R60/R61/R62/R63
家族里 longer-repeat 的最低深度；2 runs/node 在闭环规则里太浅。
其余 6 个（fresh08/10/11/12/13/14）保持在 R73 round-1-only，留给 R77/R78
后续 cohort C 扩展。

### 工具改动

新增 `scripts/tools/reality_vless_confirmation_cohorts.py`：

- `cohort_for_outbound(entry)` — 单条 by_outbound 入桶规则
- `derive_cohorts(round_summary)` — 整轮分桶
- `cohort_plan(...)` — 单 cohort 的 plan shape
- `total_planned_runs(plan)` — 跨 cohort 求和

入桶规则：
- `run_divergence > 0` → `divergence_carrier`
- `run_all_ok==0 ∧ run_same_failure>0 ∧ run_divergence==0` → `same_failure`
- `run_all_ok>0 ∧ run_same_failure==0 ∧ run_divergence==0` → `recovery_watch`
- 其余（含 mixed run_all_ok+run_same_failure，全 run_unknown）→ `neutral`，
  不自动入任何 cohort，由人工 review 决定

测试 `FreshConfirmationCohortTests`（9 用例）pin：
- fresh02/fresh06 进 divergence_carrier
- fresh03/04/05/07 进 same_failure
- fresh01 + fresh08..fresh15 全部进 recovery_watch
- mixed all_ok+same_failure 落 neutral
- cohort_plan 计算 planned_total_runs 正确
- runs_per_outbound ≤ 0 抛 ValueError
- total_planned_runs 跨 cohort 求和正确
- committed r76 plan：只有 neutral keys（regex `^fresh\d{2}$`），
  10/12/9 totals 匹配，所有 live/node-contact/sampler/dataplane/
  workflows 标志为 False

### 默认授权建议

按照最小授权原则：

1. **先授权 cohort A（10 runs）**，看 R73 的 2 个 divergence
   carriers 在第二轮是否仍只命中既有 4 个 phase labels。
2. cohort A 落地后再决定 cohort B 是否值得跑（如果 fresh02 转 timeout
   主导，B 的优先级降低）。
3. cohort C 留到最后；recovery 闭环规则要求 3 轮，所以即使 C cohort
   3/3，离正式 closure 仍差一轮。

任何后续 live 必须用户显式列出 cohort 名称授权；不接受默认放行。

### 产物

- `agents-only/mt_real_02_evidence/r76_fresh_confirmation_plan.json`
  （cohort 映射 + objective/gate/stop/expected A/B/C/D + dry-run 命令模板）
- `agents-only/mt_real_02_evidence/r76_fresh_confirmation_plan.md`
  （上面 JSON 的 redacted 渲染）
- `scripts/tools/reality_vless_confirmation_cohorts.py`（新建）
- `scripts/tools/test_reality_probe_tools.py`（+9）
- `agents-only/active_context.md`（≤95 行）
- 本文件 R76 节

### 门禁

- `python3 -B -m unittest test_reality_probe_tools test_reality_clienthello_family test_dual_kernel_verification`
  → **162 PASS**（+9 新用例）
- `cargo check --workspace` → PASS
- `git diff --check` → clean
- secret scan：扫 `/tmp/mt_mixed_fresh_config.json` 实际敏感字段在
  modified diff/docs/evidence 中是否出现 → 0 leak

### 范围确认

- 没有 live probe；没有 node contact
- 没有动 sampler/dataplane
- 没有动 `go_fork_source/*` / `.github/workflows/*`
- 没有改 golden_spec；DEV-REALITY-01 已覆盖整条 REALITY live dataplane
- BHV 52/56 不变；Rust-only quality / planning，不写成 dual-kernel parity

---

## R76b — Confirmation gate semantics correction (2026-05-08)

### 触发

R76 authorization packet 把 R73 前的 fresh-intake gate 语义误带到了
R73 后的 confirmation cohort gate：cohort A 文案要求同一 neutral subset
同时 `fresh_ready=2` 和 `covered_existing=2`。但
`reality_vless_sample_intake.py` 的分类是互斥降级：ready 候选如果已经
存在于 rollup，就从 `fresh_ready` 降级为 `covered_existing`。

### 修正

R76b 只修 authorization packet gate 口径，不改变 R76 cohort recommendation。

- fresh-intake gate：R73 前使用，目标是找到未被 baseline/rollup 覆盖的新
  候选，要求 `fresh_ready>0`。
- confirmation gate：R73 后使用，目标是确认 selected neutral keys 已在
  rollup 中；neutralized subset intake 预期
  `covered_existing=selected_count`, `fresh_ready=0`, `duplicate=0`,
  `not_ready=0`。
- A divergence-carrier: `covered_existing=2`, `fresh_ready=0`,
  `duplicate=0`, `not_ready=0`。
- B same-failure: `covered_existing=4`, `fresh_ready=0`, `duplicate=0`,
  `not_ready=0`。
- C recovery-watch: `covered_existing=3`, `fresh_ready=0`, `duplicate=0`,
  `not_ready=0`。

文档只允许描述“使用本地 `/tmp` 映射生成 neutralized cohort subset”；
不提交、不渲染 raw tag/server/uuid/public_key/short_id/path/header/
server_name/password 映射。

### 范围确认

- 没有 live probe；没有 node contact
- 没有动 sampler/dataplane
- 没有动 `go_fork_source/*` / `.github/workflows/*`
- 默认下一步仍是 cohort A only 10 runs
- BHV 52/56 不变；authorization packet correction，不写成 parity 变化

---

## R77 — Cohort A divergence-carrier bounded live confirmation (2026-05-08)

### 授权范围

用户显式授权 **ONLY cohort A** live probe：

- outbounds: fresh02, fresh06
- runs_per_outbound: 5
- planned_total_runs: 10
- target: `example.com:80`
- scope: REALITY/VLESS only

禁止 cohort B/C、Hysteria2、WS/plain-VLESS，禁止超过 10 runs 自动扩展。

### Pre-gate

- HEAD at gate: `214eb67a`；`main` 与 `origin/main` 同步
- 使用本地 `/tmp` 映射生成 cohort-only neutralized subset，仅含
  fresh02/fresh06；raw material 未写入 git
- confirmation intake:
  `covered_existing=2`, `fresh_ready=0`, `duplicate=0`, `not_ready=0`
- dry-run plan:
  `selected_count=2`, `runs_per_outbound=5`, `planned_total_runs=10`,
  `target=example.com:80`
- golden_spec S1 仍为 52/56 BHV (92.9%)

### Live 结果

- executed_runs: 10 / 10
- status_counts: `{completed: 10}`
- run-level: `run_all_ok=10`, `run_divergence=0`,
  `run_same_failure=0`, `run_unknown=0`
- label_counts: `{all_ok: 10}`
- class_counts: `{ok: 90}`
- divergence_phase_label_count=0；unexpected phase labels=0

Per-outbound R73 → R77:

| outbound | R73 | R77 | 结论 |
| --- | --- | --- | --- |
| fresh02 | 1 run_divergence + 4 run_same_failure; phase labels app_minimal + app_pre_post | 5 run_all_ok | divergence 未重复；timeout same-failure 消失 |
| fresh06 | 1 run_all_ok + 1 run_divergence + 3 run_same_failure; phase labels app_minimal + bridge_io + minimal_transport | 5 run_all_ok | divergence 未重复；same-failure 消失 |

### 分类

**A — actionable; no new structural divergence.** R73 两个
divergence-carrier 在 R77 全部转为 5/5 `run_all_ok`；phase divergence
没有重复，但也没有出现 taxonomy 外的新 phase label。该结果属于
“resolved inside existing taxonomy”，不新增 S4，不写成 dual-kernel parity。

### Rollup delta

- total_rounds: 19 → 20
- total_executed_runs: 188 → 198
- total_all_ok_runs: 70 → 80
- latest_divergence_outbound_count: 2 → 0
- recovered_outbound_count: 3 → 5
- fresh02/fresh06 latest_health: `latest_all_ok`

### 产物

- `agents-only/mt_real_02_evidence/round77_cohort_a_divergence_confirmation_summary.json`
- `agents-only/mt_real_02_evidence/round77_cohort_a_divergence_confirmation_summary.md`
- `agents-only/mt_real_02_evidence/live_rollup.json`
- `agents-only/mt_real_02_evidence/live_rollup.md`
- `scripts/tools/test_reality_probe_tools.py`（R77 committed-evidence contract）
- `agents-only/active_context.md`（≤95 行）
- 本文件 R77 节

### 范围确认

- cohort B/C: 0 runs
- Hysteria2 live: 0 runs
- WS/plain-VLESS live: 0 runs
- 没有动 sampler/dataplane
- 没有动 `go_fork_source/*` / `.github/workflows/*`
- BHV 52/56 不变；Rust/live supporting evidence，不写成 parity completion

---

## R78 — Cohort B same-failure bounded live confirmation (2026-05-08)

### 授权范围

用户显式授权 **ONLY cohort B** live probe：

- outbounds: fresh03, fresh04, fresh05, fresh07
- runs_per_outbound: 3
- planned_total_runs: 12
- target: `example.com:80`
- scope: REALITY/VLESS only

禁止 cohort A/C、Hysteria2、WS/plain-VLESS，禁止超过 12 runs 自动扩展。

### Pre-gate

- HEAD at gate: `65cabe41`；`main` 与 `origin/main` 同步
- 使用本地 `/tmp` 映射生成 cohort-only neutralized subset，仅含
  fresh03/fresh04/fresh05/fresh07；raw material 未写入 git
- confirmation intake:
  `covered_existing=4`, `fresh_ready=0`, `duplicate=0`, `not_ready=0`
- dry-run plan:
  `selected_count=4`, `runs_per_outbound=3`, `planned_total_runs=12`,
  `target=example.com:80`
- golden_spec S1 仍为 52/56 BHV (92.9%)

### Live 结果

- executed_runs: 12 / 12
- status_counts: `{completed: 12}`
- run-level: `run_all_ok=8`, `run_divergence=1`,
  `run_same_failure=3`, `run_unknown=0`
- label_counts: `{all_ok:8, app_pre_post_diverged:1,
  probe_io_all_timeout:3, reality_all_timeout:3}`
- class_counts: `{ok:80, timeout:27, connection_reset:1}`
- divergence_phase_label_count=1；unexpected phase labels=0

Per-outbound R73 → R78:

| outbound | R73 | R78 | 结论 |
| --- | --- | --- | --- |
| fresh03 | 5/5 same-failure, other | 3/3 all_ok | resolved_to_all_ok |
| fresh04 | 5/5 same-failure, other | 3/3 same-failure, timeout | node/env-health limited; same-failure persists but class shifted |
| fresh05 | 5/5 same-failure, other | 2 all_ok + 1 run_divergence (`app_pre_post_diverged`) | known-taxonomy divergence; surface for cohort A-style re-evaluation |
| fresh07 | 5/5 same-failure, connection_reset | 3/3 all_ok | HK-like connection_reset same-type did not persist |

fresh07 R73 同 HK-A-BGP-2.0 R61-R63 的 connection_reset same-failure；
R78 为 3/3 all_ok，所以不再保持 HK 同型 connection_reset。

### 分类

**A — actionable; no new structural divergence; mixed cohort B outcome.**
fresh05 从 R73 same-failure 翻到 1 个已知 taxonomy 内
`app_pre_post_diverged` run + 2 个 all_ok run；按 R76 packet 规则不扩展
cohort B，应单独列入后续 cohort A-style re-evaluation。fresh04 仍按
node/env-health limited 处理；不能写成 sampler/dataplane regression。

### Rollup delta

- total_rounds: 20 → 21
- total_executed_runs: 198 → 210
- total_all_ok_runs: 80 → 88
- latest_divergence_outbound_count: 0 → 1 (`fresh05`)
- latest_same_failure_outbound_count: 10 → 7
- recovered_outbound_count: 5 → 7
- fresh03/fresh07 latest_health: `latest_all_ok`
- fresh04 latest_health: `latest_same_failure`
- fresh05 latest_health: `latest_divergence`

### 产物

- `agents-only/mt_real_02_evidence/round78_cohort_b_same_failure_confirmation_summary.json`
- `agents-only/mt_real_02_evidence/round78_cohort_b_same_failure_confirmation_summary.md`
- `agents-only/mt_real_02_evidence/live_rollup.json`
- `agents-only/mt_real_02_evidence/live_rollup.md`
- `scripts/tools/test_reality_probe_tools.py`（R78 committed-evidence contract）
- `agents-only/active_context.md`（≤95 行）
- 本文件 R78 节

### 范围确认

- cohort A/C: 0 runs
- Hysteria2 live: 0 runs
- WS/plain-VLESS live: 0 runs
- 没有动 sampler/dataplane
- 没有动 `go_fork_source/*` / `.github/workflows/*`
- BHV 52/56 不变；Rust/live supporting evidence，不写成 parity completion

---

## R79 — Fresh05 divergence-carrier bounded live recheck (2026-05-08)

### 授权范围

用户显式授权 **ONLY fresh05** live probe：

- outbound: fresh05
- runs_per_outbound: 5
- planned_total_runs: 5
- target: `example.com:80`
- scope: REALITY/VLESS only

禁止 fresh04 / cohort C / 其他 fresh 节点、Hysteria2、WS/plain-VLESS，
禁止超出 5 runs 自动扩展。

### Pre-gate

- HEAD at gate: `c178402e`；`main` 与 `origin/main` 同步
- 使用本地 `/tmp` 映射生成 fresh05-only neutralized subset；raw
  material 未写入 git
- recheck intake:
  `covered_existing=1`, `fresh_ready=0`, `duplicate=0`, `not_ready=0`
- dry-run plan:
  `selected_count=1`, `runs_per_outbound=5`, `planned_total_runs=5`,
  `target=example.com:80`
- golden_spec S1 仍为 52/56 BHV (92.9%)

### Live 结果

- executed_runs: 5 / 5
- status_counts: `{completed: 5}`
- run-level: `run_all_ok=5`, `run_divergence=0`,
  `run_same_failure=0`, `run_unknown=0`
- label_counts: `{all_ok:5}`
- class_counts: `{ok:45}`
- divergence_phase_label_count=0；unexpected phase labels=0

Per-round R73 → R78 → R79 (fresh05):

| round | run_health | labels / phase labels | state |
| --- | --- | --- | --- |
| R73 | ok=0, div=0, same_failure=5 | probe_io_all_other=5, reality_all_other=5 | same_failure |
| R78 | ok=2, div=1, same_failure=0 | all_ok=2, app_pre_post_diverged=1 | divergence |
| R79 | ok=5, div=0, same_failure=0 | all_ok=5 | all_ok |

R78 的 `app_pre_post_diverged` 在 R79 没有重复，same-failure(other) 也
没有回归，未出现 taxonomy 之外的 phase label。

### 分类

**A — actionable; no new structural divergence; fresh05 resolved to
all_ok.** R78 的已知 taxonomy `app_pre_post_diverged` 在 R79 5 次重测中
未复现，同时 R73 的 same-failure(other) 未回归；按现有规则归入
node/env-health churn 已落回 taxonomy 内，禁止写成
sampler/dataplane regression。

### Rollup delta

- total_rounds: 21 → 22
- total_executed_runs: 210 → 215
- total_all_ok_runs: 88 → 93
- latest_divergence_outbound_count: 1 → 0
- latest_same_failure_outbound_count: 7 → 7
- recovered_outbound_count: 7 → 8
- fresh05 latest_round: 78 → 79
- fresh05 latest_health: `latest_divergence` → `latest_all_ok`

### 产物

- `agents-only/mt_real_02_evidence/round79_fresh05_divergence_recheck_summary.json`
- `agents-only/mt_real_02_evidence/round79_fresh05_divergence_recheck_summary.md`
- `agents-only/mt_real_02_evidence/live_rollup.json`
- `agents-only/mt_real_02_evidence/live_rollup.md`
- `scripts/tools/test_reality_probe_tools.py`（R79 committed-evidence contract）
- `agents-only/active_context.md`（≤95 行）
- 本文件 R79 节

### 范围确认

- fresh04 / cohort C / 其他 fresh 节点: 0 runs
- Hysteria2 live: 0 runs
- WS/plain-VLESS live: 0 runs
- 没有动 sampler/dataplane
- 没有动 `go_fork_source/*` / `.github/workflows/*`
- BHV 52/56 不变；Rust/live supporting evidence，不写成 parity completion

---

## R80 — Fresh04 same-failure bounded live recheck (2026-05-08)

### 授权范围

用户显式授权 **ONLY fresh04** live probe：

- outbound: fresh04
- runs_per_outbound: 3
- planned_total_runs: 3
- target: `example.com:80`
- scope: REALITY/VLESS only

禁止 fresh05 / cohort C / 其他 fresh 节点、Hysteria2、WS/plain-VLESS，
禁止超出 3 runs 自动扩展。

### Pre-gate

- HEAD at gate: `ef26f1cf`；`main` 与 `origin/main` 同步
- 使用本地 `/tmp` 映射生成 fresh04-only neutralized subset；raw
  material 未写入 git
- recheck intake:
  `covered_existing=1`, `fresh_ready=0`, `duplicate=0`, `not_ready=0`
- dry-run plan:
  `selected_count=1`, `runs_per_outbound=3`, `planned_total_runs=3`,
  `target=example.com:80`
- golden_spec S1 仍为 52/56 BHV (92.9%)
- **Pre-gate gap**：counts (intake + dry-run) 全部通过，但 dry-run 不
  在 rust app 进程内载入 subset config，所以 schema 不匹配只在 live
  matrix 执行时暴露。

### Live 结果

- executed_runs: 3 / 3
- status_counts: `{matrix_error: 3}`
- run-level: `run_all_ok=0`, `run_divergence=0`,
  `run_same_failure=0`, `run_unknown=3`
- label_counts: `{}`（matrix_error 无 labels）
- class_counts: `{}`
- divergence_phase_label_count=0；unexpected phase labels=0

### Tooling blocker（C 分类核心）

- **Blocker**：rust app 配置校验在全部 3 次 run 中失败，matrix 脚本
  返回 exit 1。
- **Root cause**：fresh04 subset 沿用了
  `/tmp/mt_mixed_fresh_subset_reality_neutral.json` 中的
  `__id_in_gui` 字段；rust app 的配置 schema 拒绝该字段，报
  `unknown field at /outbounds/0/__id_in_gui`。
- **Matrix 状态**：所有 3 次 run 均 `matrix_status=1`。
- **Fix recommendation**：fresh REALITY/VLESS subset 提取必须在 live
  之前剥离 GUI-only 字段（`__id_in_gui` 及任何非 rust schema 字段）；
  pre-gate dry-run 不会捕获该问题，因为 dry-run 不会在 rust app 进程
  里载入配置。
- **Follow-up**：未来 fresh-cohort live 应通过清洗助手或对 subset 的
  键集做白名单校验，再执行 live。

### Phase probe supporting evidence

matrix 脚本里的 phase probe 在全部 3 次尝试都跑完，并产生 4 个 phase
（`direct_reality`/`transport_reality`/`vless_dial`/`vless_probe_io`）
全部 `timeout` 类的一致输出。这是 fresh04 网络可达性仍然超时的辅助
证据，性质上与 R78 same-failure(timeout) 一致；但因为 matrix 层 app
probe 与 compare 没有跑，per-run `run_health` 仍然是 `run_unknown`，
不能视为 same-failure 在 matrix 层的正式复核。

| run | direct_reality | transport_reality | vless_dial | vless_probe_io |
| ---: | --- | --- | --- | --- |
| 1 | timeout | timeout | timeout | timeout |
| 2 | timeout | timeout | timeout | timeout |
| 3 | timeout | timeout | timeout | timeout |

### Per-round R73 → R78 → R80 (fresh04)

| round | run_health | labels / phase labels | state |
| --- | --- | --- | --- |
| R73 | ok=0, div=0, same_failure=5 | probe_io_all_other=5, reality_all_other=5 | same_failure (other) |
| R78 | ok=0, div=0, same_failure=3 | probe_io_all_timeout=3, reality_all_timeout=3 | same_failure (timeout) |
| R80 | ok=0, div=0, same_failure=0, unknown=3 | (matrix_error: 无 labels) | matrix_error / run_unknown |

R80 没有从 matrix 层正式复核 fresh04 的 same-failure；phase probe 的
3/3 timeout 与 R78 timeout 在 class 上一致，但仅作辅助证据。

### 分类

**C — tooling/config blocker; fresh04 same-failure recheck not
formally re-confirmed at matrix level.** 3 次 fresh04 matrix run 全部
返回 matrix_error，原因是 rust app 配置校验拒绝了 subset 里的
`__id_in_gui` 字段。phase probe 数据（3/3 timeout）与 R78
same-failure(timeout) 在网络层一致，但不能作为 matrix 层 same-failure
复核的权威结论。不写成 sampler/dataplane regression；不在本轮自动
追加 run；如需正式复核 fresh04 same-failure，需另起一轮独立授权，并
使用清洗后的 subset。

### Rollup delta

- total_rounds: 22 → 23
- total_executed_runs: 215 → 218
- total_all_ok_runs: 88 (R78) / 93 (R79) → 93 (R80 无 all_ok)
- latest_divergence_outbound_count: 0 → 0
- latest_same_failure_outbound_count: 7 → 6（fresh04 离开
  same_failure，进入 unknown）
- latest_stable_same_failure_outbound_count: 7 → 6
- recovered_outbound_count: 8 → 8（fresh04 不是 recovered，是
  unknown）
- fresh04 latest_round: 78 → 80
- fresh04 latest_health: `latest_same_failure` → `latest_unknown`
- fresh04 latest_status_counts: `{completed:3}` →
  `{matrix_error:3}`
- fresh04 latest_run_health_counts: `{run_same_failure:3}` →
  `{run_unknown:3}`

### 产物

- `agents-only/mt_real_02_evidence/round80_fresh04_same_failure_recheck_summary.json`
- `agents-only/mt_real_02_evidence/round80_fresh04_same_failure_recheck_summary.md`
- `agents-only/mt_real_02_evidence/live_rollup.json`
- `agents-only/mt_real_02_evidence/live_rollup.md`
- `scripts/tools/test_reality_probe_tools.py`（R80 committed-evidence
  contract）
- `agents-only/active_context.md`（≤95 行）
- 本文件 R80 节

### 范围确认

- fresh05 / cohort C / 其他 fresh 节点: 0 runs
- Hysteria2 live: 0 runs
- WS/plain-VLESS live: 0 runs
- 没有动 sampler/dataplane
- 没有动 `go_fork_source/*` / `.github/workflows/*`
- BHV 52/56 不变；Rust/live supporting evidence，不写成 parity completion

## R81 — Subset-schema pre-gate hardening (no-live, tooling)

### 起因

R80 暴露了一条 C-class tooling/config 路径：fresh04 subset 残留 GUI-only
字段 `__id_in_gui`，rust app 配置校验在 live matrix 时 3/3 拒掉
（unknown field at /outbounds/0/__id_in_gui）；pre-gate dry-run
counts 全过，但 dry-run 不在 rust app 进程内 load subset，所以 schema
mismatch 只在 live 时炸。R76 plan-C 已经预言过这条路径。

任何 fresh-cohort live（fresh04 重测、cohort C round-2、R73 6 个未选
recovery 节点）在这条路径关掉前都背着同一种结构性风险，所以 R81
作为纯 tooling 修复优先于 fresh04 重测。

### 范围

- 无 live、无 node 联系、不动 sampler/dataplane
- 不动 `go_fork_source/*`、不动 `.github/workflows/*`
- BHV 52/56 不变；不写成 parity completion
- 不授权任何 live；fresh04 重测仍待另起一轮（建议 R82）

### 改动

- 新增 `scripts/tools/reality_vless_subset_schema_gate.py`
  - `validate_subset_schema(subset_path, *, allowed_outbound_fields,
    rejected_field_prefixes)` 返回 `{ok, violations, stats}`
  - 两条独立分支（reason 字符串区分）：
    - 前缀分支：outbound-level 任何 `__` 前缀字段（GUI-only）
    - 白名单分支：outbound-level 不在 reality/vless allow-list 的字段
  - 嵌套层只跑前缀分支（不强制嵌套白名单；rust loader 嵌套 schema 太大）
  - 违规输出只携带 `path` + `field` + `reason`，从不读取/泄漏 value
  - allow-list 来源：`crates/sb-config/src/outbound/raw.rs::RawVlessConfig`
    + `crates/sb-config/src/compat.rs` 别名（`tag↔name`、`server_port↔port`）
  - allow-list 严格 reality/vless 范围，不是协议联合
- 在 `scripts/tools/reality_vless_probe_batch.py` 的 dry-run 路径前置
  此 gate
  - dry-run 时 plan/summary/stdout 加 `subset_schema_gate_passed`
    + `subset_schema_gate` 字段
  - gate 失败时 plan/summary 仍写出（带 violations），exit 2
  - live 路径完全不动；live shape 不带 gate 字段（向后兼容）

### 兼容审计

- `reality_vless_confirmation_cohorts.py`：消费 round_summary，不消费
  probe_batch dry-run shape；无破坏。
- `reality_vless_probe_plan.py` / `reality_vless_probe_evidence.py`：
  `dict.get` 已有字段；新字段是纯叠加；无破坏。

### 测试

- 三模块 unittest baseline：176 PASS
- R81 新增 14 用例（11 即时 + 3 committed-evidence contract）
- R81 后实测：**190 PASS**
- 分支覆盖：前缀 vs 白名单两分支独立 pin、嵌套前缀、清洁通过、redaction、
  dry-run 失败/通过、live 路径不变、allow-list 范围、非对象根、非-vless
  outbound、committed-evidence 三项契约

### 安全/redaction

- 提交文件中无 raw uuid/public_key/short_id/password/tag/server/server_name
- 测试 fixture 全部使用合成 redacted 值（如 `redacted-uuid`、
  `redacted.example.invalid`）
- secret 扫描覆盖所有 modified+new 文件，0 命中

### 分类

**A — actionable; tooling hardening; no live; no node contact.**

R81 把 R76 plan-C 预言、R80 操作上确认的结构性 pre-gate gap 关掉。
未来任何 fresh-cohort live 在 dry-run 阶段就能拒绝带残留 GUI-only
字段的 subset。BHV 52/56 不变；不是 sampler/dataplane regression；
不是 dual-kernel parity completion。

### Rollup delta

R81 不改 live 数据，不改 rollup：

- total_rounds、total_executed_runs、total_all_ok_runs：与 R80 一致
- 无 fresh\_\* outbound 状态变化
- BHV 52/56 不变

### 产物

- `scripts/tools/reality_vless_subset_schema_gate.py`（新增）
- `scripts/tools/reality_vless_probe_batch.py`（dry-run 路径加 gate；
  live 路径不动）
- `scripts/tools/test_reality_probe_tools.py`（R81 类 + 三项 committed-
  evidence 契约）
- `agents-only/mt_real_02_evidence/round81_subset_schema_gate_summary.json`
- `agents-only/mt_real_02_evidence/round81_subset_schema_gate_summary.md`
- `agents-only/active_context.md`（≤95 行）
- 本文件 R81 节

### Follow-up

- fresh04 重测仍 pending；R81 不授权任何 live。
- 建议 R82：fresh04 same-failure recheck 用清洗后的 subset（fresh04
  only / REALITY/VLESS only / ×3 / no auto-extend），需用户显式再次
  授权。

### 范围确认

- live runs in R81: 0
- node contact in R81: 0
- sampler / dataplane changes: 0
- `go_fork_source/*` / `.github/workflows/*` 改动: 0
- BHV 52/56 不变；Rust-only quality / tooling，不写成 parity completion

## R82 — fresh04 same-failure live recheck with cleansed subset

### 起因

R81 在 dry-run 阶段把 R80 暴露的 `__id_in_gui` schema-mismatch 路径关掉
之后，fresh04 的 matrix-level same-failure 复核第一次有了真正可行
路径。fresh04 仍是 fresh REALITY 面唯一 `latest_unknown` 的样本。
R82 用清洗后的 subset 一次性把 fresh04 ×3 跑完。

### 范围

- live REALITY/VLESS、fresh04 only ×3 = 3 runs、target example.com:80
- HEAD at gate: d6fd23a2；main 与 origin/main 同步 ✓
- 不动 sampler/dataplane / `go_fork_source/*` / `.github/workflows/*`
  / golden_spec
- BHV 52/56 不变；不写成 dual-kernel parity completion
- 不允许 auto-extend > 3；不允许本轮 retry "修补" 失败 run

### Subset 清洗（一次过 R81 两条分支）

- (a) `__`-prefixed 字段任意深度移除：`__id_in_gui` 已剥（R80 直接踩到的路径）
- (b) outbound-level 字段全部落在 reality/vless allow-list 内
- 清洗后的 `subset_schema_gate.violations==[]`，即 R81 gate 两条分支
  都通过

### Pre-gate 全部通过

- intake_counts: `covered_existing=1, fresh_ready=0, duplicate=0,
  not_ready=0`
- dry-run: `selected_count=1, runs_per_outbound=3,
  planned_total_runs=3, target=example.com:80,
  subset_schema_gate_passed=true, subset_schema_gate.violations=[]`
- BHV: 52/56 不变

### 实测分类: A.1

- 3/3 status=`completed`
- 3/3 same-failure，`same_failure_class=timeout`
- label_counts: `probe_io_all_timeout=3, reality_all_timeout=3`
- class_counts: `timeout=27`（9 类 × 3 runs，全部 timeout）
- divergence_phase_label_count=0；不存在 four-element taxonomy 之外
  的新 phase label

### 闭环计数（按 prompt v2 修订）

- R73 = same_failure(**other**)：other-class round 1（不属于 timeout class）
- R78 = same_failure(**timeout**)：timeout-class **round 1**（class
  从 R73 翻 timeout，不是 R73 的 longer-repeat 延续）
- R80 = matrix_error：**不计入** closure counting
- R82 = same_failure(**timeout**)：timeout-class **round 2 of 3**
- class_history: `['other', 'timeout', null, 'timeout']`
- fresh04 cohort-B 单 outbound 闭环还差 1 轮（建议 R83），R82 **不是**
  cohort-B 单 outbound 闭环完成

### Phase probe supporting evidence

3/3 runs 在 direct_reality / transport_reality / vless_dial /
vless_probe_io 四级全部 timeout class。与 matrix-level
same-failure(timeout) 一致；matrix-level 结果是权威的。

### Rollup delta

- total_rounds: 23 → **24**
- total_executed_runs: 218 → **221**
- total_all_ok_runs: 93 → **93**（R82 无 all_ok）
- latest_same_failure_outbound_count: 6 → **7**（fresh04 重新进入
  same_failure；之前 R80 临时落到 unknown）
- latest_stable_same_failure_outbound_count: 6 → **7**
- latest_divergence_outbound_count: 0 → **0**
- recovered_outbound_count: 8 → **8**
- fresh04 latest_round: 80 → **82**
- fresh04 latest_health: `latest_unknown` → **`latest_same_failure`**
- fresh04 latest_status_counts: `{matrix_error:3}` →
  `{completed:3}`
- fresh04 latest_run_health_counts: `{run_unknown:3}` →
  `{run_same_failure:3}`

### 产物

- `agents-only/mt_real_02_evidence/round82_fresh04_recheck_summary.json`
- `agents-only/mt_real_02_evidence/round82_fresh04_recheck_summary.md`
- `agents-only/mt_real_02_evidence/live_rollup.json`（24 rounds 重新生成）
- `agents-only/mt_real_02_evidence/live_rollup.md`
- `scripts/tools/test_reality_probe_tools.py`（R82 committed-evidence
  contract）
- `agents-only/active_context.md`（≤95 行）
- 本文件 R82 节

### Follow-up

- 建议 R83：fresh04 timeout-class round 3 of 3 with cleansed subset，
  完成 cohort-B 单 outbound 闭环叙事。需要用户显式再次授权。
- 不要在本轮 evidence / 文档里把 R82 写成 "cohort B 闭环完成"。

### 范围确认

- live runs in R82: 3（fresh04 only）
- node contact in R82: 1（fresh04）
- fresh05 / cohort C / 其他 fresh / Hys2 / WS / plain-VLESS live: 0
- sampler / dataplane changes: 0
- `go_fork_source/*` / `.github/workflows/*` 改动: 0
- BHV 52/56 不变；Rust/live evidence，不写成 parity completion

## R83 — fresh04 timeout-class round 3 of 3 longer-repeat (cohort-B closure attempt; closure NOT achieved)

### 起因

R82 把 fresh04 timeout-class same-failure 钉到 round 2 of 3，R83 是
顺成的 cohort-B 单 outbound closure attempt：跑同尺寸 ×3，看
timeout-class 链条是否能延到 round 3。

### 范围

- live REALITY/VLESS、fresh04 only ×3 = 3 runs、target example.com:80
- HEAD at gate: 8b0ab0c2；main 与 origin/main 同步 ✓
- 不动 sampler/dataplane / `go_fork_source/*` / `.github/workflows/*`
  / golden_spec
- BHV 52/56 不变
- 不允许 auto-extend > 3；不允许本轮 retry "修补" 失败 run

### Subset 清洗 + Pre-gate

- 与 R82 同 recipe：`__id_in_gui` 等 `__`-prefixed 字段任意深度剥除；
  outbound-level 字段全部落在 reality/vless allow-list
- intake_counts: `covered_existing=1, fresh_ready=0, duplicate=0,
  not_ready=0` ✓
- dry-run: `selected_count=1, runs_per_outbound=3, planned_total_runs=3,
  target=example.com:80, subset_schema_gate_passed=true,
  subset_schema_gate.violations=[]` ✓
- BHV: 52/56 不变

### 实测分类: B（mixed）

- 3/3 status=`completed`
- 1 run_divergence (run 1: `app_minimal_diverged`) + 2 run_same_failure
  (runs 2/3: timeout)
- label_counts: `app_minimal_diverged=1, probe_io_all_timeout=3,
  reality_all_timeout=3`
- class_counts: `connection_reset=1, timeout=26`
- divergence_phase_label_count=1，divergence_phase_label_breakdown
  `{app_minimal_diverged: 1}`
- run 1 根因：`minimal.vless_dial=connection_reset` 而其余 8 类全部
  timeout，app/minimal 在 vless_dial 层不对称 → 触发
  `app_minimal_diverged`
- runs 2/3 没有复现这种不对称
- 标签全部在四元 taxonomy 之内：no new structural divergence

### Closure verdict（关键）

- timeout-class consecutive rounds: **2**（R78 round 1 + R82 round 2）
- timeout-class consecutive round ids: `[78, 82]`
- chain broken at: **R83**
- chain broken reason: R83 = 1 run_divergence + 2 run_same_failure(timeout)
  ≠ 3/3 same_failure(timeout)；timeout-class longer-repeat 链停在
  round 2，不延到 round 3
- **`cohort_b_single_outbound_closure_achieved=false`**
- closure scope: fresh04 single-outbound + timeout class（不扩张到
  cohort B 整组；不影响 6 个历史 stable same-failure 的既有闭环）

### fresh04 R73 -> R78 -> R80 -> R82 -> R83

| round | run_health | labels | state | same_failure_class |
| --- | --- | --- | --- | --- |
| R73 | ok=0 div=0 sf=5 | probe_io_all_other=5, reality_all_other=5 | same_failure | other |
| R78 | ok=0 div=0 sf=3 | probe_io_all_timeout=3, reality_all_timeout=3 | same_failure | timeout |
| R80 | ok=0 div=0 sf=0 unk=3 | (matrix_error: no labels) | matrix_error | n/a |
| R82 | ok=0 div=0 sf=3 | probe_io_all_timeout=3, reality_all_timeout=3 | same_failure | timeout |
| R83 | ok=0 **div=1** sf=2 | app_minimal_diverged=1, probe_io_all_timeout=3, reality_all_timeout=3 | **mixed** | n/a (mixed) |

`class_history`: `[other, timeout, null, timeout, null]`

### 后续叙事

- fresh04 saga 从稳定 cohort-B same_failure 候选翻成
  cohort-A-style re-evaluation 候选。后续若再次授权 fresh04，按
  divergence-carrier 语义处理（R76 cohort A），不当作 same_failure
  carrier。
- closure 不成立；不要在任何 evidence/文档里把 R83 写成 cohort-B
  闭环完成。

### Rollup delta

- total_rounds: 24 → **25**
- total_executed_runs: 221 → **224**
- total_all_ok_runs: 93 → **93**（R83 无 all_ok）
- latest_same_failure_outbound_count: 7 → **6**（fresh04 离开
  same_failure 列表，进 divergence/mixed）
- latest_stable_same_failure_outbound_count: 7 → **6**
- latest_divergence_outbound_count: 0 → **1**
  （`latest_divergence_outbounds=['fresh04']`）
- latest_mixed_run_health_outbound_count: 0 → **1**
  （`latest_mixed_run_health_outbounds=['fresh04']`）
- recovered_outbound_count: 8 → **8**
- fresh04 latest_round: 82 → **83**
- fresh04 latest_health: `latest_same_failure` → **`latest_divergence`**
- fresh04 latest_run_health_counts:
  `{run_same_failure:3}` → `{run_divergence:1, run_same_failure:2}`

### 产物

- `agents-only/mt_real_02_evidence/round83_fresh04_recheck_summary.json`
- `agents-only/mt_real_02_evidence/round83_fresh04_recheck_summary.md`
- `agents-only/mt_real_02_evidence/live_rollup.json`（25 rounds 重新生成）
- `agents-only/mt_real_02_evidence/live_rollup.md`
- `scripts/tools/test_reality_probe_tools.py`（R83 committed-evidence
  contract）
- `agents-only/active_context.md`（≤95 行；显式记 closure NOT achieved）
- 本文件 R83 节

### Follow-up

- 不再追加 fresh04 round（B 分支禁扩展）。
- 后续若用户授权 fresh04 再起，应按 divergence-carrier 语义另起一轮
  独立 cohort A-style 评估，不延续 cohort-B 闭环叙事。
- cohort C round-2（fresh01/09/15 ×3）与 6 节点 round-2 仍是独立线，
  不受 R83 影响。

### 范围确认

- live runs in R83: 3（fresh04 only）
- node contact in R83: 1（fresh04）
- fresh05 / cohort C / 其他 fresh / Hys2 / WS / plain-VLESS live: 0
- sampler / dataplane changes: 0
- `go_fork_source/*` / `.github/workflows/*` 改动: 0
- BHV 52/56 不变；Rust/live evidence，不写成 parity completion；
  closure 不成立，scope 限 fresh04 单 outbound + timeout class

## R84 — fresh04 cohort-A-style divergence-carrier re-evaluation (5-run depth)

### 起因

R83 把 fresh04 从 stable cohort-B same_failure 候选翻成
cohort-A-style 候选（1 run_divergence: app_minimal_diverged
+ 2 run_same_failure(timeout)）。R84 是 R76 cohort-A-style
深度（×5）re-evaluation：测 R83 的 phase divergence 是单次
偶发还是稳定 phase divergence carrier。

### 范围

- live REALITY/VLESS、fresh04 only ×5 = 5 runs、target
  example.com:80
- HEAD at gate: ae54c501；main 与 origin/main 同步 ✓
- 不动 sampler/dataplane / `go_fork_source/*` /
  `.github/workflows/*` / golden_spec
- BHV 52/56 不变
- 不允许 auto-extend > 5；不允许本轮 retry "修补" 失败 run
- **R84 不是 closure attempt round；closure_status.evaluated=false**

### Subset 清洗 + Pre-gate

- 与 R82/R83 同 recipe；R81 gate 双分支都过
- intake_counts: `covered_existing=1, fresh_ready=0,
  duplicate=0, not_ready=0` ✓
- dry-run: `selected_count=1, runs_per_outbound=5,
  planned_total_runs=5, target=example.com:80,
  subset_schema_gate_passed=true, subset_schema_gate.violations=[]` ✓
- BHV: 52/56 不变

### 实测分类: A.same_failure_only (class=timeout)

- 5/5 status=`completed`
- 5/5 run_same_failure
- label_counts: `probe_io_all_timeout=5, reality_all_timeout=5`
- class_counts: `timeout=45`（9 类 × 5 runs，全 timeout）
- divergence_phase_label_count=**0**
- **R83 的 `app_minimal_diverged` 没有复现** —— 在 5-run
  深度上 cohort-A-style stable phase divergence carrier
  假设 **被证伪**

### Cohort-A-style assessment

| 字段 | 值 |
| --- | --- |
| verdict | A.same_failure_only |
| stable_phase_divergence_observed | false |
| r83_app_minimal_diverged_reproduced | false |

R83 的 phase divergence event 应读作 single transient event，
不是 fresh04 的结构性 carrier 行为。fresh04 回到看起来像
timeout-class same_failure 候选；只是 R83 mixed round 留在
历史里。

### Closure verdict（关键，不同于 R82/R83）

R84 **不**是 closure attempt round。closure_status 字段：

| 字段 | 值 |
| --- | --- |
| evaluated | **false** |
| reason | fresh04 reclassified to cohort-A-style at R83; closure semantics apply only to cohort-B single-outbound + single-class consecutive 3-round longer-repeat |
| scope | fresh04 cohort-A-style re-evaluation |
| broken_chain_can_restart_only_in_new_round | true |
| broken_chain_round | 83 |
| this_round_extends_broken_chain | **false** |

R78+R82 的 timeout-class chain（被 R83 断掉）**不能**与 R84
拼接重组成 3 连续。如果未来想做 fresh04 cohort-B closure，
需要从 R84 = round 1 of fresh sequence 起算，再加两轮独立
授权。R78 和 R82 不计入这个新序列。

### fresh04 R73 -> R78 -> R80 -> R82 -> R83 -> R84

| round | run_health | labels | state | sf_class |
| --- | --- | --- | --- | --- |
| R73 | sf=5 | probe_io_all_other×5, reality_all_other×5 | same_failure | other |
| R78 | sf=3 | probe_io_all_timeout×3, reality_all_timeout×3 | same_failure | timeout |
| R80 | unk=3 | (matrix_error) | matrix_error | n/a |
| R82 | sf=3 | probe_io_all_timeout×3, reality_all_timeout×3 | same_failure | timeout |
| R83 | div=1 sf=2 | app_minimal_diverged×1, probe_io_all_timeout×3, reality_all_timeout×3 | mixed | n/a |
| **R84** | **sf=5** | **probe_io_all_timeout×5, reality_all_timeout×5** | **same_failure** | **timeout** |

`class_history`: `[other, timeout, null, timeout, null, timeout]`

### Rollup delta

- total_rounds: 25 → **26**
- total_executed_runs: 224 → **229**
- total_all_ok_runs: 93 → **93**
- latest_same_failure_outbound_count: 6 → **7**（fresh04
  从 latest_divergence 翻回 latest_same_failure）
- latest_stable_same_failure_outbound_count: 6 → **7**
- latest_divergence_outbound_count: 1 → **0**（fresh04
  离开 divergence 列表）
- latest_mixed_run_health_outbound_count: 1 → **0**
- recovered_outbound_count: 8 → **8**
- fresh04 latest_round: 83 → **84**
- fresh04 latest_health: `latest_divergence` →
  **`latest_same_failure`**
- fresh04 latest_run_health_counts:
  `{run_divergence:1, run_same_failure:2}` →
  `{run_same_failure:5}`

### 后续叙事

- R83 phase divergence 被证伪为 single transient event，
  fresh04 的稳定面回归 cohort-B same_failure（timeout class）
  形态；但 R83 的 mixed round 在历史里永远不消失，
  closure chain 也无法跨 R83 拼接
- 不再追加 fresh04 round（A.same_failure_only 分支不扩展）
- 后续路线：
  - cohort C round-2（fresh01/09/15 ×3）
  - 6 个 R73 未选 recovery 节点 round-2
  - 或：用户授权后另起 fresh04 cohort-B closure 新序列
    （R84 round 1 + 两轮独立授权）

### 产物

- `agents-only/mt_real_02_evidence/round84_fresh04_recheck_summary.json`
- `agents-only/mt_real_02_evidence/round84_fresh04_recheck_summary.md`
- `agents-only/mt_real_02_evidence/live_rollup.json`（26 rounds 重新生成）
- `agents-only/mt_real_02_evidence/live_rollup.md`
- `scripts/tools/test_reality_probe_tools.py`（R84
  committed-evidence contract）
- `agents-only/active_context.md`（≤95 行）
- 本文件 R84 节

### Follow-up

- 不再追加 fresh04 round。
- cohort C round-2（fresh01/09/15 ×3 = 9）与 6 节点 round-2
  仍是独立线，是自然下一步候选。
- 用户若希望另起 fresh04 cohort-B closure 新序列，需独立
  授权且明确以 R84 为 round 1 of fresh sequence。

### 范围确认

- live runs in R84: 5（fresh04 only）
- node contact in R84: 1（fresh04）
- fresh05 / cohort C / 其他 fresh / Hys2 / WS / plain-VLESS live: 0
- sampler / dataplane changes: 0
- `go_fork_source/*` / `.github/workflows/*` 改动: 0
- BHV 52/56 不变；Rust/live evidence，不写成 parity completion；
  R84 evidence 不出现 "closure achieved" / "closure NOT achieved"
  任何措辞（closure_status.evaluated=false）

## R85 — cohort C recovery-watch round 2 of 3

### 起因

R84 后 fresh04 的 high-variance saga 已经足够说明继续追
fresh04 的边际信息价值偏低。R85 回到 R76 plan 原路径：
cohort C recovery-watch 三个代表（fresh01 / fresh09 / fresh15）
做 round 2 of 3。

### 范围

- live REALITY/VLESS、fresh01/fresh09/fresh15 ×3 = 9 runs、
  target example.com:80
- HEAD at gate: 2e0433ca；main 与 origin/main 同步 ✓
- 不动 sampler/dataplane / `go_fork_source/*` /
  `.github/workflows/*` / golden_spec
- BHV 52/56 不变
- 不允许 auto-extend > 3 runs/rep；不允许本轮 retry
  "修补" 失败 run；不允许临场 rotate 失败 rep

### Subset 清洗 + Pre-gate

- R81 gate 双分支都过：任意深度移除 `__` 字段，
  outbound-level 字段落在 REALITY/VLESS allow-list 内
- intake_counts: `covered_existing=3, fresh_ready=0,
  duplicate=0, not_ready=0` ✓
- dry-run: `selected_count=3, runs_per_outbound=3,
  planned_total_runs=9, target=example.com:80,
  subset_schema_gate_passed=true, subset_schema_gate.violations=[]` ✓
- BHV: 52/56 不变

### 实测分类: B.partial_per_rep

- 9/9 status=`completed`，9/9 `matrix_status=0`
- run_health_counts:
  `{run_all_ok=6, run_divergence=0, run_same_failure=3, run_unknown=0}`
- label_counts:
  `{all_ok=6, probe_io_all_timeout=3, reality_all_timeout=3}`
- class_counts: `{ok=54, timeout=27}`
- divergence_phase_label_count=**0**
- unexpected_phase_labels=[]；没有 NEW phase label

### Cohort C recovery status

| rep | R73 | R85 | recovery_consecutive_rounds | latest_state |
| --- | --- | --- | ---: | --- |
| fresh01 | 5/5 all_ok | 3/3 all_ok | 2 | all_ok |
| fresh09 | 5/5 all_ok | 3/3 timeout same_failure | 0 | same_failure |
| fresh15 | 5/5 all_ok | 3/3 all_ok | 2 | all_ok |

R85 **不是** recovery closure。cohort C recovery closure 仍要求
完整 3 轮 consecutive all_ok；fresh01/fresh15 只是 round 2
banked。fresh09 在 R85 被 timeout same_failure 打断，recovery
连续 all_ok 计数 reset 为 0。

### R73 -> R85 transition

| rep | round | state | labels | sf_class |
| --- | --- | --- | --- | --- |
| fresh01 | R73 | all_ok | all_ok×5 | n/a |
| fresh01 | R85 | all_ok | all_ok×3 | n/a |
| fresh09 | R73 | all_ok | all_ok×5 | n/a |
| fresh09 | R85 | same_failure | probe_io_all_timeout×3, reality_all_timeout×3 | timeout |
| fresh15 | R73 | all_ok | all_ok×5 | n/a |
| fresh15 | R85 | all_ok | all_ok×3 | n/a |

### Rollup delta

- total_rounds: 26 → **27**
- total_executed_runs: 229 → **238**
- total_all_ok_runs: 93 → **99**
- latest_same_failure_outbound_count: 7 → **8**（fresh09
  进入 latest_same_failure）
- latest_stable_same_failure_outbound_count: 7 → **8**
- latest_non_all_ok_outbound_count: 7 → **8**
- fresh01 latest_round: 73 → **85**；latest_health 仍
  `latest_all_ok`
- fresh09 latest_round: 73 → **85**；latest_health:
  `latest_all_ok` → **`latest_same_failure`**
- fresh15 latest_round: 73 → **85**；latest_health 仍
  `latest_all_ok`

### 后续叙事

- R85 落 `B.partial_per_rep`，不是 cohort C closure
- fresh01/fresh15 可在未来授权 round 3 closure attempt
  里继续；fresh09 需要先做 rotation/retry 策略选择
- 推荐下一步不是简单 R86 all-three closure，而是对 fresh09
  做 rotation 决策：从 R73 round-1-only recovery pool
  替换，或单独重测 fresh09 判断 timeout 是否偶发
- 不在 R85 内执行 rotation，不追加 run

### 产物

- `agents-only/mt_real_02_evidence/round85_cohort_c_round2_summary.json`
- `agents-only/mt_real_02_evidence/round85_cohort_c_round2_summary.md`
- `agents-only/mt_real_02_evidence/live_rollup.json`（27 rounds 重新生成）
- `agents-only/mt_real_02_evidence/live_rollup.md`
- `scripts/tools/test_reality_probe_tools.py`（R85
  committed-evidence contract，4 tests）
- `agents-only/active_context.md`（≤95 行）
- 本文件 R85 节

### 范围确认

- live runs in R85: 9（fresh01/fresh09/fresh15 only）
- node contact in R85: 3 reps
- fresh04 / fresh02/03/05/06/07/08/10/11/12/13/14 /
  Hys2 / WS / plain-VLESS live: 0
- sampler / dataplane changes: 0
- `go_fork_source/*` / `.github/workflows/*` 改动: 0
- BHV 52/56 不变；Rust/live evidence，不写成 parity completion；
  R85 evidence 不带 `closure_achieved` 字段，不写 recovery
  closure achieved

## R86 — cohort C rotation-bank round

### 起因

R85 把 cohort C 三代表拆成两条状态：fresh01/fresh15
连续 all_ok 到 round 2，fresh09 在 R85 3/3 timeout
same_failure 断链 reset。R86 因此不是 fresh01/fresh09/fresh15
all-three closure attempt，而是 rotation-bank：保留 clean reps
做 round 3 per-rep closure attempt，同时从 R73 round-1-only
recovery pool 里用 fresh10 替换 fresh09。

### 范围

- live REALITY/VLESS、fresh01/fresh15/fresh10 ×3 = 9 runs、
  target example.com:80
- HEAD at gate: 370e26ed；main 与 origin/main 同步 ✓
- 不跑 fresh09 / fresh04 / fresh08/fresh11/fresh12/fresh13/fresh14 /
  Hys2 / WS / plain-VLESS
- 不动 sampler/dataplane / `go_fork_source/*` /
  `.github/workflows/*` / golden_spec
- BHV 52/56 不变
- 不允许 auto-extend；不允许 retry 修补；不允许现场 rotate

### Subset 清洗 + Pre-gate

- R81 gate 双分支都过：任意深度移除 `__` 字段，
  outbound-level 字段落在 REALITY/VLESS allow-list 内
- intake_counts: `covered_existing=3, fresh_ready=0,
  duplicate=0, not_ready=0` ✓
- dry-run: `selected_count=3, runs_per_outbound=3,
  planned_total_runs=9, target=example.com:80,
  subset_schema_gate_passed=true, subset_schema_gate.violations=[]` ✓
- BHV: 52/56 不变

### 实测分类: A.rotation_bank_clean

- 9/9 status=`completed`，9/9 `matrix_status=0`
- run_health_counts:
  `{run_all_ok=9, run_divergence=0, run_same_failure=0, run_unknown=0}`
- label_counts: `{all_ok=9}`
- class_counts: `{ok=81}`
- divergence_phase_label_count=**0**
- unexpected_phase_labels=[]；没有 NEW phase label

### Rotation-bank recovery status

| rep | chain | R86 | recovery_consecutive_rounds | closure |
| --- | --- | --- | ---: | --- |
| fresh01 | R73 + R85 + R86 | 3/3 all_ok | 3 | per-rep achieved |
| fresh15 | R73 + R85 + R86 | 3/3 all_ok | 3 | per-rep achieved |
| fresh10 | R73 + R86 | 3/3 all_ok | 2 | not closure |

R86 只允许写 **per-rep recovery closure achieved** for
fresh01/fresh15。不能写 whole cohort C closure：fresh09 在 R85
断链且 R86 未跑；fresh10 作为 replacement 只有 R73 + R86 两轮。

### Recovery transitions

| rep | round | state | labels | consecutive |
| --- | --- | --- | --- | ---: |
| fresh01 | R73 | all_ok | all_ok×5 | 1 |
| fresh01 | R85 | all_ok | all_ok×3 | 2 |
| fresh01 | R86 | all_ok | all_ok×3 | 3 |
| fresh15 | R73 | all_ok | all_ok×5 | 1 |
| fresh15 | R85 | all_ok | all_ok×3 | 2 |
| fresh15 | R86 | all_ok | all_ok×3 | 3 |
| fresh10 | R73 | all_ok | all_ok×5 | 1 |
| fresh10 | R86 | all_ok | all_ok×3 | 2 |

### Rollup delta

- total_rounds: 27 → **28**
- total_executed_runs: 238 → **247**
- total_all_ok_runs: 99 → **108**
- latest_same_failure_outbound_count: **8**（unchanged；fresh09 仍 latest_same_failure）
- latest_stable_same_failure_outbound_count: **8**（unchanged）
- latest_non_all_ok_outbound_count: **8**（unchanged）
- fresh01 latest_round: 85 → **86**；latest_health 仍 `latest_all_ok`
- fresh15 latest_round: 85 → **86**；latest_health 仍 `latest_all_ok`
- fresh10 latest_round: 73 → **86**；latest_health 仍 `latest_all_ok`
- fresh09 latest_round remains **85**；latest_health remains
  `latest_same_failure`

### 后续叙事

- R86 落 `A.rotation_bank_clean`
- fresh01/fresh15 per-rep recovery closure achieved
- fresh10 round 2 banked；下一轮自然候选是 fresh10 round-3
  closure attempt（需独立授权）
- 不再把 fresh09 带入 closure attempt；fresh09 仍是 broken rep
- 不把 R86 写成 whole cohort C closure / dual-kernel parity completion

### 产物

- `agents-only/mt_real_02_evidence/round86_cohort_c_rotation_bank_summary.json`
- `agents-only/mt_real_02_evidence/round86_cohort_c_rotation_bank_summary.md`
- `agents-only/mt_real_02_evidence/live_rollup.json`（28 rounds 重新生成）
- `agents-only/mt_real_02_evidence/live_rollup.md`
- `scripts/tools/test_reality_probe_tools.py`（R86
  committed-evidence contract）
- `agents-only/active_context.md`（≤100 行）
- 本文件 R86 节

### 范围确认

- live runs in R86: 9（fresh01/fresh15/fresh10 only）
- node contact in R86: 3 reps
- fresh09 / fresh04 / fresh08/fresh11/fresh12/fresh13/fresh14 /
  Hys2 / WS / plain-VLESS live: 0
- sampler / dataplane changes: 0
- `go_fork_source/*` / `.github/workflows/*` 改动: 0
- BHV 52/56 不变；Rust/live evidence，不写成 parity completion；
  R86 不宣称 whole cohort C closure

## R87 — fresh10 round-3 closure attempt

### 起因

R86 把 cohort C rotation-bank 收成两条状态：fresh01/fresh15
R73+R85+R86 三连 all_ok，per-rep recovery closure achieved；
fresh10 作为 fresh09 的 rotation replacement，只有 R73 + R86 两轮，
属于 round 2 banked。R87 因此是单节点定向授权：只对 fresh10
做 round-3 closure attempt，把 fresh10 的 recovery chain 推到三连。

### 范围

- live REALITY/VLESS、fresh10 only ×3 = 3 runs、target example.com:80
- HEAD at gate: `ee229a27`；main 与 origin/main 同步 ✓
- 不跑 fresh01 / fresh15 / fresh09 / fresh04 /
  fresh02/03/05/06/07 / fresh08/11/12/13/14 /
  Hys2 / WS / plain-VLESS
- 不动 sampler/dataplane / `go_fork_source/*` /
  `.github/workflows/*` / golden_spec
- BHV 52/56 不变
- 不允许 auto-extend；不允许 retry 修补；不允许现场 rotate

### Subset 清洗 + Pre-gate

- 用 R86 的 subset_clean 提取 fresh10 single-outbound subset
- R81 gate 双分支都过：任意深度移除 `__` 字段，
  outbound-level 字段落在 REALITY/VLESS allow-list 内
- intake_counts: `covered_existing=1, fresh_ready=0,
  duplicate=0, not_ready=0` ✓
- dry-run: `selected_count=1, runs_per_outbound=3,
  planned_total_runs=3, target=example.com:80,
  subset_schema_gate_passed=true, subset_schema_gate.violations=[]` ✓
- BHV: 52/56 不变

### 实测分类: A.per_rep_recovery_closure

- 3/3 status=`completed`，3/3 `matrix_status=0`
- run_health_counts:
  `{run_all_ok=3, run_divergence=0, run_same_failure=0, run_unknown=0}`
- label_counts: `{all_ok=3}`
- class_counts: `{ok=27}`
- divergence_phase_label_count=**0**
- unexpected_phase_labels=[]；没有 NEW phase label

### fresh10 round-3 closure status

| field | value |
| --- | --- |
| scope | per-rep only (fresh10) |
| chain | R73 + R86 + R87 |
| recovery_consecutive_rounds | 3 |
| per_rep_recovery_closure_achieved | **true** |
| original_cohort_c_closure_achieved | **false** |
| fresh09 recovered | **false** |

### Rotated active set 状态（post-R87）

| rep | per_rep closure | closed at | chain |
| --- | --- | --- | --- |
| fresh01 | true | R86 | R73 + R85 + R86 |
| fresh15 | true | R86 | R73 + R85 + R86 |
| fresh10 | true | R87 | R73 + R86 + R87 |

R87 把 rotated active set 三个代表的 per-rep recovery closure
全部完成。但 **不能** 写成 original cohort C closure：
原 cohort C identity 是 fresh01+fresh09+fresh15。fresh09
在 R85 3/3 timeout same_failure 断链，R87 未跑；fresh10 是
rotation replacement，不能替代 fresh09 的原-cohort 身份。

### Recovery transitions（fresh10）

| round | state | labels | consecutive |
| --- | --- | --- | ---: |
| R73 | all_ok | all_ok×5 | 1 |
| R86 | all_ok | all_ok×3 | 2 |
| R87 | all_ok | all_ok×3 | 3 |

### Rollup delta

- total_rounds: 28 → **29**
- total_executed_runs: 247 → **250**
- total_all_ok_runs: 108 → **111**
- latest_same_failure_outbound_count: **8**（unchanged；fresh09
  仍 latest_same_failure）
- latest_stable_same_failure_outbound_count: **8**（unchanged）
- latest_non_all_ok_outbound_count: **8**（unchanged）
- fresh10 latest_round: 86 → **87**；latest_health 仍 `latest_all_ok`
- fresh09 latest_round remains **85**；latest_health remains
  `latest_same_failure`

### 后续叙事

- R87 落 `A.per_rep_recovery_closure`
- fresh10 per-rep recovery closure achieved
- rotated active set（fresh01/fresh15/fresh10）per-rep closure 全部完成
- **不写** original / whole cohort C closure
- **不写** fresh09 recovered
- **不写** dual-kernel parity completion；BHV 52/56 不变
- 下一轮自然候选两路（任一都需独立授权）：
  (a) 从 R73 round-1-only recovery pool（fresh08/fresh11/fresh12/
  fresh13/fresh14）选一个做单独 rotation；或
  (b) 单独重测 fresh09，决定 R85 timeout 是否稳态

### 产物

- `agents-only/mt_real_02_evidence/round87_fresh10_round3_closure_summary.json`
- `agents-only/mt_real_02_evidence/round87_fresh10_round3_closure_summary.md`
- `agents-only/mt_real_02_evidence/live_rollup.json`（29 rounds 重新生成）
- `agents-only/mt_real_02_evidence/live_rollup.md`
- `scripts/tools/test_reality_probe_tools.py`（R87
  committed-evidence contract）
- `agents-only/active_context.md`（≤100 行）
- 本文件 R87 节

### 范围确认

- live runs in R87: 3（fresh10 only）
- node contact in R87: 1 rep
- fresh01/fresh15/fresh09/fresh04 /
  fresh02/03/05/06/07/08/11/12/13/14 /
  Hys2 / WS / plain-VLESS live: 0
- sampler / dataplane changes: 0
- `go_fork_source/*` / `.github/workflows/*` / `golden_spec` 改动: 0
- BHV 52/56 不变；Rust/live evidence，不写成 parity completion；
  R87 不宣称 original / whole cohort C closure；fresh09 仍 broken

## R88 — fresh09 single-node recheck

### 起因

R87 把 rotated active set（fresh01/fresh15/fresh10）三代表的 per-rep
recovery closure 全部完成；但 fresh09 自 R85 3/3 timeout same_failure
断链至今未 re-run，原 cohort C identity（fresh01+fresh09+fresh15）
未声明 closure。R88 是单节点定向授权：只对 fresh09 做独立 recheck，
判断 R85 timeout 是稳态还是噪声。R88 **不是** closure attempt：
fresh09 recovery chain 已在 R85 reset 为 0；即使 R88 5/5 all_ok，
也只能开启 fresh09 新 recovery chain 的 round 1，不能补上 R85 断链。

### 范围

- live REALITY/VLESS、fresh09 only ×5 = 5 runs、target example.com:80
- HEAD at gate: `c56fd368`；main 与 origin/main 同步 ✓
- 不跑 fresh01 / fresh15 / fresh10 / fresh04 /
  fresh02/03/05/06/07 / fresh08/11/12/13/14 /
  Hys2 / WS / plain-VLESS
- 不动 sampler/dataplane / `go_fork_source/*` /
  `.github/workflows/*` / golden_spec
- BHV 52/56 不变
- 不允许 auto-extend；不允许 retry 修补；不允许现场 rotate

### Subset 清洗 + Pre-gate

- 用 R85 的 fresh09 raw 作为 single-outbound subset；只保留 R81
  allow-list 字段（type/tag/server/server_port/uuid/packet_encoding/
  flow/tls→reality/utls）
- R81 gate 双分支都过：任意深度移除 `__` 字段，
  outbound-level 字段落在 REALITY/VLESS allow-list 内
- intake_counts: `covered_existing=1, fresh_ready=0,
  duplicate=0, not_ready=0` ✓
- dry-run: `selected_count=1, runs_per_outbound=5,
  planned_total_runs=5, target=example.com:80,
  subset_schema_gate_passed=true, subset_schema_gate.violations=[]` ✓
- BHV: 52/56 不变

### 实测分类: A.fresh09_timeout_steady_state

- 5/5 status=`completed`，5/5 `matrix_status=0`
- run_health_counts:
  `{run_all_ok=0, run_divergence=0, run_same_failure=5, run_unknown=0}`
- label_counts: `{probe_io_all_timeout=5, reality_all_timeout=5}`
- class_counts: `{timeout=45}`
- divergence_phase_label_count=**0**
- unexpected_phase_labels=[]；没有 NEW phase label；没有 NEW
  structural divergence；没有 matrix_error
- R85 3/3 timeout same_failure → R88 5/5 timeout same_failure
  → R85 timeout 复现，**稳态而非噪声**

### fresh09 recheck status

| field | value |
| --- | --- |
| scope | single-node recheck (fresh09) |
| is_closure_attempt | **false**（chain 已在 R85 reset） |
| fresh09 R85 state | same_failure (timeout) |
| fresh09 R88 state | same_failure (timeout) |
| R85 timeout reproduced | **true** |
| recovery_consecutive_rounds | **0** |
| per_rep_recovery_closure_achieved | **false** |
| fresh09 recovered | **false** |
| original_cohort_c_closure_achieved | **false** |

R88 不是 closure attempt：broken closure chain 不能补丁，
restart 需要新的 consecutive sequence。fresh09 R88 5/5 timeout
确认 R85 不是 noise。原 cohort C closure 仍不成立：fresh10
R87 closure 是 rotated-replacement closure，不替代 fresh09 的
原-cohort 身份。

### Rotated active set 状态（post-R88，与 R87 一致）

| rep | per_rep closure | closed at | chain |
| --- | --- | --- | --- |
| fresh01 | true | R86 | R73 + R85 + R86 |
| fresh15 | true | R86 | R73 + R85 + R86 |
| fresh10 | true | R87 | R73 + R86 + R87 |

### fresh09 transition history

| round | state | labels | consecutive |
| --- | --- | --- | ---: |
| R73 | all_ok | all_ok×5 | 1 |
| R85 | same_failure (timeout) | probe_io_all_timeout×3, reality_all_timeout×3 | 0 |
| R88 | same_failure (timeout) | probe_io_all_timeout×5, reality_all_timeout×5 | 0 |

### Rollup delta

- total_rounds: 29 → **30**
- total_executed_runs: 250 → **255**
- total_all_ok_runs: 111 → **111**（unchanged）
- latest_same_failure_outbound_count: **8**（unchanged；fresh09 仍 latest_same_failure）
- latest_stable_same_failure_outbound_count: **8**（unchanged）
- latest_non_all_ok_outbound_count: **8**（unchanged）
- fresh09 latest_round: 85 → **88**；latest_health remains
  `latest_same_failure`；latest_run_health_counts 从
  `{run_same_failure: 3}`（R85）变为 `{run_same_failure: 5}`（R88）
- fresh01/fresh15/fresh10 latest_round 不变（86/86/87）

### 后续叙事

- R88 落 `A.fresh09_timeout_steady_state`
- fresh09 R85 timeout 稳态确认；不是 noise
- fresh09 recovery_consecutive_rounds=0；**不写** per-rep closure
- **不写** fresh09 recovered
- **不写** whole / original cohort C closure
- **不写** dual-kernel parity completion；BHV 52/56 不变
- 下一轮自然候选两路（任一都需独立授权）：
  (a) 接受 fresh09 稳态 broken，继续 rotated active set 覆盖，
  可从 R73 round-1-only recovery pool（fresh08/fresh11/fresh12/
  fresh13/fresh14）选一个做单独 rotation；或
  (b) 仅当有 R85+R88 timeout 可能为 transient 的具体假设
  （例如 upstream 节点维护窗口）才再做一次 fresh09 recheck

### 产物

- `agents-only/mt_real_02_evidence/round88_fresh09_recheck_summary.json`
- `agents-only/mt_real_02_evidence/round88_fresh09_recheck_summary.md`
- `agents-only/mt_real_02_evidence/live_rollup.json`（30 rounds 重新生成）
- `agents-only/mt_real_02_evidence/live_rollup.md`
- `scripts/tools/test_reality_probe_tools.py`（R88
  committed-evidence contract）
- `agents-only/active_context.md`（≤100 行）
- 本文件 R88 节

### 范围确认

- live runs in R88: 5（fresh09 only）
- node contact in R88: 1 rep
- fresh01/fresh15/fresh10/fresh04 /
  fresh02/03/05/06/07/08/11/12/13/14 /
  Hys2 / WS / plain-VLESS live: 0
- sampler / dataplane changes: 0
- `go_fork_source/*` / `.github/workflows/*` / `golden_spec` 改动: 0
- BHV 52/56 不变；Rust/live evidence，不写成 parity completion；
  R88 不是 closure attempt；fresh09 仍 broken；R85 timeout 稳态确认

## R89 — fresh12 isolated rotation-bank round

### 起因

R88 接受 fresh09 为 steady-state broken 后，本轮不再跑 fresh09，
也不回到 fresh01/fresh15/fresh10/fresh04 或其他已排除 fresh 节点。
R89 从 R73 round-1-only recovery pool 选 fresh12 作为中位代表，
做 isolated rotation-bank round：目标只判断 fresh12 能否从 R73
round 1 进入 round 2 bank，不声明 closure，不替代 original cohort C。

### 范围

- live REALITY/VLESS、fresh12 only ×3 = 3 runs、target example.com:80
- HEAD at gate: `a1d92ffc8d088f5d15a952d20fa1d3ecdf605618`；
  main 与 origin/main 同步 ✓
- 不跑 fresh09 / fresh01 / fresh15 / fresh10 / fresh04 /
  fresh02/03/05/06/07 / fresh08/11/13/14 /
  Hys2 / WS / plain-VLESS
- 不动 sampler/dataplane / `go_fork_source/*` /
  `.github/workflows/*` / golden_spec
- BHV 52/56 不变
- 不允许 auto-extend；不允许 retry 修补；不允许现场 rotate

### Subset 清洗 + Pre-gate

- 从 `/tmp/mt_mixed_fresh_subset_reality_neutral.json` 取 fresh12
  单节点 subset，移除 `__id_in_gui` 等 `__` GUI-only 字段，只保留
  R81 REALITY/VLESS allow-list 字段
- intake_counts: `covered_existing=1, fresh_ready=0,
  duplicate=0, not_ready=0` ✓
- dry-run: `selected_count=1, runs_per_outbound=3,
  planned_total_runs=3, target=example.com:80,
  subset_schema_gate_passed=true, subset_schema_gate.violations=[]` ✓
- BHV: 52/56 不变

### 实测分类: D.matrix_error_inconclusive

- 3/3 planned runs 执行完成；没有补跑
- status_counts: `{completed=1, matrix_timeout=2}`
- matrix_status_counts: `{0=1, 124=2}`
- run_health_counts:
  `{run_all_ok=0, run_divergence=0, run_same_failure=1, run_unknown=2}`
- completed run: `probe_io_all_connection_reset` +
  `reality_all_connection_reset`；class_counts `{connection_reset=9}`
- divergence_phase_label_count=**0**
- unexpected_phase_labels=[]；没有 NEW phase label；没有 NEW
  structural divergence
- 因为 2 个 run 是 matrix_timeout 且没有 compare payload，本轮按
  matrix/tooling error → inconclusive 处理，不计入 recovery success

### fresh12 rotation-bank status

| field | value |
| --- | --- |
| scope | isolated rotation bank round (fresh12) |
| prior state | R73 round-1-only all_ok |
| R89 state | matrix_error_inconclusive |
| completed run state | same_failure (connection_reset) |
| round_counted_for_recovery_success | **false** |
| recovery_consecutive_rounds_after_r89 | **1**（R73 carry-forward） |
| fresh12 round 2 banked | **false** |
| fresh12 closure declared | **false** |

R89 不是 fresh12 closure attempt；它原本只是 round-2 bank attempt。
因为 matrix_timeout 让本轮 inconclusive，fresh12 不能记 round 2
bank，不能写 closure。若后续继续 fresh12，需要新授权重新做
round-2 bank attempt，不能把 R89 当作 recovery success。

### Rollup delta

- total_rounds: 30 → **31**
- total_executed_runs: 255 → **258**
- total_all_ok_runs: 111 → **111**（unchanged）
- total_non_all_ok_runs: 144 → **147**
- latest_same_failure_outbound_count: 8 → **9**
- latest_mixed_run_health_outbound_count: 0 → **1**（fresh12:
  run_same_failure=1 + run_unknown=2）
- fresh12 latest_round: 73 → **89**；latest_health becomes
  `latest_same_failure` from the single completed compare payload, but
  round classification remains `D.matrix_error_inconclusive`
- latest_run_health_counts now includes `run_unknown=2`

### 后续叙事

- R89 落 `D.matrix_error_inconclusive`
- fresh12 recovery_consecutive_rounds=1（R73 carry-forward；R89 不计 success）
- **不写** fresh12 round 2 banked
- **不写** fresh12 closure
- fresh09 仍按 R88 口径为 steady-state broken；**不写** fresh09 recovered
- **不写** whole / original cohort C closure
- **不写** dual-kernel parity completion；BHV 52/56 不变
- 下一轮自然候选：若继续 fresh12，需独立授权重做 round-2 bank
  attempt；也可选 fresh08/fresh11/fresh13/fresh14 中另一代表做
  isolated rotation-bank round。任一路都不能 auto-extend R89。

### 产物

- `agents-only/mt_real_02_evidence/round89_fresh12_rotation_bank_summary.json`
- `agents-only/mt_real_02_evidence/round89_fresh12_rotation_bank_summary.md`
- `agents-only/mt_real_02_evidence/live_rollup.json`（31 rounds 重新生成）
- `agents-only/mt_real_02_evidence/live_rollup.md`
- `scripts/tools/test_reality_probe_tools.py`（R89
  committed-evidence contract）
- `agents-only/active_context.md`（≤100 行）
- 本文件 R89 节

### 范围确认

- live runs in R89: 3（fresh12 only）
- node contact in R89: 1 rep
- fresh09/fresh01/fresh15/fresh10/fresh04 /
  fresh02/03/05/06/07/08/11/13/14 /
  Hys2 / WS / plain-VLESS live: 0
- sampler / dataplane changes: 0
- `go_fork_source/*` / `.github/workflows/*` / `golden_spec` 改动: 0
- BHV 52/56 不变；Rust/live evidence，不写成 parity completion；
  R89 不声明 fresh12 bank/closure，也不声明 original cohort C closure

## R90 — fresh13 isolated rotation-bank round

### 起因

R89 的 fresh12 是 matrix_error/inconclusive，不计 recovery success，
不能补跑、不能把 fresh12 写成 banked。本轮继续 rotated active set
扩展覆盖，从仍未使用的 R73 round-1-only recovery pool 中选 fresh13
做 isolated rotation-bank round。R90 不重试 fresh12，不跑 fresh09，
也不替代 original cohort C closure。

### 范围

- live REALITY/VLESS、fresh13 only ×3 = 3 runs、target example.com:80
- HEAD at gate: `0e69cccdd8ae300c0626f007498833984db757f7`；
  main 与 origin/main 同步 ✓
- 不跑 fresh12 / fresh09 / fresh01 / fresh15 / fresh10 / fresh04 /
  fresh02/03/05/06/07 / fresh08/11/14 /
  Hys2 / WS / plain-VLESS
- 不动 sampler/dataplane / `go_fork_source/*` /
  `.github/workflows/*` / golden_spec
- BHV 52/56 不变
- 不允许 auto-extend；不允许 retry 修补；不允许现场 rotate

### Subset 清洗 + Pre-gate

- 从 `/tmp/mt_mixed_fresh_subset_reality_neutral.json` 取 fresh13
  单节点 subset，移除 `__id_in_gui` 等 `__` GUI-only 字段，只保留
  R81 REALITY/VLESS allow-list 字段
- intake_counts: `covered_existing=1, fresh_ready=0,
  duplicate=0, not_ready=0` ✓
- dry-run: `selected_count=1, runs_per_outbound=3,
  planned_total_runs=3, target=example.com:80,
  subset_schema_gate_passed=true, subset_schema_gate.violations=[]` ✓
- BHV: 52/56 不变

### 实测分类: A.fresh13_round2_banked

- 3/3 status=`completed`，3/3 `matrix_status=0`
- run_health_counts:
  `{run_all_ok=3, run_divergence=0, run_same_failure=0, run_unknown=0}`
- label_counts: `{all_ok=3}`
- class_counts: `{ok=27}`
- divergence_phase_label_count=**0**
- matrix_timeout=0；matrix_error=false；inconclusive=false
- unexpected_phase_labels=[]；没有 NEW phase label；没有 NEW
  structural divergence

### fresh13 rotation-bank status

| field | value |
| --- | --- |
| scope | isolated rotation bank round (fresh13) |
| prior state | R73 round-1-only all_ok |
| R90 state | all_ok |
| round_counted_for_recovery_success | **true** |
| recovery_consecutive_rounds_after_r90 | **2**（R73 + R90） |
| fresh13 round 2 banked | **true** |
| fresh13 closure declared | **false** |

R90 只声明 fresh13 round 2 banked。fresh13 尚未达到 3 连
clean 的 per-rep closure threshold，因此不能写 closure。若后续继续
fresh13，需要新授权做 round-3 closure attempt。

### Rollup delta

- total_rounds: 31 → **32**
- total_executed_runs: 258 → **261**
- total_all_ok_runs: 111 → **114**
- total_non_all_ok_runs: **147**（unchanged）
- latest_same_failure_outbound_count: **9**（unchanged）
- latest_mixed_run_health_outbound_count: **1**（unchanged；仍是
  fresh12 R89）
- fresh13 latest_round: 73 → **90**；latest_health remains
  `latest_all_ok`；latest_run_health_counts `{run_all_ok=3}`
- fresh12 latest_round remains **89**；R89 remains
  `D.matrix_error_inconclusive` and **not banked**

### 后续叙事

- R90 落 `A.fresh13_round2_banked`
- fresh13 recovery_consecutive_rounds=2（R73 + R90）
- **写** fresh13 round 2 banked
- **不写** fresh13 closure
- fresh12 R89 仍是 inconclusive；**不写** fresh12 banked
- fresh09 仍按 R88 口径为 steady-state broken；**不写** fresh09 recovered
- **不写** whole / original cohort C closure
- **不写** dual-kernel parity completion；BHV 52/56 不变
- 下一轮自然候选：对 fresh13 做 round-3 closure attempt，或从
  fresh08/fresh11/fresh14 中另选代表做 isolated rotation-bank round。

### 产物

- `agents-only/mt_real_02_evidence/round90_fresh13_rotation_bank_summary.json`
- `agents-only/mt_real_02_evidence/round90_fresh13_rotation_bank_summary.md`
- `agents-only/mt_real_02_evidence/live_rollup.json`（32 rounds 重新生成）
- `agents-only/mt_real_02_evidence/live_rollup.md`
- `scripts/tools/test_reality_probe_tools.py`（R90
  committed-evidence contract）
- `agents-only/active_context.md`（≤100 行）
- 本文件 R90 节

### 范围确认

- live runs in R90: 3（fresh13 only）
- node contact in R90: 1 rep
- fresh12/fresh09/fresh01/fresh15/fresh10/fresh04 /
  fresh02/03/05/06/07/08/11/14 /
  Hys2 / WS / plain-VLESS live: 0
- sampler / dataplane changes: 0
- `go_fork_source/*` / `.github/workflows/*` / `golden_spec` 改动: 0
- BHV 52/56 不变；Rust/live evidence，不写成 parity completion；
  R90 只声明 fresh13 round-2 bank，不声明 closure 或 original cohort C closure

## R91 — fresh13 round-3 per-rep closure attempt

### 起因

R90 已把 fresh13 从 R73 round-1-only 推进到 round-2 bank。
R91 是独立授权的 fresh13 round-3 closure attempt，只判断
fresh13 这个 rotated coverage rep 能否达到 per-rep recovery
closure。R91 不重试 fresh12，不修饰 fresh09，也不替代 original
cohort C closure。

### 范围

- live REALITY/VLESS、fresh13 only ×3 = 3 runs、target example.com:80
- HEAD at gate: `ce7fa0bfe9c454dba2b617e9633f3f98cd410b9b`；
  main 与 origin/main 同步 ✓
- 不跑 fresh12 / fresh09 / fresh01 / fresh15 / fresh10 / fresh04 /
  fresh02/03/05/06/07 / fresh08/11/14 /
  Hys2 / WS / plain-VLESS
- 不动 sampler/dataplane / `go_fork_source/*` /
  `.github/workflows/*` / golden_spec
- BHV 52/56 不变
- 不允许 auto-extend；不允许 retry 修补；不允许现场 rotate

### Subset 清洗 + Pre-gate

- 从 `/tmp/mt_mixed_fresh_subset_reality_neutral.json` 取 fresh13
  单节点 subset，移除 `__id_in_gui` 等 `__` GUI-only 字段，只保留
  R81 REALITY/VLESS allow-list 字段
- intake_counts: `covered_existing=1, fresh_ready=0,
  duplicate=0, not_ready=0` ✓
- dry-run: `selected_count=1, runs_per_outbound=3,
  planned_total_runs=3, target=example.com:80,
  subset_schema_gate_passed=true, subset_schema_gate.violations=[]` ✓
- BHV: 52/56 不变

### 实测分类: A.fresh13_per_rep_recovery_closure

- 3/3 status=`completed`，3/3 `matrix_status=0`
- run_health_counts:
  `{run_all_ok=3, run_divergence=0, run_same_failure=0, run_unknown=0}`
- label_counts: `{all_ok=3}`
- class_counts: `{ok=27}`
- divergence_phase_label_count=**0**
- matrix_timeout=0；matrix_error=false；inconclusive=false
- unexpected_phase_labels=[]；没有 NEW phase label；没有 NEW
  structural divergence

### fresh13 per-rep closure status

| field | value |
| --- | --- |
| scope | per-rep recovery closure attempt (fresh13) |
| prior bank | R73 + R90 consecutive all_ok evidence |
| R91 state | all_ok |
| round_counted_for_recovery_success | **true** |
| recovery_consecutive_rounds_after_r91 | **3**（R73 + R90 + R91） |
| fresh13 per-rep recovery closure achieved | **true** |
| original cohort C closure declared | **false** |

R91 只声明 fresh13 per-rep recovery closure。它仍是 rotated
coverage rep 范围内的 closure，不是 original cohort C closure，也
不是 dual-kernel parity completion。

### Rollup delta

- total_rounds: 32 → **33**
- total_executed_runs: 261 → **264**
- total_all_ok_runs: 114 → **117**
- total_non_all_ok_runs: **147**（unchanged）
- latest_same_failure_outbound_count: **9**（unchanged）
- latest_mixed_run_health_outbound_count: **1**（unchanged；仍是
  fresh12 R89）
- fresh13 latest_round: 90 → **91**；latest_health remains
  `latest_all_ok`；latest_run_health_counts `{run_all_ok=3}`
- fresh12 latest_round remains **89**；R89 remains
  `D.matrix_error_inconclusive` and **not banked**

### 后续叙事

- R91 落 `A.fresh13_per_rep_recovery_closure`
- fresh13 recovery_consecutive_rounds=3（R73 + R90 + R91）
- **写** fresh13 per-rep recovery closure
- fresh12 R89 仍是 inconclusive；**不写** fresh12 banked
- fresh09 仍按 R88 口径为 steady-state broken；**不写** fresh09 recovered
- **不写** whole / original cohort C closure
- **不写** dual-kernel parity completion；BHV 52/56 不变
- 下一轮自然候选：继续 rotated active set 覆盖，可从 fresh08 /
  fresh11 / fresh14 选代表做 isolated rotation-bank round，或按新授权
  处理其它 still-open rep。

### 产物

- `agents-only/mt_real_02_evidence/round91_fresh13_round3_closure_summary.json`
- `agents-only/mt_real_02_evidence/round91_fresh13_round3_closure_summary.md`
- `agents-only/mt_real_02_evidence/live_rollup.json`（33 rounds 重新生成）
- `agents-only/mt_real_02_evidence/live_rollup.md`
- `scripts/tools/test_reality_probe_tools.py`（R91
  committed-evidence contract）
- `agents-only/active_context.md`（≤100 行）
- 本文件 R91 节

### 范围确认

- live runs in R91: 3（fresh13 only）
- node contact in R91: 1 rep
- fresh12/fresh09/fresh01/fresh15/fresh10/fresh04 /
  fresh02/03/05/06/07/08/11/14 /
  Hys2 / WS / plain-VLESS live: 0
- sampler / dataplane changes: 0
- `go_fork_source/*` / `.github/workflows/*` / `golden_spec` 改动: 0
- BHV 52/56 不变；Rust/live evidence，不写成 parity completion；
  R91 只声明 fresh13 per-rep closure，不声明 original cohort C closure
