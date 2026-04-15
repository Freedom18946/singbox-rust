# MT-REAL-01-FIX-05: REALITY Typed ClientHello Substructure GREASE Spike

日期：2026-04-15

## 目标

- 在 `FIX-04` 已证明“最小顶层指纹补丁不足以打通 live”后，继续补齐 **Chrome-like 子结构指纹**。
- 重点验证以下差异是否是 REALITY live 的最后阻断：
  - `supported_versions` 中的 GREASE + TLS 1.2
  - `supported_groups` 中的 GREASE group
  - `key_share` 中的 GREASE entry
  - `signature_algorithms` 的 Chrome-style 固定列表

## 实现范围

- `vendor/rustls/src/client/client_conn.rs`
  - 扩展 `ClientHelloFingerprint`：
    - `supported_versions_override`
    - `supported_groups_override`
    - `key_share_grease`
    - `signature_algorithms_override`
- `vendor/rustls/src/client/hs.rs`
  - 在 ClientHello 构造期把上述 typed extension payload 覆写为 **raw opaque bytes**：
    - `supported_versions`
    - `supported_groups`
    - `key_share`
    - `signature_algorithms`
  - `key_share` 改为在原有 X25519 share 之前 prepend GREASE share
- `crates/sb-tls/src/reality/handshake.rs`
  - REALITY chrome-like fingerprint 增补：
    - `supported_versions = [GREASE, 0x0304, 0x0303]`
    - `supported_groups = [GREASE, x25519, secp256r1, secp384r1]`
    - `key_share = [GREASE(1B), x25519(32B)]`
    - `signature_algorithms` 固定为一组 Chrome-style 顺序
  - `parse_client_key_share()` 改为扫描 key_share 列表并提取 `x25519`，不再假设第一个 entry 就是目标 share

## 本地验证

- `cargo test -p sb-tls test_chrome_fingerprinted_client_hello -- --nocapture` → `PASS`
- `cargo test -p sb-tls test_rustls_emits_encrypted_reality_session_id -- --nocapture` → `PASS`
- `cargo test -p sb-tls` → `PASS` (`100 passed`)
- `cargo check --workspace` → `PASS`
- `cargo build -p app --features acceptance,parity --bin app` → `PASS`
- `cargo clippy -p sb-tls --all-features --all-targets -- -D warnings` → `PASS`

## 新增测试结论

- `reality::handshake::tests::test_chrome_fingerprinted_client_hello`
  - 已确认 Rust ClientHello 现在具备：
    - 顶层 deterministic extension ordering
    - GREASE extension presence
    - padding extension presence
    - encrypted REALITY `session_id`
    - `supported_versions = [GREASE, TLS1.3, TLS1.2]`
    - `supported_groups = [GREASE, x25519, secp256r1, secp384r1]`
    - `key_share` 首项为 GREASE entry，后续仍携带 X25519 share
    - `signature_algorithms` 使用固定 Chrome-style 起始顺序

## Live 复测

### 1. 配置前提

- 原始 `agents-only/mt_real_01_evidence/phase3_ip_direct.json` 的 **22 个** REALITY 节点仍全部是：
  - `tls.utls.fingerprint = "firefox"`
- 因此继续使用临时文件：
  - `/tmp/phase3_ip_direct_fix05_chrome.json`
- 只变更：
  - 对所有 `vless` + `tls.utls.enabled == true` 节点，把 `tls.utls.fingerprint` 强制改成 `chrome`

### 2. 样本

- `HK-A-BGP-0.3倍率`
- `HK-A-BGP-1.0倍率`
- `HK-A-BGP-2.0倍率`

### 3. 结果

- 控制面仍正常启动：
  - Clash API `127.0.0.1:19090` → `PASS`
  - mixed inbound `127.0.0.1:11080` → `PASS`
- 三个样本的 selector 切换都成功
- 三个样本的 SOCKS5 探测全部失败：
  - `curl: (97) Can't complete SOCKS5 connection to httpbin.org. (1)`
- app 运行日志三次都统一落在：
  - `REALITY handshake failed: Handshake failed: TLS handshake failed: tls handshake eof`

## 结论

- `FIX-05` 已进一步补齐 **typed extension 子结构层** 的浏览器化差异，但 **仍未取得任何 live 成功样本**。
- 这意味着剩余阻断已经不太可能只靠：
  - `supported_versions` GREASE
  - `supported_groups` GREASE
  - `key_share` GREASE
  - `signature_algorithms` 顺序
  来解决。
- 当前更合理的工程判断是：
  - REALITY 对 `utls` 级别浏览器拟态的依赖比先前假设更深
  - `rustls` 上继续逐项补齐会进入高侵入、长尾、脆弱的“打鼹鼠”模式

## 当前状态判定

- 本卡取得的是：
  - **typed substructure fingerprint spike 完成**
  - **本地 wire-format / build / clippy 全通过**
  - **live 仍然统一失败**
- 因而 `FIX-05` 更像一次最终证伪：
  - “补齐顶层 + 子结构 GREASE / versions / groups / key_share / sigalgs，仍不足以打通 REALITY live”
- 下一步若继续推进，应优先考虑把 REALITY live 失败正式收敛为：
  - `ARCH-LIMIT: rustls lacks utls-equivalent browser fingerprinting`
