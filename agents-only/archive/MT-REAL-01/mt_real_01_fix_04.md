# MT-REAL-01-FIX-04: REALITY Chrome-like ClientHello Fingerprint Spike

日期：2026-04-15

## 目标

- 在不回退到“发出后篡改 ClientHello”旧错误路径的前提下，给 vendored `rustls` 增加 **opt-in** 的 ClientHello 指纹控制能力。
- 仅为 REALITY client 注入一组 Chrome-like 指纹参数，验证这是否足以突破 `tls handshake eof` 的 live 阻断。

## 实现范围

- `vendor/rustls/src/client/client_conn.rs`
  - 新增 `client::ClientHelloFingerprint`
  - `ClientConfig` 新增 `fingerprint: Option<ClientHelloFingerprint>`
- `vendor/rustls/src/client/hs.rs`
  - 在 ClientHello 构造阶段应用 fingerprint：
    - prepend GREASE cipher suite
    - append raw extra cipher suites
    - 注入空 `session_ticket`
    - 注入 `renegotiation_info`
    - 注入 opaque extensions
    - 强制扩展顺序
- `vendor/rustls/src/msgs/handshake.rs`
  - `ClientExtensions` 新增：
    - `opaque_extensions`
    - `forced_extension_order`
  - 编码路径支持：
    - arbitrary extension bytes
    - deterministic ordering override
- `crates/sb-tls/src/reality/handshake.rs`
  - REALITY client 仅在 **chrome-like fingerprint 名称** 下启用一组 Chrome-style fingerprint：
    - GREASE cipher suite `0x1a1a`
    - GREASE extensions `0x0a0a` / `0x4a4a`
    - `SCT` empty extension
    - fixed padding extension (`224` bytes)
    - forced extension order
  - 保持 `SessionIdGenerator` 线路不变

## 本地验证

- `cargo test -p sb-tls test_chrome_fingerprinted_client_hello -- --nocapture` → `PASS`
- `cargo test -p sb-tls test_rustls_emits_encrypted_reality_session_id -- --nocapture` → `PASS`
- `cargo test -p sb-tls` → `PASS` (`100 passed`)
- `cargo check --workspace` → `PASS`
- `cargo build -p app --features acceptance,parity --bin app` → `PASS`
- `cargo clippy -p sb-tls --all-features --all-targets -- -D warnings` → `PASS`

## 新增测试结论

- `reality::handshake::tests::test_chrome_fingerprinted_client_hello`
  - 证明 rustls 发出的 REALITY ClientHello 现在具备：
    - deterministic extension ordering
    - GREASE extension presence
    - padding extension presence
    - non-zero encrypted REALITY session_id

## Live 复测

### 1. 先校正配置前提

- `agents-only/mt_real_01_evidence/phase3_ip_direct.json` 中 **22 个** `vless+reality` 节点全部是：
  - `tls.utls.fingerprint = "firefox"`
- 因此直接用原始 Phase 3 配置复测，**不会命中本卡新增的 chrome-like 指纹路径**。

### 2. 生成临时 chrome 复测配置

- 基于 `phase3_ip_direct.json` 生成临时文件：
  - `/tmp/phase3_ip_direct_fix04_chrome.json`
- 只做一件事：
  - 对所有 `vless` + `tls.utls.enabled == true` 节点，把 `tls.utls.fingerprint` 从 `firefox` 改为 `chrome`

### 3. 结果

- 用 `/tmp/phase3_ip_direct_fix04_chrome.json` 启动 Rust 内核后，控制面仍正常：
  - Clash API `127.0.0.1:19090` → `PASS`
  - mixed inbound `127.0.0.1:11080` → `PASS`
- 选取 3 个不同伪装域名样本做 live 复测：
  - `HK-A-BGP-0.3倍率` (`gamedownloads-rockstargames-com.akamaized.net`)
  - `HK-A-BGP-1.0倍率` (`d1--ov-gotcha07.bilivideo.com`)
  - `HK-A-BGP-2.0倍率` (`www.douyin.com`)
- 三个样本均失败，运行日志统一为：
  - `REALITY handshake failed: Handshake failed: TLS handshake failed: tls handshake eof`

## 结论

- `FIX-04` 这轮 **最小 Chrome-like ClientHello 指纹补丁** 已完成代码和测试验证，但 **未取得 live 成功样本**。
- 这说明当前阻断并不只是：
  - 扩展顺序
  - 顶层 GREASE extension
  - 空 `session_ticket`
  - `renegotiation_info`
  - 固定 padding
- 剩余差异大概率仍包括更深层的浏览器拟态细节，例如：
  - GREASE 在更多子结构中的布局
  - supported_groups / key_share / versions 的浏览器化内容
  - 更贴近 utls 的 extension/value 细节
  - record shaping / fragmentation 等更靠近真实浏览器 I/O 的行为

## 当前状态判定

- 本卡取得的是：
  - **代码级 spike 完成**
  - **本地 wire-format 单测通过**
  - **live 复测仍失败**
- 因而 `FIX-04` 目前**不能宣告完成**；它更像一次证伪：
  - “最小指纹补丁”不足以打通 REALITY live
