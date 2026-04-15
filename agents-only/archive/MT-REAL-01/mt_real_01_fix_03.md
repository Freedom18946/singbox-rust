# MT-REAL-01-FIX-03: REALITY 客户端握手协议重写（Go 对齐）

## Scope

- 重写 Rust REALITY client 的握手注入路径，移除首次写入时篡改 `ClientHello` 的 stream wrapper。
- 让 REALITY 认证数据改为使用 **TLS 同一把 X25519 ECDHE key share** 导出，而不是独立 `RealityAuth` 临时密钥。
- 保持改动范围在 `crates/sb-tls/src/reality/`，不改其他协议，不改 REALITY server。

## Root Cause Recap

- 旧实现有两处结构性错误：
  - `ClientHello` 在 rustls 已经编码并进入 transcript 之后才被 wrapper 改写，导致客户端/服务端 transcript hash 不一致。
  - 认证数据放在自定义 TLS 扩展里，Go REALITY server 不认这个扩展；Go 协议要求把认证数据塞进加密后的 `SessionID`。

## Implemented Fix

### 1. 新增 `crates/sb-tls/src/reality/handshake.rs`

- 新增 `RealityHandshake` 握手核心，改为利用 vendored `rustls` 0.23.35 已存在的两个 hook：
  - `client::SessionIdGenerator`
  - `crypto::SupportedKxGroup`
- 不再手改网络上已经发出的 `ClientHello` 字节；改为在 rustls **正式编码 ClientHello 时** 生成 REALITY `SessionID`。

### 2. 用 TLS 自己的 X25519 key share 导出 REALITY auth key

- 新增自定义 `RealityX25519KxGroup`：
  - rustls 生成 TLS 1.3 `key_share` 时，使用这套自定义 X25519 实现
  - 生成的临时私钥按公钥索引暂存，供 `SessionIdGenerator` 取用
- `SessionIdGenerator` 从零化 `session_id` 的完整 `ClientHello` 中提取：
  - `client_random`
  - `key_share` 公钥
- 然后按 Go REALITY 路径计算：
  - `ECDH(tls_ecdhe_private, server_reality_public)`
  - `HKDF-SHA256(salt=random[:20], info="REALITY")`
  - `AES-256-GCM(nonce=random[20:32], plaintext=session_id[:16], aad=raw_client_hello_with_zeroed_session_id)`

### 3. `SessionID` 改为 Go 对齐格式

- 生成的 `SessionID[:16]` 为：
  - `[1, 8, 1, ts_byte, uint32(now), short_id[0:8]]`
- 再拼接 GCM tag，得到 32-byte 密文 `SessionID`，由 rustls 直接带入 transcript 和网络发送。

### 4. REALITY 临时证书验证改为共享同一份 auth key 状态

- `RealityVerifier` 现在从握手状态中读取由 `SessionIdGenerator` 产出的 `auth_key`
- 保留原有 HMAC-SHA512(`auth_key`, cert_ed25519_pubkey) 校验逻辑
- 如果握手只通过 WebPKI fallback，而没有命中 REALITY 临时证书校验，则连接返回 `reality verification failed`

### 5. `client.rs` 改为薄封装

- `RealityConnector::reality_handshake()` 不再创建 `RealityClientStream`
- 直接调用 `RealityHandshake::new(...).perform(stream).await`

## Verification

### Package Gates

- `cargo test -p sb-tls`: `PASS`
  - `99 passed`, `0 failed`
- `cargo clippy -p sb-tls --all-features --all-targets -- -D warnings`: `PASS`
- `cargo build -p app --features acceptance,parity --bin app`: `PASS`

### New Unit Coverage

- `reality::handshake::tests::test_build_reality_plaintext_session_id`
- `reality::handshake::tests::test_seal_reality_session_id_matches_expected_length`
- `reality::handshake::tests::test_session_id_generator_stores_auth_key_and_emits_ciphertext`
- `reality::handshake::tests::test_rustls_emits_encrypted_reality_session_id`

这些测试确认：

- REALITY `SessionID[:16]` 生成格式正确
- `SessionIdGenerator` 使用的是 TLS 同一把 X25519 key share 对应的私钥
- rustls 真正发出的 `ClientHello` 已带加密后的 32-byte `SessionID`

## Phase 3 Smoke

- 用 `agents-only/mt_real_01_evidence/phase3_real_upstream.json` 启动 Rust 内核：
  - Clash API `127.0.0.1:19090`: `PASS`
  - mixed inbound `127.0.0.1:11080`: `PASS`
  - `/version`: `PASS`
  - `/proxies`: `PASS`
- `curl -x socks5h://127.0.0.1:11080 https://httpbin.org/ip`: 仍 `FAIL`
  - app log 仍出现 `REALITY handshake failed ... tls handshake eof`

## Live Validation Limitation

- 当前机器解析 `hk08.ctcxianyu.com` 仍返回 `198.18.1.79`
- 直接指定公共 DNS（`@1.1.1.1` / `@8.8.8.8`）解析结果仍是同一个 `198.18.1.79`
- 因而当前 Phase 3 现网复测仍然处在 **fake-IP / 基线 DNS 污染环境** 下，无法确认：
  - 现在的 `handshake eof` 是 REALITY 协议仍有剩余差异
  - 还是根本没打到真实服务端

## Conclusion

- `MT-REAL-01-FIX-03` 的**代码级协议路径**已经完成：
  - 不再使用错误的 wrapper 改写路径
  - REALITY `SessionID` 改为 Go 协议格式
  - `auth_key` 改为来源于 TLS 同一把 X25519 ECDHE key share
- 但 **Phase 3 真实服务器验收** 在当前机器上仍是 `ENV-LIMITED`：
  - 需要一个不被 fake-IP 污染的网络环境，或明确的真实节点 IP，才能最终判定 live handshake 是否彻底恢复
