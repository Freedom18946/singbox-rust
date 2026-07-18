<!-- tier: B -->
# REALITY active-probing 差分与规范 server 重写（Go vs Rust）

> 交付物 #1（DoD）。本卡是 `DEV-REALITY-01`（golden_spec S4，ARCH-LIMIT）下"不得伪造关闭"
> 四项 OPEN 尾巴之一：**active-probing 抵抗**。
> **纪律**：REALITY 无 S3 BHV-ID，不进 52/56 分母——本文件**不声称任何 parity 数字移动**。
>
> **2026-07-18 supersession:** 本文件下方 `enable_fallback=false` 与 Rust inbound Vision
> 记录保留为当时差分。A1 v3 已拒绝关闭 fallback，并用 Go Vision→Rust Vision 反向 lane
> 关闭 framing；当前状态以 `agents-only/active_context.md` 与 golden spec 为准。

## 0. Scope / 权威源

- 规范参照：`github.com/metacubex/utls@v1.8.4/reality.go`（`RealityServer`），薄封装在
  `go_fork_source/sing-box-1.13.13/common/tls/reality_server.go:180`。
- Rust 落位：`crates/sb-tls/src/reality/{server,handshake,auth,config,tls_record}.rs`。
- golden_spec S2 维度：Traffic（`traffic_mismatches`）、Connections（`connection_mismatches`）；
  TLS 握手无专用维度。最近似 S3 BHV：`BHV-DP-005`（direct connect）、`BHV-DP-011`
  （route.final unmatched）、`BHV-LC-007/008/009`（graceful shutdown / close-notify / cleanup）。
- S4 排除：唯一相关登记偏差 = `DEV-REALITY-01`（tag=ARCH-LIMIT），active probing 明文记为 open。

## 1. Go 规范 server 行为（reality.go）

1. 顶部**无条件 dial target**（`reality.go:326`），读任何 client 字节前。
2. `realityMirrorConn`（`:38-50`）：client 每读一字节即镜像转发给 target，ClientHello 边解析边
   到达真实 target。
3. auth 在 **SessionID**（AES-**256**-GCM，key=AuthKey=HKDF-SHA256(salt=random[:20], info="REALITY",
   ikm=X25519(serverPriv, clientKeySharePub))；nonce=random[20:32]；AAD=零化 sessionId 的原始
   ClientHello）。plaintext[4:8]=unix time、[8:16]=short_id。
4. auth 成功：劫持，借 target ServerHello 的 cipher/keyshare 组 + record framing 字节长度，用自签
   ed25519（signature=HMAC-SHA512(AuthKey) over ed25519 pubkey）**本地终结** TLS，丢弃 target 真握手。
5. **任何非认证**（普通 TLS / SNI 不匹配 / 无 keyshare / 解密失败 / short_id/time 不符）→ 保持
   mirror → **透明中继**：真实 target 完成握手出示真证书。error 只在中继跑完后才返回 caller，
   **绝不 RST / 绝不提前关 / 绝不自造响应**。

> 注：agent 初报"AES-128-GCM"经互通证据纠正为 **AES-256-GCM**——Rust client 的
> `seal_reality_session_id`（handshake.rs:1104）用 `AES_256_GCM` 且被 Go server 接受（前向 fixture
> 通过），故 Go 侧亦为 AES-256-GCM。

## 2. Rust 现状（重写前）与差分

| # | 维度(S2) | Go | Rust（重写前） | 探测可区分 | 处置 |
|---|---------|-----|---------------|-----------|------|
| **D-probe** | Traffic/Conn；近 DP-011/LC-008 | 非认证一律透明中继真实 target（真证书） | 普通TLS/无扩展/无SNI/解析失败 → `parse_and_buffer_client_hello` 硬 `Err`（旧 server.rs:246-248）→ 调用方 `warn!`+drop socket（vless.rs:295 / trojan.rs:358） | **是（严重）** | **已修**：非认证一律中继 |
| **D-auth** | —（无 TLS 维度） | auth 在 session_id（AES-256-GCM） | 自定义扩展 `0xFFCE` + `SHA256(shared‖short_id‖random)`（非规范，无真实 client 会发） | 间接（真 client 全落中继/无法认证） | **已修**：改 session_id AEAD |
| D-SNI | Connections | 无 SNI / SNI 不匹配 → 中继 | 无 SNI → 硬 `Err`；SNI 不匹配 → fallback | 是（无 SNI 情形） | **已修**：并入中继 |
| **D-serverhello** | Traffic（成功路径） | 借 target ServerHello cipher/keyshare/record-framing 字节长度伪造 | rustls 默认 ServerHello；仅偷 cert 模板 | 否（需有效 auth 才可达，探测者到不了） | **残余 ARCH-LIMIT**（rustls 不暴露字节级握手伪造） |
| D-timing | Traffic 时序 | accept 时 dial target；镜像转发 CH | 读 CH 后即 dial+relay | 极小（见 §4） | 缓解至可忽略；精确跨网时序登记残余 |
| D-fallback-toggle | 配置面 | 无开关，恒中继 | `enable_fallback=false` → 认证失败仍 drop | 是（该配置下） | 保留开关、默认 true；登记 footgun |

## 3. 已实施改动（重写后）

- **Phase 1 规范 session_id 认证**：新增 `handshake.rs::open_reality_session_id`（镜像
  `seal_reality_session_id`：AES-256-GCM、nonce=random[20:32]、AAD=零化 sessionId 的原始 CH）+
  `open_reality_client_auth`（从 key_share 取 client 公钥、X25519、`derive_auth_key`、AEAD open、
  取 short_id/time）。server.rs `authenticate()` 用之替换 0xFFCE。`config.rs::accepts_reality_short_id`
  对齐 Go：空 short_ids → 只接受全零 short_id（非"接受全部"）。
  证据：`handshake::tests::test_reality_session_id_seal_open_round_trip`（client seal → server open
  往返，含错误 server key 拒绝）。
- **Phase 2 中继架构**：`server.rs` `handle_handshake` 重构为 `read_first_record`（先缓冲原始首
  record）+ `authenticate`（纯内存判定）：**任何非认证/不可解析输入一律 `fallback_to_target` 中继**，
  `accept()` 对可读的非认证连接不再返回 `Err`。调用方 vless/trojan inbound 未改（现成中继 Fallback）。
- **Phase 3 成功路径 + rustls fork patch**：保持 rustls 终结 + ed25519 HMAC temp cert；client 侧
  `RealityVerifier`（handshake.rs:920）已 HMAC-only 校验。**关键 patch**：Chrome 指纹 client 的
  `signature_algorithms` 不含 ed25519，stock rustls server 拒发未 advertise 的 CertVerify scheme
  （`NoSignatureSchemesInCommon`，server/tls13.rs:750）。在 `vendor/rustls` 加 opt-in
  `ServerConfig::reality_force_signature_scheme`（默认 None，仅 REALITY 设 `Some(ED25519)`），
  在 `server/tls13.rs` handle_client_hello 处强制注入 ED25519。与 fork 的 client 侧既有 ed25519
  容忍对称（前向 Go-server↔Rust-client fixture 已证 client 容忍）。

## 4. D-timing 分析（为何非阻断）

Go 在 TCP accept 时 dial target；Rust 在读完 CH（client accept 后立即发送）后 dial。两者 target 均
在 **accept 后约 1 RTT** 被联系（client CH 立即到达），故两模型的"target 首响应时刻"实质一致。
精确跨网时序 parity 受网络抖动主导，属 tier-2/external，登记为 NON-gating 残余。

## 5. 本卡闭合（本地可判定，无 skip、真断言）

`crates/sb-tls/tests/reality_active_probing.rs`（decoy rustls TLS server + `RealityAcceptor`→decoy）：

1. `plain_tls_probe_wrong_sni_is_relayed_to_decoy` —— 普通 TLS + 未接受 SNI → 中继；probe 观测到
   **与直连 decoy 相同的证书 DER**（含 oracle 直连对照）。**本卡新覆盖**（旧行为=drop）。
2. `plain_tls_probe_accepted_sni_no_auth_is_relayed` —— SNI 接受但无有效 session_id → 中继、cert 相等。
3. `malformed_handshake_record_is_relayed_not_dropped` —— 畸形/非 REALITY record → 中继（decoy 响应
   TLS record，首字节 0x16/0x15），**非 drop**（旧行为=硬 Err+drop 的回归护栏）。
4. `authenticated_reality_client_reaches_proxy` —— 正控 + **Rust-server↔Rust-client 规范互通**：
   有效 session_id → 认证 → ed25519 temp cert 终结 → client HMAC 校验通过 → 收到 `PROXY_PAYLOAD`
   （区别于 decoy banner）。

全 4 测试 PASS；`sb-tls` 全量 121 lib + 4 harness + 1 e2e PASS；boundaries 0 违规；consistency exit0。

## 6. 反向跨核 empirical fixture（2026-07-18 CLOSED）

- A1 fixture 升级为 bidirectional v2：新增 Go `with_utls` REALITY client → Rust
  `RealityAcceptor` + VLESS inbound → 本地 HTTP target 正向 token oracle。
- 反向 lane 使用 standard VLESS flow（空 flow）隔离 REALITY server 认证/TLS 互操作；Rust inbound
  Vision framing 不在此 lane 内，继续作为独立功能缺口。
- 一键入口仍为 `make verify-reality-local`；配置校验、forward 两 lane、reverse lane、Rust phase
  probe 与四个负控共同决定 verdict。精确重复次数与 per-run 证据只在
  `labs/interop-lab/reality_local_fixture/evidence/round-summary.json`。
- 结果：Go client 接受 Rust ed25519 temp cert/HMAC，完成 REALITY session_id auth、VLESS 请求及
  HTTP token 往返。此前“by construction only”现已被真实 Go client empirical evidence 取代。

## 7. 残余 OPEN（NON-gating，登记）

- **D-serverhello**：成功路径 ServerHello 的 cipher/keyshare/record-framing 借用 = rustls ARCH-LIMIT
  （rustls 不暴露字节级握手伪造）。探测者无有效 auth 到不了此路径 → **非 active-probing 向量**；对已
  认证 client 做 target 二次指纹时可见。同 `DEV-REALITY-01` 同类限制。
- **精确跨网中继时序 parity** = tier-2/external。
- **可配置 MaxTimeDiff 时间窗强制**：session_id 的 unix time 已解出但未 gate（对齐 Go 默认
  `MaxTimeDiff==0` 不校验）；未加 `max_time_difference` config 字段（避免 17 处字面量 churn）。
- **`enable_fallback=false` footgun**：Go 无此开关（恒中继）；置 false 时认证失败仍 drop，探测可区分。
  默认 true；文档登记。
- **Rust inbound Vision framing**：反向 fixture 为隔离 REALITY server 互操作使用 standard VLESS
  flow；`xtls-rprx-vision` inbound data framing 未由本卡验证。
- real-network camouflage + healthy-cohort = tier-2/3 external（本卡范围外）。

## 8. 边界

- 未动已封箱 ClientHello 指纹（Chrome-150 / BoringSSL 序 / GREASE / JA4）。
- 未碰 `a0_reality_spike/`、`.github/workflows/*`、Wails desktop。
- 未声称 52/56 BHV 移动（REALITY 无 BHV-ID）。
- vendored rustls patch 为 opt-in、默认 None、向后兼容（唯一 struct 字面量在 builder.rs 已更新；
  内部 `server_config_for_rpk` 用 builder）。
