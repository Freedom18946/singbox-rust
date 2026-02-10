# 09 TLS 与证书体系（TLS / ECH / Reality / ACME / 证书信任库）

如果说协议是语言，那么 TLS 是“信任”。它既是安全的底座，也常常是对抗封锁与流量识别的舞台。但舞台越大，越需要谨慎：功能要全，默认要稳，风险要讲清。

## 1) 证书信任库（Certificate）

### 1.1 目标

- MUST：支持 `certificate` 配置段，用于定义“默认信任的 CA 列表”与额外证书加载。
- MUST：支持信任库类型 `store`（官方列出）：  
  - `system`（默认）  
  - `mozilla`（Mozilla 列表，移除 China CA）  
  - `chrome`（Chrome Root Store，移除 China CA）  
  - `none`（空列表）

### 1.2 额外证书注入

- MUST：支持直接提供 PEM 行数组：`certificate`。
- MUST：支持从文件加载 PEM：`certificate_path`（并在文件修改后自动重载）。
- MUST：支持从目录加载 PEM：`certificate_directory_path`（并在文件修改后自动重载）。

## 2) TLS 共享能力（Shared / TLS）

### 2.1 基础 TLS 字段

- MUST：支持客户端与服务端两侧 TLS 配置（inbound/outbound）。
- MUST：支持 SNI 控制：`disable_sni`、`server_name`、`insecure`。
- MUST：支持 ALPN 列表、TLS 最小/最大版本（1.0–1.3）。
- SHOULD：支持 cipher_suites（1.0–1.2）与 curve_preferences（含 X25519MLKEM768 等新机制）。

### 2.2 证书校验与 pinning

- SHOULD：支持 `certificate_public_key_sha256`（客户端侧对服务端公钥 pinning），增强对中间人风险的抵抗。
- SHOULD：支持客户端证书（mTLS）：client_certificate / client_key 及对应 path 形式。
- SHOULD：服务端侧支持 client_authentication（no/request/require/verify 等模式）并校验客户端证书。

### 2.3 ECH（Encrypted Client Hello）

- SHOULD：支持 ECH 配置/加载（可从 DNS 或文件加载 config），并提供生成 keypair 的 CLI（`sing-box generate ech-keypair`）。
- SHOULD：在 QUIC 场景中遵循文档限制（文档明确“QUIC 仅支持 ECH”这类限制性描述）。

### 2.4 uTLS（客户端指纹伪装）

- COULD：支持 uTLS fingerprint 选项（chrome/firefox/edge/safari 等）。
- MUST（文档取向）：对 uTLS 的风险做显式提示，并提供更推荐的替代方案（文档明确“并不推荐，存在被指纹识别与维护风险”等观点）。

### 2.5 Reality（特定握手与密钥体系）

- SHOULD：支持 Reality 配置（public_key/private_key、short_id、握手 server + Dial Fields），并提供生成 keypair 的 CLI（`sing-box generate reality-keypair`）。

### 2.6 TLS Fragment / Record Fragment

- SHOULD：支持 `fragment` 与 `record_fragment` 等“握手分片”能力，并明确该能力的适用边界：  
  - 适用于绕过简单明文匹配型防火墙  
  - 不应被定位为对抗强审查的万能手段  
  - 性能代价与回退策略（fallback delay）可配置

### 2.7 kTLS（Linux 内核 TLS offload）

- COULD：支持 Linux 5.1+ 的 `kernel_tx` / `kernel_rx`（仅 TLS 1.3），并遵循文档提示：  
  - tx 可能在 splice(2) 场景提升性能，否则可能退化  
  - rx 通常会退化，默认不建议开启

## 3) ACME 自动签发与 DNS‑01 Challenge

- SHOULD：支持 ACME 字段（domain、data_directory、email、external_account 等），用于自动申请/续期证书。
- SHOULD：支持 `dns01_challenge`：配置后禁用其它 challenge 方法，仅使用 DNS‑01。
- MUST：实现 DNS‑01 provider 字段集合（官方文档示例中出现：`alidns`、`cloudflare`、`acmedns` 等，并可能包含更多 provider）；实现需覆盖官方文档列出的全部 provider 与字段。

## 4) 验收清单

- 证书 store 可切换；额外证书加载可热重载。
- TLS 版本/ALPN/SNI/mTLS/pinning 等按配置生效。
- ECH/Reality/fragment 等高级功能具备清晰开关与故障可诊断性。
- ACME + DNS‑01 可在无人工干预情况下完成签发与续期（在具备外部 DNS 权限的前提下）。

## 来源链接（官方文档）

- Certificate（store/certificate_path 等）  
  https://sing-box.sagernet.org/configuration/certificate/
- TLS（字段全集、ECH/uTLS/Reality/ACME/kTLS/fragment 等）  
  https://sing-box.sagernet.org/configuration/shared/tls/
- DNS01 Challenge Fields（provider 字段）  
  https://sing-box.sagernet.org/configuration/shared/dns01_challenge/
