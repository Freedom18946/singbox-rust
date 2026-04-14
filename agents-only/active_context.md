<!-- tier: S -->
# 当前上下文（Active Context）
> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。
---
## 战略状态
**当前阶段**: MT-REAL-01-ENV-01 已完成 — fake-IP DNS 污染已隔离，REALITY live dataplane 失败已确认不是“连到 198.18.x.x 假 IP”，而是剩余协议层阻断  
**Parity**: 52/56 BHV (92.9%)，以 `labs/interop-lab/docs/dual_kernel_golden_spec.md` 为准  
**当前焦点**: 基于真实公网 IP 的 Phase 3 结果推进下一卡 FIX-04；不要再把 `tls handshake eof` 归因到 DNS fake-IP

## 最近闭环（2026-04-14）

### MT-REAL-01-ENV-01: DNS 隔离 + REALITY 握手验证 — 已完成，结论指向协议残差

- 基于 `agents-only/mt_real_01_evidence/phase3_real_upstream.json` 抽取 **19** 个订阅域名，使用固定 DoH IP 旁路系统 DNS 解析，生成：
  - `agents-only/mt_real_01_evidence/phase3_domain_ip_map.md`
  - `agents-only/mt_real_01_evidence/phase3_domain_ip_map.json`
  - `agents-only/mt_real_01_evidence/phase3_ip_direct.json`
- Rust 内核用 `phase3_ip_direct.json` 启动后继续控制面 PASS：
  - Clash API `127.0.0.1:19090` → `/version` 200
  - `/proxies` 可见全部 `21` 个真实 `vless+reality` 节点 + `1` 个无效控制节点
  - 启动日志未再出现 DNS 解析失败 / `198.18.x.x` fake-IP 相关报错
- 逐节点 selector + SOCKS 冒烟结果：
  - **0/21** 真实 REALITY 节点成功拿到 `https://httpbin.org/ip` 出口 IP
  - **19/21** 为 `tls handshake eof`
  - **1/21** 为 `timeout`（`HK-A-BGP-2.5倍率`）
  - **1/21** 为 `REALITY requires DNS server name`（`UK-A-BGP-0.5倍率`）
  - 控制节点 `__phase3_invalid_vless` 为 `connection refused`
- 关键证据：
  - `agents-only/mt_real_01_evidence/phase3_reality_matrix.md`
  - `agents-only/mt_real_01_evidence/phase3_reality_matrix.json`
  - `agents-only/mt_real_01_evidence/phase3_runtime/phase3_ip_direct_rust.log`
- 关键判定：
  - 对 **19** 个 `tls handshake eof` 节点，进程级连接观测都命中了对应真实公网 `server_ip:server_port`
  - 所以当前 REALITY 失败已从“可能仍连到 fake-IP”收敛为“确实连到真实节点后仍握手失败”
  - **FIX-03 未取得 live 成功验收**；下一步应进入 **FIX-04**，继续对齐 REALITY 握手细节
- 报告：`agents-only/mt_real_01_env_01.md`

### MT-REAL-01-FIX-03: REALITY 客户端握手协议重写（Go 对齐）— 已提交，live 仍未打通

- 已提交：`f58916e8 fix(reality): align client handshake with rustls session ids`
- 代码侧完成内容：
  - REALITY client 从旧的 `ClientHello` stream-wrapper 路径切到 rustls `SessionIdGenerator`
  - 自定义 X25519 key-share，让 REALITY `auth_key` 直接来自 TLS 同一把 ECDHE
  - `SessionID` 改为 Go REALITY 使用的 32-byte 密文格式
  - verifier 改为读取共享握手态并要求临时证书校验命中
- 本机补验：
  - `cargo build -p app --features acceptance,parity --bin app` PASS
  - `cargo test -p sb-tls` 在本机仍有 1 个现存环境项 `global::tests::test_chrome_mode_non_empty`，与本卡 REALITY live 结论无关
- 报告：`agents-only/mt_real_01_fix_03.md`

### MT-REAL-01-FIX-02 / FIX-01 / Phase 3 Probe — 已完成，前置阻断已清

- FIX-02：REALITY `public_key` 支持 base64url；旧错误 `public_key must be 64 hex characters` 已消失
- FIX-01：域名型 VMess/VLESS 出站注册改为 host+port 延迟解析；旧错误 `invalid config` 已消失
- Phase 3 probe：GUI 订阅缓存已确认含 `21` 个 VLESS 节点；Rust 可加载真实订阅并稳定启动 `19090/11080`
- 当前剩余 live dataplane 阻断只剩 REALITY 握手层

### MT-REAL-01 Phase 1-2 — 已完成（维持原结论）

- Phase 1：Rust Clash API 冒烟 PASS；端口回收 PASS
- Phase 2：strict+both 有效矩阵 **30 PASS / 7 FAIL**
- 当前 7 个 FAIL 仍归因于 Go/环境、GUI cosmetic、soak 门限、以及本地协议联通双侧共同失败；本卡未改变该结论

## 当前验证事实

- fake-IP DNS 仍存在于基线环境，但已不再是 Phase 3 REALITY 失败的主要解释
- `phase3_ip_direct.json` 证明 Rust 可直接拨到真实公网节点 IP
- 真实节点矩阵中没有任何成功样本，因此 **FIX-03 不能宣告完成 live 握手验收**
- 下一卡应优先分析：
  - `19` 个 `tls handshake eof`
  - `1` 个 `REALITY requires DNS server name`
  - `1` 个真实节点 timeout

## 当前默认准则

- maintenance 线继续；不要把本卡写成 parity completion
- 不改 Go 基线配置，不恢复 `.github/workflows/*`
- Phase 3 敏感配置继续只放 git-ignore 证据目录
- 后续若继续 live 联测，默认复用 `phase3_ip_direct.json` 与 `phase3_reality_matrix.*`
