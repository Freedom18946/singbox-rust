<!-- tier: S -->
# 当前上下文（Active Context）
> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。
---
## 战略状态
**当前阶段**: MT-REAL-01-FIX-02 已完成 — REALITY `public_key` base64url 兼容已修；Phase 3 当前前移到真实握手期阻断
**Parity**: 52/56 BHV (92.9%)，以 `labs/interop-lab/docs/dual_kernel_golden_spec.md` 为准
**当前阶段焦点**: 真实双内核联测收口。Phase 1 PASS；Phase 2 有效矩阵 30 PASS / 7 FAIL；Phase 3 已拿到真实订阅，域名型 VMess/VLESS 注册阻断与 REALITY `public_key` base64url 兼容阻断都已修复，当前新的真实出站阻断是 REALITY 握手期 `tls handshake eof`

## 最近闭环（2026-04-14）

### MT-REAL-01-FIX-02: REALITY `public_key` base64url 兼容 — 已完成

- 修复 `crates/sb-tls/src/reality/config.rs` 的 REALITY client public key 解析：
  - 保留原有 64-char hex 支持
  - 新增 43-char base64url raw（no padding）支持
  - 新增 44-char base64url padded 支持
  - decode 后强制必须是 32-byte X25519 public key
- `RealityClientConfig::validate()` 与 `public_key_bytes()` 已统一走同一条 decode helper
- `short_id` / server-side private key 格式未改
- 验证状态：
  - `cargo test -p sb-tls` PASS（96/96）
  - `cargo clippy --workspace --all-features --all-targets -- -D warnings` PASS
  - `cargo test -p sb-adapters` PASS
  - `cargo test -p interop-lab` PASS（29/29）
  - `cargo test -p sb-core` ENV-LIMITED：仍是 `dns_steady` 在当前机器的 DNS 环境问题，不是本次改动回归
- 回到 Phase 3 复测后确认：
  - Rust 可正常加载真实订阅配置并启动 `19090/11080`
  - 旧阻断 `public_key must be 64 hex characters` 已彻底消失
  - 新阻断前移到真实握手阶段：`REALITY handshake failed ... tls handshake eof`
- 报告：`agents-only/mt_real_01_fix_02.md`

### MT-REAL-01-FIX-01: 域名型 VMess/VLESS 出站注册阻断修复 — 已完成

- 修复 `crates/sb-adapters/src/register.rs` 的 VMess/VLESS 注册路径：
  - 不再把 `server:port` 强制解析为 `SocketAddr`
  - 改为保留 `server: String` + `port: u16`，把 DNS 解析推迟到真实连接阶段
- `crates/sb-adapters/src/outbound/vmess.rs` / `outbound/vless.rs` 已同步改成 host+port 模型
- 新增/更新测试：
  - 域名型 `example.com:443` 现在对 VMess/VLESS 注册应成功
  - 空 server / 零端口继续拒绝
  - app 侧相关集成测试已切到 `server` + `port`
- 验证状态：
  - `cargo test -p sb-adapters` PASS
  - `cargo clippy --workspace --all-features --all-targets -- -D warnings` PASS
  - `cargo test -p interop-lab` PASS（29/29）
  - `cargo test -p sb-core` ENV-LIMITED：`dns_steady::bad_domain_returns_err` 在当前机器被 DNS 劫持解析到 `198.18.1.100`，不是本次改动回归
- 回到 Phase 3 复测后确认：
  - Rust 现在可以加载真实订阅配置并正常启动 `19090/11080`
  - 之前的“域名型 VLESS 启动即 invalid config”阻断已消失
  - 新阻断前移到 REALITY 拨号期：`public_key must be 64 hex characters`
- 报告：`agents-only/mt_real_01_fix_01.md`

### MT-REAL-01 Phase 3: 真实订阅 + GUI 拉取能力探测 — 部分完成 / 当前阻断已定位

- 用户提供 1 条真实订阅；原始内容为 **22** 条链接：`21 x vless` + `1 x anytls`
- 本机 `GUI.for.SingBox` 已存在同一订阅的本地落盘：
  - `subscribes.yaml` 中可见该 URL 对应订阅项（名称 `CTC2`）
  - GUI 缓存文件 `~/Library/Application Support/GUI.for.SingBox/subscribes/ID_ekfvjidr.json`
  - 最近 `updateTime` 为 **2026-04-13 15:29:02 +08:00**
  - GUI 成功导入 **21 个 VLESS** 节点；`anytls` 未进入该缓存文件
- Rust Phase 3 本地测试配置已生成到 git-ignore 路径 `agents-only/mt_real_01_evidence/phase3_real_upstream.json`
  - 控制面 PASS：`/version`、`/configs`、`/proxies` 可达；`mixed-port=11080`；`selector` / `auto` 组可见
  - 数据面当前仍 BLOCKED：经 `socks5h://127.0.0.1:11080` 访问 `https://httpbin.org/ip` 失败
- 阻断演进：
  - 已修复：域名型 VLESS/VMess 出站注册期 `invalid config`
  - 已修复：REALITY `public_key` 兼容性，现网订阅使用的 43-char base64url 已可通过 validate
  - 当前新阻断：REALITY 握手期 `tls handshake eof`
  - 环境因素仍在：当前网络环境下，订阅域名解析结果落到 `198.18.1.x` fake-IP 段，说明现网 DNS 受基线 TUN/代理影响
- 当前结论：GUI 的“拉取订阅并解析 VLESS 节点”能力已确认；Rust “真实 VLESS 上游连通”下一步需要继续排 REALITY 握手期差异，或换用不触发该路径的真实 SS/Trojan/VMess 节点
- 报告：`agents-only/mt_real_01_phase3_subscription_probe.md`

### MT-REAL-01 Phase 1-2: 真实双内核联测首轮 — 已完成（Phase 3 待环境）

- **不是** parity completion；是 maintenance 线下的真实双内核验证
- Phase 1：`cargo build -p app --features acceptance,clash_api --bin app` + Rust Clash API `127.0.0.1:19090` 冒烟
  - `/version` `/configs` `/proxies` 全 200
  - `/traffic` `/connections` `/logs` `/memory` WS Upgrade 全 101
  - 端口按要求回收确认
- Phase 2：`interop-lab` strict+both 首轮先暴露两个 harness/blocker
  - `p1_sniff_rule_action_tls` 缺失 `payload_tls_client_hello` 执行支持
  - 同 case 的 Rust `ready_path` 误写成 `/healthz`（应探 `/version`）
- 进一步发现：`acceptance,clash_api` 构建只够控制面冒烟，不含 strict 双核数据面所需 adapter/protocol builder
  - 补 `cargo build -p app --features acceptance,parity --bin app` 后，strict+both 37 case 有效矩阵为 **30 PASS / 7 FAIL**
- 当前 7 个 FAIL 归因：
  - Go/环境侧：`p1_fakeip_cache_flush_contract`、`p1_gui_group_delay_replay`
  - 已知 Rust GUI-cosmetic 侧：`p1_gui_connections_tracking`、`p1_gui_full_session_replay`
  - 双侧/环境或 soak 门限：`p2_connections_ws_soak_dual_core`
  - 协议本地联通双侧共同失败：`p2_vless_dual_dataplane_local`、`p2_vmess_dual_dataplane_local`
- 证据：
  - `agents-only/mt_real_01_evidence/phase2_both_matrix_effective.tsv`
  - `agents-only/mt_real_01_evidence/phase2_both_cases_after_parity.log`
  - `agents-only/mt_real_01_phase1_phase2.md`

## 最近闭环（2026-04-12）

### MT-GUI-04: 声明完成能力全量逐项验收 — 已完成

- **不是** parity completion；是对所有声明完成项的 exhaustive per-capability acceptance sweep
- 从 golden spec §S3 + GUI kernel.ts + MT-DEPLOY-01 + MT-GUI-01/02 枚举出 55 项能力
- 6 个类别：启动/生命周期(5) + 控制平面API(21) + 流量面(17) + 订阅(5) + 可观察性(5) + 关闭(2)
- 双内核同时运行 + mock 公网 → 逐项测试每一项能力
- **结果：55/55 通过，0 FAIL，0 NEW FINDING**
  - 35 PASS-STRICT (63.6%)
  - 7 PASS-DIV-COVERED (12.7%) — 全部挂到 DIV-M-005..011
  - 13 PASS-ENV-LIMITED (23.6%) — 全部有 interop-lab 真实 WS 覆盖
- 报告：`mt_gui_04_acceptance.md`、`mt_gui_04_matrix.md`、`mt_gui_04_capability_inventory.md`、`mt_gui_04_gap_list.md`
- 证据：`mt_gui_04_evidence/raw_sweep.txt` + `exhaustive_sweep.sh`

### MT-GUI-03: GUI 双内核差异归类 — 已完成（仍生效）

- 10 项差异全部归类：5 Covered + 2 Non-Blocking + 1 Env-Limited + 2 Extension
- 新增 DIV-M-010 / DIV-M-011（COSMETIC，无 oracle 变更）

### MT-GUI-02/01/DEPLOY-01 — 已完成（仍生效）

- MT-GUI-02: 35 场景，32 PASS-STRICT / 1 ENV-LIMITED / 1 NEW / 1 CONFIRMED / 0 FAIL
- MT-GUI-01: 15 场景，10 PASS-STRICT / 4 ENV-LIMITED / 1 NEW
- MT-DEPLOY-01: 9 项部署链全 PASS-STRICT

## 当前验证事实

- 55 项声明完成能力全部逐条清账，无"粗颗粒已过、细项未清"空白
- 7 个 COSMETIC DIV (M-005..011) 覆盖所有已知差异
- 4 个 BHV (SV.2 provider + LC.3 service isolation) 因 Go 侧结构限制无法双核测试（不变）
- 双内核 GUI-shape 配置启动 + Clash API REST/WS 全面可达
- SOCKS5 数据面：HTTP/HTTPS/SSE/chunked/1MiB/slow/早关/RST/dead-port 全部双侧一致
- 订阅拉取（Bearer + ETag + 304）+ 配置解析双侧通过

## 环境限制项

- WS 探测用 curl probe（真实 WS 由 interop-lab p0/p1/p2 案例覆盖）
- GUI 桌面二进制未构建（通过读 GUI 源码复现 API 调用）
- 真实上游代理链路 / Docker / k8s：未测试

## 当前默认准则

- 全量逐项验收已完成，维护状态继续
- 不把验收结果改写成 parity completion
- 不推进 public RuntimePlan / PlannedConfigIR / generic query API
- 不恢复 .github/workflows/*
