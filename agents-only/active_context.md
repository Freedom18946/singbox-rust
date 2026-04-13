<!-- tier: S -->
# 当前上下文（Active Context）
> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。
---
## 战略状态
**当前阶段**: MT-REAL-01 Phase 3 订阅实探已启动 — GUI 订阅拉取已确认，Rust 真实 VLESS 数据面被新阻断卡住
**Parity**: 52/56 BHV (92.9%)，以 `labs/interop-lab/docs/dual_kernel_golden_spec.md` 为准
**当前阶段焦点**: 真实双内核联测收口。Phase 1 PASS；Phase 2 有效矩阵 30 PASS / 7 FAIL；Phase 3 已拿到真实订阅，但当前 Rust `vless` 域名型出站注册 + 现网 fake-IP DNS 环境共同阻断真实出站验证

## 最近闭环（2026-04-14）

### MT-REAL-01 Phase 3: 真实订阅 + GUI 拉取能力探测 — 部分完成 / 当前阻断已定位

- 用户提供 1 条真实订阅；原始内容为 **22** 条链接：`21 x vless` + `1 x anytls`
- 本机 `GUI.for.SingBox` 已存在同一订阅的本地落盘：
  - `subscribes.yaml` 中可见该 URL 对应订阅项（名称 `CTC2`）
  - GUI 缓存文件 `~/Library/Application Support/GUI.for.SingBox/subscribes/ID_ekfvjidr.json`
  - 最近 `updateTime` 为 **2026-04-13 15:29:02 +08:00**
  - GUI 成功导入 **21 个 VLESS** 节点；`anytls` 未进入该缓存文件
- Rust Phase 3 本地测试配置已生成到 git-ignore 路径 `agents-only/mt_real_01_evidence/phase3_real_upstream.json`
  - 控制面 PASS：`/version`、`/configs`、`/proxies` 可达；`mixed-port=11080`；`selector` / `auto` 组可见
  - 数据面 BLOCKED：经 `socks5h://127.0.0.1:11080` 访问 `https://httpbin.org/ip` 直接失败
- 新阻断定位：
  - Rust bug：`crates/sb-adapters/src/register.rs` 中 `parse_required_outbound_socket_addr()` 强行把 `server:port` 解析为 `SocketAddr`，导致**域名型 VLESS 出站全部在注册期失效**
  - 环境因素：当前网络环境下，订阅域名解析结果落到 `198.18.1.x` fake-IP 段，说明现网 DNS 受基线 TUN/代理影响；简单本地域名转 IP workaround 不可靠
- 当前结论：GUI 的“拉取订阅并解析 VLESS 节点”能力已确认；Rust “真实 VLESS 上游连通”尚未通过，需额外真实 SS/Trojan/VMess 节点或先修复域名型 VLESS 出站注册
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
