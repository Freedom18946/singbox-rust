<!-- tier: B -->
# Goal Prompt — Clash API strict-parity 线收口

> 交接给独立 AI 执行。此文件自包含,但**权威状态仍以 `agents-only/active_context.md` 为准**。
> 若本文与 active_context 冲突,以 active_context 为准并在收尾时同步本文。
>
> **CLOSED 2026-07-23** — 结果见同目录 `acceptance.md`;本文仅保留为历史执行输入。

---

## 你的角色与目标

你在 `singbox-rust`(Go sing-box 1.13.13 的 Rust 重写,须与 GUI.for.SingBox 完全兼容)上工作。
Clash API strict-wire-parity 的**代码实现已提交并 push**(commit `9703879e`),但这条线**尚未收口**:
活体双核(Go ⇄ Rust)interop case 尚未 promote,BHV 覆盖变动未核实,文档未更新。

**你的目标:把 Clash API strict-parity 线收口到可归档状态。** 具体交付:
1. 活体双核跑通已改的 strict interop cases,证明 Rust 控制面 wire 输出与 Go 1.13.13 逐字段对齐。
2. 用 golden_spec S6 公式**重新核算** dual-kernel BHV 覆盖,确认哪些 BHV-ID 从 open 转 both/closed(不要照抄下方推测数字)。
3. 更新 `active_context.md`(唯一权威)+ 归档审计草稿。
4. triage 一个已知并行测试 flake(见下),给出修复或登记为已接受偏差的结论。

---

## 先读这些(启动必读)

- `agents-only/active_context.md` —— 当前易变状态唯一权威(阶段/parity/门禁)。
- `agents-only/init.md` —— 启动检查清单。
- `labs/interop-lab/docs/dual_kernel_golden_spec.md` —— **行为对齐权威**。收口必须:
  - S2/S3 定位 BHV-ID;S4 排除已知偏差;S5 promote 优先级;**S6 公式算覆盖率(禁止手编数字)**;
    S8 Go 配置字段映射与端口约定。
- `agents-only/pending/clash_api_strict_parity_audit.md` —— 本次改动的逐项 DIV-M-001..012 决策
  (7 FIX / 5 KEEP)与 strict promotion mapping,是这批改动的原始依据。
- `agents-only/reference/AGENT-DEVELOPMENT-GUIDELINES.md`。
- `labs/interop-lab/README.md` —— interop-lab CLI 与 build 前置。

---

## 已落地的改动(commit `9703879e`)

`feat(clash-api): align strict wire parity with sing-box 1.13.13`,22 个 tracked 文件。实现了审计里的 FIX:

| DIV | 内容 | 关键落点 |
|---|---|---|
| M-001 | `POST /cache/fakeip/flush` 返回 204(原 DELETE + JSON 200) | `sb-api/clash` |
| M-004 | connections websocket 遵守 `?interval=` ticker | `sb-api/clash/websocket.rs` |
| M-005 | `GET /dns/query` 返回 DNS-message 字段(Status/Question/Answer/Server/flags) | `sb-api/clash/handlers.rs` |
| M-006 | `GET /configs` 零 port 字段、null tun、无 interface-name;**mode 原样小写透传** | `handlers.rs` |
| M-007 | proxies 输出 Go wire 投影(type/name/udp/history + group all/now) | `handlers.rs` |
| M-011 | traffic 上下行总量跨连接关闭累计 | `sb-core` ConnTracker |
| M-012 | fakeip reset 清 mappings 但保留 allocation cursor;分配走 Go `Create()`-advances-first(start=base+1,首次 Create 得 base+2) | `sb-core/dns/fakeip.rs` |

interop cases / Go oracle configs / orchestrator / diff_report / case_spec 已同步 strict 契约。

> **M-006 的 mode 语义已核实,勿回退**:Go `server.go:157/223` 对 cache-load 原样透传、
> 仅 SetMode 才 canonical 化;GUI `frontend/src/enums/kernel.ts` 的 `ClashMode` 枚举值是**小写**、
> 且 `tray.ts:197`/`OverView.vue:256` 用 `===` 严格比较 —— 故 `mode` 必须返回小写。

---

## 执行步骤

### 1. 建立活体双核前置

```bash
# Rust app 二进制须含 clash_api
cargo build -p app --features acceptance,clash_api,adapters --bin app
# Go oracle(sing-box 1.13.13,with_clash_api)按 golden_spec S8 / interop-lab 脚本约定构建
```

Go oracle 构建/管理见 `labs/interop-lab/scripts/` 与 README「External Clash API replay」段
(`MANAGE_GO_ORACLE=1` 及相关 env)。

### 2. 逐 case 跑 `--kernel both` 并 diff

本次触及的 cases(以 `git show --stat 9703879e` 为准复核清单):

- `p0_clash_api_contract_strict`
- `p1_clash_mode_rule_switch_via_socks`
- `p1_dns_query_endpoint_contract`
- `p1_fakeip_cache_flush_contract`
- `p1_fakeip_dns_query_contract`
- `p1_gui_connections_tracking`
- `p1_gui_proxy_switch_replay`
- `p2_connections_ws_soak_dual_core`

```bash
cargo run -p interop-lab -- case run <case> --kernel both
cargo run -p interop-lab -- case diff <case>
```

要求:normalized diff 干净、strict 断言全过。记录 run ID(格式 `<ts>-<uuid>`)。
差分失败**先查 golden_spec S4** 排除已知偏差,再动源码。

### 3. 核算 BHV 覆盖(禁止照抄)

审计的 strict promotion mapping **推测**解锁:`DP-016/017`、`CP-010`、`CP-021`、
`CP-001`/`LC-004`/`DP-029`、`CP-003/004`、`CP-006`(connection 维度)、M-011 post-close 总量。
**这是待验证的推测,不是结论。** 你必须:

- 对每个 case 通过后,按 golden_spec S3 确认它实际覆盖的 BHV-ID 及 kernel_mode(both/…)。
- 用 **S6 公式**重算 closed/both/total,得出新 parity 数字。
- 当前 active_context 记录基线为 `75/79 BHV`、inventory `65 both / 126 total`(易变,以文件实时值为准)。
  只有 case 真过 + S6 重算才允许写新数字,且只写进 active_context。

### 4. triage 并行测试 flake

`crates/sb-api/tests/clash_http_e2e.rs::test_flush_dns_cache` 在全 binary 并行下约 1/10 概率
返回 502(`POST /dns/flush` 期望 204)。串行(`--test-threads=1`)与隔离单跑恒过。根因疑为
**进程级全局 DNS resolver 状态在并发测试间被清**(与 2026-07-18 `sb-tls/src/global.rs` 证书竞态同型)。

结论二选一,并给证据:
- **修**:给共享全局状态加进程级测试锁 + RAII 快照恢复(参照 sb-tls global.rs 的做法),
  跑 ≥4 轮 16-thread stress 证明消除。
- **登记**:若判定为纯测试基建、非运行时逻辑,按偏差登记并在 active_context 注明,不阻断收口。

### 5. 门禁

至少:sb-api 全测、sb-core focused fakeip/dns、interop-lab、`make boundaries`(严格,失败先
`make boundaries-report` 归因)、consistency(`06-scripts/verify-consistency.sh`)、clippy(仓库策略
口径,非 `--all-targets`——注意 `--all-targets` 下有**预存**的 `suffix_trie_bench` bench_api
feature-gate 报错,与本线无关)、fmt、diff-check。

### 6. 收尾文档

- 更新 `agents-only/active_context.md`:顶部加一条 Resume 段(≤300 行纪律,写前先删 >7 天旧段),
  记录 run ID、S6 重算后的 parity、flake 结论。
- 审计草稿 `agents-only/pending/clash_api_strict_parity_audit.md` 与本 goal 文件:线闭合后
  `git mv` 进 `agents-only/archive/{track}/`;未闭合则留 `pending/`。
- 若 cases 全过且覆盖有净增,提交(直接落 main,仓库惯例线性提交)并 push;commit 用
  conventional 风格(`test(interop): promote clash-api strict dual-kernel cases` 等)。

---

## 约束与非目标

- **Task subagent 必须 `model: "opus"`**(haiku/sonnet 返回 403)。
- 任何易变数字只允许活在权威源(parity → active_context + golden_spec;目录树 → `agents-only/README.md`)。
  其它文档引用只给指针,不抄数字。
- 不在仓库根目录新建工作目录;产物落 `agents-only/`,关闭即归档。清理类任务(ignored/scratch/stale)
  **先问用户**。`.claude/` 永不 track/commit。
- 不恢复 `.github/workflows/*`;不把维护误写成 parity completion;不搞 WP-30k 微卡化。
- KEEP 项(M-002/003/008/009/010)是**有意偏差**,勿"顺手对齐":
  M-008 非 Linux 内存 0、M-010 Rust 500 vs Go 合成 fake-IP 200 等,按审计理由保留。
- 非目标:超出这 8 个 case 的其它 Clash API 端点;REALITY / 数据面行为(另有线)。

## 完成判据(DoD)

- 8 个 case `--kernel both` 全过、normalized diff 干净,run ID 已记。
- S6 重算的 parity 已写进 active_context(仅当真有 case 通过支撑)。
- flake 有明确结论(修复+stress 证据,或偏差登记)。
- 所有门禁 PASS,已提交并 push。
- 审计草稿 + 本文件按闭合状态归档或留存,active_context 与实际一致。
