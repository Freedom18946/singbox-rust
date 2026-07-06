<!-- tier: B -->
# MIG-03 WP04 — scaffold vs adapters 逐协议语义差异审计

Status: PLANNED
Priority: P0
Depends on: 无（可与 Phase A 并行）
Blocks: WP05, WP06
性质: **纯文档包**——不改任何代码。

Primary evidence:

- `crates/sb-core/src/adapter/bridge.rs:1` 自述："Prioritizes sb-adapter registry;
  falls back to scaffold implementations"；registry 查询点 `:595`（inbound）、
  `:604`（outbound）。
- scaffold inbound 实现：`crates/sb-core/src/inbound/socks5.rs`（约 800 行）、
  `inbound/http_connect.rs`、`inbound/mixed.rs`（mixed 内部复用前两者）。
- scaffold outbound 实现：`crates/sb-core/src/outbound/` 下 `socks5.rs`、
  `socks5_udp.rs`、`udp_socks5.rs`、`socks_upstream.rs`、`http_proxy.rs`、
  `http_upstream.rs`、`ss/`、`direct.rs`、`direct_simple.rs`、`direct_connector.rs`、
  `block.rs`、`block_connector.rs`、`selector*.rs`（组类见 WP12）。
- 对照物：`crates/sb-adapters/src/outbound/`（25 个协议）与
  `crates/sb-adapters/src/inbound/`（socks/、http.rs、mixed.rs 等）。
- 强制双编译：`crates/sb-adapters/Cargo.toml:61`（features 含 "scaffold"）、
  `app/Cargo.toml:377/:440`。
- 交叉依赖（删除时的雷）：`crates/sb-adapters/src/inbound/socks/udp.rs:18` 引用
  `sb_core::outbound::socks5_udp::UpSocksSession`；
  `crates/sb-core/src/net/udp_upstream_map.rs:3` 同源引用。

## Goal

产出一份**逐协议、逐维度**的语义覆盖矩阵（`mig03_wp04_coverage_matrix.md`），
对每个 scaffold 实现给出三态判定，作为 WP05（补齐）与 WP06（删除）的唯一施工单：

- `ADAPTERS-COVERS`：adapters 实现语义完全覆盖，scaffold 可直接删；
- `GAP`：adapters 缺口（逐条列出缺什么，交 WP05）；
- `SCAFFOLD-ONLY`：仅 scaffold 有的能力/行为（列出，交用户决策：移植 or 放弃）。

## Current Gap

两套实现共存且运行时"registry 未命中就静默走 scaffold"，意味着删除 scaffold
之前必须证明 adapters 版语义等价，否则删除=行为变更。目前没有任何文档记录
两套实现的差异面。

## Non-goals

- 不改代码、不删文件。
- hysteria/hysteria2/naive/quic 家族**不在本包矩阵内**（它们不是 scaffold 双轨，
  是"实现只在 sb-core、注册在 adapters"的错位问题，由 WP07 单独处理）。

## Task Split

1. **协议清单定稿**：以 bridge.rs 中 scaffold 分支实际可构造的 kind 字符串为准
   （读 `build_inbound_service`/`build_outbound_*` 的 match 分支），列出全部
   scaffold 协议。预期至少：direct、block、socks(4/5)、http、mixed、ssh?、
   selector/urltest 组、dns。逐一与 adapters registry 的注册 kind 对照。
2. **逐协议差异审计**，每个协议固定审这些维度（矩阵列）：
   - 配置字段接受面（IR 字段哪些被读、默认值各是什么）；
   - 认证行为（用户名/密码、多用户、匿名回退）；
   - TCP 建连语义（超时、重试、bind_interface/routing_mark 等 socket 选项）；
   - UDP 语义（是否支持、NAT/会话生命周期、报文封装差异）；
   - 错误路径（连接失败映射成什么错误/日志/metrics）；
   - metrics 标签与名称（两套实现打点是否一致）；
   - 读取的 SB_* 环境变量（scaffold 侧大概率更多，逐个列出）；
   - sniff/路由集成点（scaffold inbound 直连 `routing::engine`，adapters 走
     registry context——记录集成差异）。
3. **交叉依赖清单**：grep 找出 adapters/app/tests 对 scaffold 模块符号的全部
   直接引用（如 `UpSocksSession`），每条记录"WP06 删除前必须先解开"的解法建议。
4. **测试资产盘点**：scaffold 实现挂着哪些测试（如
   `app/tests/adapter_bridge_scaffold.rs`）、哪些需要移植到 adapters 侧、
   哪些随删除退役。
5. **三态判定 + D9 策略套用**：矩阵末尾汇总 `SCAFFOLD-ONLY` 项，逐条套用 D9
   （Go 有同等能力 → 移植；Go 无且无消费证据 → DROP；Go 无但有验收/GUI/
   scripts/xtests 消费证据 → 保留登记为 Rust-only 扩展，挂 feature 默认不启用）。
   每条判定附 Go 侧 grep 证据 + 消费面证据；套不进三档的个例按 D18 升级。
   另：Go 有、但两侧都没有的能力 = parity 缺口，登记"发现移交"，不属本轨迹。

## Acceptance

- [ ] `mig03_wp04_coverage_matrix.md` 覆盖 bridge scaffold 分支的**全部** kind，
      每协议 8 个维度无空格（查不到就写"两侧均无此能力"，不许留空）。
- [ ] 每条 GAP 有精确锚点（scaffold 侧 file:line ↔ adapters 侧 file:line 或"缺失"）。
- [ ] 交叉依赖清单完整（至少含 evidence 中已知两条），每条有解法建议。
- [ ] SCAFFOLD-ONLY 项已逐条套用 D9 并记录判定依据（Go 侧证据 + 消费面证据）；
      D18 升级项清零或已获用户答复。
- [ ] `git status` 确认只新增本目录文档。

## 验证命令

```bash
git status --porcelain
# 矩阵中引用的每条 grep 证据可复现
```

## Risks / known traps

- bridge 的 scaffold 分支可能有 kind 别名/兜底 match arm（`_ =>`），漏数一个
  协议就会让 WP06 删出行为洞——以 match 分支为准清点，不要以文件名为准。
- scaffold socks5 inbound 的 UDP 与 adapters socks/udp.rs 存在**共享代码**
  （UpSocksSession），不是纯双轨——这类"半共享"结构要在矩阵里单独标注，
  防止 WP06 一刀切。
- metrics 名称差异属于用户可见行为（Prometheus 面板），别当作等价忽略。

## 发现移交

（执行时填写。）
