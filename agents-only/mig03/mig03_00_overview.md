<!-- tier: B -->
# MIG-03 总览 — 调研证据、阶段划分、全局验收

Status: ACTIVE（轨迹进行中；各包状态见各包头部）
立项日期: 2026-07-06
决策背景: 用户否决"新仓库重写 + cp 搬运"方案，确定仓内迁移（strangler-fig）。
技术抉择: 全部可选项已由用户委托按"现实可行性 + 长远维护 + 完美等价 Go 内核
（不计短期成本）"三轴敲定，见 `mig03_01_decisions.md`（D1–D18）。

---

## 1. 调研证据（2026-07-06 实测，作为本轨迹的问题基线）

### 1.1 规模画像

| 对象 | 数值 | 备注 |
|------|------|------|
| sb-core | 108,129 LOC / 280 文件 | 103 features / 1,077 个 `#[cfg(feature)]` / 221 处 `env::var` / 161 个不同 SB_* |
| sb-adapters | 50,756 LOC | register.rs 单文件 4,264 行，几乎全是 trait 适配胶水 |
| app | 39,141 LOC / 133 文件 | 27 个 binary；admin_debug 13,634 LOC 且头部整页 `#![allow(dead_code, ...)]` |
| sb-config | 31,906 LOC | 结构健康（ir/ + validator/v2/），非本轨迹目标 |
| sb-core/router/ | 23,340 LOC | 与 routing/（1,487 LOC）双栈并存，均为活代码 |
| sb-core/dns/ | 21,977 LOC | rule_engine.rs（2,646 行）重复实现域名匹配原语 |
| sb-core/services/ | 14,016 LOC | derp/server.rs 单文件 5,311 行；axum/tonic 跑在内核 |

### 1.2 六大结构病灶（与工作包的映射）

1. **Trait 契约碎片化** → WP01-03。`OutboundConnector` 定义至少 6 处：
   `sb-types/src/ports/outbound.rs:11`、`sb-proto/src/connector.rs:116`、
   `sb-core/src/adapter/mod.rs:120`（返回具体 `TcpStream`，逼出 `connect_io` 旁路）、
   `sb-core/src/outbound/traits.rs:16`、`sb-core/src/runtime/switchboard.rs:149`、
   `sb-adapters/src/traits.rs:535`；另有 `pipeline.rs:14`、`outbound/types.rs:158`
   两个 `Outbound`。sb-types ports 全仓仅 12 个文件引用——契约层是装饰性的。
2. **scaffold 双轨** → WP04-07。`adapter/bridge.rs` 自述"registry 优先、scaffold
   兜底"；sb-core/inbound 有 socks5/http_connect/mixed 第二套完整实现，
   sb-core/outbound 有 socks5/http_proxy/ss/quic/hysteria/hysteria2 等完整实现；
   `sb-adapters/Cargo.toml:61` 生产依赖 sb-core 时强制 `features=["router","scaffold","v2ray_transport"]`，
   两套实现都编进生产二进制，行为不保证一致。
3. **路由双栈** → WP08。`routing::engine` 是 supervisor/bridge/registry 的入口，
   内部却又拿 `router::RouterHandle::from_env()`（routing/engine.rs:107）；
   sb-adapters 的 inbound 与 app 直接用 `sb_core::router`。
4. **控制面三栈** → WP09-10。sb-api（7.8k）/ sb-core/services（14k，违反
   ARCHITECTURE-SPEC"Web 框架优先放 sb-api"）/ app/admin_debug（13.6k）。
5. **env 隐性配置面** → WP11。sb-core 161 个 SB_*（全仓 357 个），热点：
   dns/mod.rs(25)、dns/resolve.rs(16)、dns/upstream.rs(15)、router/mod.rs(12)、
   router/engine.rs(11)。与"drop-in 替换 Go"目标冲突（Go 为纯配置文件驱动）。
6. **重复实现与 feature 爆炸** → WP12-13。WireGuard 三处（endpoint 1,382 /
   adapters 456 / transport 1,803）、tailscale 双处、selector 家族 5 变体（2,115 LOC，
   adapters 侧仅 46/60 行 shim）、sb-core 影子模块（transport/ tls/ subscribe/
   config/ socks5/ metrics/）；legacy 空 `out_*` feature 仍激活 145 处 cfg 引用。

## 2. 目标 / 非目标

**目标**（轨迹收口时全部成立）：
- 全仓 outbound/inbound 契约唯一（落位 sb-types），register.rs 不再有逐协议 Wrapper。
- sb-core 中不再存在与 sb-adapters 重复的协议实现；`scaffold` feature 消失。
- 路由单栈；DNS 与路由共享匹配原语。
- sb-core 依赖图中 axum/tonic 清零；控制面归位 sb-api（或独立 service crate）。
- sb-core 内 `env::var` 收敛到一张 ≤10 项的白名单表，其余解析全部上收 app 组合根。
- sb-core feature 数较基线下降 ≥30%，cfg 块下降 ≥25%。

**非目标**：
- 不追求任何 parity/BHV 数字变化（本轨迹是结构迁移；行为保持是红线不是目标）。
- 不重写 sb-config / sb-transport / sb-tls 内部实现。
- 不动 REALITY 封箱结论、不重开 MT-REAL-02。
- 不恢复 CI workflows；不建 public RuntimePlan / PlannedConfigIR / generic query API。

## 3. 阶段与依赖图

```
Phase A 契约        WP01 ──→ WP02 ──→ WP03
                      │        │
Phase B 退役  WP04 ───┴──→ WP05 ──→ WP06 ──→ WP07
                                      │
Phase C 并行线            WP09  WP10  ├──→ WP08 ──→ WP11
                                      │
Phase D 收网              (WP03,WP06,WP07 齐) ──→ WP12 ──→ WP13 ──→ WP14
```

- WP01、WP04 是纯文档包，随时可开工，互相独立。
- WP06 / WP08 / WP11 因共同触碰 `adapter/bridge.rs`、`router/`，强制串行。
- WP09、WP10 与其它车道文件交集小，可全程并行。

## 4. 全局验收门禁（每个改代码的包必过；包内可另加专项）

```bash
cargo fmt --all -- --check
cargo check --workspace --all-features
cargo clippy --workspace --all-targets --all-features   # 工作区 lint 策略：unwrap/expect/panic 为 deny
make boundaries                                          # 严格边界门禁，当前基线 exit 0
git diff --check
```

外加（涉及路由/协议数据面的包）：
- 相关 focused tests + `cargo test -p <crate>`；
- interop 差分：`labs/interop-lab` 相关 case，归因遵循 golden spec S4；
- Python 套件不回归：reality_probe_tools / clienthello_family /
  dual_kernel_verification / trojan_integration（现基线 20 PASS）。

## 5. 全局风险登记

| 风险 | 缓解 |
|------|------|
| 双核行为漂移（删 scaffold 后 fallback 语义变化） | WP04 矩阵先行；WP06 保留结构化错误替代静默回退；interop case 回归 |
| boundary 断言因文件搬迁失配（历史已发生过） | 每包收尾五件套之 d；WP14 终局重基线 |
| feature 组合爆炸导致漏测 | 改动 feature 的包必须跑 `--all-features` + app 聚合 profile（`acceptance`/`gui_runtime`/`parity`）三构建 |
| 大文件搬迁引发 git 历史断裂 | 用 `git mv` 保留 rename 检测；单包单 PR 粒度 |
| env 上收造成隐性行为变化 | WP11 逐变量登记"读取点→注入点"映射，默认值逐一比对 |

## 6. 基线 vs 终局指标（WP14 收口时填写右列）

| 指标 | 基线（2026-07-06） | 终局 |
|------|--------------------|------|
| sb-core LOC | 108,129 | |
| sb-core features | 103 | |
| sb-core cfg(feature) 块 | 1,077 | |
| sb-core 内不同 SB_* env | 161 | |
| register.rs LOC | 4,264 | |
| OutboundConnector 定义数 | ≥6 | |
| sb-core 内协议双实现（与 adapters 重叠） | socks5/http/mixed/ss/hysteria/hysteria2/naive/quic | |
| 路由栈数 | 2 | |
| sb-core 内 axum/tonic | 有（service_* 门下） | |
