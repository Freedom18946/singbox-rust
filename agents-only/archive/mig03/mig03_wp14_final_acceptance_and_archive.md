<!-- tier: B -->
# MIG-03 WP14 — 终验收、文档修正、boundary 重基线、轨迹归档

Status: DONE (2026-07-12)
Priority: P1
Depends on: WP01–WP13 全部 DONE
Blocks: 无（轨迹收口包）

Primary evidence:

- `mig03_00_overview.md` §6 基线 vs 终局指标表（本包填写右列）。
- CLAUDE.md 架构节的**过期声明**（本包修正）："sb-core/outbound 仅保留
  管理/调度 + hysteria inbound + naive_h2"（立项时已与事实不符，收口后按
  终局事实重写）；"out_* features 在 sb-core 中为空数组"（WP13 后失效）；
  Feature Gate 要点节（依赖随 WP07/WP09 迁移后失效）。
- `agents-only/reference/ARCHITECTURE-SPEC.md`（L19.3.1 的 sb-core"内核合集层"
  容忍条款随 WP09 关闭，§1.2 职责表需更新）。
- `agents-only/06-scripts/check-boundaries.sh`（V7 断言基线 537 条，大量文件
  搬迁后需重基线）。

## Goal

MIG-03 全轨迹的终局验证、指标结算、文档真相同步、按项目纪律归档。
收口后：任何 agent 读 CLAUDE.md/ARCHITECTURE-SPEC 得到的架构描述与代码事实
一致；boundary 门禁在新结构上严格 exit 0。

## Task Split

1. **全量门禁终验**（输出全部记录在包内）：
   ```
   cargo fmt --all -- --check
   cargo check --workspace --all-features
   cargo clippy --workspace --all-targets --all-features
   cargo test --workspace --all-features        # 或按 crate 分批，全绿
   make boundaries                               # 严格模式 exit 0
   ```
   外加 app 五聚合 profile 构建、python 套件（reality_probe_tools /
   clienthello_family / dual_kernel_verification / trojan_integration 基线
   20 PASS）不回归。
2. **双核终局回归**：interop-lab 全量现有 case 跑一轮；出现差分按 S4 归因，
   逐条记录归因结论。**本轨迹验收标准是"无新增差分"，不是 BHV 数字变化**。
3. **指标结算**：overview §6 表右列填实测值；不达标项（如 feature 降幅 <30%）
   按 D17 默认**补做**（新开跟进包），仅当存在阻塞性证据时才升级用户裁决
   "接受"，差距与原因记录在包内。
4. **文档真相同步**（只改指针与稳定事实，不写易变数字）：
   - CLAUDE.md：架构图、"核心事实"三条、Feature Gate 要点、目录结构节按
     终局重写；
   - `reference/ARCHITECTURE-SPEC.md`：§1.2 sb-core 职责表关闭"内核合集层"
     容忍条款，更新依赖方向图（新增 crate 如 sb-service-derp）；
   - `PROJECT_STRUCTURE_NAVIGATION.md`、`reference/SCRIPTS-MAP.md` 涉及处；
   - `reference/GO_PARITY_MATRIX.md` **不动**（验收基线与结构迁移无关，
     如个别条目引用了被移动的文件路径，只修路径）。
5. **boundary 重基线**：check-boundaries.sh 断言总数与各 V 层策略在新结构上
   重新核准；把"断言数变化 537 → N"写入包内记录。
6. **经验沉淀**：本轨迹踩坑（各包"发现移交"与 Risks 命中情况）汇总 3–8 条
   进 `agents-only/memory/LEARNED-PATTERNS.md` / `TROUBLESHOOTING.md`（查重后写）。
7. **归档执行**（D17：终验全绿即归档，无需请示）：
   - `git mv agents-only/mig03 agents-only/archive/mig03/`；
   - `workpackage_latest.md` 的 MIG-03 行压缩为一行"已关闭"；
   - `active_context.md` 加收口 Resume（Scope note：结构迁移完成，无 parity
     movement 声明）。

## Acceptance

- [x] 任务 1 全部命令 exit 0，输出存档。
- [x] interop 全量 case 无未归因差分。
- [x] overview §6 指标表填写完毕；不达标项已按 D17 处置（补做包已立项，
      或阻塞证据 + 用户"接受"裁决记录在案）。
- [x] CLAUDE.md / ARCHITECTURE-SPEC 更新后，用 `grep` 抽查 5 条架构声明与
      代码事实一致（抽查记录在包内）。
- [x] `make boundaries` 严格 exit 0，断言数已重基线并记录。
- [x] LEARNED-PATTERNS / TROUBLESHOOTING 沉淀完成（含查重说明）。
- [x] 归档动作已按 D17 执行；workpackage_latest / active_context 同步。

## Final evidence (2026-07-12)

- 终局实测：sb-core 79,973 Rust LOC、65 features、787 个 source
  `cfg(feature)`、0 个 `SB_*` 字面量；`register.rs` 7 行；正典
  `sb_types::Outbound` 定义唯一；协议双实现 0；路由栈 1；core axum/tonic 0。
- D17 指标全部达标：features -36.9%，cfg -26.9%；无需跟进包或用户豁免。
- WP08 兼容周期债务实际清除：删除 `sb-core/src/routing/mod.rs` 与 crate export；
  V8 新增防回流断言。
- V7 基线仍为 427 条有效 L20/L21 迁移断言；MIG-03 终局新增 V8 策略层，严格
  `make boundaries` exit 0。旧计划中的 537 是立项时陈旧描述，不据此伪造重基线。
- 文档抽查：正典契约、单 router、协议 owner、控制面 owner、DERP crate、core
  Web 依赖清零均与源码/Cargo workspace 一致。
- 经验文件先按关键词查重；新增仅限兼容 facade 终局删除、指标口径重放、陈旧
  boundary 数字不可沿用三项。
- 验收命令：fmt、workspace all-feature check/clippy/test、app 五 profile、三组
  Python unittest、Trojan integration、strict boundaries、diff-check 均 PASS。

## Interop final regression

- 按 README 构建 `acceptance,clash_api` app 后全量运行 103 cases：87 PASS、16 FAIL。
  首轮 78/103 的结果由前序 minimal profile 覆盖 `target/debug/app` 导致，已废弃。
- 4 个外部环境 case（`p0_clash_api_contract`、两个 auth negative、
  `p1_optional_endpoints_contract`）双核均无自管理 command，缺少 `INTEROP_*` 外部 API，
  同为 launch-not-ready，不构成产品差分。
- 5 个双核/Go-oracle 已知项：graceful-drain 双核同失败（DIV-M-003 语义）；WS soak
  双核同报 leak 且历史 effective matrix 已失败；GUI group-delay 为 Go 404；lifecycle
  reload 为 Go-only reload 后 API 不可用；fakeip 同时命中 Rust launch 与 Go reference
  漂移（历史 effective matrix 已失败、DIV-M-001）。
- 2 个 Rust 专项/断言项：deprecated WireGuard 是 golden spec 明列 non-promotable 的
  Rust migration detector；DNS TTL 的 `ne_ref expected=2 actual=2` 是 harness/oracle 断言，
  不是 MIG-03 ownership 行为差分。
- 5 个 protocol-local 项：Shadowsocks、ShadowTLS、Trojan 失败停在 kernel launch；后两项
  与 Shadowsocks 历史 raw matrix 同型且 effective matrix 通过。VLESS/VMess 历史
  effective matrix 均已失败，本轮无新增类别；golden spec 亦锁定 VLESS inbound TCP-only。
- 结论：16 个失败均可归入外部环境、双核/Go oracle、non-promotable Rust 专项、
  harness assertion 或历史 S4 baseline；MIG-03 无新增未归因差分。不声明 parity/BHV movement。

## Risks / known traps

- 终验最常见的坑：`--workspace --all-features` 含网络/特权测试。不许临时 ignore
  有效测试；从未启动对应协议服务的伪 E2E 必须显式标注 unsupported。VMess TLS 五例
  helper 实际只启动 plain TCP，改为明确 ignore，避免继续伪造 TLS-success 证据。
- CLAUDE.md 是"只放稳定事实"的 S-tier 文档——重写架构节时不要把 MIG-03 的
  过程性数字（删了多少行等）写进去，那些留在 archive 的本目录里。
- 归档后本目录内的相互链接（README ↔ 各包）仍以相对路径工作，检查一遍。

## 发现移交

（收口包无移交；未尽事项以新轨迹立项。）
