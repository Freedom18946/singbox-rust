<!-- tier: B -->
# MIG-03 WP14 — 终验收、文档修正、boundary 重基线、轨迹归档

Status: PLANNED
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

- [ ] 任务 1 全部命令 exit 0，输出存档。
- [ ] interop 全量 case 无未归因差分。
- [ ] overview §6 指标表填写完毕；不达标项已按 D17 处置（补做包已立项，
      或阻塞证据 + 用户"接受"裁决记录在案）。
- [ ] CLAUDE.md / ARCHITECTURE-SPEC 更新后，用 `grep` 抽查 5 条架构声明与
      代码事实一致（抽查记录在包内）。
- [ ] `make boundaries` 严格 exit 0，断言数已重基线并记录。
- [ ] LEARNED-PATTERNS / TROUBLESHOOTING 沉淀完成（含查重说明）。
- [ ] 归档动作已按 D17 执行；workpackage_latest / active_context 同步。

## Risks / known traps

- 终验最常见的坑：`--workspace --all-features` 的 test 跑道里有需要网络/特权的
  测试——沿用项目现行的 ignore 约定，不许为过门禁临时 ignore 新测试。
- CLAUDE.md 是"只放稳定事实"的 S-tier 文档——重写架构节时不要把 MIG-03 的
  过程性数字（删了多少行等）写进去，那些留在 archive 的本目录里。
- 归档后本目录内的相互链接（README ↔ 各包）仍以相对路径工作，检查一遍。

## 发现移交

（收口包无移交；未尽事项以新轨迹立项。）
