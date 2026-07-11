<!-- tier: B -->
# MIG-03 — 架构去重迁移（2026-07 立项）

Status: DONE（2026-07-12；WP01-WP14 全部关闭）

> 本目录是 MIG-03 轨迹的唯一规划落点：调研结论、阶段划分、全部工作包。
> **各包实时状态以各包头部 `Status:` 字段为唯一权威**；全局易变状态照旧以
> `agents-only/active_context.md` 为准。本 README 不复制任何状态数字。

---

## 一句话背景

仓库历史上几次大迁移（L1 协议迁出、adapter registry 化）只做了一半，留下系统性
双轨/三轨结构：OutboundConnector 一个概念 6+ 处定义、scaffold 双协议栈同时编入
生产二进制、路由双栈（`router/` + `routing/`）、控制面三栈（sb-api /
sb-core/services / app/admin_debug）、sb-core 内 161 个 SB_* 环境变量隐性配置面。
MIG-03 用**仓内绞杀（strangler-fig）**方式收敛：每包"先在干净目标立好新实现 →
门禁绿 → 删旧"，删除动作放在每包末尾，仓库任何时刻保持完整可验。
证据与基线指标见 `mig03_00_overview.md`。

## 包索引

> 技术抉择权威：[`mig03_01_decisions.md`](mig03_01_decisions.md)（D1–D18，
> 2026-07-06 用户委托敲定）。各包正文中的 D 编号均指向该登记册。

| 包 | 阶段 | 优先级 | 依赖 | 一句话 |
|----|------|--------|------|--------|
| [WP01](mig03_wp01_trait_census_and_adr.md) | A 契约 | P0 | 无 | Trait 全量盘点 + 正典契约 ADR（纯文档包） |
| [WP02](mig03_wp02_adapters_implement_canonical.md) | A 契约 | P0 | WP01 | sb-adapters 直接实现正典契约，削平 register.rs 胶水 |
| [WP03](mig03_wp03_core_trait_consolidation.md) | A 契约 | P1 | WP01 | sb-core 内部三套 trait 收敛 + sb-proto 处置 |
| [WP04](mig03_wp04_scaffold_semantic_audit.md) | B 退役 | P0 | 无（可与 A 并行） | scaffold vs adapters 逐协议语义差异矩阵（纯文档包） |
| [WP05](mig03_wp05_adapters_gap_closure.md) | B 退役 | P0 | WP02, WP04 | 按矩阵把缺口语义补进 adapters |
| [WP06](mig03_wp06_bridge_fallback_removal.md) | B 退役 | P0 | WP05 | bridge 回退移除 + scaffold 实现与 feature 删除 |
| [WP07](mig03_wp07_quic_family_relocation.md) | B 退役 | P1 | WP06 | hysteria/hysteria2/naive/quic 家族迁出 sb-core |
| [WP08](mig03_wp08_router_stack_merge.md) | C 并行线 | P1 | WP06（文件冲突串行） | router/ + routing/ 双栈合并，matcher 原语共享给 DNS |
| [WP09](mig03_wp09_services_out_of_core.md) | C 并行线 | P1 | 无 | derp/ssmapi/v2ray_api 迁出 sb-core，axum/tonic 清零 |
| [WP10](mig03_wp10_admin_debug_consolidation.md) | C 并行线 | P2 | 无 | app/admin_debug 死代码清点 + 与 sb-api 收敛（需用户决策） |
| [WP11](mig03_wp11_env_config_convergence.md) | C 并行线 | P1 | WP08 | SB_* 环境变量解析上收 app 组合根 |
| [WP12](mig03_wp12_duplicate_impl_cleanup.md) | D 收网 | P2 | WP03, WP06 | WireGuard×3 / tailscale / selector×5 / 影子模块清理 |
| [WP13](mig03_wp13_feature_matrix_slim.md) | D 收网 | P2 | WP07, WP12 | 103 个 feature 普查瘦身，legacy out_* 退役 |
| [WP14](mig03_wp14_final_acceptance_and_archive.md) | D 收网 | P1 | 其余全部 | 终验收、文档修正、boundary 重基线、归档 |

## 施工车道（并行/串行约束）

- **车道 α（契约）**：WP01 → WP02 → WP03。
- **车道 β（scaffold 退役）**：WP04（随时可做）→ WP05 → WP06 → WP07。
  WP05 需要 WP02 的正典 trait 已落地。
- **车道 γ（控制面）**：WP09、WP10 互相独立，可与 α/β 并行。
- **串行约束**：WP06、WP08、WP11 都会碰 `adapter/bridge.rs` / `router/` 文件，
  **禁止并行**，顺序固定为 WP06 → WP08 → WP11。
- **车道 δ（收网）**：WP12 → WP13 → WP14，在 α/β 收口后进行。

## 全局纪律（每个执行 agent 开工前必读）

1. **读序**：本 README → `mig03_00_overview.md` → `mig03_01_decisions.md` →
   你认领的包全文 → `agents-only/active_context.md`。不读完不开工。
2. **行为保持红线**：MIG-03 是结构迁移，不是行为变更。默认配置下的任何用户可见
   行为（CLI 输出、路由决策、协议线上行为、metrics 名称）不得改变。发现"删旧"
   会改变行为时：停下、在包内登记、问用户，不得自行取舍。
3. **技术抉择已由用户委托预决策**：全轨迹可选项（正典契约形状、sb-proto /
   admin_debug / 影子模块处置、SCAFFOLD-ONLY 取舍、env 白名单、router 常驻化、
   归档时机等）已于 2026-07-06 敲定并登记在 `mig03_01_decisions.md`（D1–D18）。
   各包**直接执行对应 D 条目，不再就这些事项回头请示**。仅当包内证据与 D 条目
   冲突、或出现 D 未覆盖的删除/用户可见行为变更时，按 D18 停下升级用户
   （这是项目 cleanup 纪律在本轨迹的运行形态）。
4. **每包收尾五件套**：
   a. 包头 `Status:` 改 `DONE`，验收清单逐项打勾（做不到就不许标 DONE）；
   b. 验收命令全绿（各包"验证命令"一节，不得跳过）；
   c. `agents-only/active_context.md` 顶部加 Resume 段，套用现有格式，
      **必须带 Scope note**，禁止宣称 parity/BHV movement；
   d. 移动过文件的包：同步更新 `agents-only/06-scripts/check-boundaries.sh`
      的目标路径（历史上 boundary 断言因文件搬迁失配是已知坑）；
   e. 不 commit / push，除非用户明确要求。
5. **范围纪律**：只做包内列明的事。顺手发现的其它问题记入包尾"发现移交"小节，
   不顺手修。
6. **产物落位**：本轨迹一切分析/矩阵/ADR 产物落 `agents-only/mig03/`，
   不在仓库根目录新建任何东西。
7. **双核差分归因**：任何 interop 差分失败，先按
   `labs/interop-lab/docs/dual_kernel_golden_spec.md` S4 排除已知偏差再归因。
8. **明确暂停项仍然有效**：不恢复 `.github/workflows/*`；不推进 public
   RuntimePlan / public PlannedConfigIR / generic query API——WP01 的正典契约
   是内部契约统一，不是新公共查询 API。
