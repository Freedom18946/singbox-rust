<!-- tier: S -->
# 工作阶段总览（Workpackage Map）
> **用途**：阶段划分 + 当前位置。S-tier，每次会话必读。
> **纪律**：Phase 关闭后压缩为一行状态。本文件严格 ≤120 行。
> **对比**：本文件管"在哪"；`active_context.md` 管"刚做了什么 / 当前基线"。
---
## 已关闭阶段（一行总结）
| 阶段 | 交付 | 关闭时间 |
|------|------|----------|
| L1-L17 | 架构整固、功能对齐、CI / 发布收口 | 2026-01 ~ 2026-02 |
| MIG-02 / L21 | 隐式回退消除，541 V7 assertions，生产路径零隐式直连回退 | 2026-03-07 |
| L18 Phase 1-4 | 认证替换、证据模型收口、GUI gate 复验、长跑恢复决策门 | 2026-03-11 |
| L22 | dual-kernel parity 52/60 (86.7%)，16 个 both-case，Sniff Phase A+B | 2026-03-15 |
| 后 L22 补丁 | QUIC 多包重组、OverrideDestination、UDP datagram sniff、编译修复 | 2026-03-15 |
| L23 | TUN/Sniff 运行时补全、Provider wiring、T4 Protocol Suite、parity 92.9% | 2026-03-16 |
| L24 | 性能/安全/质量/功能补全，30 任务 (B1-B4)，综合验收 39/41 PASS | 2026-03-17 |
| L25 | 生产加固 + 跨平台补全 + 文档完善，10/10 任务，4 批次全部交付 | 2026-03-17 |

---

## 当前状态：GUI 全面验收已取证（MT-GUI-02 完成）

**全部阶段关闭**。dual-kernel parity 以 `labs/interop-lab/docs/dual_kernel_golden_spec.md` 为准。**MT-DEPLOY-01 部署基线完成；MT-GUI-01 取证完成；MT-GUI-02 在本地 mock 公网基础设施上的 35 场景全量取证完成**。

### 维护线 + 部署/验收 close-out 清单

| 线 | 状态 | 日期 |
|--------|------|------|
| MT-CONTRACT-01/02 | 已完成 | 2026-04 |
| MT-RECAP-01 | 已完成 | 2026-04 |
| MT-CONV-01/02/03 | 已完成 | 2026-04-05 |
| MT-AUDIT-01 | 已完成 | 2026-04-06 |
| 文档闭环 / 准则固化 | 已完成 | 2026-04-09 |
| MT-DEPLOY-01 | 已完成 | 2026-04-10 |
| MT-GUI-01 | 已完成 | 2026-04-10 |
| **MT-GUI-02** | **已完成** | **2026-04-11** |

### MT-DEPLOY-01 结论

- 修复 2 个阻塞 `parity` feature 构建的真实 blocker（tracing_init.rs cfg gate + tokio-util dep）
- 验收链 9 项全部 PASS-STRICT：构建、版本、配置检查、近启动、打包、清单一致性
- 环境限制：E2E proxy / Docker 镜像 / k8s 部署为 PASS-ENV-LIMITED
- 详细报告：`agents-only/mt_deploy_01_acceptance.md`

### MT-GUI-01 结论

- **不是** parity completion；仅产出 GUI 驱动下 Go/Rust 双内核的实测证据
- 通过读 `GUI_fork_source/GUI.for.SingBox-1.19.0/frontend/src/api/kernel.ts` 复原 GUI 完整 API 契约
- 共 15 个场景：10 PASS-STRICT / 4 PASS-ENV-LIMITED / 1 NEW FINDING / 0 FAIL
- 4 个观察到的差异全部对得上 golden spec 已记录的 DIV-M-006/007/008/009
- 一个新观察项：post-close `downloadTotal` Rust=0 vs Go=2454，分类暂缓，不开新 maintenance 卡
- 报告：`agents-only/mt_gui_01_acceptance.md`、`agents-only/mt_gui_01_matrix.md`
- 证据脚本与原始输出：`agents-only/mt_gui_01_evidence/`

### MT-GUI-02 结论

- **不是** parity completion；扩展 MT-GUI-01 到更真实的用户路径，增加 mock 公网基础设施让证据可复现
- 构建单文件纯 stdlib Python mock（HTTP/HTTPS 自签/RFC 6455 WS/SSE/chunked/大 body/慢上游/订阅 Bearer+ETag+304/early-close/RST/dead port）
- 双内核驱动同一 GUI-shape 配置 + 三平面全面覆盖：控制 14 + 数据 16 + 订阅 5 = **35 场景**
- **32 PASS-STRICT / 1 PASS-ENV-LIMITED / 1 NEW FINDING / 1 CONFIRMED FINDING / 0 FAIL**
- 5 个已知差异全部对得上 golden spec：DIV-M-005/006/007/008/009
- NEW FINDING：`/dns/query` 对不可解析域名 Rust=500 Go=200+fake answer（设计级差异而非 parity bug）
- CONFIRMED FINDING：MT-GUI-01 §5 cumulative `downloadTotal` 在 1 MiB 流量下仍重现，分类暂缓
- 报告：`agents-only/mt_gui_02_acceptance.md`、`agents-only/mt_gui_02_matrix.md`、`agents-only/mt_gui_02_mock_public_infra.md`
- 证据 + 脚本：`agents-only/mt_gui_02_evidence/`（orchestrator + mock + 4 个测试脚本 + 全部 raw txt/log）

### 维护线分类（按当前仓库事实）

- **archive-safe close-out**
  - `WP-30` archive baseline / planned seam baseline
  - `MT-SVC-01`, `MT-TEST-01`, `MT-ADP-01`
  - `MT-AUDIT-01` (reconciliation archived)
- **close-out but future boundary remains**
  - `MT-CONV-01`, `MT-CONV-02`, `MT-CONV-03`
  - `MT-OBS-01`, `MT-RTC-01/02/03`
  - `MT-HOT-OBS-01`, `MT-RD-01`, `MT-PERF-01`
  - `MT-MLOG-01`, `MT-ADM-01`, `MT-DEEP-01`
- **still active / needs regrouping**
  - 无旧 maintenance 线继续维持为单独 active 卡

### 下一阶段默认路线

- **默认结论**：部署验收基线已建立；后续可进入实际部署或环境集成
- **后续 agents 先看**
  - `agents-only/active_context.md`
  - `agents-only/mt_deploy_01_acceptance.md`
  - `agents-only/reference/AGENT-DEVELOPMENT-GUIDELINES.md`
- **若未来必须继续开卡，只保留少数高层 regroup 主题**
  - boundary assertion script 更新（21 stale targets）
  - `tun_enhanced.rs` residual panic density 收缩（仅在出现真实信号时）
  - mega-file 治理（仅在功能需求或部署验收收益明确时附带推进）

### 明确暂停事项

- 不恢复 `.github/workflows/*`
- 不把 maintenance 工作误写成 dual-kernel parity completion
- 不再继续 `WP-30k` 风格微卡化排程
- 不把 `future boundary` 直接写成"下一卡默认继续做"
- 不推进 public `RuntimePlan`、public `PlannedConfigIR`、generic query API
