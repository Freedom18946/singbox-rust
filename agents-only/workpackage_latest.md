<!-- tier: S -->
# 工作阶段总览（Workpackage Map）

> **用途**：阶段划分 + 当前位置。S-tier，每次会话必读。
> **纪律**：Phase 关闭后压缩为一行状态。本文件严格 ≤120 行。
> **对比**：本文件管"在哪"（阶段地图）；`active_context.md` 管"刚做了什么 / 下一步"（事件细节）。
> **历史**：完整 5728 行原文见 `archive/logs/workpackage_latest.md`。

---

## 已关闭阶段（一行总结）

| 阶段 | 交付 | 关闭时间 |
|------|------|----------|
| L1 | 架构整固，crate 边界固化，check-boundaries.sh | 2026-01 |
| L2 | 功能对齐 88%→99%，Tier 1+2 全部完成 | 2026-01 |
| L3-L4 | DERP/CacheFile/ConnMetadata prework | 2026-02 |
| L5 | 协议×故障矩阵（6×4=24 cell） | 2026-02 |
| L6 | WsRoundTrip/TlsRoundTrip + delay 注入 + 趋势报告 | 2026-02 |
| L7 | GUI 回放 + E2E capstone | 2026-02 |
| L8-L11 | CI smoke/nightly + 趋势门禁 + JSONL 追踪 + 回归检测 | 2026-02 |
| L12 | 弃用检测 + 迁移诊断 + WG 迁移辅助 | 2026-02 |
| L13 | Clash API/SSMAPI 认证 + 故障隔离 + 健康 API | 2026-02 |
| L14 | TLS 证书存储 + 热重载 + 能力矩阵 | 2026-02 |
| L15 | CLI generate/convert/format + 验收清单签署 | 2026-02 |
| L16 | feature-matrix 46/46 + benchmark + 稳定性 + CI bench gate | 2026-02 |
| L17 | 发布收口 PASS_ENV_LIMITED | 2026-02 |

## MIG-02 隐式回退消除

| 状态 | 范围 | 断言数 | 关闭时间 |
|------|------|--------|----------|
| ✅ ACCEPTED | wave#1-202, 全部生产路径零隐式回退 | 541 V7 | 2026-03-07 |

大验收 Step 0-5 全绿（boundaries/parity/test/fmt/clippy + hot_reload 20x + signal 5x + interop-lab 27 + V7 负样例 3/3）。

---

## 当前阶段：L18 认证替换

### Phase 1（脚本开发 + daily 收敛）— ✅ 完成

| Batch | 主题 | 状态 |
|-------|------|------|
| A | preflight + Go Oracle 构建 | ✅ |
| B | 双核差分 + GUI 双轨认证 | ✅ |
| C | 性能门禁 + capstone | ✅ |
| D | CI 调度 + 状态总线 | ✅ |

证据：daily 3 轮 PASS + 48x 高压排练 PASS。
详见 `archive/L12-L17/12-L18-REPLACEMENT-CERTIFICATION-WORKPACKAGES.md`。

### Phase 2（Post-MIG-02 开封首跑）— ✅ 完成

> **Phase 2 结论**：MIG-02 后代码基线上首次端到端跑通 L18 全链路。
> 18 WP 全部完成，Batch J 已由旧 `PASS_ATTRIBUTED` 收敛为 clean full `PASS`。Rust 性能优于 Go。基线已锁定。

| Batch | 主题 | WP 数 | 依赖 | 状态 |
|-------|------|--------|------|------|
| **E** | 环境开封与基线固化 | 3 | 无 | ✅ 完成 |
| **F** | MIG-02 后适配审计 | 3 | E | ✅ 完成（含 F3 selector fix） |
| **G** | Rust 单核认证首跑 | 3 | E+F | ✅ 完成（含 RSS threshold 调整） |
| **H** | 双核差分首跑 | 3 | E+F+G | ✅ 完成（daily PASS, nightly PASS_ENV_LIMITED） |
| **I** | GUI 替换首跑 | 3 | H | ✅ 完成（Go+Rust 五步全 PASS + sandbox 验证） |
| **J** | Capstone 首跑与基线锁定 | 3 | G+H+I | ✅ 完成（`20260307T211512Z` clean full PASS，docker WARN） |

目标：在 MIG-02 后代码基线上首次端到端跑通 L18 全链路。
详见 `planning/L18-PHASE2.md`。

### Phase 3（nightly/certify 级别运行）— 🔄 进行中

- 前置：Phase 2 clean full PASS 已满足（batch `20260307T211512Z`）
- nightly：`20260307T230356Z-l18-nightly-24h` 已 full PASS（`overall=PASS`，仅 `docker=WARN`）
- certify：当前无活动批次；`20260309T004601Z-l18-certify-7d` 因 `11810/11811` 遗留 perf runtime 占口废弃，`20260309T004649Z-l18-certify-7d` 在会话切换前被中断，未形成有效证据
- 当前重点：先处理即将到来的全局静态审议意见，再决定 `certify` 重发顺序
- 目标：nightly 24h PASS 已达成；下一目标是完成全局静态审议 triage，并在必要整改后再取一次有效 `certify` 7d PASS
- 入口：`agents-only/planning/L18-PHASE3.md`

---

## 下一阶段评估

L18 关闭后可选方向：
- MIG-03 (Hysteria2) / MIG-04 (HTTP/Mixed) / MIG-05 (Transport) 具体迁移
- Codebase hardening / 性能优化
- Server-side 能力补齐
