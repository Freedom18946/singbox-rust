# 下一阶段：实际部署收尾验收准备

> **用途**：定义 maintenance close-out 之后，仓库进入“实际部署的收尾验收”阶段时，后续 agents 应如何组织工作。  
> **口径**：这是部署收尾准备文档，不是 parity completion 声明。

---

## 1. 当前阶段起点

截至 2026-04-09，仓库已经完成：

- `WP-30` archive baseline
- `MT-OBS-01`
- `MT-RTC-01/02/03`
- `MT-HOT-OBS-01`
- `MT-SVC-01`
- `MT-TEST-01`
- `MT-RD-01`
- `MT-PERF-01`
- `MT-ADP-01`
- `MT-MLOG-01`
- `MT-ADM-01`
- `MT-DEEP-01`
- `MT-CONV-01/02/03`
- `MT-AUDIT-01`

当前仓库事实：

- maintenance 主线已大体收束
- 当前没有新的最前置 blocker
- 全量复扫结论为 `Partial clearance, no current blocker`
- 默认下一阶段不再是继续拆 maintenance 卡，而是准备部署收尾验收

---

## 2. 进入部署收尾验收前，后续 agents 的默认任务

后续任务默认应围绕以下四类展开：

1. 真实部署路径验证
2. 实际运行配置与 entrypoint 收尾
3. 本地可重复验收链固化
4. 文档与交付口径闭环

不再默认围绕：

- metrics/logging compat 小尾巴
- admin_debug helper 小尾巴
- protocol corner-case 零碎修补
- mega-file 纯结构洁癖拆分

---

## 3. 部署收尾验收的判断标准

### 3.1 什么算值得继续做

只有满足以下任一条件，才值得继续开卡：

- 阻塞真实部署路径
- 阻塞本地验收链
- 阻塞 release/package/bootstrap 入口
- 影响实际运行稳定性或配置交付

### 3.2 什么不算值得继续做

以下默认不再单开卡：

- 只影响内部整洁度、但不影响部署验收的 compat shell
- 已降级为 future boundary 的结构债
- 无新信号支撑的历史审稿残项
- 纯“看起来还能再优雅一点”的 helper 收敛

---

## 4. 下一阶段推荐的工作方式

### 4.1 优先顺序

1. 先验证真实部署入口
2. 再验证验收命令链是否可重复
3. 最后再补文档和模板

### 4.2 推荐证据

下一阶段的工作应尽量产出这些证据：

- 可执行命令
- 产物路径
- release/package/bootstrap 成功输出
- 配置模板或部署模板的可用性
- 环境限制说明

### 4.3 验收状态口径

继续使用 `reference/ACCEPTANCE-CRITERIA.md` 中的三态：

- `PASS-STRICT`
- `PASS-ENV-LIMITED`
- `FAIL`

不得把 `PASS-ENV-LIMITED` 伪装成功能已完整验证。

---

## 5. 当前仍保留的高层 boundary

这些问题仍存在，但默认不阻塞部署收尾验收：

- lifecycle-aware compat shells
- prometheus metric-family statics
- `registry_ext.rs` 的局部 `'static` promotion
- 4 个 mega-file bulk
- `tun_enhanced.rs` 中 residual panic density
- boundary script stale targets
- dev/debug bins 的局部 tracing/bootstrap 差异

处理原则：

- 除非直接阻塞部署验收，否则不主动继续拆

---

## 6. 下一阶段的文档要求

后续 agents 在部署收尾验收阶段至少应持续维护：

- `agents-only/active_context.md`
- `agents-only/workpackage_latest.md`
- 部署验收阶段专用记录文档

若出现新的真实 blocker，应新增“部署验收问题”文档，而不是重开旧 maintenance 线名。

---

## 7. 一句话结论

当前仓库的正确后续动作是：

**以部署收尾验收为默认主线，只有在真实部署阻塞出现时才重新开高层问题线。**

