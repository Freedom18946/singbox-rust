<!-- tier: S -->
# 当前上下文（Active Context）
> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。
---
## 战略状态
**当前阶段**: 维护态 — MT-REAL-01 已正式收口为 `ARCH-LIMIT-REALITY`
**Parity**: 52/56 BHV (92.9%)；REALITY 4 个行为槽位登记为 `known_deviation(ARCH-LIMIT-REALITY)`
**当前焦点**: 无活跃开发卡；后续仅处理维护性响应与证据检索

## 收口结论（2026-04-15）

- `ARCH-LIMIT-REALITY` 已确认：
  - `rustls` 缺乏 `uTLS` 等价的完整浏览器 TLS 拟态能力
  - REALITY 服务端在 session auth 前即依赖浏览器级 ClientHello 指纹识别
  - Rust 端通过增量 patch 无法收敛到可用的 live dataplane 状态
- FIX 证伪链已完成：
  - `FIX-03`：密码学 / `session_id` / 共享握手态对齐
  - `FIX-04`：顶层 ClientHello 指纹、扩展顺序、GREASE、padding 对齐
  - `FIX-05`：typed 子结构 GREASE / versions / groups / key_share / sigalgs 对齐
- live 事实保持不变：
  - Phase 3 真实节点矩阵 `0/21` 成功
  - 主要失败形态为 `REALITY handshake failed ... tls handshake eof`

## 当前权威入口

- Dual-kernel 口径与偏差注册表：
  - `labs/interop-lab/docs/dual_kernel_golden_spec.md`
- Go/Rust 模块级 parity 口径：
  - `agents-only/reference/GO_PARITY_MATRIX.md`
- MT-REAL-01 归档报告：
  - `agents-only/archive/MT-REAL-01/mt_real_01_env_01.md`
  - `agents-only/archive/MT-REAL-01/mt_real_01_fix_03.md`
  - `agents-only/archive/MT-REAL-01/mt_real_01_fix_04.md`
  - `agents-only/archive/MT-REAL-01/mt_real_01_fix_05.md`
- Phase 3 证据：
  - `agents-only/mt_real_01_evidence/phase3_reality_matrix.md`
  - `agents-only/mt_real_01_evidence/phase3_reality_matrix.json`

## 当前默认准则

- 不再继续逐项排除 REALITY 指纹细节
- 不引入 FFI/BoringSSL/OpenSSL 方案
- 不自建 TLS 1.3 栈
- FIX-04/FIX-05 spike 代码按本地未提交状态保留，不进入主线
