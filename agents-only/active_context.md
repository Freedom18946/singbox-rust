<!-- tier: S -->
# 当前上下文（Active Context）

> **用途**：高频更新，每次任务结束时维护。**S-tier：每次会话必读。**
> **纪律**：仅保留当前阶段最关键事实。本文件严格 ≤100 行。

---

## 战略状态

**当前阶段**: L22 dual-kernel parity — **天花板已达 86.7%**
**当前工作包 ID**: `WP-L22`
**Source of Truth**: `labs/interop-lab/docs/dual_kernel_golden_spec.md`
**工作区状态**: Sniff Phase A + Phase B 均已落地并提交

## 已提交覆盖（2026-03-15 最新快照）

- `Both-Covered = 52 / 60`，覆盖率 `86.7%`
- strict both 覆盖：`43 / 60`
- both-case ratio：`36 / 100`

## 本轮新增 (2026-03-15)

### Sniff Phase B: QUIC SNI Extraction（已落地）

- **实现**: QUIC Initial 包解密 + SNI 提取（Go parity: `common/sniff/quic.go`）
- 算法: HKDF 密钥派生 → AES-ECB 头部保护移除 → AES-128-GCM 载荷解密 → CRYPTO 帧重组 → TLS ClientHello SNI 提取
- 支持 QUIC v1 / v2 / Draft-29 三种版本
- 新增文件：`sb-core/src/router/sniff_quic.rs`（~280 行）
- 新增依赖：`aes = "0.8"`（已为 aes-gcm 传递依赖）
- `sniff_datagram()` 先尝试完整 SNI 提取，失败回退到检测模式
- 删除已过时的 `sniff_quic_initial_extended()`
- Go 测试向量验证：Firefox / Safari / uQUIC Chrome115 均 SNI = "www.google.com"
- 10 个新测试全部通过，sb-core 504 测试零失败

### Sniff Phase A（前次会话已落地）

- `Decision::Sniff` 非终端规则动作 + SniffedStream 包装器
- DIV-C-003 CLOSED, BHV-DP-014 both-case

## 天花板分析

剩余 8 个未覆盖 BHV：7 SV 结构性阻塞 + 1 已确认不可行（LC-003）
天花板：**52/60 (86.7%)**（无更多 KNOWN-GAP 可关闭）

## 下一步候选

1. **宣布 L22 完成** → 归档，开始下一阶段
2. 可选：QUIC multi-packet reassembly（Chrome 多包 ClientHello）
3. 可选：OverrideDestination（sniff 域名替换路由目标）

## 关键文件速查

| 内容 | 路径 |
|------|------|
| 当前工作包 | `agents-only/planning/L22-DUAL-KERNEL-PARITY.md` |
| 当前阶段地图 | `agents-only/workpackage_latest.md` |
| SoT spec | `labs/interop-lab/docs/dual_kernel_golden_spec.md` |
| 兼容矩阵 | `labs/interop-lab/docs/compat_matrix.md` |
| case 积压 | `labs/interop-lab/docs/case_backlog.md` |
