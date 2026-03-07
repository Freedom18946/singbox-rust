# 重构进度追踪（Refactor Progress）

> **更新频率**：L1 完成前高频更新；L1 完成后停更（以 `active_context.md` / `workpackage_latest.md` 为准）
> **状态**：已归档（2026-02-10）

---

## 总体进度

| 阶段 | 状态 | 进度 |
|------|------|------|
| L1.1 依赖边界硬化 | ✅ 已完成 | 100% |
| L1.2 代码归属清理 | ✅ 已完成 | 100% |
| L1.3 接口契约明确 | ✅ 已完成 | 100% |

---

## 各 Crate 状态

| Crate | 当前状态 | 违规数 | 进度 | 备注 |
|-------|---------|-------|------|------|
| sb-types | ✅ 已完成 | 0* | 100% | Ports 契约层完成 |
| sb-core | ✅ 已完成 | 0* | 100% | check-boundaries exit 0 |
| sb-adapters | ✅ 已完成 | 0* | 100% | 反向依赖切断 |
| sb-config | — 未纳入 L1 | — | — | |
| sb-transport | — 未纳入 L1 | — | — | |
| sb-tls | — 未纳入 L1 | — | — | |
| sb-platform | — 未纳入 L1 | — | — | |
| sb-api | — 未纳入 L1 | — | — | |
| sb-metrics | — 未纳入 L1 | — | — | |
| sb-runtime | — 未纳入 L1 | — | — | |
| sb-security | — 未纳入 L1 | — | — | |
| sb-common | — 未纳入 L1 | — | — | |
| sb-proto | — 未纳入 L1 | — | — | |
| sb-subscribe | — 未纳入 L1 | — | — | |
| sb-test-utils | — 未纳入 L1 | — | — | |
| sb-admin-contract | — 未纳入 L1 | — | — | |

---

## 状态图例

- ⬜ 待审计/未开始
- 🔴 违规严重
- 🟠 有违规
- 🟡 进行中
- ✅ 已完成
- — 未纳入 L1

---

## 更新日志

### [2026-02-07] 初始化
- 创建进度追踪文档
- 根据依赖审计标记 sb-core、sb-adapters 违规状态

### [2026-02-10] 归档更新
- 标记 L1.1~L1.3 已完成
- 说明：L1 之后该文档停更，改以 active_context/workpackage_latest 为准

*注：0* 为全局边界检查 exit 0 的结果，非逐 crate 独立审计。*
