# singbox_archspec_v2 归档内容索引

> **来源**：已删除的 `singbox_archspec_v2/` 目录
> **归档日期**：2026-02-07
> **说明**：该目录包含 59 个详细的架构规范文档，核心内容已合并到 agents-only 各文档中

---

## 核心依赖关系（已合并到 01-spec/ARCHITECTURE-SPEC.md）

```
sb-types   ← sb-config
   ↑            ↑
   │            │
sb-core   ← sb-adapters  ← sb-transport / sb-tls / sb-platform / sb-security
   ↑
   │
sb-api / sb-metrics / sb-runtime
   ↑
   │
  app (composition root)
```

---

## 原始目录结构（已删除）

| 目录 | 内容 | 合并位置 |
|------|------|---------|
| `00-goals/` | 目标与术语 | `00-overview/PROJECT-OVERVIEW.md` |
| `01-constitution/` | 依赖宪法、错误模型 | `01-spec/ARCHITECTURE-SPEC.md` |
| `02-architecture/` | 数据面/控制面 | `01-spec/ARCHITECTURE-SPEC.md` |
| `03-crates/` | 各 crate 规范 | `04-workflows/CRATE-DETAIL.md` |
| `04-interfaces/` | Ports 定义 | `01-spec/ARCHITECTURE-SPEC.md` |
| `07-migration/` | 迁移计划 | `03-planning/STRATEGIC-ROADMAP.md` |
| `08-refactor-tracking/` | 重构追踪 | `04-workflows/` |

---

## 关键规则摘要

### sb-types（契约层）
- ✅ 允许：领域类型、Ports traits、serde/bytes/ipnet
- ❌ 禁止：tokio/hyper/axum/tonic/reqwest/rustls/quinn

### sb-core（引擎层）
- ✅ 允许：路由/策略/会话编排、通过 Ports 交互
- ❌ 禁止：协议实现、平台服务、Web 框架、TLS/QUIC/WS

### sb-adapters（协议层）
- ✅ 允许：所有协议实现、使用 sb-transport/sb-tls
- ❌ 禁止：反向依赖 sb-core、控制面职责

### sb-platform（平台层）
- ✅ 允许：TUN、tproxy、socket options、netlink
- ❌ 禁止：协议实现、路由策略

---

## 如需查看原始文档

原始文件已从 Git 历史中删除。如需恢复：

```bash
git checkout <commit-before-deletion> -- singbox_archspec_v2/
```

---

*本文档保留关键规范摘要，详细内容见 agents-only 各子目录*
