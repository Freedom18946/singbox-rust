# 测试映射（Test Mapping）

> **用途**：追踪测试与功能的对应关系，重构时同步更新

---

## 测试目录结构

```
tests/
├── integration/     # 集成测试
├── e2e/             # 端到端测试
├── stress/          # 压力测试
├── configs/         # 测试配置
└── *.rs             # 顶层测试文件
```

---

## 功能 → 测试映射

| 功能模块 | 测试位置 | 重构影响 |
|---------|---------|---------|
| Router | `tests/integration/router/` | ⬜ 待评估 |
| DNS | `tests/integration/dns/` | ⬜ 待评估 |
| Inbound | `tests/integration/inbound/` | ⬜ 待评估 |
| Outbound | `tests/integration/outbound/` | ⬜ 待评估 |
| Config | `crates/sb-config/tests/` | ⬜ 待评估 |

---

## Crate 单元测试

| Crate | 测试位置 | 测试数 | 重构后行动 |
|-------|---------|-------|-----------|
| sb-core | `crates/sb-core/src/*/tests.rs` | ? | 可能需要拆分 |
| sb-adapters | `crates/sb-adapters/tests/` | ? | 迁移后更新 imports |
| sb-config | `crates/sb-config/tests/` | ? | 保持 |

---

## 重构后测试更新清单

| 迁移 | 测试影响 | 更新状态 |
|------|---------|---------|
| sb-core → sb-api | 相关单测迁移 | ⬜ 待完成 |
| sb-core → sb-adapters | 相关单测迁移 | ⬜ 待完成 |
