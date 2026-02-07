# 违规代码位置（Violation Locations）

> **更新方式**：运行 `find-violations.sh` 后更新

---

## sb-core 违规清单

### Web 框架依赖

| 文件 | 行号 | 违规内容 | 迁移目标 |
|------|------|---------|---------|
| 待分析 | - | `use axum::*` | sb-api |
| 待分析 | - | `use tonic::*` | sb-api |
| 待分析 | - | `use tower::*` | sb-api |
| 待分析 | - | `use hyper::*` | sb-api |

### TLS/QUIC 依赖

| 文件 | 行号 | 违规内容 | 迁移目标 |
|------|------|---------|---------|
| 待分析 | - | `use rustls::*` | sb-tls |
| 待分析 | - | `use quinn::*` | sb-transport |

### 协议实现代码

| 文件 | 行号 | 违规内容 | 迁移目标 |
|------|------|---------|---------|
| 待分析 | - | 具体协议实现 | sb-adapters |

---

## sb-adapters 违规清单

### 反向依赖 sb-core

| 文件 | 行号 | 违规内容 | 解决方案 |
|------|------|---------|---------|
| Cargo.toml | - | `sb-core = { ... }` | 改用 sb-types |

---

## 分析命令

```bash
# 查找 sb-core 中的 axum 引用
grep -rn "use axum" crates/sb-core/src/

# 查找 sb-core 中的 rustls 引用
grep -rn "use rustls" crates/sb-core/src/

# 查找 sb-adapters 中的 sb-core 引用
grep -rn "sb_core" crates/sb-adapters/src/
```
