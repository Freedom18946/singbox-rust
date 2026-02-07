# Feature Flag 分析（Feature Flags Analysis）

> **更新方式**：从 Cargo.toml 分析后更新

---

## 全局 Features

| Feature | 描述 | 涉及 Crate |
|---------|------|-----------|
| `parity` | Go parity 构建 | app, sb-core |
| `default` | 默认特性 | 全部 |

---

## sb-core Features

待分析：`crates/sb-core/Cargo.toml`

| Feature | 依赖 | 用途 |
|---------|------|------|
| 待分析 | | |

---

## sb-adapters Features

待分析：`crates/sb-adapters/Cargo.toml`

| Feature | 依赖 | 用途 |
|---------|------|------|
| 待分析 | | |

---

## Feature 冲突矩阵

| Feature A | Feature B | 冲突？ | 说明 |
|-----------|-----------|--------|------|
| 待分析 | | | |

---

## 分析命令

```bash
# 列出所有 features
cargo metadata --format-version 1 | jq '.packages[] | select(.name | startswith("sb-")) | {name: .name, features: .features}'
```
