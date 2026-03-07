# AI Agent 操作规则

> **强制规则**：所有 AI Agent 必须遵守

---

## 🚫 禁止操作

| 操作 | 说明 |
|------|------|
| **自动 git commit/push** | 必须等用户明确要求 |
| **自动写入关键文件** | README.md、Cargo.toml 等核心文件 |
| **触发 CI/CD** | GitHub Actions 已禁用，本地编译 |
| **自动升级依赖** | 需用户确认 |

---

## ✅ 允许操作

| 操作 | 说明 |
|------|------|
| 读取任何文件 | 分析、理解项目 |
| 写入 agents-only/ | 文档、日志、分析结果 |
| 写入 dump/ | 临时生成内容 |
| 本地编译/测试 | `cargo check/build/test` |
| 提出建议 | 向用户说明后等待确认 |
| 清理过期 dump | 删除 7 天前的 dump 文件 |

---

## 🎭 角色设定（Persona）

### 代码风格
| 偏好 | 说明 | 强制执行 |
|------|------|---------|
| **惯用 Rust** | 优先使用标准库和惯用模式 | clippy |
| **避免 `.unwrap()`** | 核心逻辑禁用，测试代码可用 | clippy |
| **错误链保留** | `?` + `thiserror` / `anyhow::Context` | clippy |
| **文档注释** | 公共 API 必须有 `///` 注释 | clippy |

### 沟通风格
| 偏好 | 说明 |
|------|------|
| **简洁** | 使用要点列表，避免冗长 |
| **中文优先** | 文档和注释使用中文 |
| **代码英文** | 变量名、函数名使用英文 |

### 思维链要求
| 场景 | 要求 |
|------|------|
| **架构变更** | 提出 2-3 个方案供选择 |
| **删除代码** | 说明原因和影响 |
| **新增依赖** | 评估边界影响 |

---

## 📁 Dump 文件管理

### 命名规范

```
dump/{YYYY-MM-DD}_{category}_{short_desc}.md
```

| 类别 | 用途 |
|------|------|
| `analysis` | 分析结果 |
| `report` | 任务报告 |
| `debug` | 调试记录 |
| `temp` | 临时文件 |

### 生命周期（TTL）

| 规则 | 说明 |
|------|------|
| **TTL = 7 天** | dump 文件默认存活 7 天 |
| **初始化清理** | Agent 初始化时可删除过期文件 |
| **归档保留** | 重要内容移动到 `archive/` 前保留 |

```bash
# 清理命令（在 init.md Step 6 执行）
find agents-only/dump -type f -mtime +7 -name "*.md" -delete
```

---

## ⚖️ 代码强制执行

以下规则由 `clippy.toml` 和 `cargo clippy` 强制执行：

| 规则 | Clippy Lint |
|------|------------|
| 避免 unwrap | `clippy::unwrap_used` (deny in lib) |
| 避免 expect | `clippy::expect_used` (deny in lib) |
| 避免 panic | `clippy::panic` (deny in lib) |
| 文档缺失 | `missing_docs` (warn) |

> **编译器当恶人**：让 `cargo clippy` 报错，而不是靠文档提醒

---

## 📋 工作流程

1. **开始前**：读取 `active_context.md` → 执行 `init.md`
2. **验证一致性**：确认 active_context 与 workpackage 同步
3. **执行中**：遵守本规则
4. **遇到问题**：记录到 `07-memory/TROUBLESHOOTING.md`
5. **学到模式**：记录到 `07-memory/LEARNED-PATTERNS.md`
6. **需要 commit**：通知用户，等待确认
7. **结束后**：更新 `active_context.md` + `log.md`

---

*本规则生效日期：2026-02-07*
