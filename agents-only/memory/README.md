# 长期记忆目录（Memory）

> **用途**：积累项目经验，防止重复踩坑

---

## 📂 文件说明

| 文件 | 用途 | 更新时机 |
|------|------|---------|
| [LEARNED-PATTERNS.md](./LEARNED-PATTERNS.md) | 代码模式、约定、最佳实践 | 发现有效模式时 |
| [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) | 报错及解决方案 | 解决问题后 |

---

## 🧠 记忆类型

| 类型 | 说明 | 示例 |
|------|------|------|
| **模式** | 项目特定编码约定 | "使用 thiserror 定义错误" |
| **故障** | 遇到的问题和解决方案 | "linker error → brew install cmake" |
| **决策** | 重大技术选择 | "选择 tokio 而非 async-std" |

---

## ✍️ 如何记录

### 添加模式
在 `LEARNED-PATTERNS.md` 的对应表格中添加行：

```markdown
| 约定名 | 原因 | 添加日期 |
|--------|------|---------|
| 新模式描述 | 为什么采用 | YYYY-MM-DD |
```

### 添加故障
在 `TROUBLESHOOTING.md` 的对应表格中添加行：

```markdown
| 错误 | 原因 | 解决方案 |
|------|------|---------|
| 错误描述 | 根本原因 | 修复命令或步骤 |
```

---

## 🔍 使用时机

- **初始化时**：`init.md` Step 3 要求查阅此目录
- **遇到问题时**：先查 `TROUBLESHOOTING.md`
- **编码前**：查 `LEARNED-PATTERNS.md` 了解约定

---

*本目录是项目知识积累的核心*
