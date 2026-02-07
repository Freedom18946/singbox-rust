# 模板索引（Templates Index）

> 此目录包含可复用的文档模板，供 AI Agent 创建新文档时参考

---

## 模板清单

| 模板 | 用途 | 使用场景 |
|------|------|---------|
| [TASK-REPORT.template.md](./TASK-REPORT.template.md) | 任务报告 | 完成一个任务后 |
| [ANALYSIS-RESULT.template.md](./ANALYSIS-RESULT.template.md) | 分析结果 | 源码分析完成后 |
| [MIGRATION-RECORD.template.md](./MIGRATION-RECORD.template.md) | 迁移记录 | 代码迁移后 |
| [DECISION.template.md](./DECISION.template.md) | 决策记录 | 需要记录技术决策时 |

---

## 使用方式

```bash
# 复制模板并重命名
cp templates/TASK-REPORT.template.md dump/2026-02-07-task-xxx.md
```

**注意**：生成的一次性文档放入 `dump/` 目录
