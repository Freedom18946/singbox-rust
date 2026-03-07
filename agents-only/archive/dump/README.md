# Dump 目录

> 此目录存放临时生成的一次性文档和脚本

---

## 用途

- AI Agent 执行任务时生成的临时报告
- 一次性分析结果
- 临时脚本和代码片段
- 可以定期清理的内容

---

## 命名规范

```
YYYY-MM-DD-{类型}-{描述}.md
```

**示例**：
- `2026-02-07-analysis-sb-core-deps.md`
- `2026-02-07-task-refactor-router.md`
- `2026-02-07-script-batch-rename.sh`

---

## 清理策略

超过 30 天的文件可以安全删除：

```bash
find dump/ -type f -mtime +30 -delete
```

---

## 当前文件

<!-- 自动生成或手动维护 -->
*此目录当前为空*
