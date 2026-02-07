# AI 初始化检查（Init Checklist）

> ⚠️ **强制执行**：任何 AI/Agent/LLM 首次读到本文件，必须立即执行以下校验和更新操作。

---

## 🚨 初始化流程（必须按顺序执行）

### Step 1: 读取当前上下文（优先）
```
查阅 agents-only/active_context.md
```
**目的**：瞬间抓住当前聚焦模块、活跃阻碍项、最近构建状态

> ⚠️ **DRP（灾难恢复）**：如果 `active_context.md` 为空或损坏，立即执行：
> ```bash
> ./agents-only/06-scripts/restore-context.sh
> ```

### Step 2: 验证战略一致性
```bash
./agents-only/06-scripts/verify-consistency.sh
```
**目的**：防止战术-战略漂移

### Step 3: 检查长期记忆
```
查阅 agents-only/07-memory/LEARNED-PATTERNS.md
查阅 agents-only/07-memory/TROUBLESHOOTING.md
```
**目的**：避免重复踩坑，复用已积累的经验

### Step 4: 检查代码库变更
```bash
git log --oneline -5 && git status --short
```
**目的**：确认当前代码状态，识别进行中的工作

### Step 5: 了解可用工具
```
查阅 agents-only/06-scripts/TOOLS_DEF.md
```
**目的**：了解可调用的脚本，避免重复造轮子

### Step 6: 归档过期 dump 文件（软删除）
```bash
# 将 7 天前的 dump 文件移动到归档（可选执行）
mkdir -p agents-only/archive/dump
find agents-only/dump -type f -mtime +7 -name "*.md" \
  -exec mv {} agents-only/archive/dump/ \;
```
**目的**：防止僵尸文件误导，但保留可恢复性

---

## ⚡ 快速校验命令

```bash
cd /Users/bob/Desktop/Projects/ING/sing/singbox-rust

# Git 状态
git log --oneline -5 && git status --short

# 构建验证
cargo check -p app 2>&1 | tail -5
```

---

## 📋 AI 行为准则

1. **先读后写**：执行任何修改前，先完成初始化检查
2. **验证一致性**：确保 active_context 与 workpackage 同步
3. **更新上下文**：任务结束前，更新 `active_context.md`
4. **记录经验**：遇到问题或学到模式，更新 `07-memory/`
5. **遵守规则**：严格遵守 `AI-RULES.md`
6. **查阅术语**：不确定术语时查阅 `02-reference/GLOSSARY.md`

---

## 🔍 上下文获取优先级

| 优先级 | 文件 | 用途 |
|--------|------|------|
| 1️⃣ | `active_context.md` | 当前状态快照 |
| 2️⃣ | `workpackage_latest.md` | 战略验证 |
| 3️⃣ | `07-memory/*.md` | 经验积累 |
| 4️⃣ | `02-reference/GLOSSARY.md` | 术语确认 |
| 5️⃣ | `log.md` | 历史记录（按需） |

---

*本文件是 AI 工作的入口点。违反初始化流程可能导致工作重复或冲突。*
