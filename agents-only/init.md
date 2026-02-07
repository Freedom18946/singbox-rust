# AI 初始化检查（Init Checklist）

> ⚠️ **强制执行**：任何 AI/Agent/LLM 首次读到本文件，必须立即执行以下校验和更新操作。

---

## 🚨 初始化流程（必须按顺序执行）

### Step 1: 读取最新日志
```
查阅 agents-only/log.md 中的最新 3-5 条日志记录
```
**目的**：了解上一个 AI 做了什么，避免重复或冲突

### Step 2: 检查代码库变更
```bash
# 查看最近的 git 提交
git log --oneline -10

# 查看未提交的变更
git status
git diff --stat
```
**目的**：确认当前代码状态，识别进行中的工作

### Step 3: 验证关键状态
| 检查项 | 当前值 | 验证方式 |
|--------|--------|---------|
| Parity 百分比 | 88% | 查看 `GO_PARITY_MATRIX.md` 顶部 |
| Rust 版本 | 1.92+ | 查看 `rust-toolchain.toml` |
| 上次更新日期 | 2026-02-07 | 查看 `log.md` 最新条目 |

### Step 4: 更新过期信息
如果发现以下信息过期，必须更新：
- [ ] `00-PROJECT-OVERVIEW.md` 中的状态数据
- [ ] `01-REQUIREMENTS-ANALYSIS.md` 中的 Gap 分析
- [ ] `02-ACCEPTANCE-CRITERIA.md` 中的验收指标

### Step 5: 记录初始化
在 `log.md` 中追加初始化记录：
```markdown
### [YYYY-MM-DD HH:MM] Agent: [Your ID]

**任务**: 初始化检查
**变更**: 无 / [列出更新的文件]
**结果**: 成功
**备注**: 已确认信息最新 / [说明发现的不一致]
```

---

## ⚡ 快速校验命令

```bash
# 一键检查项目状态
cd /Users/bob/Desktop/Projects/ING/sing/singbox-rust

# Git 状态
git log --oneline -5 && git status --short

# 构建验证
cargo check -p app 2>&1 | tail -5

# 测试快速验证
cargo test --lib -p sb-types 2>&1 | tail -3
```

---

## 📋 AI 行为准则

1. **先读后写**：执行任何修改前，先完成初始化检查
2. **写日志**：任务完成前，必须更新 `log.md`
3. **保持同步**：如果修改了架构或状态，更新相关 agents-only 文档
4. **不要假设**：如果信息可能过期，重新验证
5. **接续工作**：基于上一个 AI 的进度继续，不要重新开始
6. **渐进式规划**：不做超前规划，详见 `06-STRATEGIC-ROADMAP.md` 中的规划原则

---

## 🔍 上下文获取优先级

1. `agents-only/log.md` - 最新 AI 活动
2. `agents-only/06-STRATEGIC-ROADMAP.md` - 当前战略目标
3. `NEXT_STEPS.md` - 里程碑状态
4. `GO_PARITY_MATRIX.md` - 详细对齐状态
5. `git log` / `git status` - 代码变更

---

*本文件是 AI 工作的入口点。违反初始化流程可能导致工作重复或冲突。*
