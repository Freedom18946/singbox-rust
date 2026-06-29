<!-- tier: S -->
# AI 初始化检查（Init Checklist）

> ⚠️ **强制执行**：任何 AI/Agent 首次进入本仓库，按顺序执行以下校验。
> 目标：30 秒内抓住"当前在做什么 + 最近构建状态 + 别再踩的坑"。

---

## Step 1: 读取当前上下文（按此顺序）

```
1. agents-only/active_context.md          # 当前状态唯一权威（必读）
2. agents-only/workpackage_latest.md       # 阶段地图 / 全局位置
3. CLAUDE.md  +  AGENTS.md                 # 稳定约定 / 硬规则 / 单一真相源
```

**REALITY 历史参考（本地主线已封箱，T3 收口）**：
```
agents-only/mt_real_02_baseline.md         # REALITY ClientHello 基线长报告
agents-only/mt_real_02_evidence/           # 轮次证据
scripts/tools/test_reality_probe_tools.py  # 探测工具链
```

> ⚠️ **DRP（灾难恢复）**：若 `active_context.md` 为空/损坏：
> `./agents-only/06-scripts/restore-context.sh`

## Step 2: 验证战略一致性

```bash
./agents-only/06-scripts/verify-consistency.sh
```
防止 active_context 与 workpackage 漂移。

## Step 3: 检查长期记忆（避免重复踩坑）

```
agents-only/memory/LEARNED-PATTERNS.md     # 可复用模式
agents-only/memory/TROUBLESHOOTING.md      # 踩坑记录
```
（`memory/implementation-history.md` 与 `log.md` 是 C-tier 历史，**勿主动读**。）

## Step 4: 检查代码库变更

```bash
git log --oneline -5 && git status --short
cargo check -p app 2>&1 | tail -5
```

## Step 5: 了解可用工具

```
agents-only/06-scripts/TOOLS_DEF.md        # 可调用脚本，避免重复造轮子
agents-only/reference/SCRIPTS-MAP.md       # scripts/ 与 06-scripts/ 全景
```

---

## 📋 AI 行为准则

1. **先读后写**：任何修改前先完成本检查清单。
2. **单一真相源**：易变数字（parity / 测试数 / 门禁）只活在权威源里，引用不复制（见 `CLAUDE.md`）。
3. **更新上下文**：任务结束前更新 `agents-only/active_context.md`（≤300 行，先删旧快照）。
4. **记录经验**：学到模式/踩到坑 → 更新 `agents-only/memory/`（注意：是 `memory/`，不是 `07-memory/`）。
5. **关闭即归档**：工作线关闭后产物 `git mv` 进 `archive/{track}/`，不留顶层、不在根目录建工作目录。
6. **查阅术语**：不确定术语查 `reference/GLOSSARY.md`；操作规则参考 `archive/AI-RULES.md`（C-tier）。

---

## 🔍 上下文获取优先级

| 优先级 | 文件 | 用途 |
|--------|------|------|
| 1️⃣ | `active_context.md` | 当前状态唯一权威 |
| 2️⃣ | `workpackage_latest.md` | 阶段与全局位置 |
| 3️⃣ | `CLAUDE.md` / `AGENTS.md` | 稳定约定 / 硬规则 |
| 4️⃣ | `mt_real_02_baseline.md` | REALITY 基线长报告（已封箱，历史参考） |
| 5️⃣ | `reference/AGENT-DEVELOPMENT-GUIDELINES.md` | 长期开发准则 |
| 6️⃣ | `memory/*.md` | 经验积累 |
| 7️⃣ | `log.md` | 历史流水（C-tier，按需） |

---

*本文件是 AI 工作的入口点。违反初始化流程可能导致工作重复或冲突。*
