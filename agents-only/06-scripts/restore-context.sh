#!/bin/bash
# DRP 自动恢复脚本（Disaster Recovery Protocol）
# 用途：当 active_context.md 为空或损坏时，自动重建

set -e

AGENTS_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ACTIVE_CONTEXT="$AGENTS_DIR/active_context.md"
LOG_FILE="$AGENTS_DIR/log.md"
WORKPACKAGE="$AGENTS_DIR/workpackage_latest.md"
ARCHIVE_DIR="$AGENTS_DIR/archive"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}🆘 DRP: 开始恢复 active_context.md...${NC}"

# 0. 检查必要文件存在
if [[ ! -f "$WORKPACKAGE" ]]; then
    echo -e "${RED}❌ 错误: workpackage_latest.md 不存在${NC}"
    exit 1
fi

if [[ ! -f "$LOG_FILE" ]]; then
    echo -e "${YELLOW}⚠️  警告: log.md 不存在，使用默认值${NC}"
fi

# 1. 备份现有文件（如果存在且非空）
if [[ -f "$ACTIVE_CONTEXT" && -s "$ACTIVE_CONTEXT" ]]; then
    mkdir -p "$ARCHIVE_DIR"
    BACKUP_NAME="$ARCHIVE_DIR/active_context_$(date +%Y%m%d_%H%M%S).md.bak"
    cp "$ACTIVE_CONTEXT" "$BACKUP_NAME"
    echo -e "${GREEN}✓ 已备份到: $BACKUP_NAME${NC}"
fi

# 2. 提取 workpackage 当前 ID（带默认值）
WP_ID=$(grep -m1 "当前工作包" "$WORKPACKAGE" 2>/dev/null | grep -oE "WP-[A-Z0-9.]+" || echo "WP-UNKNOWN")
WP_STAGE=$(grep -m1 "当前阶段" "$WORKPACKAGE" 2>/dev/null | sed 's/.*：//' || echo "未知阶段")

echo -e "  📋 工作包: ${GREEN}$WP_ID${NC}"
echo -e "  📊 阶段: ${GREEN}$WP_STAGE${NC}"

# 3. 获取最近 commit（带默认值）
LAST_COMMIT=$(git log --oneline -1 2>/dev/null || echo "无 git 记录")

# 4. 提取 log 最后一个任务描述（带默认值）
if [[ -f "$LOG_FILE" ]]; then
    LAST_TASK=$(grep -E "^\*\*任务\*\*:" "$LOG_FILE" 2>/dev/null | tail -1 | sed 's/\*\*任务\*\*: //' || echo "未知任务")
else
    LAST_TASK="未知任务（log.md 不存在）"
fi

# 5. 生成恢复的 active_context.md
cat > "$ACTIVE_CONTEXT" << EOF
# 当前上下文（Active Context）

> **⚠️ DRP 恢复**：本文件由 restore-context.sh 自动生成
> **恢复时间**：$(date "+%Y-%m-%d %H:%M")

---

## 🔗 战略链接

**当前工作包**: [$WP_ID](workpackage_latest.md)
**里程碑**: $WP_STAGE

---

## 🎯 当前聚焦

**模块**: 待确认（DRP 恢复后需手动更新）
**任务**: $LAST_TASK

---

## 🚧 活跃阻碍项（Active Blockers）

| ID | 描述 | 严重程度 | 状态 |
|----|------|---------|------|
| DRP-001 | active_context 曾损坏，需验证状态 | 🟡 中 | 待处理 |

---

## 🔨 最近构建状态

| 项目 | 状态 | 时间 |
|------|------|------|
| 最近 commit | $LAST_COMMIT | - |
| \`cargo check\` | ⏸️ 待验证 | - |

---

## 📋 下一步行动

1. **验证恢复内容**：检查工作包状态是否正确
2. **更新聚焦模块**：根据实际情况修改
3. **运行构建**：确认代码状态

---

*⚠️ 本文件由 DRP 自动生成，请在验证后更新*
EOF

echo -e "${GREEN}✅ DRP 恢复完成: $ACTIVE_CONTEXT${NC}"
echo -e "${YELLOW}⚠️  请手动验证并更新聚焦模块${NC}"

# 自动运行一致性验证
echo -e "\n运行一致性验证..."
SCRIPT_DIR="$(dirname "$0")"
"$SCRIPT_DIR/verify-consistency.sh" || echo -e "${YELLOW}⚠️ 验证有警告，请检查恢复内容${NC}"
