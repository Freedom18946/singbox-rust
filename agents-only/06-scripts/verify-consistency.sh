#!/bin/bash
# 一致性验证脚本 (Verify Consistency)
# 用途：检查 active_context 与 workpackage 的一致性
# 兼容性：macOS（date -j 为 macOS 专用语法）

set -e

AGENTS_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ACTIVE_CONTEXT="$AGENTS_DIR/active_context.md"
WORKPACKAGE="$AGENTS_DIR/workpackage_latest.md"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ERRORS=0

echo "🔍 一致性验证开始..."
echo "---"

# 1. 检查文件存在性
echo "检查文件存在..."

if [[ ! -f "$ACTIVE_CONTEXT" ]]; then
    echo -e "${RED}❌ active_context.md 不存在${NC}"
    ERRORS=$((ERRORS + 1))
else
    echo -e "${GREEN}✓ active_context.md 存在${NC}"
fi

if [[ ! -f "$WORKPACKAGE" ]]; then
    echo -e "${RED}❌ workpackage_latest.md 不存在${NC}"
    ERRORS=$((ERRORS + 1))
else
    echo -e "${GREEN}✓ workpackage_latest.md 存在${NC}"
fi

# 如果基础文件不存在，提前退出
if [[ $ERRORS -gt 0 ]]; then
    echo -e "\n${RED}❌ 基础文件缺失，无法继续验证${NC}"
    exit 1
fi

# 2. 检查文件非空
echo -e "\n检查文件内容..."

if [[ ! -s "$ACTIVE_CONTEXT" ]]; then
    echo -e "${RED}❌ active_context.md 为空${NC}"
    ERRORS=$((ERRORS + 1))
else
    LINES=$(wc -l < "$ACTIVE_CONTEXT")
    echo -e "${GREEN}✓ active_context.md 有内容 ($LINES 行)${NC}"
fi

# 3. 检查 WP ID 一致性
echo -e "\n检查工作包 ID 一致性..."

WP_ID_CONTEXT=$(grep -oE "WP-[A-Z0-9.]+" "$ACTIVE_CONTEXT" | head -1 || echo "")
WP_ID_PACKAGE=$(grep -oE "WP-[A-Z0-9.]+" "$WORKPACKAGE" | head -1 || echo "")

if [[ -z "$WP_ID_CONTEXT" ]]; then
    echo -e "${YELLOW}⚠️  active_context.md 中未找到工作包 ID${NC}"
    ERRORS=$((ERRORS + 1))
elif [[ -z "$WP_ID_PACKAGE" ]]; then
    echo -e "${YELLOW}⚠️  workpackage_latest.md 中未找到工作包 ID${NC}"
    ERRORS=$((ERRORS + 1))
elif [[ "$WP_ID_CONTEXT" != "$WP_ID_PACKAGE" ]]; then
    echo -e "${RED}❌ 工作包 ID 不一致:${NC}"
    echo -e "   active_context: $WP_ID_CONTEXT"
    echo -e "   workpackage:    $WP_ID_PACKAGE"
    ERRORS=$((ERRORS + 1))
else
    echo -e "${GREEN}✓ 工作包 ID 一致: $WP_ID_CONTEXT${NC}"
fi

# 4. 检查日期合理性
echo -e "\n检查日期合理性..."

LAST_UPDATE=$(grep -oE "[0-9]{4}-[0-9]{2}-[0-9]{2}" "$ACTIVE_CONTEXT" | tail -1 || echo "")
if [[ -n "$LAST_UPDATE" ]]; then
    DAYS_AGO=$(( ($(date +%s) - $(date -j -f "%Y-%m-%d" "$LAST_UPDATE" +%s 2>/dev/null || echo 0)) / 86400 ))
    if [[ $DAYS_AGO -gt 7 ]]; then
        echo -e "${YELLOW}⚠️  active_context 可能过期 (最后更新: $LAST_UPDATE, $DAYS_AGO 天前)${NC}"
    else
        echo -e "${GREEN}✓ 日期合理: $LAST_UPDATE${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  未找到日期信息${NC}"
fi

# 5. 检查 DRP 标记
echo -e "\n检查 DRP 状态..."

if grep -q "DRP 恢复" "$ACTIVE_CONTEXT"; then
    echo -e "${YELLOW}⚠️  检测到 DRP 恢复标记，请验证内容准确性${NC}"
else
    echo -e "${GREEN}✓ 无 DRP 恢复标记${NC}"
fi

# 结果汇总
echo -e "\n---"
if [[ $ERRORS -eq 0 ]]; then
    echo -e "${GREEN}✅ 一致性验证通过${NC}"
    exit 0
else
    echo -e "${RED}❌ 发现 $ERRORS 个问题${NC}"
    exit 1
fi
