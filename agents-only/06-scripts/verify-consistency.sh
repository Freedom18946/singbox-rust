#!/bin/bash
# 一致性验证脚本 (Verify Consistency)
# 用途：检查 active_context 与 workpackage 的一致性（启动门，init.md Step 2）。
#   硬失败 (exit 1)：基础文件缺失/为空、active_context 指针指向不存在的文件、日期记录无法解析。
#   advisory (不失败)：遗留 WP-NNN id 不一致（格式已退役）、active_context 过期>7天、DRP 标记。
# 兼容性：macOS（date -j 为 macOS 专用语法）。

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

# 3. 工作包标识（advisory）+ active_context 指针完整性（hard）
# WP-NNN 微卡 id 格式已退役（workpackage_latest.md：不再继续 WP-30k 风格微卡化排程）。
# 当前工作以 phase/track 名（active_context "Resume" 段）标识，两文件间无单一 cross-check
# token，故 WP-NNN 比对降级为 reviewer 可读 advisory，不作为硬失败；当前权威的硬一致性
# invariant 改为 active_context 单一真相源指针的可解析性（见下）。
echo -e "\n检查工作包标识（advisory，WP-NNN 已退役）..."

WP_ID_CONTEXT=$(grep -oE "WP-[A-Z0-9.]+" "$ACTIVE_CONTEXT" | head -1 || echo "")
WP_ID_PACKAGE=$(grep -oE "WP-[A-Z0-9.]+" "$WORKPACKAGE" | head -1 || echo "")
if [[ -n "$WP_ID_CONTEXT" && -n "$WP_ID_PACKAGE" && "$WP_ID_CONTEXT" != "$WP_ID_PACKAGE" ]]; then
    echo -e "${YELLOW}⚠️  advisory: 遗留 WP-NNN id 不一致 (active_context=$WP_ID_CONTEXT, workpackage=$WP_ID_PACKAGE)${NC}"
    echo -e "   提示: WP-NNN 格式已退役；对齐或移除遗留 id（非硬失败）。"
else
    echo -e "${GREEN}✓ WP-NNN id 已退役且无遗留不一致（当前以 phase/track 名标识工作）${NC}"
fi

# 指针完整性（hard）：active_context 引用的每个 .md 单一真相源指针必须可解析。
# 解析顺序：含 '/' 的按 repo-root 相对；裸文件名先 agents-only 再 repo-root。
echo -e "\n检查 active_context 指针完整性..."
REPO_ROOT="$(cd "$AGENTS_DIR/.." && pwd)"
BROKEN_PTRS=""
PTR_TOKENS=$(grep -oE "[A-Za-z0-9_./-]+\.md" "$ACTIVE_CONTEXT" | sort -u || true)
while IFS= read -r ptr; do
    if [[ -z "$ptr" ]]; then continue; fi
    if [[ "$ptr" == */* ]]; then
        candidates=("$REPO_ROOT/$ptr" "$AGENTS_DIR/$ptr")
    else
        candidates=("$AGENTS_DIR/$ptr" "$REPO_ROOT/$ptr")
    fi
    found=0
    for c in "${candidates[@]}"; do
        if [[ -f "$c" ]]; then found=1; break; fi
    done
    if [[ $found -eq 0 ]]; then BROKEN_PTRS="$BROKEN_PTRS $ptr"; fi
done <<< "$PTR_TOKENS"
if [[ -n "$BROKEN_PTRS" ]]; then
    echo -e "${RED}❌ active_context 指针指向不存在的文件:${NC}"
    echo -e "   检查名: active_context pointer integrity"
    for p in $BROKEN_PTRS; do echo -e "   实际:   缺失引用 → $p"; done
    echo -e "   期望:   每个 .md 指针可解析；提示: 修正路径或补建被引用文件。"
    ERRORS=$((ERRORS + 1))
else
    echo -e "${GREEN}✓ active_context 指针均可解析${NC}"
fi

# 4. 检查日期合理性（最新日期 = filter→sort→max，不依赖文件尾部恰好是目标记录）
echo -e "\n检查日期合理性..."

LAST_UPDATE=$(grep -oE "[0-9]{4}-[0-9]{2}-[0-9]{2}" "$ACTIVE_CONTEXT" | sort | tail -1 || echo "")
if [[ -z "$LAST_UPDATE" ]]; then
    echo -e "${YELLOW}⚠️  未找到日期信息 (期望 active_context 含 YYYY-MM-DD)${NC}"
else
    UPDATE_EPOCH=$(date -j -f "%Y-%m-%d" "$LAST_UPDATE" +%s 2>/dev/null || echo 0)
    if [[ "$UPDATE_EPOCH" -eq 0 ]]; then
        echo -e "${RED}❌ 日期记录异常（无法解析）:${NC}"
        echo -e "   检查名: active_context 日期记录有效性"
        echo -e "   实际:   最新日期 token = $LAST_UPDATE"
        echo -e "   期望:   合法 YYYY-MM-DD；提示: 修正 active_context 中的日期记录。"
        ERRORS=$((ERRORS + 1))
    else
        DAYS_AGO=$(( ($(date +%s) - UPDATE_EPOCH) / 86400 ))
        if [[ $DAYS_AGO -gt 7 ]]; then
            echo -e "${YELLOW}⚠️  advisory: active_context 可能过期 (最新 $LAST_UPDATE, $DAYS_AGO 天前)${NC}"
        else
            echo -e "${GREEN}✓ 日期合理: 最新 $LAST_UPDATE ($DAYS_AGO 天前)${NC}"
        fi
    fi
fi

# 5. 检查 DRP 标记
echo -e "\n检查 DRP 状态..."

if grep -q "DRP 恢复" "$ACTIVE_CONTEXT"; then
    echo -e "${YELLOW}⚠️  检测到 DRP 恢复标记，请验证内容准确性${NC}"
else
    echo -e "${GREEN}✓ 无 DRP 恢复标记${NC}"
fi

# 6. S-tier 行数上限（hard）：CLAUDE.md / 文件头声明的纪律，超限即失败。
#    修复方式：压缩最老的 Resume 段进 Closed Tracks / archive，不是调高上限。
echo -e "\n检查 S-tier 行数上限..."

AC_LINES=$(wc -l < "$ACTIVE_CONTEXT")
WP_LINES=$(wc -l < "$WORKPACKAGE")
if [[ $AC_LINES -gt 300 ]]; then
    echo -e "${RED}❌ active_context.md 超限: $AC_LINES 行 (上限 300)${NC}"
    echo -e "   修复: 压缩最老 Resume 段（同质段合并为一条，细节留 git 历史 + log.md）。"
    ERRORS=$((ERRORS + 1))
else
    echo -e "${GREEN}✓ active_context.md $AC_LINES/300 行${NC}"
fi
if [[ $WP_LINES -gt 120 ]]; then
    echo -e "${RED}❌ workpackage_latest.md 超限: $WP_LINES 行 (上限 120)${NC}"
    echo -e "   修复: 已关闭 phase 压成一行；细节归档。"
    ERRORS=$((ERRORS + 1))
else
    echo -e "${GREEN}✓ workpackage_latest.md $WP_LINES/120 行${NC}"
fi

# 7. agents-only 顶层白名单：
#    文件 = hard（散文件是"关闭不归档"的主要违规形态）；
#    目录 = advisory（新轨迹目录立项合法，但要登记进 README.md + 本清单）。
echo -e "\n检查 agents-only 顶层白名单..."

ALLOWED_FILES="active_context.md workpackage_latest.md init.md README.md log.md"
ALLOWED_DIRS="06-scripts archive fable5审计报告 memory mig03 mt_real_01_evidence mt_real_02_evidence post1313 reference templates"

TOPLEVEL_VIOLATION=0
for entry in "$AGENTS_DIR"/*; do
    name=$(basename "$entry")
    if [[ -f "$entry" ]]; then
        if ! grep -qw "$name" <<< "$ALLOWED_FILES"; then
            echo -e "${RED}❌ 顶层散文件不在白名单: $name${NC}"
            echo -e "   修复: git mv 进所属轨迹目录或 archive/{track}/（关闭即归档）。"
            ERRORS=$((ERRORS + 1)); TOPLEVEL_VIOLATION=1
        fi
    elif [[ -d "$entry" ]]; then
        if ! grep -qw "$name" <<< "$ALLOWED_DIRS"; then
            echo -e "${YELLOW}⚠️  advisory: 顶层目录不在已知清单: $name/${NC}"
            echo -e "   若为新活动轨迹: 登记进 agents-only/README.md 目录树 + 本脚本 ALLOWED_DIRS；"
            echo -e "   若轨迹已关闭: git mv 进 archive/。"
            TOPLEVEL_VIOLATION=1
        fi
    fi
done
if [[ $TOPLEVEL_VIOLATION -eq 0 ]]; then
    echo -e "${GREEN}✓ 顶层无白名单外条目${NC}"
fi

# 8. 陈旧度 advisory：最老 Resume 段 >14 天提示压缩；log.md >10000 行提示滚动归档。
echo -e "\n检查文档陈旧度（advisory）..."

OLDEST_RESUME=$(grep -oE "^## Resume \([0-9]{4}-[0-9]{2}-[0-9]{2}\)" "$ACTIVE_CONTEXT" \
    | grep -oE "[0-9]{4}-[0-9]{2}-[0-9]{2}" | sort | head -1 || echo "")
if [[ -n "$OLDEST_RESUME" ]]; then
    OLDEST_EPOCH=$(date -j -f "%Y-%m-%d" "$OLDEST_RESUME" +%s 2>/dev/null || echo 0)
    if [[ "$OLDEST_EPOCH" -gt 0 ]]; then
        RESUME_DAYS=$(( ($(date +%s) - OLDEST_EPOCH) / 86400 ))
        if [[ $RESUME_DAYS -gt 14 ]]; then
            echo -e "${YELLOW}⚠️  advisory: 最老 Resume 段 $OLDEST_RESUME ($RESUME_DAYS 天前) — 压缩进 Closed Tracks${NC}"
        else
            echo -e "${GREEN}✓ 最老 Resume 段 $OLDEST_RESUME ($RESUME_DAYS 天前)${NC}"
        fi
    fi
else
    echo -e "${GREEN}✓ 无 Resume 段日期可检${NC}"
fi

LOG_FILE="$AGENTS_DIR/log.md"
if [[ -f "$LOG_FILE" ]]; then
    LOG_LINES=$(wc -l < "$LOG_FILE")
    if [[ $LOG_LINES -gt 10000 ]]; then
        echo -e "${YELLOW}⚠️  advisory: log.md $LOG_LINES 行 — 旧段滚动归档进 archive/logs/（保留头部+最近条目）${NC}"
    else
        echo -e "${GREEN}✓ log.md $LOG_LINES/10000 行${NC}"
    fi
fi

# tier 标记（advisory）：顶层 md 首行应有 <!-- tier: S/A/B/C -->
for f in "$AGENTS_DIR"/*.md; do
    if ! head -1 "$f" | grep -q "tier:"; then
        echo -e "${YELLOW}⚠️  advisory: $(basename "$f") 首行缺 tier 标记${NC}"
    fi
done

# 结果汇总
echo -e "\n---"
if [[ $ERRORS -eq 0 ]]; then
    echo -e "${GREEN}✅ 一致性验证通过${NC}"
    exit 0
else
    echo -e "${RED}❌ 发现 $ERRORS 个问题${NC}"
    exit 1
fi
