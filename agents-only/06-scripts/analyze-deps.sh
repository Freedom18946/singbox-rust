#!/bin/bash
# analyze-deps.sh - 分析 crate 依赖关系
# 用法: ./analyze-deps.sh [crate_name]

set -e

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$PROJECT_ROOT"

echo "=== 依赖分析 ==="
echo "项目根目录: $PROJECT_ROOT"
echo ""

if [ -n "$1" ]; then
    echo "分析 $1 的依赖..."
    cargo tree -p "$1" --depth 2
else
    echo "分析所有 sb-* crates..."
    for crate in crates/sb-*/; do
        name=$(basename "$crate")
        echo ""
        echo "--- $name ---"
        cargo tree -p "$name" --depth 1 2>/dev/null || echo "跳过: $name"
    done
fi

echo ""
echo "=== 完成 ==="
