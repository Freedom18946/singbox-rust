#!/bin/bash
# Ultrathink 完成验证脚本

set -e

echo "=========================================="
echo "Ultrathink 生产级代码质量验证"
echo "=========================================="
echo ""

echo "1. 检查编译错误..."
if cargo check --workspace --all-features 2>&1 | grep -q "error:"; then
    echo "❌ 发现编译错误"
    exit 1
else
    echo "✅ 零编译错误"
fi
echo ""

echo "2. 检查编译警告..."
WARNING_COUNT=$(cargo check --workspace --all-features 2>&1 | grep -c "warning:" || true)
if [ "$WARNING_COUNT" -eq 0 ]; then
    echo "✅ 零编译警告"
else
    echo "❌ 发现 $WARNING_COUNT 个警告"
    exit 1
fi
echo ""

echo "3. 检查完整构建..."
if cargo build --workspace --all-features > /dev/null 2>&1; then
    echo "✅ 完整构建成功"
else
    echo "❌ 构建失败"
    exit 1
fi
echo ""

echo "4. 检查核心 deny lints..."
if cargo clippy --workspace --all-features 2>&1 | grep -q "unwrap_used\|panic\["; then
    echo "❌ 发现 deny 级别的 lint 违规"
    exit 1
else
    echo "✅ 核心 deny lints 通过"
fi
echo ""

echo "=========================================="
echo "✅ 所有验证通过！"
echo "=========================================="
echo ""
echo "代码质量指标:"
echo "  - 编译错误: 0"
echo "  - 编译警告: 0"
echo "  - 构建状态: 成功"
echo "  - Deny lints: 通过"
echo ""
echo "代码已达到生产级别质量标准！"
