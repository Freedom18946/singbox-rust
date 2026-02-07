#!/bin/bash
# check-boundaries.sh - CI 用边界检查（失败时返回非零）
# 用法: ./check-boundaries.sh

set -e

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$PROJECT_ROOT"

FAILED=0

echo "=== CI 边界检查 ==="
echo ""

# 检查 sb-core 不应有的依赖
echo "检查 sb-core 依赖边界..."
if cargo tree -p sb-core 2>/dev/null | grep -qE "axum|tonic|tower[^-]|hyper[^-]"; then
    echo "❌ FAIL: sb-core 包含禁止的 Web 框架依赖"
    FAILED=1
else
    echo "✅ PASS: sb-core 无 Web 框架依赖"
fi

if cargo tree -p sb-core 2>/dev/null | grep -qE "^[├└].*rustls|^[├└].*quinn"; then
    echo "❌ FAIL: sb-core 包含禁止的 TLS/QUIC 直接依赖"
    FAILED=1
else
    echo "✅ PASS: sb-core 无 TLS/QUIC 直接依赖"
fi

# 检查 sb-adapters 不应反向依赖 sb-core
echo ""
echo "检查 sb-adapters 依赖方向..."
if cargo tree -p sb-adapters 2>/dev/null | grep -q "sb-core"; then
    echo "❌ FAIL: sb-adapters 反向依赖 sb-core"
    FAILED=1
else
    echo "✅ PASS: sb-adapters 无 sb-core 反向依赖"
fi

# 检查 sb-types 纯净性
echo ""
echo "检查 sb-types 纯净性..."
if cargo tree -p sb-types 2>/dev/null | grep -qE "tokio|async-std"; then
    echo "❌ FAIL: sb-types 包含运行时依赖"
    FAILED=1
else
    echo "✅ PASS: sb-types 无运行时依赖"
fi

echo ""
if [ $FAILED -eq 0 ]; then
    echo "=== 全部检查通过 ✅ ==="
    exit 0
else
    echo "=== 存在违规 ❌ ==="
    exit 1
fi
