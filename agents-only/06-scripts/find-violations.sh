#!/bin/bash
# find-violations.sh - 查找依赖边界违规
# 用法: ./find-violations.sh

set -e

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$PROJECT_ROOT"

echo "=== 依赖边界违规检查 ==="
echo ""

echo "--- 1. sb-core 中的 Web 框架引用 ---"
grep -rn "use axum" crates/sb-core/src/ 2>/dev/null || echo "无 axum 引用"
grep -rn "use tonic" crates/sb-core/src/ 2>/dev/null || echo "无 tonic 引用"
grep -rn "use tower" crates/sb-core/src/ 2>/dev/null || echo "无 tower 引用"
grep -rn "use hyper" crates/sb-core/src/ 2>/dev/null || echo "无 hyper 引用"
echo ""

echo "--- 2. sb-core 中的 TLS/QUIC 引用 ---"
grep -rn "use rustls" crates/sb-core/src/ 2>/dev/null || echo "无 rustls 引用"
grep -rn "use quinn" crates/sb-core/src/ 2>/dev/null || echo "无 quinn 引用"
echo ""

echo "--- 3. sb-adapters 中的 sb-core 引用 ---"
grep -rn "sb_core::" crates/sb-adapters/src/ 2>/dev/null || echo "无 sb-core 引用"
grep -rn "use sb_core" crates/sb-adapters/src/ 2>/dev/null || echo "无 sb-core 引用"
echo ""

echo "--- 4. sb-types 中的运行时依赖 ---"
grep -rn "use tokio" crates/sb-types/src/ 2>/dev/null || echo "无 tokio 引用"
grep -rn "use async_std" crates/sb-types/src/ 2>/dev/null || echo "无 async_std 引用"
echo ""

echo "=== 检查完成 ==="
