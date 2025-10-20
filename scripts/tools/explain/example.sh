#!/usr/bin/env zsh
set -euo pipefail
# 需要: sb-route-explain (feature=explain)

args=("$@")
echo "[STEP] 生成 DOT"

# 确保输出目录存在
mkdir -p .e2e

# 编译explain功能
echo "[STEP] 编译 explain 功能"
cargo build --features explain --bin sb-route-explain

# 生成解释
echo "[STEP] 运行路由解释"
./target/debug/sb-route-explain --sni example.com --port 443 --proto tcp --format dot > .e2e/explain.dot

echo "[OK] 见 .e2e/explain.dot (使用 dot -Tpng .e2e/explain.dot -o explain.png 渲染)"

# 也生成JSON格式用于验证
./target/debug/sb-route-explain --sni example.com --port 443 --proto tcp --format json > .e2e/explain.json
echo "[OK] JSON格式见 .e2e/explain.json"