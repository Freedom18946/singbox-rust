#!/bin/bash
# 发布脚本：自动发布到 crates.io

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 获取当前版本
VERSION=$(grep '^version =' Cargo.toml | sed 's/version = "\(.*\)"/\1/')
TAG="v${VERSION}"

echo -e "${GREEN}🚀 准备发布 anytls-rs v${VERSION}${NC}"
echo ""

# 检查 Git 状态
if ! git diff-index --quiet HEAD --; then
    echo -e "${RED}❌ 错误: 工作目录有未提交的更改${NC}"
    exit 1
fi

# 检查是否已存在标签
if git rev-parse "$TAG" >/dev/null 2>&1; then
    echo -e "${YELLOW}⚠️  标签 $TAG 已存在${NC}"
    read -p "是否继续? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# 运行检查
echo -e "${GREEN}📋 运行检查...${NC}"

echo "  - 格式化检查..."
cargo fmt --check || {
    echo -e "${RED}❌ 格式化检查失败${NC}"
    exit 1
}

echo "  - Clippy 检查..."
cargo clippy --all-targets --all-features -- -D warnings || {
    echo -e "${RED}❌ Clippy 检查失败${NC}"
    exit 1
}

echo "  - 构建检查..."
cargo build --release || {
    echo -e "${RED}❌ 构建失败${NC}"
    exit 1
}

echo "  - 测试..."
cargo test --all-features || {
    echo -e "${RED}❌ 测试失败${NC}"
    exit 1
}

echo "  - 包验证..."
cargo package --verify || {
    echo -e "${RED}❌ 包验证失败${NC}"
    exit 1
}

echo -e "${GREEN}✅ 所有检查通过${NC}"
echo ""

# 确认发布
echo -e "${YELLOW}准备发布:${NC}"
echo "  版本: $VERSION"
echo "  标签: $TAG"
echo "  仓库: $(git remote get-url origin)"
echo ""
read -p "确认发布到 crates.io? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "已取消"
    exit 0
fi

# 创建标签
echo -e "${GREEN}📌 创建 Git 标签...${NC}"
git tag -a "$TAG" -m "Release v${VERSION}"

# 推送标签
echo -e "${GREEN}📤 推送标签...${NC}"
git push origin "$TAG"

echo -e "${GREEN}✅ 标签已推送${NC}"
echo ""
echo -e "${YELLOW}📝 下一步:${NC}"
echo "  1. 本脚本保留 upstream 发布标签流程；当前仓库禁用 GitHub Actions 自动发布"
echo "  2. 如需发布，请使用当前仓库批准的手动发布流程"
echo "  3. 验证发布: https://crates.io/crates/anytls-rs"
