# singbox-rust Makefile
# 常用开发命令

.PHONY: check test clippy boundaries boundaries-report clean

# 默认：快速编译检查
check:
	cargo check --workspace

# 测试
test:
	cargo test --workspace

# Lint
clippy:
	cargo clippy --workspace -- -D warnings

# 依赖边界检查（严格模式，失败则阻断）
boundaries:
	@bash agents-only/06-scripts/check-boundaries.sh

# 依赖边界检查（报告模式，仅输出）
boundaries-report:
	@bash agents-only/06-scripts/check-boundaries.sh --report

# 清理
clean:
	cargo clean
