# singbox-rust Makefile
# 常用开发命令

.PHONY: check test clippy boundaries boundaries-report verify-reality-local clean

# 默认：快速编译检查
check:
	cargo check --workspace

# 测试
test:
	cargo test --workspace

# Lint — relies on workspace.lints policy (safety lints stay `deny`, the rest are
# `warn`). Intentionally no `-- -D warnings`, so pedantic/nursery stay non-blocking.
clippy:
	cargo clippy --workspace --all-features --all-targets

# 依赖边界检查（严格模式，失败则阻断）
boundaries:
	@bash agents-only/06-scripts/check-boundaries.sh

# 依赖边界检查（报告模式，仅输出）
boundaries-report:
	@bash agents-only/06-scripts/check-boundaries.sh --report

# REALITY local deterministic gate (A1 fixture) — optional merge-precheck.
# Builds the kernels, runs the 20x positive matrix (Go->Go, Rust->Go, Go->Rust,
# phase probe) plus the 4 negative controls, and exits non-zero on ANY positive /
# negative / config-validation / readiness / teardown failure. Output goes to the
# gitignored runtime artifacts dir (run_fixture.py default --out); it never
# overwrites the committed evidence snapshot under
# labs/interop-lab/reality_local_fixture/evidence/.
verify-reality-local:
	python3 labs/interop-lab/reality_local_fixture/run_fixture.py --runs 20

# 清理
clean:
	cargo clean
