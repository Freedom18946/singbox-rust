# singbox-rust

A pragmatic rewrite path for sing-box in Rust. Focused on **good taste**, **never break userspace**, and **boring clarity**.

## 🚨 重要：项目导航权威文档

**⚠️ 开发者必读：在开始任何开发工作之前，请务必阅读并验证 [`PROJECT_STRUCTURE_NAVIGATION.md`](./PROJECT_STRUCTURE_NAVIGATION.md) 的准确性。**

- 📋 **权威性**: 该文档是项目结构的唯一权威参考
- 🔄 **更新责任**: 任何修改项目结构的开发者都必须同步更新该导航文档
- ✅ **验证要求**: 新的开发者或AI助手在开始工作前必须验证导航文档的准确性
- 📍 **导航优先**: 所有开发活动都应基于该导航文档进行路径规划

**如发现导航文档与实际项目结构不符，请立即更新文档后再继续开发工作。**

## Quick Start

```bash
cargo check --workspace --all-features
bash scripts/ci-local.sh
scripts/e2e-run.sh   # optional e2e summary → .e2e/summary.json
```

### Logging & Docs

- Runtime logs use `tracing` across binaries and libraries.
- Enable and filter logs via env:
  - `RUST_LOG=info` enables info-level logs (use `debug` for more detail).
  - Example: `RUST_LOG=sb_core=debug,app=info cargo run -p app -- version`.
  - JSON output (when subscriber configured): `RUST_LOG=info APP_LOG_JSON=1 ...`.

CLI bench (HTTP/2) requires feature `reqwest`:

```bash
cargo run -p app --features reqwest -- bench io --h2 --url https://example.com --requests 10 --concurrency 2 --json
```

## Lint Baseline

- Workspace default denies warnings: `cargo clippy --workspace --all-targets -- -D warnings`
- Strict lib-only checks (pedantic + nursery):
  - `cargo clippy -p sb-core --lib --features metrics -- -D warnings -W clippy::pedantic -W clippy::nursery -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic -D clippy::todo -D clippy::unimplemented -D clippy::undocumented_unsafe_blocks`
  - `cargo clippy -p sb-platform --lib -- -D warnings -W clippy::pedantic -W clippy::nursery -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic -D clippy::todo -D clippy::unimplemented -D clippy::undocumented_unsafe_blocks`
  - `cargo clippy -p sb-transport --lib -- -D warnings -W clippy::pedantic -W clippy::nursery -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic -D clippy::todo -D clippy::unimplemented -D clippy::undocumented_unsafe_blocks`

Docs & guides:
- Cookbook: docs/COOKBOOK.md
- Development gates: docs/DEVELOPMENT.md
- Operations: docs/OPS.md

Local verification:
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test -p app -q -- --nocapture`
- `cargo test -p sb-core --features metrics -q`

Run with an example:

```bash
bash scripts/run-examples.sh examples/configs/full_stack.json
```

## 📚 文档导航

### 🗺️ 项目结构导航 (必读)
- **[PROJECT_STRUCTURE_NAVIGATION.md](./PROJECT_STRUCTURE_NAVIGATION.md)** - 项目结构权威导航文档

### 📖 核心文档
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) - 架构设计文档
- [docs/ROUTER_RULES.md](docs/ROUTER_RULES.md) - 路由规则文档
- [docs/ENV_VARS.md](docs/ENV_VARS.md) - 环境变量配置
 - [docs/COOKBOOK.md](docs/COOKBOOK.md) - 快速上手/常见问题/可运行示例

### 🧪 测试文档
- [tests/README.md](tests/README.md) - 测试指南和目录结构

### Admin 实现选择
运行期可通过 CLI 或环境变量在 **核心实现** 与 **Debug 实现**间切换：

```bash
# 核心 Admin（默认）
run --admin-impl core

# Debug Admin（包含 Dry-Run、审计、config_version 等扩展）
SB_PREFETCH_ENABLE=1 \
SB_PREFETCH_CAP=256 \
SB_PREFETCH_WORKERS=2 \
run --admin-impl debug --admin-listen 127.0.0.1:8088
```

### 预取（Prefetch）
当 `/subs/...` 响应 `Cache-Control: max-age>=60` 时将触发异步预取，并在 `__metrics` 暴露：
```
sb_prefetch_queue_depth
sb_prefetch_jobs_total{event=...}
```
可使用 `scripts/prefetch-heat.sh` 观察指标变化。

## Status

Phase 2.4: inbounds (HTTP/SOCKS) wired, rule engine minimal, env-driven suffix rules.

## Deployment (Quickstart)

- Systemd (Linux): see `packaging/systemd/singbox-rs.service`, then:
  - `sudo cp packaging/systemd/singbox-rs.service /etc/systemd/system/`
  - `sudo systemctl daemon-reload && sudo systemctl enable --now singbox-rs`

- Docker (MUSL image): see `packaging/docker/Dockerfile.musl` and `packaging/docker/entrypoint.sh`.
  - Exposes admin/metrics and mounts `/data` for configs.
  - Example: `docker run -p 18088:18088 -v $PWD:/data singbox-rs:latest --config /data/minimal.yaml`

Health probe: `curl -fsS http://127.0.0.1:18088/metrics` (or admin ping endpoint if enabled).
## Troubleshooting

- Set `SB_PRINT_ENV=1` to print a one-line JSON snapshot of relevant environment variables at startup.
- Common errors and meanings:
  - `outbound_error_total{kind="udp",class="no_upstream"}`: proxy mode selected but no upstream configured; falls back to direct.
  - `balancer_failures_total{reason}`: upstream connect/send/recv failures with exponential backoff applied.
  - `udp_nat_reject_total{reason="capacity"}`: NAT table reached capacity; increase `SB_UDP_NAT_MAX` or reduce churn.
