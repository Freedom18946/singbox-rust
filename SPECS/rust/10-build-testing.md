# 构建与测试

## 1. 构建系统

### 1.1 Cargo Workspace

项目使用 Cargo workspace 组织，根 `Cargo.toml` 定义：

```toml
[workspace]
resolver = "2"
members = [
    "app",                    # 主应用
    "benches",                # 基准测试
    "crates/sb-adapters",     # 协议适配器
    "crates/sb-admin-contract", # 管理接口契约
    "crates/sb-common",       # 通用工具
    "crates/sb-core",         # 核心引擎
    "crates/sb-config",       # 配置系统
    "crates/sb-metrics",      # 指标
    "crates/sb-security",     # 安全工具
    "crates/sb-test-utils",   # 测试工具
    "crates/sb-types",        # 共享类型
    "crates/sb-proto",        # 协议定义
    "crates/sb-runtime",      # 运行时
    "crates/sb-platform",     # 平台适配
    "crates/sb-transport",    # 传输层
    "crates/sb-subscribe",    # 订阅解析
    "crates/sb-api",          # REST API
    "crates/sb-tls",          # TLS 实现
    "xtask",                  # 构建任务
    "xtests",                 # 扩展测试
]
default-members = ["app"]

[workspace.package]
rust-version = "1.92"
license = "Apache-2.0"
```

### 1.2 Lints 配置

```toml
[workspace.lints.rust]
warnings = { level = "deny", priority = -1 }
dead_code = "deny"
missing_docs = "allow"

[workspace.lints.clippy]
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
undocumented_unsafe_blocks = "deny"
pedantic = { level = "warn", priority = -1 }
nursery = { level = "warn", priority = -1 }
```

### 1.3 编译优化

```toml
[profile.dev]
opt-level = 1

[profile.release]
opt-level = 3         # 最高优化
lto = "fat"           # 跨 crate LTO
codegen-units = 1     # 单 codegen unit
```

---

## 2. Vendor 依赖

### 2.1 本地 Patch

```toml
[patch.crates-io]
tun2socks = { path = "vendor/tun2socks" }
anytls-rs = { path = "vendor/anytls-rs" }
```

### 2.2 vendor/tun2socks

TUN 设备的用户态网络栈存根：

```
vendor/tun2socks/
├── Cargo.toml
├── src/
│   └── lib.rs  # 存根实现
└── README.md
```

### 2.3 vendor/anytls-rs

AnyTLS 协议的 Rust 实现：

```
vendor/anytls-rs/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── client.rs
│   ├── server.rs
│   ├── protocol.rs
│   └── ...
└── README.md
```

---

## 3. xtask - 构建任务

```
xtask/
├── Cargo.toml
└── src/
    ├── main.rs
    └── lib.rs
```

用于自动化构建任务：
- 生成 schema
- 更新依赖
- 发布流程

```bash
# 运行 xtask
cargo xtask <task-name>
```

---

## 4. 测试结构

### 4.1 单元测试

各 crate 内的 `#[cfg(test)]` 模块：

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_example() {
        // ...
    }
    
    #[tokio::test]
    async fn test_async_example() {
        // ...
    }
}
```

### 4.2 集成测试

```
tests/
├── integration/              # 集成测试
├── e2e/                      # 端到端测试
├── stress/                   # 压力测试
│
├── e2e_connect.rs            # 连接测试
├── reality_tls_e2e.rs        # REALITY TLS 测试
├── ech_handshake_e2e.rs      # ECH 握手测试
├── hysteria_v1_e2e.rs        # Hysteria v1 测试
├── trojan_httpupgrade_integration.rs
├── vless_grpc_integration.rs
├── vmess_websocket_integration.rs
├── selector_integration_tests.rs
├── failpoints_integration.rs
│
├── configs/                  # 测试配置
├── data/                     # 测试数据
├── scripts/                  # 测试脚本
└── docs/                     # 测试文档
```

### 4.3 基准测试

```
benches/
├── Cargo.toml
├── src/
│   └── lib.rs
├── benches/
│   ├── protocol_bench.rs     # 协议基准
│   ├── router_bench.rs       # 路由基准
│   ├── dns_bench.rs          # DNS 基准
│   └── ...
└── README.md
```

```bash
# 运行基准测试
cargo bench --package benches

# app 内的基准测试
cargo bench -p app --features bench
```

---

## 5. 常用命令

### 5.1 构建

```bash
# 最小构建
cargo build -p app

# 验收构建
cargo build -p app --features acceptance

# 完整构建
cargo build -p app --all-features

# Release 构建
cargo build -p app --features acceptance --release
```

### 5.2 测试

```bash
# 所有测试
cargo test --workspace

# 特定 crate
cargo test -p sb-core

# 特定测试
cargo test -p app test_name

# 集成测试
cargo test --test reality_tls_e2e

# 带 features
cargo test -p app --features admin_debug
```

### 5.3 检查

```bash
# Clippy
cargo clippy --workspace --all-targets

# 格式检查
cargo fmt --check

# 依赖审计
cargo deny check
```

### 5.4 运行

```bash
# 运行代理
cargo run -p app --features router --bin run -- -c config.json

# 检查配置
cargo run -p app --bin check -- config.json

# 格式化配置
cargo run -p app --bin format -- config.json
```

---

## 6. CI/CD

### 6.1 GitHub Actions 工作流

| 工作流 | 触发 | 内容 |
|--------|------|------|
| `build.yml` | push/PR | 构建和测试 |
| `clippy.yml` | push/PR | Clippy 检查 |
| `release.yml` | tag | 发布构建 |
| `bench.yml` | 手动 | 基准测试 |

### 6.2 检查矩阵

| 检查项 | 命令 |
|--------|------|
| 编译 | `cargo build --workspace` |
| 测试 | `cargo test --workspace` |
| Clippy | `cargo clippy --workspace` |
| 格式 | `cargo fmt --check` |
| 依赖 | `cargo deny check` |
| 文档 | `cargo doc --no-deps` |

---

## 7. Feature 组合测试

### 7.1 最小构建

```bash
cargo build -p app  # 无 features
```

### 7.2 路由构建

```bash
cargo build -p app --features router
```

### 7.3 完整适配器

```bash
cargo build -p app --features adapters
```

### 7.4 验收构建

```bash
cargo build -p app --features acceptance
```

### 7.5 All Features

```bash
cargo build -p app --all-features
```

---

## 8. 调试技巧

### 8.1 日志级别

```bash
RUST_LOG=debug cargo run -p app --features router --bin run -- -c config.json
RUST_LOG=sb_core::router=trace,sb_adapters=debug cargo run ...
```

### 8.2 Backtrace

```bash
RUST_BACKTRACE=1 cargo run ...
RUST_BACKTRACE=full cargo run ...
```

### 8.3 Tokio Console

```bash
cargo run -p app --features "router tokio-console" --bin run -- -c config.json
```
