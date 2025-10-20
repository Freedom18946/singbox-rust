# xtests - 工作区集成测试

工作区级别的集成测试套件，用于验证跨 crate 功能和端到端行为。

## 概述

`xtests` 是一个独立的测试 crate，用于测试整个 singbox-rust 工作区的集成点。与各 crate 内部的 `tests/` 目录不同，这里的测试：

- ✅ 跨越多个 crate 边界
- ✅ 测试实际的二进制输出和 CLI 行为
- ✅ 验证配置格式和 schema 兼容性
- ✅ 进行性能基准测试
- ✅ 测试特性门控和条件编译

## 测试分类

### 📋 CLI 和工具测试

| 文件 | 描述 | 依赖特性 |
|------|------|---------|
| `cli_help_snapshot.rs` | CLI 帮助信息快照测试 | - |
| `version_cli.rs` | 版本命令测试 | - |
| `check_json.rs` | check 命令 JSON 输出 | - |
| `check_sarif.rs` | check 命令 SARIF 输出 | - |

### 🔍 Schema 和配置测试

| 文件 | 描述 | 依赖特性 |
|------|------|---------|
| `check_schema.rs` | 配置 schema 验证 | - |
| `explain_schema.rs` | explain 命令 schema | `explain` |
| `explain_cli_schema.rs` | explain CLI schema 验证 | `explain` |
| `check_analyze_groups.rs` | 配置分析测试 | `dsl_analyze` |

### 🔄 路由测试

| 文件 | 描述 | 依赖特性 |
|------|------|---------|
| `route_parity.rs` | 路由规则对等性测试 | - |

### 📊 性能测试

| 文件 | 描述 | 依赖特性 |
|------|------|---------|
| `bench_v1.rs` | V1 配置格式基准 | - |
| `bench_v2.rs` | V2 配置格式基准 | - |

### 🌐 协议测试

| 文件 | 描述 | 依赖特性 |
|------|------|---------|
| `out_ss_smoke.rs` | Shadowsocks 出站冒烟测试 | `out_ss` |
| `out_trojan_smoke.rs` | Trojan 出站冒烟测试 | `out_trojan` |
| `pprof_smoke.rs` | pprof 性能分析测试 | `pprof` |

### 📦 发布测试

| 文件 | 描述 | 依赖特性 |
|------|------|---------|
| `rc_pack.rs` | RC 包验证测试 | - |
| `env_doc_drift.rs` | 环境变量文档一致性 | - |

## 运行测试

### 运行所有测试

```bash
cargo test -p xtests
```

### 运行特定类别

```bash
# CLI 测试
cargo test -p xtests cli_

# Schema 测试
cargo test -p xtests schema

# 协议测试（需要特性）
cargo test -p xtests --features out_ss,out_trojan
```

### 运行单个测试

```bash
cargo test -p xtests --test cli_help_snapshot
```

### 带特性的测试

```bash
# 测试 explain 功能
cargo test -p xtests --features explain

# 测试所有可选功能
cargo test -p xtests --all-features
```

## 特性标志

`xtests` 使用特性标志来控制测试范围，避免不必要的依赖：

- `explain`: 启用路由解释相关测试
- `metrics`: 启用 metrics 相关测试（映射到 app 的 `prom` 特性）
- `dsl_analyze`: 启用配置分析测试
- `pprof`: 启用性能分析测试
- `out_trojan`: 启用 Trojan 协议测试
- `out_ss`: 启用 Shadowsocks 协议测试

## 测试数据

测试配置文件位于：

```
xtests/tests/assets/
├── check/
│   ├── bad_conflict.yaml     # 冲突配置（预期失败）
│   └── bad_unreachable.yaml  # 不可达配置（预期失败）
└── ...（其他测试资源）
```

## 工具函数

`xtests/src/lib.rs` 提供共享工具：

```rust
/// 定位工作区二进制文件
pub fn workspace_bin(name: &str) -> PathBuf
```

用法示例：

```rust
use xtests::workspace_bin;

#[test]
fn test_version() {
    let bin = workspace_bin("singbox-rust");
    let output = Command::new(bin)
        .arg("version")
        .output()
        .unwrap();
    assert!(output.status.success());
}
```

## 最佳实践

### ✅ 推荐

1. **使用 `assert_cmd`** 进行 CLI 测试
   ```rust
   use assert_cmd::Command;

   #[test]
   fn test_help() {
       Command::cargo_bin("singbox-rust")
           .unwrap()
           .arg("help")
           .assert()
           .success();
   }
   ```

2. **使用特性门控** 避免不必要的编译
   ```rust
   #[cfg(feature = "explain")]
   #[test]
   fn test_explain() { /* ... */ }
   ```

3. **快照测试** 用于验证输出格式
   ```rust
   use predicates::prelude::*;

   #[test]
   fn test_output_format() {
       let output = /* ... */;
       assert!(predicate::str::contains("expected text").eval(&output));
   }
   ```

### ❌ 避免

1. ❌ 在 xtests 中测试单个 crate 的内部逻辑（应该放在 crate 自己的 tests/ 中）
2. ❌ 硬编码文件路径（使用 `workspace_bin` 等工具）
3. ❌ 依赖网络或外部服务（除非明确标注）
4. ❌ 长时间运行的测试（应该放在 benches/ 或单独的压力测试中）

## CI 集成

xtests 在 CI 中的运行顺序：

1. **基础测试** (无特性)
   ```bash
   cargo test -p xtests --no-default-features
   ```

2. **完整测试** (所有特性)
   ```bash
   cargo test -p xtests --all-features
   ```

3. **特性矩阵** (关键组合)
   ```bash
   cargo test -p xtests --features explain,metrics
   cargo test -p xtests --features out_ss,out_trojan
   ```

参见 `.github/workflows/ci.yml` 了解完整配置。

## 添加新测试

1. 在 `tests/` 目录创建新文件：
   ```bash
   # 示例：添加 DNS 集成测试
   touch xtests/tests/dns_integration.rs
   ```

2. 如果需要新特性，更新 `Cargo.toml`：
   ```toml
   [features]
   dns_integration = ["singbox-bin/dns"]
   ```

3. 编写测试：
   ```rust
   use assert_cmd::Command;
   use xtests::workspace_bin;

   #[test]
   fn test_dns_query() {
       // 测试逻辑...
   }
   ```

4. 更新本 README 的分类表格

5. 运行并验证：
   ```bash
   cargo test -p xtests --test dns_integration
   ```

## 故障排查

### 找不到二进制文件

```bash
# 确保先构建应用
cargo build -p app
# 然后运行测试
cargo test -p xtests
```

### 特性相关错误

```bash
# 检查特性是否正确传递
cargo test -p xtests --features explain --verbose
```

### 测试超时

```bash
# 增加超时时间
RUST_TEST_THREADS=1 cargo test -p xtests -- --test-threads=1
```

## 相关资源

- [Rust 集成测试](https://doc.rust-lang.org/book/ch11-03-test-organization.html#integration-tests)
- [assert_cmd 文档](https://docs.rs/assert_cmd/)
- [predicates 文档](https://docs.rs/predicates/)
- [测试工具函数](./src/lib.rs)
