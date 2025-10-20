# xtask - 开发者任务工具

基于 [cargo-xtask 模式](https://github.com/matklad/cargo-xtask) 的开发者工具集，提供项目自动化任务。

## 快速开始

```bash
# 显示所有可用命令
cargo xtask help

# 运行端到端测试
cargo xtask e2e

# 检查所有特性组合
cargo xtask check-all

# 运行完整 CI 流程（本地）
cargo xtask ci
```

## 可用命令

### 🔍 代码质量

#### `fmt`
格式化整个工作区的代码

```bash
cargo xtask fmt
```

等价于：`cargo fmt --all`

#### `clippy`
运行 clippy 检查所有 crate

```bash
cargo xtask clippy
```

配置：
- 使用工作区 `Cargo.toml` 中定义的 lint 规则
- 包含 `--all-features` 和 `--all-targets`

#### `check-all`
检查所有特性组合的编译

```bash
cargo xtask check-all
```

检查内容：
- 无特性构建
- 默认特性构建
- 所有特性构建
- 关键特性组合（TUN、admin、metrics 等）

### 🧪 测试

#### `e2e`
运行端到端测试流程

```bash
cargo xtask e2e
```

测试流程：
1. 构建带有关键特性的应用
2. 验证 CLI 命令（version, check, route）
3. 启动服务器并测试 API 端点
4. 验证 metrics 端点
5. 测试 admin 认证和限流

#### `test-all`
运行所有测试套件

```bash
cargo xtask test-all
```

包括：
- 单元测试（所有 crate）
- 集成测试（app/tests）
- 工作区测试（xtests）
- 文档测试

### 📊 工具

#### `schema`
生成和验证 JSON schema

```bash
# 打印 schema 统计信息
cargo xtask schema

# 导出完整 schema（未来实现）
cargo xtask schema --export > schema.json
```

#### `metrics-check`
验证 Prometheus metrics 端点

```bash
# 默认地址 127.0.0.1:19090
cargo xtask metrics-check

# 自定义地址
cargo xtask metrics-check --addr 127.0.0.1:9090
```

验证项：
- 必需的 metric 名称存在
- Label 名称在白名单内
- Metric 值格式正确

#### `bench`
运行基准测试（需要 nightly）

```bash
cargo xtask bench
```

### 🚀 CI/CD

#### `ci`
模拟完整 CI 流程

```bash
cargo xtask ci
```

执行步骤：
1. `cargo xtask fmt` - 检查格式
2. `cargo xtask clippy` - Lint 检查
3. `cargo xtask check-all` - 特性组合
4. `cargo xtask test-all` - 所有测试
5. `cargo xtask e2e` - 端到端测试

#### `preflight`
提交前快速检查

```bash
cargo xtask preflight
```

快速版本的 CI 检查，跳过耗时的测试。

## 环境变量

- `CARGO_TARGET_DIR`: 自定义构建目录（默认：`target`）
- `RUST_LOG`: 控制 xtask 输出详细度（默认：`info`）
- `XTASK_SKIP_BUILD`: 跳过构建步骤（用于调试）

## 开发指南

### 添加新命令

1. 在 `src/main.rs` 的 `Command` enum 中添加变体
2. 实现对应的处理函数
3. 更新 `help()` 函数的文档
4. 添加单元测试（如果适用）

### 命令组织

```
src/
├── main.rs           # 入口和命令分发
├── check.rs          # 代码检查相关
├── test.rs           # 测试相关
├── tools.rs          # 工具命令
├── ci.rs             # CI 流程
└── helpers.rs        # 共享工具函数
```

### 最佳实践

- ✅ 使用 `anyhow::Result` 进行错误处理
- ✅ 为耗时操作提供进度反馈
- ✅ 支持 `--help` 和详细的错误消息
- ✅ 尽量复用 cargo 工具链（不重复造轮子）
- ✅ 保持最小依赖（避免 async runtime）

## 依赖项

- `anyhow`: 错误处理
- `serde_json`: JSON 解析
- `reqwest`: HTTP 客户端（blocking）
- `humantime`: 时间格式化
- `which`: 工具检测

## MSRV

与项目保持一致：Rust 1.90+

## 相关资源

- [cargo-xtask 模式](https://github.com/matklad/cargo-xtask)
- [项目 CI 配置](../.github/workflows/)
- [开发者指南](../README.md#development)
