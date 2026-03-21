# xtask - 开发者任务工具

基于 [cargo-xtask 模式](https://github.com/matklad/cargo-xtask) 的开发者工具集。

## 用法

```bash
cargo xtask help
```

## 可用命令

| 命令 | 描述 |
|------|------|
| `fmt` | 格式化所有代码 |
| `clippy` | 运行 clippy 检查 |
| `check-all` | 检查所有特性组合 |
| `feature-matrix` | 构建 CLI/DNS/adapter 特性矩阵 |
| `e2e` | 端到端测试流程 |
| `test-all` | 运行所有测试套件 |
| `bench` | 运行基准测试（需要 nightly） |
| `schema` | 生成/验证 JSON schema |
| `metrics-check` | 验证 Prometheus metrics 端点 |
| `ci` | 完整 CI 流程（本地模拟） |
| `preflight` | 提交前快速检查 |

## 环境变量

- `CARGO_TARGET_DIR`: 自定义构建目录（默认：`target`）
- `RUST_LOG`: 控制输出详细度
- `XTASK_SKIP_BUILD`: 跳过构建步骤（调试用）

## 依赖

- `anyhow`: 错误处理
- `serde` / `serde_json`: JSON 解析
- `reqwest` (blocking): HTTP 客户端（metrics-check 用）
- `libc` (unix): 进程信号处理
