# xtests - 工作区集成测试

工作区级别的集成测试套件，验证跨 crate 功能和端到端行为。

## 测试文件

| 文件 | 描述 | 依赖特性 |
|------|------|---------|
| `bench_v1.rs` | V1 配置格式基准 | - |
| `bench_v2.rs` | V2 配置格式基准 | - |
| `check_analyze_groups.rs` | 配置诊断测试 | - |
| `check_schema.rs` | 配置 schema 验证 | - |
| `cli_help_snapshot.rs` | CLI 帮助信息快照测试 | - |
| `env_doc_drift.rs` | 环境变量文档一致性 | - |
| `explain_cli_schema.rs` | `route --explain` 输出契约 | - |
| `explain_schema.rs` | `route --explain` 输出 schema | - |
| `pprof_smoke.rs` | pprof 性能分析手动 smoke | `explain,pprof` |
| `rc_pack.rs` | RC 包验证测试 | - |

## 运行

```bash
# 全部测试
cargo test -p xtests

# 单个测试
cargo test -p xtests --test cli_help_snapshot

# 带特性
cargo test -p xtests --features explain

# 手动 pprof smoke
cargo test -p xtests --features explain,pprof --test pprof_smoke -- --ignored
```

## 工具函数

`src/lib.rs` 提供 `workspace_bin(name)` 和 `ensure_workspace_bin(package, name, features)` 用于定位和构建工作区二进制。
