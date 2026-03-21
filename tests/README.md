# tests/ — 共享测试资源

此目录包含被 `app` crate 通过 `#[path]` 引用的测试文件和共享测试资源。

## 结构

```
tests/
├── configs/        # 测试配置文件（YAML/JSON/PEM）
├── data/           # 测试数据文件
├── docs/           # 测试相关实现文档
├── e2e/            # E2E 测试模块（被根 .rs 文件通过 #[path] 引用）
├── integration/    # 集成测试（.rs 源文件）
├── scripts/        # 验证脚本
├── stress/         # 压力测试模块（被 app/tests/stress_tests.rs 引用）
├── hysteria_v1_e2e.rs   # → app [[test]]
└── reality_tls_e2e.rs   # → app [[test]]
```

## 运行

这些测试通过 `app` crate 执行：

```bash
cargo test -p app --test reality_tls_e2e
cargo test -p app --test hysteria_v1_e2e
cargo test -p app --test stress_tests
```

## 沙盒环境

部分需要端口绑定或系统 DNS 的测试会在受限环境中自动跳过。
设置 `SB_TEST_REQUIRE_NET=1` 可强制这些测试报错而非跳过。
