# E2E Test Artifacts Directory

存放端到端测试的临时文件、日志和测试报告。除 `README.md`、`config.yaml`、`.gitignore` 外，所有文件均不纳入版本控制。

## 目录结构

```
.e2e/
├── config.yaml           # E2E 测试配置（版本控制）
├── logs/                 # 运行时日志（sb.log, echo.log, explain.log）
├── reports/              # JSON 格式测试报告
├── artifacts/            # 构建产物和校验和
├── visualizations/       # explain.dot, flame.svg
├── pids/                 # 进程 PID 文件
├── soak/                 # 负载测试结果
└── archives/             # 历史测试归档
```

## 关联脚本

| 脚本 | 用途 |
|------|------|
| `scripts/e2e/run.sh` | 运行完整 E2E 测试套件 |
| `scripts/e2e/clean.sh` | 清理产物（支持 `--smart`、`--logs-only`、`--dry-run` 等） |
| `scripts/ci/accept.sh` | 验收测试，生成 config.yaml 并启动服务 |
| `scripts/soak/soak-30m.sh` | 30 分钟稳定性测试 |
| `scripts/tools/explain/run.sh` | 路由解释报告生成 |

## 清理

```bash
scripts/e2e/clean.sh          # 完全清理（保留文档和配置）
scripts/e2e/clean.sh --smart  # 智能清理（保留重要报告）
scripts/e2e/clean.sh --help   # 查看所有选项
```

## 相关文档

- [tests/README.md](../tests/README.md)
