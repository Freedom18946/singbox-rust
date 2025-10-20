# E2E Test Artifacts Directory

这个目录用于存放端到端测试的临时文件、日志和测试报告。

## 📁 目录结构

```
.e2e/
├── README.md              # 本说明文档（纳入版本控制）
├── .gitignore            # Git 忽略规则（纳入版本控制）
├── config.yaml           # E2E 测试配置（纳入版本控制）
├── logs/                 # 运行时日志
│   ├── echo.log          # UDP echo 服务日志
│   ├── explain.log       # 路由解释服务日志
│   └── sb.log            # singbox-rust 主服务日志
├── reports/              # JSON 格式测试报告
│   ├── summary.json      # E2E 测试汇总报告
│   ├── explain.json      # 路由解释结果（JSON）
│   ├── snap.json         # 路由快照
│   ├── pprof_status.json # 性能分析状态
│   └── release-matrix.json # 发布矩阵报告
├── visualizations/       # 可视化输出
│   ├── explain.dot       # 路由解释图（Graphviz）
│   └── flame.svg         # 火焰图（性能分析）
├── artifacts/            # 构建产物和校验和
│   ├── release.sha256    # 发布包校验和
│   └── sha1.txt          # SHA1 校验值
├── pids/                 # 进程 ID 文件
│   ├── echo.pid          # UDP echo 服务 PID
│   ├── ex.pid            # 解释服务 PID
│   └── sb.pid            # singbox-rust 主进程 PID
├── soak/                 # 负载测试（Soak Test）结果
│   └── report.json       # 30 分钟稳定性测试报告
└── archives/             # 历史测试归档
    └── [timestamp-based archives]
```

## 🔄 文件生命周期

### 自动生成的文件

所有测试产物均由以下脚本自动生成：

- **`scripts/e2e/run.sh`**: 运行完整的 E2E 测试套件，生成 summary.json
- **`scripts/tools/explain/run.sh`**: 生成路由解释报告（JSON 和 DOT 格式）
- **`scripts/soak/soak-30m.sh`**: 运行 30 分钟稳定性测试
- **`scripts/ci/accept.sh`**: 验收测试脚本，生成多个日志和报告文件
- **`scripts/release-matrix`**: 生成发布矩阵和校验和

### 文件保留策略

- **临时文件**: 日志、PID 文件 - 每次测试后可清理
- **重要报告**: summary.json, 负载测试报告 - 建议保留用于对比
- **可视化文件**: flame.svg, explain.dot - 按需保留
- **归档文件**: archives/ 目录 - 自动归档重要测试结果

## 🧹 清理策略

### 完全清理（保留 README.md 和配置）

```bash
scripts/e2e/clean.sh
```

### 智能清理（按类型）

```bash
# 仅清理日志文件
scripts/e2e/clean.sh --logs-only

# 仅清理测试报告
scripts/e2e/clean.sh --reports-only

# 清理可视化文件
scripts/e2e/clean.sh --visualizations-only

# 清理构建产物
scripts/e2e/clean.sh --artifacts-only
```

### 按时间清理

```bash
# 清理 7 天前的文件
scripts/e2e/clean.sh --older-than 7d

# 保留最近 5 次测试结果
scripts/e2e/clean.sh --keep-last 5
```

### 智能清理（保留重要文件）

```bash
# 清理临时文件，保留重要报告
scripts/e2e/clean.sh --smart
```

## 📊 主要文件说明

### summary.json

E2E 测试的汇总报告，包含：
- 测试时间戳
- 测试状态（tests_status）
- Go 兼容性检测结果（compat）
- Benchmark JSON 探测结果（bench_json）
- 验收测试结果（acceptance）：A1-A5 测试状态

**示例**:
```json
{
  "ts": "2025-10-18T06:30:00Z",
  "tests_status": 0,
  "go_present": true,
  "compat": "ok",
  "bench_json": "ok",
  "acceptance": {
    "overall": "pass",
    "results": ["A1:pass", "A2:pass", "A3:pass", "A4:pass", "A5:pass"]
  }
}
```

### soak/report.json

30 分钟稳定性测试报告，监控：
- UDP NAT 表大小变化（variance < 5%）
- 代理切换计数单调性
- DNS RTT 直方图
- 速率限制和 DNS 错误增量

**关键指标**:
- `udp_nat_variance_pct`: UDP NAT 表大小波动百分比
- `switch_monotonic`: 代理切换计数是否单调递增
- `status`: "passed" 或 "failed"

### explain.json

路由决策详细跟踪，包含：
- 最终决策（decision）
- 执行阶段（override, cidr, suffix, geo, default）
- 匹配的规则 ID
- 出站代理链

### flame.svg

性能分析火焰图，通过 pprof 接口生成：
- HTTP 端点：`http://127.0.0.1:18089/debug/pprof?sec=1`
- 仅在启用 `pprof` feature 时可用
- 最小文件大小 > 100 字节才有效

## 🔧 环境变量配置

### 时间戳支持

```bash
# 启用时间戳模式（文件名包含时间戳）
export E2E_ENABLE_TIMESTAMP=1

# 保留历史记录数量
export E2E_KEEP_HISTORY=10
```

### 自动归档

```bash
# 启用自动归档
export SB_E2E_ARCHIVE=1

# 归档保留天数（默认 30 天）
export E2E_ARCHIVE_RETENTION_DAYS=30
```

### 负载测试配置

```bash
# SOAK 测试时长（秒，默认 1800 = 30 分钟）
export SOAK_DURATION_SEC=1800

# UDP NAT 变化容忍度（百分比，默认 5%）
export SOAK_NAT_VAR_PCT_MAX=5

# 速率限制错误阈值
export SOAK_RATE_LIMIT_MAX=50

# DNS 错误阈值
export SOAK_DNS_ERR_MAX=20

# 使用虚拟数据（用于测试脚本本身）
export SOAK_FAKE=1
```

## 🔍 故障排查

### 查看最近的测试日志

```bash
# 查看主服务日志（最近 200 行）
tail -n 200 .e2e/logs/sb.log

# 查看路由解释日志
tail -n 200 .e2e/logs/explain.log
```

### 检查测试摘要

```bash
# 查看 E2E 测试摘要
cat .e2e/reports/summary.json | jq

# 查看负载测试结果
cat .e2e/soak/report.json | jq
```

### 验证进程状态

```bash
# 检查运行中的测试进程
for pid_file in .e2e/pids/*.pid; do
  if [ -f "$pid_file" ]; then
    pid=$(cat "$pid_file")
    echo "$pid_file: $(ps -p $pid -o comm= 2>/dev/null || echo 'not running')"
  fi
done
```

### 端口占用检查

```bash
# HTTP 代理端口
lsof -nP -iTCP:11080 -sTCP:LISTEN

# 指标端口
lsof -nP -iTCP:18089 -sTCP:LISTEN
```

## 📋 相关文档

- **E2E 测试指南**: [docs/README-e2e.md](../docs/README-e2e.md)
- **验收测试文档**: [docs/ACCEPTANCE.json5](../docs/ACCEPTANCE.json5)
- **测试目录说明**: [tests/README.md](../tests/README.md)
- **开发文档**: [docs/DEVELOPMENT.md](../docs/DEVELOPMENT.md)

## 🏷️ 版本信息

- **创建日期**: 2025-10-18
- **最后更新**: 2025-10-18
- **维护者**: singbox-rust team
- **状态**: 生产就绪

## 📝 注意事项

1. ⚠️ 该目录下的所有文件（除 README.md, config.yaml, .gitignore）均不应纳入版本控制
2. 🔒 PID 文件用于进程管理，测试结束后会自动清理
3. 📦 归档功能需要设置 `SB_E2E_ARCHIVE=1` 环境变量
4. 🔄 定期运行清理脚本以避免磁盘空间浪费
5. 📊 重要的测试报告建议手动备份到 archives/ 目录
6. 🎯 CI/CD 环境中建议每次测试前运行清理脚本

## 🤝 贡献指南

如果修改了 E2E 测试流程或添加了新的测试产物：

1. 更新本 README.md 文档
2. 相应更新 `.gitignore` 规则
3. 更新清理脚本 `scripts/e2e/clean.sh`
4. 在 PR 中说明变更原因和影响

---

**文档版本**: 2.0  
**最后更新**: 2025-10-18  
**优化内容**: 新增目录结构、清理策略、环境变量、故障排查章节
