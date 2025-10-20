# Docs 文件夹重构提案

## 执行摘要

本提案旨在重组 `docs/` 目录，提升文档的可发现性、可维护性和用户体验。

**当前状态**：77+ 个 Markdown 文件，结构扁平，分类不清
**目标状态**：分层清晰、易于导航、按用户角色组织的文档体系

## 🎯 重构目标

1. **用户友好**：按使用场景和用户角色组织文档
2. **开发者友好**：清晰的开发指南和 API 参考
3. **易于维护**：减少重复，明确文档生命周期
4. **国际化**：中英文文档分离管理

## 📁 推荐的新目录结构

```
docs/
├── README.md                          # 文档总索引（重写）
├── 00-getting-started/               # 🚀 快速开始（用户视角）
│   ├── README.md                      # 5 分钟快速开始
│   ├── installation.md                # 安装指南（新建）
│   ├── basic-configuration.md         # 基础配置（提取自 COOKBOOK.md）
│   └── first-proxy.md                # 第一个代理配置（新建）
│
├── 01-user-guide/                    # 📖 用户指南
│   ├── README.md                      # 用户指南索引
│   ├── configuration/                # 配置参考
│   │   ├── overview.md               # 配置文件概览
│   │   ├── inbounds.md               # 入站配置（新建）
│   │   ├── outbounds.md              # 出站配置（新建）
│   │   ├── routing.md                # 路由配置 <- ROUTER_RULES.md
│   │   ├── dns.md                    # DNS 配置（新建）
│   │   ├── tls.md                    # TLS 配置（合并 TLS*.md）
│   │   └── schema-migration.md       # V1→V2 迁移（提取）
│   ├── protocols/                    # 协议说明
│   │   ├── reality.md                # REALITY 协议
│   │   ├── ech.md                    # ECH 协议 <- ECH_CONFIG.md
│   │   ├── hysteria.md               # Hysteria v1/v2
│   │   ├── tuic.md                   # TUIC
│   │   └── shadowsocks.md            # Shadowsocks
│   ├── features/                     # 特性说明
│   │   ├── multiplex.md              # <- MULTIPLEX_USAGE.md
│   │   ├── udp-relay.md              # <- UDP_SUPPORT.md
│   │   ├── subscription.md           # 订阅管理 <- SUBS_*.md
│   │   └── process-matching.md       # 进程匹配（新建）
│   └── troubleshooting.md           # 故障排查（合并 COOKBOOK.md 部分）
│
├── 02-cli-reference/                 # 🔧 CLI 工具参考
│   ├── README.md                      # CLI 总览 <- CLI_TOOLS.md
│   ├── run.md                        # run 命令详解
│   ├── check.md                      # check 命令详解
│   ├── format.md                     # format 命令详解
│   ├── generate.md                   # generate 命令详解
│   ├── geoip-geosite.md             # geoip/geosite 工具
│   ├── rule-set.md                   # rule-set 工具
│   ├── route-explain.md              # <- ROUTE_EXPLAIN.md
│   ├── exit-codes.md                 # <- CLI_EXIT_CODES.md
│   └── environment-variables.md      # <- ENV_VARS.md
│
├── 03-operations/                    # 🏗️ 运维部署
│   ├── README.md                      # <- OPS.md
│   ├── deployment/                   # 部署指南
│   │   ├── systemd.md                # Linux systemd
│   │   ├── docker.md                 # Docker 容器
│   │   ├── kubernetes.md             # K8s（新建，如需要）
│   │   └── windows-service.md        # Windows 服务（新建）
│   ├── monitoring/                   # 监控观测
│   │   ├── metrics.md                # Prometheus 指标 <- metrics-compat.md
│   │   ├── logging.md                # 日志配置（新建）
│   │   ├── tracing.md                # 分布式追踪（如有）
│   │   └── grafana-dashboards.md     # Grafana 配置
│   ├── performance/                  # <- performance/ 目录
│   │   ├── optimization-guide.md     # <- OPTIMIZATION_GUIDE.md
│   │   ├── optimization-checklist.md # <- OPTIMIZATION_CHECKLIST.md
│   │   └── quick-start.md            # <- OPTIMIZATION_QUICK_START.md
│   └── security/                     # 安全最佳实践
│       ├── hardening.md              # 系统加固（新建）
│       ├── tls-best-practices.md     # TLS 安全配置
│       └── credential-management.md  # 凭证管理（新建）
│
├── 04-development/                   # 💻 开发文档
│   ├── README.md                      # <- DEVELOPMENT.md（重写为索引）
│   ├── architecture/                 # 架构设计
│   │   ├── overview.md               # <- ARCHITECTURE.md（精简）
│   │   ├── router-engine.md          # 路由引擎详解
│   │   ├── tls-infrastructure.md     # <- TLS.md（技术细节）
│   │   ├── transport-layer.md        # 传输层架构
│   │   └── data-flow.md              # 数据流详解
│   ├── contributing/                 # 贡献指南
│   │   ├── getting-started.md        # 开发环境搭建
│   │   ├── code-style.md             # 代码风格
│   │   ├── testing-guide.md          # 测试指南 <- testing/
│   │   ├── documentation.md          # 文档贡献指南（新建）
│   │   └── pull-requests.md          # PR 流程（新建）
│   ├── build-system/                 # 构建系统
│   │   ├── overview.md               # <- BUILD_NOTES.md
│   │   ├── feature-flags.md          # Feature flags 详解（新建）
│   │   ├── cross-compilation.md      # 交叉编译（新建）
│   │   └── ci-matrix.md              # <- CI_MATRIX.md
│   ├── quality-gates/                # 质量门禁
│   │   ├── linting.md                # Clippy 规则
│   │   ├── testing.md                # 测试策略 <- README-e2e.md
│   │   ├── benchmarking.md           # <- benchmarks/README.md
│   │   └── stress-testing.md         # <- STRESS_TESTING.md
│   └── protocols/                    # 协议实现详解
│       ├── implementation-guide.md   # 新协议实现指南
│       ├── adapter-bridge.md         # <- ADAPTER_BRIDGE_CONTRACT.md
│       └── upstream-compat.md        # <- P0_UPSTREAM_COMPATIBILITY.md
│
├── 05-api-reference/                 # 📡 API 参考
│   ├── README.md                      # API 总览
│   ├── admin-api/                    # Admin HTTP API
│   │   ├── overview.md               # <- ADMIN_API_CONTRACT.md（合并）
│   │   ├── authentication.md         # JWT 认证
│   │   ├── endpoints.md              # 端点详细说明
│   │   └── examples.md               # API 使用示例
│   ├── v2ray-stats/                  # V2Ray Stats gRPC API
│   │   ├── overview.md               # gRPC 接口说明
│   │   └── examples.md               # 使用示例
│   └── internal/                     # 内部 API（开发者）
│       ├── router-api.md             # 路由器 API
│       ├── outbound-api.md           # 出站 API
│       └── shared-types.md           # <- SHARED_TYPES.md
│
├── 06-advanced-topics/               # 🎓 高级主题
│   ├── README.md                      # 高级主题索引
│   ├── reality-deployment.md         # REALITY 部署实战
│   ├── ech-deployment.md             # ECH 部署实战
│   ├── custom-routing.md             # 高级路由策略
│   ├── subscription-system.md        # 订阅系统详解
│   ├── dsl-rules.md                  # <- DSL_PLUS.md
│   ├── scenarios.md                  # <- SCENARIOS.md
│   └── zero-breakage.md              # <- ZERO_BREAKAGE_GUARANTEES.md
│
├── 07-reference/                     # 📚 参考资料
│   ├── README.md                      # 参考资料索引
│   ├── schemas/                      # JSON Schema 文档
│   │   ├── config-v2.md              # <- SCHEMA.*.json5 说明
│   │   └── subscription.md           # 订阅格式说明
│   ├── error-codes.md                # <- ERRORS.md
│   ├── compatibility-matrix.md       # 兼容性矩阵
│   └── glossary.md                   # 术语表（新建）
│
├── 08-examples/                      # 💡 示例配置
│   ├── README.md                      # 示例索引
│   ├── basic/                        # 基础示例
│   │   ├── socks5-proxy.md           # 简单 SOCKS5 代理
│   │   ├── http-proxy.md             # HTTP 代理
│   │   └── tun-mode.md               # TUN 模式
│   ├── advanced/                     # 高级示例
│   │   ├── reality-server.md         # REALITY 服务器
│   │   ├── hysteria2-client.md       # Hysteria2 客户端
│   │   └── load-balancing.md         # 负载均衡
│   ├── transport/                    # 传输层示例
│   │   └── v2ray-transports.json     # <- examples/v2ray_transport_config.json
│   └── dns/                          # DNS 示例
│       └── dns-pool.md               # <- examples/dns_pool.md
│
├── archive/                          # 🗄️ 历史归档
│   ├── README.md                      # 归档说明（标注不再维护）
│   ├── sprints/                      # Sprint 报告归档
│   │   └── [移动所有 SPRINT*.md]
│   ├── tasks/                        # Task 报告归档
│   │   └── [移动所有 TASK*.md]
│   ├── phases/                       # 阶段文档归档
│   │   └── [移动 PHASE_8_*.md]
│   └── deprecated/                   # 已废弃文档
│       ├── admin_api.md              # （如果已被合并）
│       └── TLS_INTEGRATION.md        # （如果已被合并）
│
├── locales/                          # 🌐 国际化（可选）
│   ├── zh-CN/                        # 中文文档
│   │   ├── README.md                 # 中文索引
│   │   ├── getting-started.md        # 快速开始（中文）
│   │   └── 验收脚本踩坑与修复手册.md   # 移动到这里
│   └── en/                           # 英文文档（或保持根目录为英文）
│
└── internal/                         # 🔒 内部文档（团队专用）
    ├── handshake-alpha.md            # <- HANDSHAKE_ALPHA.md
    ├── analyze-guide.md              # <- ANALYZE_GUIDE.md
    ├── compare-sampling.md           # <- COMPARE_SAMPLING.md
    ├── normalize-schema.md           # <- NORMALIZE_SCHEMA.md
    ├── file-organization.md          # <- FILE_ORGANIZATION_SUMMARY.md
    └── rc-prep/                      # RC 准备材料
        ├── environment-snapshot.txt  # <- rc-environment-snapshot-example.txt
        └── fingerprints.txt          # <- rc-fingerprints-example.txt
```

## 🔄 重构步骤建议

### Phase 1: 准备阶段（1-2 天）

1. **创建新目录结构**（空目录）
2. **建立文档映射表**（旧路径 → 新路径）
3. **设置重定向机制**（如果有自动化文档网站）
4. **备份当前 docs 目录**

### Phase 2: 内容迁移（3-5 天）

1. **合并重复文档**：
   - `TLS.md` + `TLS_INTEGRATION.md` → `user-guide/configuration/tls.md` + `development/architecture/tls-infrastructure.md`
   - `admin_api.md` + `ADMIN_API_CONTRACT.md` + `ADMIN_HTTP.md` → `api-reference/admin-api/overview.md`
2. **拆分大型文档**：

   - `COOKBOOK.md` → 拆分到 getting-started 和 troubleshooting
   - `ARCHITECTURE.md` → 拆分为多个专题文档
   - `CLI_TOOLS.md` → 拆分为各命令详解

3. **归档历史文档**：

   - 移动所有 Sprint/Task 报告到 `archive/`
   - 移动 Phase 8 文档到 `archive/phases/`
   - 在归档目录添加 README.md 说明这些是历史记录

4. **标准化命名**：
   - 统一使用小写 + 连字符：`cli-reference/exit-codes.md`
   - 目录名使用数字前缀便于排序：`01-user-guide/`

### Phase 3: 内容优化（5-7 天）

1. **改进首页 README.md**：

   - 清晰的文档导航（按角色：用户/开发者/运维）
   - Quick Links 到常用文档
   - 搜索提示

2. **完善各级索引**：

   - 每个目录都有 README.md
   - 包含该目录下所有文档的简介
   - 提供导航路径（面包屑）

3. **更新交叉引用**：

   - 修改所有文档中的内部链接
   - 使用相对路径
   - 添加"另见"章节

4. **补充缺失文档**：
   - 安装指南、基础配置等入门文档
   - 各 CLI 命令的详细说明
   - 安全最佳实践

### Phase 4: 验证与发布（2-3 天）

1. **验证所有链接**：使用工具检查断链
2. **更新根目录 README.md** 的文档链接
3. **更新 CI/CD** 中的文档路径引用（如有）
4. **发布变更日志**：说明文档重组

## 📊 预期收益

### 用户体验

- ✅ 新用户 5 分钟内找到入门文档
- ✅ 按使用场景快速定位相关文档
- ✅ 减少 50% 的重复阅读

### 维护效率

- ✅ 减少 30% 的文档重复内容
- ✅ 明确文档生命周期（活跃/归档/废弃）
- ✅ 降低新贡献者的文档贡献难度

### 项目形象

- ✅ 展示专业的项目管理
- ✅ 提升开源项目吸引力
- ✅ 便于构建文档网站（如 mdBook, Docusaurus）

## 🎯 快速执行方案（最小化改动）

如果团队资源有限，可以采用渐进式重构：

### Quick Win 1: 归档历史文档（1 小时）

```bash
mkdir -p docs/archive/{sprints,tasks,phases}
mv docs/reports/SPRINT*.md docs/archive/sprints/
mv docs/reports/TASK*.md docs/archive/tasks/
mv docs/PHASE_8_*.md docs/archive/phases/
```

### Quick Win 2: 创建分类目录（2 小时）

```bash
mkdir -p docs/{user-guide,cli-reference,operations,development,api-reference}
# 只移动最关键的文档
mv docs/ROUTER_RULES.md docs/user-guide/routing-rules.md
mv docs/CLI_TOOLS.md docs/cli-reference/README.md
mv docs/OPS.md docs/operations/README.md
```

### Quick Win 3: 改进主索引（1 小时）

重写 `docs/README.md`，按用户角色组织链接。

## 🛠️ 工具推荐

1. **链接检查**：[markdown-link-check](https://github.com/tcort/markdown-link-check)
2. **文档生成**：[mdBook](https://rust-lang.github.io/mdBook/) （Rust 生态标准）
3. **文档网站**：[Docusaurus](https://docusaurus.io/) 或 [VitePress](https://vitepress.dev/)
4. **重构脚本**：可以写 Shell/Python 脚本批量移动+更新链接

## 📌 注意事项

1. **保持向后兼容**：在根目录保留重要文档的符号链接（3-6 个月过渡期）
2. **GitHub 链接**：外部可能有链接到当前文档路径，考虑 GitHub Pages 重定向
3. **渐进迁移**：不必一次性完成，可以按目录逐步迁移
4. **团队共识**：与团队讨论新结构，确保大家认同

## 🚀 后续建议

1. **文档即代码**：将文档纳入 CI/CD（链接检查、格式检查）
2. **自动生成**：API 文档考虑从代码注释自动生成
3. **版本管理**：为重大版本保留文档快照（如 v0.2.x, v0.3.x）
4. **搜索功能**：如果构建文档网站，集成全文搜索

## 🤝 需要帮助？

如果需要具体的迁移脚本或文档模板，随时提出！

---

**文档版本**: v1.0  
**创建日期**: 2025-10-18  
**状态**: 提案（待审批）
