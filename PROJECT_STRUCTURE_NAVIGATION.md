# SingBox-Rust 项目结构导航

> **🚨 权威文档声明**  
> 本文档是 SingBox-Rust 项目结构的**唯一权威参考**。任何开发者、AI助手或自动化工具在开始工作前都必须：
> 1. ✅ 验证本文档内容与实际项目结构的一致性
> 2. 🔄 如发现不一致，立即更新本文档
> 3. 📋 基于本文档进行开发路径规划
> 
> **更新责任**: 任何修改项目结构的操作都必须同步更新本文档  
> **最后更新**: 2025年9月25日

## 项目概述

SingBox-Rust 是一个高性能的代理服务器实现，采用模块化架构设计，支持多种协议和路由策略。

## 根目录结构

```
singbox-rust/
├── 📁 .cargo/                    # Cargo 配置
├── 📁 .github/                   # GitHub Actions 工作流
├── 📁 .kiro/                     # Kiro IDE 配置和规范
├── 📁 app/                       # 主应用程序
├── 📁 crates/                    # 核心 crate 模块
├── 📁 docs/                      # 项目文档（Cookbook/Development/OPS 等）
├── 📁 examples/                  # 示例代码和配置
├── 📁 tests/                     # 测试文件（重新整理后）
├── 📁 scripts/                   # 构建和部署脚本
├── 📁 .e2e/                      # 端到端测试环境
├── 📁 grafana/                   # Grafana 监控面板
├── 📁 packaging/                 # systemd/Docker 等发布产物
├── 📁 refs/                      # 参考资料和分析
├── 📁 instruction/               # 指令和文档
├── 📄 Cargo.toml                 # 工作空间配置
├── 📄 README.md                  # 项目说明
├── 📄 进度规划与分解V5.md          # 项目进度规划
└── 📄 其他配置文件...
```

## 核心模块架构 (crates/)

### 🏗️ 架构层次

```
crates/
├── sb-core/           # 🔧 核心功能模块
│   ├── src/
│   │   ├── config/    # 配置管理
│   │   ├── dns/       # DNS 解析系统
│   │   ├── error/     # 错误处理系统
│   │   ├── metrics/   # 指标监控系统
│   │   ├── net/       # 网络层抽象
│   │   │   ├── udp_nat_core.rs    # UDP NAT 核心实现
│   │   │   ├── udp_processor.rs   # UDP 数据包处理器
│   │   │   └── ...
│   │   ├── outbound/  # 出站连接管理
│   │   ├── router/    # 路由引擎
│   │   ├── types/     # 核心类型定义
│   │   └── ...
│   └── tests/         # 单元测试
├── sb-config/         # ⚙️ 配置解析和验证
├── sb-adapters/       # 🔌 协议适配器
├── sb-transport/      # 🚀 传输层实现
├── sb-tls/            # 🔐 TLS 基础设施 (Sprint 5 新增)
│   ├── src/
│   │   ├── standard.rs    # 标准 TLS 1.2/1.3 (rustls)
│   │   ├── reality/       # REALITY 协议 (X25519 伪装)
│   │   ├── ech/           # ECH (HPKE SNI 加密)
│   │   └── utls.rs        # uTLS 指纹模拟 (计划中)
│   └── tests/         # TLS 测试套件
├── sb-metrics/        # 📊 指标收集系统
├── sb-runtime/        # ⚡ 运行时管理
├── sb-platform/       # 🖥️ 平台特定功能
├── sb-proto/          # 📡 协议定义
├── sb-security/       # 🛡️ 安全工具 (JWT, 凭据验证)
├── sb-api/            # 🌐 外部 API (V2Ray/Clash)
└── sb-subscribe/      # 📥 订阅管理
```

### 🎯 模块职责

| 模块 | 职责 | 关键组件 |
|------|------|----------|
| **sb-core** | 核心功能和抽象 | 路由引擎、DNS系统、UDP NAT、错误处理 |
| **sb-config** | 配置管理 | Schema验证、配置解析、错误报告 |
| **sb-adapters** | 协议适配 | VMess、VLESS、Hysteria v1/v2、TUIC、Trojan |
| **sb-transport** | 传输层 | TCP/UDP传输、WebSocket、HTTP/2、Multiplex |
| **sb-tls** | TLS基础设施 | 标准TLS、REALITY、ECH、uTLS(计划) |
| **sb-metrics** | 监控指标 | Prometheus集成、性能监控 |
| **sb-runtime** | 运行时 | 异步任务管理、生命周期 |
| **sb-platform** | 平台支持 | 系统调用、平台特定功能 |
| **sb-proto** | 协议定义 | 协议结构体、序列化 |
| **sb-security** | 安全工具 | JWT认证、凭据验证、密钥管理 |
| **sb-api** | 外部API | V2Ray Stats、Clash API |
| **sb-subscribe** | 订阅服务 | 节点订阅、自动更新 |

## 测试结构 (tests/)

### 📋 测试分类

```
tests/
├── 📁 integration/           # 集成测试
│   ├── test_schema_v2_integration.rs
│   ├── test_udp_nat_*        # UDP NAT 系统测试
│   └── verify_*              # 验证脚本
├── 📁 unit/                  # 单元测试（待添加）
├── 📁 configs/               # 测试配置文件
│   ├── test_*_config.yaml    # 各种配置测试用例
│   ├── test_*.json           # JSON 配置文件
│   └── test_cert.pem         # 测试证书
├── 📁 data/                  # 测试数据
│   ├── demo*.json            # 演示数据
│   ├── task_receipt*.json    # 任务回执
│   └── *.long-type-*.txt     # 类型推断临时文件
├── 📁 scripts/               # 测试脚本
│   └── verify_*.sh           # 验证脚本
└── 📁 docs/                  # 测试相关文档
    ├── UDP_NAT_*.md          # UDP NAT 实现文档
    └── SCHEMA_V2_*.md        # Schema V2 文档
```

### 🧪 测试类型说明

| 类型 | 目录 | 用途 |
|------|------|------|
| **集成测试** | `integration/` | 跨模块功能测试、端到端验证 |
| **单元测试** | `unit/` | 单个函数/模块测试 |
| **配置测试** | `configs/` | 配置解析和验证测试 |
| **数据文件** | `data/` | 测试用的静态数据 |
| **脚本测试** | `scripts/` | 自动化验证脚本 |

## 应用程序结构 (app/)

```
app/
├── src/
│   ├── cli/              # 命令行接口
│   ├── main.rs           # 主入口点
│   └── ...
├── tests/                # 应用级测试
├── examples/             # 使用示例
└── Cargo.toml            # 应用配置
```

## 文档结构 (docs/)

### 📚 文档分类

```
docs/
├── ARCHITECTURE.md           # 架构设计文档
├── CLI_TOOLS.md              # CLI 工具说明
├── COOKBOOK.md               # 可运行示例与排错
├── DEVELOPMENT.md            # 质量闸门与开发参考
├── OPS.md                    # 运维与部署（systemd/Docker）
├── ENV_VARS.md               # 环境变量清单
├── PROJECT_STRUCTURE_NAVIGATION.md  # 本导航文档
└── ...
```

## 示例和配置 (examples/)

```
examples/
├── 📁 configs/                 # 示例配置文件
├── 📁 rules/                   # 路由规则示例
├── 📁 scenarios/               # 使用场景示例
├── 📄 *.rs                     # Rust 代码示例
└── 📄 config.*.json            # 各种配置示例
```

## 脚本和工具 (scripts/)

### 🛠️ 脚本分类

```
scripts/
├── ci/                      # CI/CD 脚本
├── e2e-run.sh               # 非阻断 e2e 汇总
├── preflight.sh             # 发行前预检门禁
├── bench.sh                 # 开发态基准脚本
└── ...
```

## 开发环境配置

### 🔧 配置文件

| 文件 | 用途 |
|------|------|
| `Cargo.toml` | 工作空间配置 |
| `rust-toolchain.toml` | Rust 工具链版本 |
| `clippy.toml` | Clippy 配置 |
| `deny.toml` | 依赖检查配置 |
| `.cargo/config.toml` | Cargo 构建配置 |

## 快速导航

### 🚀 常用开发路径

1. **核心功能开发**: `crates/sb-core/src/`
2. **协议实现**: `crates/sb-adapters/src/`
3. **配置管理**: `crates/sb-config/src/`
4. **测试文件**: `tests/`
5. **文档编写**: `docs/`
6. **示例代码**: `examples/`

### 📝 重要文件

- **项目规划**: `进度规划与分解V5.md`
- **架构文档**: `docs/ARCHITECTURE.md`
- **API文档**: `docs/CLI_TOOLS.md`
- **错误处理**: `docs/ERRORS.md`
- **测试指南**: `tests/README.md`

### 🔍 查找指南

- **查找功能实现**: 在 `crates/sb-core/src/` 中按模块查找
- **查找协议支持**: 在 `crates/sb-adapters/src/` 中查找
- **查找配置选项**: 在 `crates/sb-config/src/` 和 `examples/configs/` 中查找
- **查找测试用例**: 在 `tests/` 目录中按功能分类查找
- **查找使用示例**: 在 `examples/` 目录中查找

## 最近更新

### ✅ Sprint 5 重大突破 (2025-10-09)

1. **TLS 基础设施完成** (`crates/sb-tls/`)
   - **Standard TLS**: 生产级 TLS 1.2/1.3 (rustls)
   - **REALITY**: X25519 密钥交换 + 认证数据嵌入 + 回退代理
   - **ECH**: HPKE 加密 SNI (DHKEM-X25519 + CHACHA20POLY1305)
   - E2E 测试: `tests/reality_tls_e2e.rs`, `tests/e2e/ech_handshake.rs`
   - 文档: `docs/TLS.md`

2. **协议实现完成**
   - **Direct Inbound**: TCP+UDP 转发器 (会话式 NAT, 自动超时清理)
   - **Hysteria v1**: 完整客户端/服务端 (QUIC, 自定义拥塞控制, UDP 中继)
   - **Hysteria2**: 完整实现 (Salamander 混淆, 密码认证, UDP over stream)
   - **TUIC Outbound**: 完整 UDP over stream 支持 + 认证

3. **嗅探管道集成** (`crates/sb-core/src/router/`)
   - HTTP Host 嗅探 (CONNECT 方法 Host 提取)
   - TLS SNI 嗅探 (ClientHello SNI 字段提取)
   - QUIC ALPN 嗅探 (QUIC 握手 ALPN 检测)
   - 路由引擎集成: `RouterInput::sniff_host`, `RouterInput::sniff_alpn`

4. **UDP NAT 系统** (`crates/sb-core/src/net/udp_nat_core.rs`)
   - UdpFlowKey 会话标识
   - UdpSession TTL 和活动跟踪
   - UdpNat HashMap 存储和 LRU 驱逐
   - 完整的指标集成

5. **Schema V2 错误格式** (`crates/sb-core/src/error/`)
   - 结构化错误报告
   - RFC6901 JSON 指针
   - CLI 集成

6. **测试结构重组** (`tests/`)
   - 按功能分类的清晰结构
   - 集成测试和配置分离
   - 文档和脚本整理

### 📊 覆盖率进展

- **Full 实现**: 6 → 15 (+150%)
- **功能覆盖**: 19.4% → 21.1%
- **Inbounds**: 13.3% → 33.3%
- **Outbounds**: 17.6% → 35.3%
- **TLS**: 0% → 50% (3/6 完成)

## 📋 文档维护指南

### 🔄 更新责任
- **开发者**: 修改项目结构时必须同步更新本文档
- **AI助手**: 开始工作前必须验证并更新文档准确性
- **自动化工具**: 结构变更后必须触发文档更新检查

### ✅ 验证清单
在开始开发工作前，请验证以下内容：
- [ ] 根目录结构与文档描述一致
- [ ] crates/ 模块列表完整准确
- [ ] tests/ 目录分类正确
- [ ] 文档路径引用有效
- [ ] 最近更新部分反映当前状态

### 🚨 发现不一致时的处理流程
1. **立即停止当前开发工作**
2. **更新文档以反映实际结构**
3. **验证更新后的文档准确性**
4. **继续原定开发任务**

### 📝 文档更新格式
更新时请遵循以下格式：
- 使用清晰的目录树结构
- 包含文件/目录的用途说明
- 更新"最近更新"部分
- 保持emoji图标的一致性

---

**⚠️ 重要提醒**: 本文档的准确性直接影响开发效率和代码质量。请严格遵守维护指南，确保文档始终与项目实际结构保持同步。

*文档版本: v1.2 | 最后更新: 2025年10月9日 | 最后验证: 2025年10月9日*
