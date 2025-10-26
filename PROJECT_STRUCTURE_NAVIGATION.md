# SingBox-Rust 项目结构导航

> **🚨 权威文档声明**  
> 本文档是 SingBox-Rust 项目结构的**唯一权威参考**。任何开发者、AI助手或自动化工具在开始工作前都必须：
> 1. ✅ 验证本文档内容与实际项目结构的一致性
> 2. 🔄 如发现不一致，立即更新本文档
> 3. 📋 基于本文档进行开发路径规划
> 
> **更新责任**: 任何修改项目结构的操作都必须同步更新本文档  
> **最后更新**: 2025年10月26日（已对照当前仓库结构校验）

## 项目概述

SingBox-Rust 是一个高性能的代理服务器实现，采用模块化架构设计，支持多种协议和路由策略。

## 根目录结构

```
singbox-rust/
├── 📁 .cargo/           # Cargo 配置（构建参数、别名等）
├── 📁 .e2e/             # 端到端测试产物与摘要
├── 📁 .github/          # GitHub Actions 工作流
├── 📁 app/              # 主应用与多 bin CLI（feature 门控）
├── 📁 crates/           # 工作区各核心 crate 模块
├── 📁 docs/             # 文档门户（00-.. 分区）
├── 📁 examples/         # 示例与配置
├── 📁 fuzz/             # 模糊测试
├── 📁 grafana/          # 监控看板
├── 📁 LICENSES/         # 依赖许可证
├── 📁 reports/          # 报告与基线
├── 📁 scripts/          # CI、工具、场景脚本
├── 📁 tests/            # 测试（集成/E2E/配置/数据 等）
├── 📁 vendor/           # 供应商依赖覆盖（如 tun2socks）
├── 📁 xtask/            # 开发/发布辅助任务
├── 📁 xtests/           # 扩展测试工具
├── 📄 Cargo.toml        # 工作区清单
├── 📄 Cargo.lock        # 锁文件
├── 📄 README.md         # 项目说明与快速开始
├── 📄 GO_PARITY_MATRIX.md  # 与 sing-box 对齐矩阵
├── 📄 NEXT_STEPS.md     # 下一步里程碑与工作流
├── 📄 SECURITY.md       # 安全说明
├── 📄 进度规划与分解V6.md   # 项目进度规划（当前）
└── 📄 其他：deny.toml、clippy.toml、rust-toolchain.toml 等
```

## 核心模块架构 (crates/)

### 🏗️ 架构层次

```
crates/
├── sb-core/            # 🔧 核心：路由引擎、DNS、NAT、出入站抽象
├── sb-config/          # ⚙️ 配置解析与 Schema/IR
├── sb-adapters/        # 🔌 协议适配：VMess/VLESS/Trojan/SS/TUIC/Hysteria 等
├── sb-transport/       # 🚀 传输：TCP/UDP/WS/H2/H3/Upgrade/Multiplex
├── sb-tls/             # 🔐 TLS：Standard/REALITY/ECH
├── sb-metrics/         # 📊 指标：Prometheus 集成
├── sb-runtime/         # ⚡ 运行时：任务/资源/IO 管理
├── sb-platform/        # 🖥️ 平台：系统调用与平台特性
├── sb-proto/           # 📡 协议与通用类型
├── sb-security/        # 🛡️ 安全：JWT、凭据红化
├── sb-api/             # 🌐 外部 API（V2Ray/Clash）
├── sb-subscribe/       # 📥 订阅：远程规则与节点
├── sb-admin-contract/  # 🧾 管理面契约（admin_envelope）
├── sb-test-utils/      # 🧪 测试工具与夹具
└── sb-types/           # 🧰 工作区共享类型
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
├── integration/   # 集成测试
├── e2e/           # 端到端编排/工具
├── stress/        # 压测/稳态验证
├── configs/       # 测试配置
├── data/          # 测试数据
├── scripts/       # 测试脚本
├── docs/          # 测试文档
└── 顶层若干 *.rs  # 直挂的 E2E/集成测试（如 reality_tls_e2e.rs 等）
```

### 🧪 测试类型说明

- 集成测试：`integration/` 与仓库根 `tests/*.rs`
- 端到端：`e2e/`
- 压测/稳态：`stress/`
- 配置/数据/脚本/文档：`configs/`、`data/`、`scripts/`、`docs/`

## 应用程序结构 (app/)

```
app/
├── src/                 # 主入口与子命令（bin/*）
├── tests/               # 应用级测试
├── benches/             # 基准测试
├── examples/            # 使用示例
├── scripts/             # app 层脚本
├── build.rs             # 构建期元信息
└── Cargo.toml           # 应用配置与 feature 门控
```

## 文档结构 (docs/)

### 📚 文档分类

```
docs/
├── 00-getting-started/   # 快速开始
├── 01-user-guide/        # 用户指南/配置
├── 02-cli-reference/     # CLI 参考
├── 03-operations/        # 运维/部署
├── 04-development/       # 开发与贡献
├── 05-api-reference/     # API 文档
├── 06-advanced-topics/   # 高级主题（REALITY/ECH 等）
├── 07-reference/         # 参考（Schema/错误码）
├── 08-examples/          # 示例
├── archive/              # 历史归档
├── RESTRUCTURE_SUMMARY.md
├── REFACTORING_PROPOSAL.md
├── CLEANUP_COMPLETION_REPORT.md
└── README.md
```

## 示例和配置 (examples/)

```
examples/
├── configs/      # 各类配置样例（minimal/advanced/...）
├── rules/        # 路由规则样例
├── scenarios/    # 运行场景脚本/配置
└── *.rs          # Rust 样例程序
```

## 脚本和工具 (scripts/)

### 🛠️ 脚本分类

```
scripts/
├── ci/          # CI 相关脚本
├── dev/         # 本地开发辅助
├── e2e/         # 端到端测试编排
├── lib/         # 脚本共享库
├── lint/        # 质量闸门/静态检查
├── test/        # 基准/回归守护等
├── tools/       # 工具与可视化脚本
├── run          # 单入口运行脚本（多场景）
├── run-scenarios# 预置场景批跑
└── scenarios.d/ # 场景定义集合
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

- 项目规划: `进度规划与分解V6.md`
- 文档入口: `docs/README.md` 与分区 `00-..` 目录
- CLI/使用参考：根 `README.md` 与 `docs/02-cli-reference/`
- 测试指南: `tests/README.md`

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

*文档版本: v1.3 | 最后更新: 2025年10月26日 | 最后验证: 2025年10月26日*
