# 术语表（Glossary）

> **用途**：统一项目核心概念命名，避免歧义
> **维护**：发现新术语时主动添加

---

## 架构术语

| 术语 | 定义 | 不要混淆 |
|------|------|---------|
| **sb-types** | 契约层 crate，只含 Ports + 领域类型 | 不是 sb-common |
| **sb-core** | 引擎层 crate，路由/策略/会话编排 | 不含协议实现 |
| **sb-adapters** | 协议适配器层，所有协议实现 | 不是 adapters (设计模式) |
| **Ports** | trait 定义的接口边界（六边形架构） | 不是网络端口 |
| **Composition Root** | app crate，组装所有依赖 | 不是 root 用户 |

---

## 代理术语

| 术语 | 定义 | 不要混淆 |
|------|------|---------|
| **Inbound** | 入站代理（接收客户端连接） | 不是 inbound rules |
| **Outbound** | 出站代理（连接目标服务器） | 不是 outbound rules |
| **Proxy** | 网络代理协议（Trojan/VMess/SS等） | 不是设计模式 Proxy |
| **TUN** | 虚拟网卡设备 | 不是 tunnel |
| **Mux** | 多路复用（单连接多流） | 不是 multiplexer |

---

## 工作流术语

| 术语 | 定义 | 示例 |
|------|------|------|
| **WP** | Workpackage 工作包 | WP-L1.0 |
| **L1/L2/L3** | 里程碑层级 | L1=架构整固 |
| **Blocker** | 阻碍项，阻止进度 | 依赖冲突 |
| **DRP** | Disaster Recovery Protocol | 灾难恢复协议 |
| **TTL** | Time To Live 生存时间 | dump 文件 7 天过期 |

---

## GUI 兼容术语

| 术语 | 定义 | 来源 |
|------|------|------|
| **CoreFilePath** | sing-box 二进制路径 | GUI.for.SingBox |
| **sing-box started** | 启动成功标志字符串 | kernel.ts:17 |
| **version 正则** | `/version (\S+)/` | useCoreBranch.ts:152 |

---

*最后更新：2026-02-07*
