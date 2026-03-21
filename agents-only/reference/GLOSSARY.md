# 术语表（Glossary）

> 用途：统一高频架构与实现术语，避免在维护模式下继续混用旧口径。  
> 范围：本表只覆盖当前仓库里反复出现、足以影响实现决策的核心概念；不追求穷举。

---

## 架构术语

| 术语 | 定义 | 不要混淆 |
|------|------|---------|
| **sb-types** | 契约层 crate，放 Ports、共享领域类型、错误/契约定义 | 不是 `sb-common` |
| **sb-core** | 内核合集层（Kernel Aggregate）；核心职责是路由/策略/会话编排，也允许保留现存协议/服务/传输模块，但必须 feature-gated 且受边界门禁约束 | 不是“纯引擎层、绝不含协议实现” |
| **sb-adapters** | 协议适配器层；新增 inbound/outbound 协议实现默认归属这里 | 不是 design pattern 里的 adapter 泛称 |
| **Ports** | trait 定义的跨 crate 接口边界 | 不是网络端口 |
| **Composition Root** | `app` crate；负责装配运行时、注册表、配置、服务与 feature 组合 | 不是 root 用户 |
| **ConfigIR** | 由 `sb-config` 生成的中间表示，作为配置校验后的运行时输入 | 不是原始 JSON/YAML |
| **Supervisor** | `sb-core` 运行时总控对象，负责启动、重载、状态持有与桥接 | 不是单个 task manager |
| **AdapterIoBridge** | 连接 adapter 注册表与 runtime 桥接的 IO 适配对象 | 不是协议实现本身 |
| **ContextRegistry** | 运行时上下文/注册表安装点，用于让组件拿到共享 runtime 依赖 | 不是全局配置 |
| **register_all** | `sb_adapters::register_all()`；当前产品路径中的集中注册入口，受边界策略和预算约束 | 不是所有协议都默认启用的证明 |

---

## 代理与传输术语

| 术语 | 定义 | 不要混淆 |
|------|------|---------|
| **Inbound** | 入站代理，接收客户端连接或流量 | 不是 inbound rules |
| **Outbound** | 出站代理，连接目标服务器或上游 | 不是 outbound rules |
| **Endpoint** | 端点类型，如 WireGuard endpoint；通常是特定数据面/控制面组合 | 不是普通 outbound |
| **Service** | 服务型功能，如 DERP、Resolved、SSMAPI、V2Ray API | 不是 systemd service |
| **Proxy** | 网络代理协议，如 Trojan/VMess/Shadowsocks | 不是 Proxy 设计模式 |
| **TUN** | 虚拟网卡设备路径 | 不是泛指 tunnel |
| **Mux** | 单连接多流复用能力 | 不是一般意义的 multiplexer |
| **Feature-gated** | 通过 Cargo feature 控制启用的模块或依赖 | 不是 runtime toggle |

---

## 验收与治理术语

| 术语 | 定义 | 示例 |
|------|------|------|
| **Closure** | 收口状态；表示问题是否关闭，不等于全部行为完全对齐 | `209/209 closed` |
| **Accepted Limitation** | 已记录、已接受、不再作为开放阻塞项追踪的限制 | Linux-only runtime gap |
| **Historical Snapshot** | 历史快照文档；保留证据背景，但不承担当前权威状态 | `reports/L3_AUDIT_2026-02-10.md` |
| **Slim Snapshot** | 为减小仓库体积裁剪过产物的本地快照；缺失完整证据包时不得宣称 fully verified | `snapshot_unverified` |
| **Boundary Policy** | `check-boundaries.sh` 与 `boundary-policy.json` 共同定义的当前边界门禁 | V4a threshold / pattern budgets |
| **Capability Ledger** | `reports/capabilities.json` + `docs/capabilities.md`；描述 capability tri-state，不单独构成行为级验收证明 | `docs-only` profile |

---

## GUI 兼容术语

| 术语 | 定义 | 来源 |
|------|------|------|
| **CoreFilePath** | GUI.for.SingBox 读取的 sing-box 二进制路径 | GUI.for.SingBox |
| **sing-box started** | GUI 判断核心启动成功的日志标识字符串 | `kernel.ts` |
| **version 正则** | GUI 解析版本字符串的匹配规则 | `useCoreBranch.ts` |

---

*最后更新：2026-03-21*
