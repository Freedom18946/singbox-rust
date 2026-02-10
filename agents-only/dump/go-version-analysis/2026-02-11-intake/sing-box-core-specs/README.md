# sing-box 内核核心功能需求整理（基于官方文档）

> 目标：把 https://sing-box.sagernet.org/ 文档中描述的 **sing-box 内核应具备的核心能力**，以“开发需求/功能规格（Feature Spec）”的形式拆解成可落地的模块化文档，便于实现、测试与验收。

## 使用范围与假设

- 本整理**以官方文档为唯一权威来源**（见每个模块末尾的“来源链接”）。
- 视角：**内核能力**（配置解析、协议栈、路由、DNS、透明代理、可观测性、服务/实验功能等），不展开 GUI 客户端 UI 设计。
- 时间：生成于 2026-02-10（Asia/Tokyo）；后续版本若出现新协议/弃用项，请以官方 *Migration / Change Log* 为准。

## 目录

1. `01-总体与配置入口.md` —— 项目定位、配置结构、CLI 工具链（check/format/merge 等）
2. `02-日志与运行可观测性.md` —— 日志配置、输出、时间戳、级别、输出文件
3. `03-DNS子系统.md` —— DNS server 类型、规则与动作、FakeIP、反向映射与缓存
4. `04-路由与规则系统.md` —— Route Rule、Rule Action、Protocol Sniff、Rule-Set（source/binary/remote）
5. `05-入站-Inbounds.md` —— Inbound 类型清单与公共能力（监听字段、认证、sniff、透明接入）
6. `06-出站-Outbounds.md` —— Outbound 类型清单与公共能力（拨号字段、TLS、Transport、Multiplex）
7. `07-透明代理与系统集成.md` —— TUN/Redirect/TProxy、ICMP 路由、平台差异
8. `08-Endpoint与隧道集成.md` —— Endpoint（WireGuard/Tailscale）、弃用迁移、DERP 等关联
9. `09-TLS与证书体系.md` —— TLS/ECH/Reality/Fragment/kTLS、证书信任库、ACME/DNS-01
10. `10-服务与扩展模块-Services.md` —— DERP/Resolved/SSM API/CCM/OCM 等服务能力
11. `11-实验功能与兼容迁移.md` —— cache_file、Clash API、V2Ray API、弃用与迁移策略
12. `12-时间同步与NTP.md` —— NTP 时间校验/同步与 TLS 时间依赖
12. `99-验收清单总表.md` —— 将各模块 MUST/SHOULD 汇总为一张验收 checklist

## 术语约定

- **MUST**：必须实现，否则不符合内核功能预期。
- **SHOULD**：建议实现，关系到可用性/兼容性/易运维。
- **COULD**：可选实现，用于增强或特定场景。
