# Ports 契约总览（sb-types 唯一真相）

> 本目录定义 sb-core 与外界交互的全部“端口”。coding agent 实现任何功能时：
> - 先确认是否已有 port
> - 没有则新增 port（在 sb-types）
> - 再在 adapters/platform/transport 里实现

---

## Ports 清单

- `InboundAcceptor`：接受入站连接/包
- `OutboundConnector`：建立出站连接/发包
- `DnsPort`：解析与缓存接口
- `TransportPort`：构建底层连接形态（可选：也可以直接由 adapters 依赖 sb-transport）
- `AdminPort`：控制面管理接口
- `StatsPort`：统计与连接查询
- `MetricsPort`：观测抽象
- `TimePort`（可选）：时间校准/来源（NTP/system）
- `PlatformPort`（可选）：TUN/系统能力
