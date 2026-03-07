# 06 出站能力（Outbounds）

出站是“腿”。它不只是把流量送出去，更是把“怎么送、从哪条路送、伪装成什么样”变成可配置的工程现实。

## 1) 目标与总体要求

- MUST：支持 `outbounds[]` 数组配置，每个 outbound 至少有 `type` 与 `tag`（或等价标识）。
- MUST：所有主动拨号类 outbound 应复用公共 **Dial Fields**（目标解析策略、接口选择、超时、TCP keepalive 等）。
- MUST：与 Route Rule / Rule Action 完整闭环：路由可按 tag 选择出站，或由 selector/urltest 进行动态选择。

## 2) Outbound 类型清单（官方文档列举）

内核 MUST 支持下列 outbound 类型（按文档导航列举）：

1. `direct`
2. `block`
3. `socks`
4. `http`
5. `shadowsocks`
6. `vmess`
7. `trojan`
8. `naive`
9. `wireguard`（注意：在 Migration 中有“转为 endpoint”的弃用迁移路线）
10. `hysteria`
11. `shadowtls`
12. `vless`
13. `tuic`
14. `hysteria2`
15. `anytls`
16. `tor`
17. `ssh`
18. `dns`
19. `selector`
20. `urltest`

## 3) 通用能力模板（多数协议出站）

- MUST：拨号与连接管理  
  - 支持 Dial Fields：目标解析/接口选择/超时/keep-alive 等。  
  - 支持 IPv4/IPv6 策略与回退机制（与 DNS/resolve 体系一致）。
- MUST：协议握手与转发  
  - 按协议规范完成握手（TLS/QUIC/加密层），再进行数据转发。
- SHOULD：TLS 统一配置  
  - 若协议基于 TLS/或可叠加 TLS，应统一走 Shared/TLS 配置（支持 ECH/Reality/fragment 等高级选项，见 09）。
- SHOULD：错误可观测  
  - 握手失败、认证失败、被封锁、超时等应具备可诊断日志。

## 4) 关键“能力型”出站：Block / DNS / Selector / URLTest

### 4.1 Block

- MUST：实现阻断出站（用于黑洞/拒绝），并能被路由规则直接引用（tag）。

### 4.2 DNS outbound

- MUST：实现“把请求交给 DNS 子系统处理/或作为 DNS 相关动作的承载”这一类能力（具体按官方 outbound DNS 定义）。
- SHOULD：与 Migration 中“旧 DNS 规则迁移到 domain resolver/resolve action”保持一致。

### 4.3 Selector（策略组）

- MUST：支持在多个出站 tag 中进行手动选择或外部 API 控制选择（常用于 Clash API 场景）。
- SHOULD：选择状态可查询、可持久化（可配合 cache_file）。

### 4.4 URLTest（延迟/可用性测试组）

- MUST：支持对候选出站进行 URL 探测/健康检查，选择最优出站。
- SHOULD：探测策略、间隔、超时、失败回退可配置（以官方字段为准）。

## 5) 传输层与性能模块（Shared）

- SHOULD：支持 Multiplex（多路复用）以降低握手成本（适用于支持的协议栈）。
- SHOULD：支持 V2Ray Transport（如 WS/GRPC/HTTP2 等具体 transport，以官方字段为准）。
- SHOULD：支持 UDP over TCP / TCP Brutal 等“绕行或增强传输”模块（按官方 Shared 定义）。
- SHOULD：支持 Pre-match（在连接建立早期做 reject/route/bypass 等动作）以提升策略效率。

## 6) WireGuard 出站与 Endpoint 迁移

- SHOULD：按照 Migration，逐步将 WireGuard outbound 迁移到 Endpoint 体系；实现应提供：  
  - 兼容旧配置（可选）  
  - 清晰的弃用告警与迁移建议

## 7) 验收清单

- 路由引用任意 tag 的 outbound 均可工作。
- selector/urltest 能在运行时切换选择并影响后续连接。
- shared 传输模块开启/关闭不会破坏基础功能；错误时可回退。

## 来源链接（官方文档）

- Outbound 总览（类型列表）  
  https://sing-box.sagernet.org/configuration/outbound/
- Dial Fields（公共拨号字段）  
  https://sing-box.sagernet.org/configuration/shared/dial/
- TLS（共享 TLS 能力）  
  https://sing-box.sagernet.org/configuration/shared/tls/
- Multiplex / V2Ray Transport / UDP over TCP / TCP Brutal / Pre-match  
  https://sing-box.sagernet.org/configuration/shared/multiplex/  
  https://sing-box.sagernet.org/configuration/shared/v2ray-transport/  
  https://sing-box.sagernet.org/configuration/shared/udp-over-tcp/  
  https://sing-box.sagernet.org/configuration/shared/tcp-brutal/  
  https://sing-box.sagernet.org/configuration/shared/pre-match/
- Migration（WireGuard outbound → endpoint 等）  
  https://sing-box.sagernet.org/migration/
