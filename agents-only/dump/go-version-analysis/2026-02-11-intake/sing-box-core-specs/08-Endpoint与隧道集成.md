# 08 Endpoint 与隧道集成（WireGuard / Tailscale / DERP）

Endpoint 更像“系统级隧道接口”：它不是普通出站，而是把一个网络栈（或虚拟网络）接入 sing-box 的整体路由体系。

## 1) Endpoint 模块目标

- MUST：支持 `endpoints[]` 顶层数组配置（见整体配置结构）。
- MUST：支持至少两类 endpoint（官方文档导航列出）：  
  - `wireguard`  
  - `tailscale`
- SHOULD：endpoint 与 route/dns 深度集成：  
  - 来自 endpoint 的流量可作为 inbound 输入到 route  
  - route 可将流量导出到 endpoint 或 direct 等

## 2) WireGuard：从 Outbound 迁移到 Endpoint

- SHOULD：遵循 Migration：WireGuard outbound 被标注为“可迁移到 endpoint”的路线。  
- MUST（若兼容旧配置）：提供明确迁移指引与兼容层，避免用户在升级时静默失效。

## 3) Tailscale 相关联动点（按文档导航）

- MUST：支持 Tailscale endpoint。
- SHOULD：支持 DNS server 中的 `tailscale` 类型，以便在 Tailscale 场景使用其 DNS 体系。
- SHOULD：支持 `services` 中的 DERP 相关服务（用于 Tailscale/中继类场景，具体字段以官方 service/derp 文档为准）。

## 4) 验收清单

- endpoints[] 可被加载并参与路由决策。
- WireGuard 迁移路径明确：旧配置可运行或给出强提示；新配置可稳定工作。
- Tailscale endpoint + tailscale DNS server + DERP service（若启用）可形成闭环。

## 来源链接（官方文档）

- Configuration / Introduction（endpoints 顶层结构）  
  https://sing-box.sagernet.org/configuration/
- Endpoint（WireGuard/Tailscale）  
  https://sing-box.sagernet.org/configuration/endpoint/
- Migration（WireGuard outbound → endpoint）  
  https://sing-box.sagernet.org/migration/
- DNS Server（tailscale 类型）  
  https://sing-box.sagernet.org/configuration/dns/server/
- Service / DERP  
  https://sing-box.sagernet.org/configuration/service/derp/
