# 05 入站能力（Inbounds）

入站是“门”。门开在哪里、用什么语言说话、如何识别来客——决定了这座系统能接住怎样的世界。

## 1) 目标与总体要求

- MUST：支持 `inbounds[]` 数组配置，每个 inbound 至少有 `type` 与 `tag`（或等价标识）。
- MUST：所有基于 socket 的 inbound 应复用公共 **Listen Fields**（监听地址、端口、复用/透明选项等）。
- SHOULD：入站应能与路由/嗅探/认证联动（例如按 auth_user 匹配规则、按 sniffed protocol 做路由）。

## 2) Inbound 类型清单（官方文档列举）

内核 MUST 支持下列 inbound 类型（按文档导航列举）：

1. `direct`
2. `mixed`
3. `socks`
4. `http`
5. `shadowsocks`
6. `vmess`
7. `trojan`
8. `naive`
9. `hysteria`
10. `shadowtls`
11. `vless`
12. `tuic`
13. `hysteria2`
14. `anytls`
15. `tun`
16. `redirect`
17. `tproxy`

## 3) 每类 Inbound 的功能需求（抽象层）

> 这里不复写每个协议的全部字段表，而把“应该实现的能力”抽象成统一模板，便于工程拆分。具体字段请直接对照官方每个 inbound 页面。

### 3.1 通用能力模板（适用于多数协议入站）

- MUST：监听与接入
  - 按 Listen Fields 监听（IP/端口/可选网络栈）。
  - 支持多连接并发与资源回收（防止 fd 泄露）。
- MUST：认证与会话
  - 支持协议自身的认证字段（如密码/UUID/用户表等）。
  - 能把认证用户信息暴露给路由规则（Route Rule 中的 `auth_user`）。
- MUST：协议握手与数据转发
  - 完整实现协议握手（含 TLS/QUIC 等）。
  - 将目标地址（域名/IP/端口）转交给路由系统做出站选择。
- SHOULD：嗅探联动
  - 在适用场景支持 sniff（或允许通过 route 统一 sniff），把 sniffed protocol/client 交给路由系统。
- SHOULD：错误可观测
  - 握手失败、鉴权失败、上游不可达时提供明确日志与统计点（如有）。

### 3.2 特殊入站：Mixed / SOCKS / HTTP

- MUST：`socks` inbound：提供 SOCKS 代理入口（面向系统/浏览器/应用）。
- MUST：`http` inbound：提供 HTTP 代理入口。
- MUST：`mixed` inbound：在单一监听端口同时兼容 SOCKS 与 HTTP（“一个端口两种入口”），并能正确识别协议类型。

### 3.3 透明代理入站：TUN / Redirect / TProxy

- MUST：`tun` inbound：创建/接管虚拟网卡（TUN），接收来自系统路由导入的流量。
- MUST：`redirect` inbound：接收通过 NAT/REDIRECT 等方式重定向到本地的 TCP/UDP 流量，并能还原原始目的地址用于路由。
- MUST：`tproxy` inbound：支持 Linux TProxy 等机制接管流量并保留原目标信息（适用于更强透明代理需求）。
- SHOULD：在透明代理场景下支持 ICMP（ping）路由（与 Route Rule 中 `icmp` 网络类型联动）。

## 4) 验收清单

- Inbound 类型枚举齐全；未知类型报错明确。
- Mixed 能正确识别并兼容 SOCKS/HTTP。
- 透明代理三件套在目标平台上能“拿到原始目的地址”，并与 DNS/路由协作（FakeIP、reverse mapping 等）。

## 来源链接（官方文档）

- Inbound 总览（类型列表）  
  https://sing-box.sagernet.org/configuration/inbound/
- Listen Fields（公共监听字段）  
  https://sing-box.sagernet.org/configuration/shared/listen/
- Route Rule（auth_user、icmp、透明代理场景说明）  
  https://sing-box.sagernet.org/configuration/route/rule/
- Protocol Sniff（嗅探）  
  https://sing-box.sagernet.org/configuration/route/sniff/
