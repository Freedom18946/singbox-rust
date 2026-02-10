# 03 DNS 子系统

在代理系统里，DNS 不是“查个域名”这么简单——它决定你看到的“目的地”是什么，路由能否拿到域名语义，以及透明代理是否会被系统缓存或劫持所干扰。

## 1) 目标与职责

- MUST：提供内置 DNS 子系统（`dns`），可在不同网络环境下选择上游解析方式，并把结果与路由系统联动。
- MUST：支持 DNS 路由/规则与动作（DNS Rule / DNS Rule Action），实现“按域名/请求类型/地址过滤”等策略。
- SHOULD：支持 FakeIP 与反向映射（reverse mapping），以增强透明代理/路由时的域名可见性。

## 2) DNS Servers：类型与能力矩阵

### 2.1 Server 类型（type）

- MUST：支持 `dns.servers[]` 列表，每个 server 至少包含 `type` 与 `tag`。
- MUST：支持下列 server 类型（官方文档列举）：  
  - `legacy`（旧式，已弃用路线）  
  - `local`（平台本地解析接口）  
  - `hosts`（hosts 文件/预置表）  
  - `tcp` / `udp` / `tls` / `quic`（DoQ）  
  - `https`（DoH） / `h3`（HTTP/3）  
  - `dhcp`（从 DHCP 获取）  
  - `fakeip`（Fake IP server）  
  - `tailscale`（Tailscale 集成）  
  - `resolved`（systemd-resolved 集成）  

> 说明：`legacy` 在文档中标注为 deprecated，并给出移除版本与迁移指引；实现需兼顾弃用提示。

### 2.2 Hosts server

- MUST：支持读取系统默认 hosts 路径（Linux `/etc/hosts`、Windows 默认 hosts 路径）与自定义路径列表。
- MUST：支持预置 hosts 映射（单域名到单/多 IP）。

### 2.3 Local / Resolved server 的平台差异

- SHOULD：对 `local` / `resolved` 这类“平台接口”型 server，应在不同 OS/运行模式下保持行为一致性与明确的限制说明。  
  例如：Android 客户端与 macOS Network Extension 场景对“如何获取上游 DNS”存在差异，文档已给出注意事项。

## 3) DNS Rules：匹配、过滤与动作

### 3.1 DNS Rule（匹配层）

- MUST：支持 DNS 规则匹配，并能在“地址请求（A/AAAA/HTTPS）”上执行地址过滤逻辑（例如当结果不匹配过滤项时跳过当前规则）。
- SHOULD：支持把规则集中的 `ip_cidr` 同样作为地址过滤字段（文档明确该行为）。

### 3.2 DNS Rule Action（执行层）

- MUST：支持多种 DNS 动作（至少包括：选择上游 server、改写响应、丢弃、预置应答等）。
- MUST：支持 `predefined` 动作：直接返回预定义 DNS 记录（answer/ns/extra 等）。
- SHOULD：对“高频触发导致的保护性 drop 覆盖”等行为保持可配置与可观测（文档中对 `no_drop` 有明确描述）。

## 4) FakeIP 与反向映射

- MUST：支持 FakeIP 功能开关（`dns.fakeip.enabled`），用于透明代理场景将域名映射到虚拟地址。
- SHOULD：支持 `reverse_mapping`：在响应 DNS 查询后保存“IP → 域名”的反向映射，以便路由阶段补全域名语义。  
  - 同时 MUST：在 macOS 等“系统代理与缓存 DNS”较强的环境，给出行为限制或建议（文档指出该机制可能遇到问题）。
- SHOULD：支持 DNS 缓存容量（LRU，`cache_capacity`）并对过小值作忽略保护（文档提到阈值）。

## 5) 验收清单

- server 类型枚举齐全，缺失/拼写错误给出清晰报错路径（`dns.servers[i]...`）。
- DNS Rule 的“地址过滤”只影响 A/AAAA/HTTPS，不误伤其它请求类型。
- FakeIP + reverse mapping 在透明代理场景下能向路由提供域名信息（或在受限平台给出明确告警）。
- deprecated 的 legacy server 能运行或给出迁移提示（按产品策略决定是否仅提示或也保留兼容）。

## 来源链接（官方文档）

- DNS（cache_capacity、reverse_mapping 等）  
  https://sing-box.sagernet.org/configuration/dns/
- DNS Server（类型枚举与结构）  
  https://sing-box.sagernet.org/configuration/dns/server/
- Hosts server（hosts 路径与预置）  
  https://sing-box.sagernet.org/configuration/dns/server/hosts/
- Local server（平台差异说明）  
  https://sing-box.sagernet.org/configuration/dns/server/local/
- Resolved server（systemd-resolved 集成字段）  
  https://sing-box.sagernet.org/configuration/dns/server/resolved/
- DNS Rule（地址过滤、弃用字段迁移等）  
  https://sing-box.sagernet.org/configuration/dns/rule/
- DNS Rule Action（predefined/no_drop 等）  
  https://sing-box.sagernet.org/configuration/dns/rule_action/
- FakeIP（开关结构）  
  https://sing-box.sagernet.org/configuration/dns/fakeip/
- Migration（legacy/旧规则迁移）  
  https://sing-box.sagernet.org/migration/
