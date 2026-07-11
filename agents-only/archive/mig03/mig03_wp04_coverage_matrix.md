<!-- tier: B -->
# MIG-03 WP04 — scaffold / adapters 语义覆盖矩阵

Status: DONE
Audit base: `acf3be4c` (`main`, 2026-07-11)
WP05 closure: `de25101d` (`main`, 2026-07-11)
Scope: WP04 审计基线保留；WP05 执行结果以各行 `de25101d` 锚点为准。

## 1. 判定口径

- `ADAPTERS-COVERS`：相对当前 scaffold/legacy 行为，adapter 已覆盖或更强；旧路径可按
  WP06 删除。
- `GAP`：adapter 默认产品路径仍缺 scaffold/legacy 可观察语义；交 WP05 补齐。
- `SCAFFOLD-ONLY`：仅旧实现存在；按 D9/D10/D14 裁决后迁移、隔离或删除。
- Go 有、两套 Rust 都没有：只登记 parity 发现移交，不算 MIG-03 GAP。
- “无 scaffold 实现”不等于 GAP：registry-only 协议只证明不存在双轨，不能拿
  unsupported sentinel 当协议实现。

## 2. 审计基线纠偏

原 WP04 primary evidence 已漂移。当前不是“registry 未命中后普遍静默走 scaffold”。

| 构造入口 | 当前行为 | 证据 | WP06 含义 |
|---|---|---|---|
| `adapter::bridge::build_bridge` inbound | 只查 registry；未注册/构造失败时记录错误，不 fallback | `crates/sb-core/src/adapter/bridge.rs:573-598,861-900` | 删除 scaffold 不改变此入口的协议选择 |
| 同入口普通 outbound | 先 registry；仅 direct/block 有 core fallback | `crates/sb-core/src/adapter/bridge.rs:586-615,618-660` | direct/block fallback 必须按 D11 删除 |
| 同入口 selector/urltest | 只查 registry，无 fallback | `crates/sb-core/src/adapter/bridge.rs:773-807` | adapter shim 仍依赖 core group；去重归 WP12 |
| `Bridge::new_from_config` | 活跃 legacy 公共入口；inbound 构造 SOCKS/TUN/direct，HTTP/mixed/redirect/tproxy 和其余类型为 unsupported；outbound 仅 block 为真实现 | `crates/sb-core/src/adapter/mod.rs:423-626`; caller `crates/sb-core/src/runtime/mod.rs:56-68` | WP06 必须删除/改写整条 legacy 构造路径，不能只改主 bridge |
| `SwitchboardBuilder` | direct/block 构造 core canonical；HTTP/SOCKS/组等退化为 501 connector | `crates/sb-core/src/runtime/switchboard.rs:137-165,168-230` | D11 要求改为 registry direct/block；其余 degraded 路径需显式处置 |
| `ADAPTER_FORCE` | 无运行时读取；仅注释、脚本、测试设置 | `crates/sb-core/src/adapter/bridge.rs:4`; `app/tests/adapter_bridge_scaffold.rs:61,120`; `scripts/ci/tasks/adapter-bridge.sh:23,46` | WP06 删除失效控制面和误导命名 |
| 产品 feature 可达性 | WP05 前 app product/dev profile 未启用 `sb-adapters/socks-udp`；`sb-adapters` 仍强制 `sb-core/router,scaffold,v2ray_transport` | `de25101d`：`sb-adapters` 的 `socks -> socks-udp -> adapter-socks`，app `observe -> sb-adapters/metrics`；acceptance/gui_runtime/parity 均通过 | SOCKS UDP GAP 已闭；scaffold feature 强制编译仍是 WP06 删除目标 |
| core `OutboundImpl` registry | 类型仍含 Direct/Block/Socks5/HttpProxy 与 inline dial helpers；主 bridge写入的却只有 canonical `Connector` | `crates/sb-core/src/outbound/mod.rs:235-247,295-423,842-930`; bridge mapping `adapter/bridge.rs:27-32`, legacy mapping `adapter/mod.rs:642-650` | 非主 bridge协议 fallback，但属于 WP06 必须普查的 legacy ownership；Socks5/HttpProxy 构造方当前仅测试 |

### 2.1 精确 match-arm 清单

| 入口 | 明确分支 | 实际协议实现 |
|---|---|---|
| 主 bridge inbound | 所有 IR kind 经 `p.kind` 查 registry | 无 inbound scaffold branch |
| 主 bridge普通 outbound | direct、block、其余 `_ => None` | 仅 direct/block core fallback |
| 主 bridge第二遍 | selector、urltest | registry-only |
| legacy inbound | socks、http、mixed、tun、direct、redirect、tproxy、`_` | socks/tun/direct 为实现；http/mixed/redirect/tproxy/其余为 unsupported sentinel |
| legacy outbound | direct、block、http、socks、vless、selector、shadowsocks、urltest、shadowtls、hysteria2、tuic、vmess、trojan、ssh、`_` | 仅 block 为实现；其余为 unsupported sentinel |
| switchboard | direct、block、http、socks、hysteria2、selector/urltest、`_` | direct/block 为实现；其余注册 degraded 501 connector |

因此详细八维表覆盖全部真实实现分支；registry-only/sentinel 分支按 DNS、SSH、
Shadowsocks/其余 wildcard 分组写满八维，不把 vless/vmess/trojan/QUIC-family sentinel
误报为 scaffold 实现。QUIC-family 实际错位仍归 WP07。

已删除、不能继续作为 primary evidence 的旧文件：

- `crates/sb-core/src/outbound/direct.rs`
- `crates/sb-core/src/outbound/direct_simple.rs`
- `crates/sb-core/src/outbound/block.rs`
- `crates/sb-core/src/outbound/block_connector.rs`

现存但未在 `outbound/mod.rs` 声明、无活调用方：
`outbound/socks5.rs`、`outbound/http_proxy.rs`。它们是孤立源码，不是运行时实现。

## 3. 汇总裁决

| 方向 | 协议/路径 | 裁决 | 后续 owner |
|---|---|---|---|
| inbound | SOCKS | `ADAPTERS-COVERS` (`de25101d`) | WP06：删 legacy scaffold；adapter 已承接 limiter、active/兼容 metrics、UDP owner/env |
| inbound | HTTP | `ADAPTERS-COVERS` | WP06：删 legacy unsupported arm 与孤立 scaffold 文件 |
| inbound | mixed | `ADAPTERS-COVERS` | WP06：删 legacy unsupported arm 与孤立 scaffold 文件 |
| inbound | direct | `ADAPTERS-COVERS`（共享 core 实现） | WP06：删 legacy constructor；实现归属后续去重 |
| inbound | TUN | `ADAPTERS-COVERS` | WP06：删只用默认配置的 legacy constructor arm |
| inbound | redirect/tproxy | `ADAPTERS-COVERS`（legacy 只有 unsupported） | WP06：删 sentinel；Linux registry 保留 |
| outbound | SOCKS | `ADAPTERS-COVERS` (`de25101d`) | WP06：删 orphan core UDP scaffold；adapter product profile 与迁移测试已闭 |
| outbound | HTTP | `ADAPTERS-COVERS` | WP06：删孤立 minimal connector 与 legacy sentinel |
| outbound | direct | `ADAPTERS-COVERS` | WP06：D11 registry 正典化并删所有 core fallback ownership |
| outbound | block | `ADAPTERS-COVERS` | WP06：D11 registry 正典化 |
| outbound | selector/urltest | `ADAPTERS-COVERS`（adapter shim 共享 core group） | WP12：真正合并/迁移 group 实现 |
| 双向 | DNS/SSH/Shadowsocks 及其他 registry-only 协议 | `ADAPTERS-COVERS`（无 scaffold 实现） | 无 WP05 语义补齐；WP06 只删 unsupported sentinel/陈旧文案 |

WP05 后 `GAP` 为 0。SOCKS inbound/outbound 两组均由 `de25101d` 翻转为
`ADAPTERS-COVERS`。未发现需要 D18 用户裁决的 `SCAFFOLD-ONLY` 项；D9 与 D14
同时适用时，D14 的“本轨迹不废弃任何 SB_*”构成真实保留依据，变量语义已迁移而非删除。

## 4. Inbound 八维矩阵

### 4.1 SOCKS inbound — `ADAPTERS-COVERS` (`de25101d`)

| 维度 | scaffold/legacy | adapters | 裁决/施工锚点 |
|---|---|---|---|
| 配置 | legacy 只读 listen/port，固定构造 no-auth `Socks5::new` | builder 读取 listen、UDP timeout、domain strategy、sniff，但固定 `users: None` | 相对 scaffold 配置面无丢失：`crates/sb-core/src/adapter/mod.rs:432-439` ↔ `crates/sb-adapters/src/register/builders.rs:1462-1502`；Go users 属 parity 移交 |
| 认证 | core 文件明确 no-auth，greeting 只接受 no-auth | adapter 协议层支持 users，但 registry builder 未映射 `basic_auth` | 当前两条构造路径均 no-auth；不是 MIG-03 GAP。证据 `crates/sb-core/src/inbound/socks5.rs:1,103,894-903` ↔ `crates/sb-adapters/src/inbound/socks/mod.rs:54-72,467-488`; builder `crates/sb-adapters/src/register/builders.rs:1491-1492` |
| TCP | core SOCKS5 在 construction 时装入 per-IP limiter；配置解析仍由 `tcp_rate_limit` 共享 | SOCKS/mixed accept loop 均构造同一 `TcpRateLimiter::from_env()`，拒绝时发兼容 rate-limit metric；保留原默认值 | 已覆盖；测试 `limiter_rejects_second_peer_and_active_count_recovers`、`limiter_rejects_second_mixed_peer`；commit `de25101d` |
| UDP | core 有 UDP ASSOCIATE/packet counters；`udp_sessions_estimate` 从未更新，外部恒为 0；上游会话 helper 位于 core | adapter 自有 `inbound/socks/upstream.rs` + `outbound/socks5_udp.rs`，enhanced path 改用 canonical `PacketConn`；不复制恒零 estimate | 已覆盖；无 adapter 对四个 core scaffold 符号的引用；真实 proxy roundtrip 与 wire-size 测试通过；commit `de25101d` |
| 错误 | core 返回 `io::Error` 并记录 scaffold metrics | adapter 有协议 reply、结构化 routing/connect 错误与 startup readiness | adapter 覆盖；WP05 保持 UDP 失败用户可见语义，不移植 scaffold bug |
| metrics | core 发 `inbound_active_connections`、SOCKS UDP associate/packet counters | adapter driver 返回真实 active TCP，accept/drop 更新 gauge，并补发 associate 与双向 packet counter | 已覆盖；active recovery、associate exact increment、proxy packet metrics 测试通过；commit `de25101d` |
| `SB_*` | limiter 与 UDP helper消费 D14 白名单变量 | `UpstreamRuntimeConfig::from_env()` 在 service construction 冻结 receive-task/channel、observation、capacity、timeouts 与 legacy proxy endpoint；旧 timeout alias保留 | 已覆盖；freeze/clamp/地址优先级测试与 `SB_UDP_PROXY_ADDR` 实流测试通过；commit `de25101d` |
| sniff/route | legacy constructor 仅记录 sniff stage1 noop；core handler自持旧 routing | adapter builder 注入 router/outbounds/conntrack，支持 sniff override | adapter 路由语义覆盖；WP05 缺口已清零 |

### 4.2 HTTP inbound — `ADAPTERS-COVERS`

| 维度 | scaffold/legacy | adapters | 裁决 |
|---|---|---|---|
| 配置 | `http_connect.rs` 只支持 CONNECT、单组 Basic；legacy constructor 已返回 unsupported | builder 映射 auth、system proxy、private-network policy、sniff；实现可 TLS | adapter 覆盖，`adapter/mod.rs:440-450`; `builders.rs:1004-1028` |
| 认证 | 单用户 Basic，逐头比较 | users vector、多用户 Basic | adapter 更强，`http_connect.rs:107-164`; `inbound/http.rs:500-506` |
| TCP | CONNECT only | CONNECT + plain GET forward、startup readiness、TLS、graceful drain | adapter 更强，`http_connect.rs:120-149`; `inbound/http.rs:350-403,475-555` |
| UDP | 两侧均无 HTTP inbound UDP 数据面 | 两侧均无 | 无缺口 |
| 错误 | 405/407 + `io::Error` | 400/403/405/407、结构化 metrics/log | adapter 覆盖 |
| metrics | scaffold 有旧 HTTP/inbound 打点 | adapter 显式记录 HTTP 与 inbound error、active connections | adapter 覆盖，`inbound/http.rs:371-400,486-494` |
| `SB_*` | 无 HTTP 协议专属必须保留项 | adapter 有 smoke/timeout 等现存变量 | 非 scaffold-only 缺口；变量统一归 WP11 |
| sniff/route | 直接调用旧 Engine/Bridge，Host sniff | 注入 canonical router/outbounds，支持 destination override | adapter 覆盖，`http_connect.rs:166-204`; `inbound/http.rs:632+` |

### 4.3 mixed inbound — `ADAPTERS-COVERS`

| 维度 | scaffold/legacy | adapters | 裁决 |
|---|---|---|---|
| 配置 | core mixed 组合 minimal SOCKS5 + HTTP CONNECT；legacy constructor 已 unsupported | builder 映射 users、private-network、UDP timeout、domain strategy、sniff | adapter 覆盖，`adapter/mod.rs:451-461`; `builders.rs:1510-1553` |
| 认证 | 继承两套 minimal handler | users 同时传给 SOCKS/HTTP；支持多用户 | adapter 更强 |
| TCP | 识别 SOCKS5/HTTP CONNECT | 识别 SOCKS4/5、HTTP、TLS，带 readiness/read timeout | adapter 更强，`inbound/mixed.rs:144-191` |
| UDP | scaffold mixed 无独立 UDP listener | adapter mixed 的 SOCKS 分支默认不启用 UDP ASSOCIATE | 两侧均无 mixed UDP listener；无缺口，`inbound/mixed.rs:241-255` |
| 错误 | minimal 协议探测/handler 错误 | timeout、TLS 未配置、协议错误均显式记录 | adapter 覆盖 |
| metrics | scaffold 有共享 inbound 指标 | adapter 发 mixed detection/inbound error 指标 | adapter 覆盖 |
| `SB_*` | per-IP limiter 读 `SB_INBOUND_RATE_LIMIT_*` | adapter 读 `SB_MIXED_DISABLE_STOP` 等 | D14 要求 limiter 变量语义保留；实现可共享迁入，不构成 mixed 独立 GAP |
| sniff/route | 旧 Engine/Bridge | canonical router/outbounds + sniff override | adapter 覆盖 |

### 4.4 direct inbound — `ADAPTERS-COVERS`（共享实现）

| 维度 | scaffold/legacy | adapters | 裁决 |
|---|---|---|---|
| 配置 | legacy 要求 host+port，读 UDP flag | adapter 同样要求 host+port，network 未给时默认 TCP+UDP | 语义相同；`adapter/mod.rs:473-492`; `inbound/direct.rs:27-70` |
| 认证 | 两侧均无 | 两侧均无 | 无缺口 |
| TCP | `DirectForward` 固定目标、timeout、conntrack | adapter 直接包装同一 `DirectForward` | 完全共享，`sb-adapters/src/inbound/direct.rs:1-94` |
| UDP | `DirectForward` UDP session | 同一实现 | 完全共享 |
| 错误 | 同一实现错误 | 同一实现错误 | 无差异 |
| metrics | core 发 active/UDP session | wrapper 透传两个统计方法 | 覆盖，`inbound/direct.rs:87-92`; core `direct.rs:517-523` |
| `SB_*` | 无 direct inbound scaffold-only 变量 | 同一实现 | 无差异 |
| sniff/route | 固定目标，不走常规 route | 同一固定目标语义 | 无差异；Go 支持 address-only/port-only override，属 parity 移交，见 §10 |

### 4.5 TUN inbound — `ADAPTERS-COVERS`

| 维度 | scaffold/legacy | adapters | 裁决 |
|---|---|---|---|
| 配置 | legacy 只调用 `TunInboundService::new()`，忽略 `tun_options` | 解析完整 `tun_options`，构造失败显式返回 | adapter 更强，`adapter/mod.rs:462-472`; `builders.rs:2132-2169` |
| 认证 | 两侧均无 | 两侧均无 | 无缺口 |
| TCP | legacy 自持 TUN stack | adapter `TunInbound::try_new` | adapter 是 registry 正常路径；旧路径无额外配置语义 |
| UDP | legacy 有 session map/estimate | adapter 有完整 TUN UDP path | adapter 覆盖；旧 `TunInboundService` 实现归属不在 WP04 |
| 错误 | legacy 默认构造，后置启动失败 | adapter 构造阶段报告 parse/backend 错误并写 startup error | adapter 更严格，非行为回退缺口 |
| metrics | legacy 仅 UDP session estimate 等 core surface | adapter 注入 stats | adapter 覆盖当前产品入口 |
| `SB_*` | 未发现 TUN constructor 专属旧变量 | adapter 配置面为 IR | 无 scaffold-only 项 |
| sniff/route | legacy 未注入 router/outbound manager | adapter 注入 router/outbounds/sniff | adapter 明显覆盖 |

### 4.6 redirect inbound — `ADAPTERS-COVERS`

| 维度 | legacy sentinel | adapters | 裁决 |
|---|---|---|---|
| 配置 | 不读取协议配置，直接 unsupported | Linux registry builder | 无 scaffold 实现；adapter-only |
| 认证 | 两侧均无 | 两侧均无 | 无缺口 |
| TCP | 无实现 | Linux REDIRECT 实现 | adapter-only |
| UDP | legacy 无 | 以 adapter 当前能力为准 | 无 scaffold 语义可丢失 |
| 错误 | 固定 unsupported 文案 | 构造/平台错误 | WP06 删除 sentinel |
| metrics | 无协议数据面 | adapter 数据面指标 | 无 scaffold 差异 |
| `SB_*` | 无 | 现存变量归 WP11 | 无 scaffold-only 项 |
| sniff/route | 无 | registry context | adapter-only，`adapter/mod.rs:493-502`; `builders.rs:371-375` |

### 4.7 tproxy inbound — `ADAPTERS-COVERS`

| 维度 | legacy sentinel | adapters | 裁决 |
|---|---|---|---|
| 配置 | 不读取协议配置，直接 unsupported | Linux registry builder | 无 scaffold 实现；adapter-only |
| 认证 | 两侧均无 | 两侧均无 | 无缺口 |
| TCP | 无实现 | Linux IP_TRANSPARENT 实现 | adapter-only |
| UDP | legacy 无 | 以 adapter 当前能力为准 | 无 scaffold 语义可丢失 |
| 错误 | 固定 unsupported 文案 | 构造/平台错误 | WP06 删除 sentinel |
| metrics | 无协议数据面 | adapter 数据面指标 | 无 scaffold 差异 |
| `SB_*` | 无 | 现存变量归 WP11 | 无 scaffold-only 项 |
| sniff/route | 无 | registry context | adapter-only，`adapter/mod.rs:503-512`; `builders.rs:371-375` |

## 5. Outbound 八维矩阵

### 5.1 SOCKS outbound — `ADAPTERS-COVERS` (`de25101d`)

| 维度 | scaffold/legacy | adapters | 裁决/施工锚点 |
|---|---|---|---|
| 配置 | `crates/sb-core/src/outbound/socks_upstream.rs:8-24` 仅 server/port/user/pass；legacy constructor `crates/sb-core/src/adapter/mod.rs:570-574` 已 unsupported | builder 映射 endpoint、credentials、TLS，固定 30s timeout | adapter TCP 配置覆盖，`crates/sb-adapters/src/register/builders.rs:549-599` |
| 认证 | SOCKS5 username/password | SOCKS5 username/password；另有 socks4 registry alias | adapter 覆盖；Go SOCKS4/4a/5 细节属 parity 检查 |
| TCP | minimal CONNECT，无 retry/bind/routing options | timeout、resolve mode/TLS、canonical error | adapter 更强，`crates/sb-core/src/outbound/socks_upstream.rs:26-170` ↔ `crates/sb-adapters/src/outbound/socks5.rs:355-407` |
| UDP | minimal connector明确 unsupported；core 另有 `socks5_udp`/`udp_socks5` helper | `socks` feature闭包启用 `socks-udp`；adapter owner复用 canonical `Socks5Connector::listen_packet` 并保持 control lifetime | 产品可达性已闭；isolated feature、app gui_runtime product E2E、adapter proxy E2E 均通过；commit `de25101d` |
| 错误 | `io::Error` 字符串 | `CoreError` 分类 + timeout/context | adapter 覆盖 TCP；WP05 锁 UDP error mapping |
| metrics | core helper发 upstream assoc/packet/byte/error/map metrics | adapter owner保留同名 metrics 与 observation metadata；兼容 SOCKS inbound metrics另见 §4.1 | 已覆盖；wire-size metric/return semantics保持；commit `de25101d` |
| `SB_*` | core UDP helper读取 legacy proxy/receive/observation变量 | adapter config owner承接全部 WP05 白名单变量；默认值、clamp、地址优先级不变 | D14 已执行；commit `de25101d` |
| sniff/route | upstream helper无 sniff；由 caller 选路 | canonical Session + registry | TCP/UDP 均覆盖；跨层 scaffold 引用为 0 |

### 5.2 HTTP outbound — `ADAPTERS-COVERS`

| 维度 | scaffold/legacy | adapters | 裁决 |
|---|---|---|---|
| 配置 | minimal server/port/user/pass；legacy constructor unsupported | endpoint、credentials、TLS、resolve mode、timeout | adapter 覆盖，`http_upstream.rs:1-115`; `outbound/http.rs:300-365` |
| 认证 | 单组 Basic | 单组 Basic | 等价 |
| TCP | HTTP/1.0/1.1 CONNECT 200 | CONNECT、TLS、local/remote resolve、timeout | adapter 更强，`outbound/http.rs:367-430` |
| UDP | 两侧均不支持 | 两侧均不支持 | 无缺口 |
| 错误 | 非 200 为 `io::Error` | canonical adapter/CoreError + metrics | adapter 覆盖 |
| metrics | minimal connector无独立活调用方 | adapter dial metrics | adapter 覆盖 |
| `SB_*` | 无 HTTP outbound scaffold-only 变量 | 无对应差异 | 无缺口 |
| sniff/route | caller 决定目标 | canonical Session/registry | adapter 覆盖；Go `path`/custom headers 两侧 Rust 都缺，见 §10 |

### 5.3 direct outbound — `ADAPTERS-COVERS`

| 维度 | core fallback | adapters | 裁决 |
|---|---|---|---|
| 配置 | 使用 Session timeout；不消费 IR dialer options | builder 当前明确忽略 bind/routing/TFO/multipath options | 相对 fallback 已覆盖；Go DialerOptions 差距属 parity 移交，`builders.rs:2284-2311` |
| 认证 | 两侧均无 | 两侧均无 | 无缺口 |
| TCP | 单次 `TcpStream::connect` + Session timeout | Happy Eyeballs、逐地址 timeout | adapter 更强，core `canonical_bridge.rs:16-81`; adapter `direct.rs:14-97` |
| UDP | 委托 core `DirectConnector` | adapter 自有 PacketConn、idle/explicit deadline、close enforcement | adapter 覆盖，`outbound/direct.rs:99-300` |
| 错误 | 映射 refused/reset/unreachable/timeout | canonical `CoreError` | adapter 覆盖 |
| metrics | 无独立 fallback metrics | 由 canonical wrapper/调用面承担 | 无 scaffold-only 指标 |
| `SB_*` | 无 direct fallback 专属变量 | 无对应差异 | 无缺口 |
| sniff/route | Session 目标直拨 | Session 目标直拨 | 等价；D11 要求 adapters 为唯一正典 |

### 5.4 block outbound — `ADAPTERS-COVERS`

| 维度 | core fallback | adapters | 裁决 |
|---|---|---|---|
| 配置 | 只保留 tag | 只保留 tag | 等价 |
| 认证 | 两侧均无 | 两侧均无 | 无缺口 |
| TCP | policy error | policy error | 等价 |
| UDP | policy error | policy error | 等价 |
| 错误 | `blocked by outbound policy` | `blocked by configured block outbound` | 同一 `CoreError::policy` 类；文案非稳定契约，无 GAP |
| metrics | 无独立协议指标 | 无独立协议指标 | 等价 |
| `SB_*` | 无 | 无 | 等价 |
| sniff/route | 终止路径 | 终止路径 | 等价；D11 改 registry 唯一正典，`canonical_bridge.rs:83-119`; `adapters/outbound/block.rs:1-63` |

### 5.5 selector outbound — `ADAPTERS-COVERS`（共享 core）

| 维度 | core/group | adapters | 裁决 |
|---|---|---|---|
| 配置 | `SelectorGroup::new_manual` | shim 解析 members/default 后直接构造同一 group | 完全共享，`adapters/outbound/selector.rs:1-42` |
| 认证 | 两侧均无 | 两侧均无 | 无缺口 |
| TCP | 同一成员选择与 dial | 同一实现 | 等价 |
| UDP | 同一 UDP-capable member 选择 | 同一实现 | 等价，`selector_group.rs:632-644` |
| 错误 | 无成员/成员失败 canonical error | 同一实现 | 等价 |
| metrics | active connection、select score | 同一实现 | 等价，`selector_group.rs:566-626` |
| `SB_*` | 无 adapter/scaffold 差异 | 同一实现 | 无缺口 |
| sniff/route | 依赖 bridge member registry | shim 用 registry context 解析成员 | 覆盖；真正实现迁移/去重归 WP12 |

### 5.6 urltest outbound — `ADAPTERS-COVERS`（共享 core）

| 维度 | core/group | adapters | 裁决 |
|---|---|---|---|
| 配置 | `UrlTestOptions`：URL、interval、timeout、tolerance、cache/history | shim 映射同一字段并构造同一 group | 完全共享，`adapters/outbound/urltest.rs:1-56` |
| 认证 | 两侧均无 | 两侧均无 | 无缺口 |
| TCP | 同一健康检查/选择 | 同一实现 | 等价 |
| UDP | 同一 UDP-capable member 选择 | 同一实现 | 等价 |
| 错误 | 同一 health/permanent failure 语义 | 同一实现 | 等价 |
| metrics | 同一 RTT/active/select metrics | 同一实现 | 等价 |
| `SB_*` | 无 adapter/scaffold 差异 | 同一实现 | 无缺口 |
| sniff/route | bridge 解析成员 | registry context 解析成员 | 覆盖；Go idle timeout/interrupt/defaults 差距属 parity 移交 |

## 6. Registry-only 协议八维确认

这些协议没有可运行 scaffold 实现。逐维写明“无 scaffold”，防止 WP06 把 sentinel
误当协议实现。

### 6.1 DNS（inbound/outbound）— `ADAPTERS-COVERS`

| 维度 | scaffold | adapters/结论 |
|---|---|---|
| 配置 | 无 scaffold 实现 | registry builder 读取 DNS IR |
| 认证 | 无 scaffold 实现 | 以 adapter DNS 配置为准 |
| TCP | 无 scaffold 实现 | adapter-only |
| UDP | 无 scaffold 实现 | adapter-only |
| 错误 | legacy 仅 generic unsupported | adapter 构造/运行错误；删 sentinel 不丢协议语义 |
| metrics | 无 scaffold 数据面 | adapter-only |
| `SB_*` | 无 scaffold 专属语义 | 现存变量归 WP11 |
| sniff/route | 无 scaffold | registry context；注册点 `builders.rs:268,377-380` |

### 6.2 SSH（inbound/outbound）— `ADAPTERS-COVERS`

| 维度 | scaffold | adapters/结论 |
|---|---|---|
| 配置 | 无 scaffold 实现 | registry builder/adapter-only |
| 认证 | 无 scaffold 实现 | adapter SSH 认证 |
| TCP | 无 scaffold 实现 | adapter-only |
| UDP | 无 scaffold 实现 | 以 adapter 声明为准；无旧语义可丢 |
| 错误 | legacy outbound 仅 unsupported | adapter 构造/协议错误 |
| metrics | 无 scaffold 数据面 | adapter active/session surface |
| `SB_*` | 无 scaffold 专属语义 | 现存变量归 WP11 |
| sniff/route | 无 scaffold | registry context；注册点 `builders.rs:292,382-385` |

### 6.3 Shadowsocks（及其余 wildcard 类型）— `ADAPTERS-COVERS`

| 维度 | scaffold | adapters/结论 |
|---|---|---|
| 配置 | `outbound/ss/` 仅孤立 `hkdf.rs` 原语，不是协议实现 | registry/adapter 实现 |
| 认证 | 无 scaffold 协议实现 | adapter method/password/users |
| TCP | 无 scaffold 协议实现 | adapter-only |
| UDP | 无 scaffold 协议实现 | adapter-only |
| 错误 | legacy generic unsupported | adapter canonical error |
| metrics | 无 scaffold 数据面 | adapter-only |
| `SB_*` | 无 scaffold 协议专属行为 | 现存变量归 WP11 |
| sniff/route | 无 scaffold | registry context；其余 wildcard 同理，WP07 非本包协议仍按原计划处理 |

## 7. D9 / D10 / D14 裁决表

| 旧能力/遗留物 | Go 1.13.13 | repo 消费/约束 | 裁决 |
|---|---|---|---|
| SOCKS/mixed per-IP rate limiter；`SB_INBOUND_RATE_LIMIT_PER_IP/WINDOW_SEC/QPS` | 未找到同等协议能力 | D14 明确 MIG-03 不废弃任何 `SB_*` | `de25101d` 已迁移/共享；WP11 上收解析；WP06 不得静默删除 |
| `SB_SOCKS_UDP_UP_RECV_TASK/CH` background receive tuning | 未找到同等开关 | D14 保留全部变量语义；原 core helper读取 | `de25101d` 已迁入 adapter UDP owner并锁 construction-time freeze |
| `SB_UDP_PROXY_MODE/ADDR`、`SB_UDP_SOCKS5_ADDR` | Go 无同等 env 控制 | `app/src/env_dump.rs:32-42`、tests/examples/scenario scripts 消费 | `de25101d` 已迁入 adapters，地址优先级与默认行为不变 |
| `inbound_socks_udp_associate_total`/`packets_total`、`inbound_active_connections` | Rust metrics surface | catalog/脚本消费 packet/active：`docs/METRICS_CATALOG.md:64-76`、`scripts/dev/socks_ping.sh:22` | `de25101d` 已补发兼容指标；未更新的 assoc-estimate gauge未伪装为有效统计 |
| `ADAPTER_FORCE` | 不适用 | 无运行时读取，只有注释/脚本/测试 | DROP stale control；WP06 删除并改测试/脚本命名 |
| `socks_upstream.rs` / `http_upstream.rs` | adapters 已覆盖 | 已编译但 repo 无构造方 | DROP；测试保留但改为明确锁 adapter registry |
| orphan `outbound/socks5.rs` / `http_proxy.rs` | adapters 已覆盖 | 未在 `outbound/mod.rs` 声明，零调用 | DROP |
| `OutboundImpl::Socks5/HttpProxy` + inline dial helpers | adapters 已覆盖 | 主/legacy bridge只写 `OutboundImpl::Connector`；Socks5/HttpProxy variant构造方仅测试 | DROP/收敛到 Connector；WP06 先改 tests/API type matching |
| core `http.rs` / `http_connect.rs` / `mixed.rs` | adapters 主路径已覆盖或更强 | legacy constructor 已不构造；repo 无生产构造方 | DROP after test disposition；`http.rs` 的 limiter 变量仍由 Trojan/SS 等真实 adapter 消费，不废弃变量 |
| direct/block core fallback | adapters 正典 | 主 bridge、switchboard、manager/app helper仍有 core ownership | D11：WP06 全部改 registry；非测试调用不得残留 |

## 8. 交叉依赖清单

| 依赖 | 当前证据 | 删除前解法 | owner |
|---|---|---|---|
| adapter SOCKS UDP 依赖 core `UdpUpstreamMap` | 已解除；adapter owner `inbound/socks/upstream.rs` | `de25101d` 完成；exact scaffold-reference scan 为 0 | CLOSED WP05 |
| adapter SOCKS UDP 依赖 core `UpSocksSession` | 已解除；adapter owner `outbound/socks5_udp.rs` | `de25101d` 完成；复用 canonical `PacketConn`，保留 wire-size/观测/错误语义 | CLOSED WP05 |
| enhanced UDP 依赖 core `udp_socks5` | 已解除；`udp_enhanced.rs` 使用 adapter `Socks5Connector` | `de25101d` 完成 | CLOSED WP05 |
| core `UdpUpstreamMap` 反向依赖 `UpSocksSession` | adapter 活路径不再经过该 core pair | adapter owner已闭；orphan core scaffold实体留 WP06 删除 | CLOSED WP05 / WP06 delete |
| `udp_proxy_glue`/`udp_balancer` 依赖 `udp_socks5` | SOCKS transport测试已迁；core direct balancer测试仍保留 | adapter活路径已闭；orphan glue/scaffold清理归 WP06，通用 group/balancer owner归 WP12 | CLOSED WP05 / WP06 / WP12 |
| selector/urltest shim 依赖 core group | `sb-adapters/src/outbound/selector.rs:5`; `urltest.rs:6-7` | WP06 保留共享实现；WP12 再迁/合并，禁止 WP05 顺手拆 | WP12 |
| 主 bridge direct/block fallback | `adapter/bridge.rs:605-615` | registry hard requirement；构造失败显式报错 | WP06 |
| switchboard direct/block ownership | `runtime/switchboard.rs:176-193` | 通过 registry/context 取得正典 adapter | WP06 |
| app group direct fallback | `app/src/outbound_groups.rs:145-149` | 消费 registry direct | WP06 |
| manager 多处 `DirectConnector::new` | `crates/sb-core/src/outbound/manager.rs:369+` | 区分测试 fixture 与生产 fallback；生产全部改 registry | WP06 |
| core `OutboundRegistryHandle` 内建 direct/SOCKS/HTTP dial | `crates/sb-core/src/outbound/mod.rs:295-423,842-930` | 主路径已用 `OutboundImpl::Connector`；删除 legacy variants/helpers，保留 canonical registry handle | WP06 |

## 9. 测试资产处置

| 测试/脚本 | 当前真实覆盖 | 处置 |
|---|---|---|
| `crates/sb-core/tests/socks5_udp_upstream.rs` | 原 core `UpSocksSession` 解析 | 已迁为 `sb-adapters/tests/socks5_udp_upstream.rs`，并增加真实 session/wire-size 回环；`de25101d` |
| `crates/sb-core/tests/udp_socks5_e2e.rs` | 原 core SOCKS5 UDP relay | 已并入 adapter canonical PacketConn/session E2E并删除 core 测试；`de25101d` |
| `crates/sb-core/tests/udp_proxy_glue_e2e.rs` | 原 core proxy glue | 已改写为 adapter router→legacy env→proxy roundtrip并删除 core 测试；`de25101d` |
| `crates/sb-core/tests/udp_balancer.rs` | direct/proxy helper策略 | SOCKS transport部分已迁出；仅保留 direct generic test，owner仍归 WP12；`de25101d` |
| `crates/sb-adapters/tests/socks_udp*` | adapter UDP 数据面 | scaffold 引用为 0；canonical PacketConn、proxy roundtrip与兼容 metrics均为 active test；`de25101d` |
| `app/tests/socks_udp_direct_e2e.rs` | 原 ignored core direct path | 已改为 active `gui_runtime` product-profile canonical SOCKS UDP roundtrip；`de25101d` |
| `app/tests/adapter_bridge_scaffold.rs` | 实际调用 `build_bridge` registry；`ADAPTER_FORCE` 无效 | WP06 改名 `adapter_bridge_registry.rs`，锁“未注册 kind 硬失败、无 fallback” |
| `app/tests/upstream_socks_http.rs` | 实际走 adapter registry | 保留；修正文案/测试名，锁 TCP registry 路径 |
| `app/tests/upstream_auth.rs` | 实际走 adapter registry credentials | 保留；修正文案，锁 adapter auth 映射 |
| selector/urltest tests | 共享 core group + registry shim | 保留到 WP12，不在 WP05 搬 |
| `scripts/ci/tasks/adapter-bridge.sh` | 依赖无效 `ADAPTER_FORCE`，结果不能证明双轨 | WP06 删除双模式假验收或改为 registry/缺失-builder hard-error 验收 |

## 10. parity 发现移交（不计 MIG-03 GAP）

| 协议 | Go 证据 | Rust 现状 | 移交 |
|---|---|---|---|
| direct inbound | Go 支持 address-only、port-only、host+port override：`go_fork_source/sing-box-1.13.13/protocol/direct/inbound.go:44-58,91-128` | core 与 adapter 都要求 host+port | 后续 parity 包 |
| SOCKS inbound | Go options 支持 users：`go_fork_source/sing-box-1.13.13/option/simple.go:8-12` | adapter 协议层支持 users，但 registry builder 固定 `users: None`；scaffold 同为 no-auth | 后续 parity 包；不计 WP05 scaffold GAP |
| SOCKS outbound | Go 支持 SOCKS4/4a/5、UDP、UoT：`protocol/socks/outbound.go:38-117`; options `option/simple.go:22-29` | Rust adapter主要 SOCKS5；UDP feature存在，UoT不完整 | 后续 parity 包；WP05 只恢复当前 Rust 产品语义 |
| HTTP outbound | Go 支持 `path`、custom `headers`：`option/simple.go:32-40` | 两套 Rust 都无 | 后续 parity 包 |
| direct outbound | Go 使用完整 `DialerOptions`/network behavior | adapter builder 明确忽略 bind/routing/TFO/multipath | 后续 parity 包 |
| selector/urltest | Go 有 idle timeout、existing-connection interrupt、默认 interval/idle 约束：`protocol/group/selector.go:43-58,139`; `urltest.go:49-61,211-224,429` | Rust共享 group未完全覆盖 | WP12/后续 parity 包 |
| redirect/tproxy feature closure | 非语义对照项 | Linux registry/builders 只 gate `router`，模块声明另 gate `redirect`/`tproxy`：`builders.rs:371-375,3536-3575`; `inbound/mod.rs:43-47` | WP13 feature matrix；不影响“无 scaffold 实现”裁决 |

## 11. WP05 验收记录 / WP06 唯一施工单

WP05 两组 GAP 已由 `de25101d` 关闭：

1. [x] SOCKS/mixed adapter 承接当前 Rust-only per-IP limiter 语义；变量默认值不变。
2. [x] SOCKS inbound 实现 active TCP 统计，并补发兼容 UDP associate/packet 与 active
   metrics；未复制旧恒零 `udp_sessions_estimate`。
3. [x] `UdpUpstreamMap`、`UpSocksSession` 与 active proxy transport 迁入 adapter owner；
   sb-adapters 对 `udp_upstream_map`/`socks5_udp`/`udp_socks5`/`udp_proxy_glue` scaffold
   符号引用为 0。
4. [x] 产品 adapter feature profile具备 SOCKS UDP；TCP/UDP/error/metrics 均有 active
   test锚点。
5. [x] D14 `SB_*` 语义、默认值、clamp、地址优先级与 timeout alias保留；解析上收仍留
   WP11。
6. [x] selector/urltest shared core group、WP12 balancer/group owner与 parity 发现项未改。

WP06，待 WP05 全绿后：

1. 删除主 bridge direct/block fallback，registry 缺失必须硬失败。
2. 删除/改写 `Bridge::new_from_config` legacy protocol construction 与 switchboard 501 双轨。
3. 按 D11 清理生产路径 core direct/block ownership。
4. 删除 orphan/minimal scaffold modules、`scaffold` feature 强制依赖、无效
   `ADAPTER_FORCE` 控制与陈旧脚本/测试命名。
5. 测试先迁后删；不得用 Rust-only unit tests宣称 dual-kernel parity。

上述施工均属于已规划 WP05/WP06。本 WP04 未扩大范围，也未执行后续包代码改动。

## 12. 可复现证据命令

```bash
rg -n "get_inbound|get_outbound|core_fallback_outbound|OutboundType::" \
  crates/sb-core/src/adapter/bridge.rs crates/sb-core/src/adapter/mod.rs \
  crates/sb-core/src/runtime/switchboard.rs

rg -n "register_inbound|register_outbound|users: None" \
  crates/sb-adapters/src/register/builders.rs

rg -n "sb_core::(net::udp_upstream_map|outbound::socks5_udp|outbound::udp_socks5|outbound::udp_proxy_glue)" \
  crates/sb-adapters -g '*.rs' # 目标：0

rg -n "ADAPTER_FORCE|SB_SOCKS_UDP_UP_RECV|SB_UDP_PROXY_(MODE|ADDR)|SB_UDP_SOCKS5_ADDR" \
  crates app docs scripts labs

rg -n "socks_upstream::|SocksUp::|http_upstream::|HttpUp::" crates app

rg -n "OutboundImpl::(Direct|Block|Socks5|HttpProxy)|socks5_connect|http_connect" crates app

rg -n "rate.?limit|RateLimit" \
  go_fork_source/sing-box-1.13.13/protocol/socks \
  go_fork_source/sing-box-1.13.13/protocol/mixed \
  go_fork_source/sing-box-1.13.13/option/simple.go

rg -n "OverrideAddress|OverridePort|UDPOverTCP|Path|Headers|IdleTimeout|InterruptExistConnections" \
  go_fork_source/sing-box-1.13.13/protocol go_fork_source/sing-box-1.13.13/option
```
