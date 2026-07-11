<!-- tier: B -->
# MIG-03 WP12 去重 census

日期：2026-07-11  
范围：WireGuard、Tailscale、selector 家族、sb-core 同名影子模块、direct/block 残留。  
裁决依据：`mig03_01_decisions.md` D15；未出现 D18 项。

## 1. WireGuard

| 层 | 消费证据 | 判定 |
|---|---|---|
| `sb-transport/src/wireguard/` | core endpoint 与 adapter outbound 均直接构造 `WireGuardTransport` | 唯一设备/netstack/Noise owner；`Tunn`、`decode_key32`、`WireGuardTransport` 定义各一处 |
| `sb-core/src/endpoint/wireguard.rs` | endpoint registry 在 `out_wireguard` 下注册；实现 Endpoint 生命周期、多 peer、入站 TCP/UDP | 保留 endpoint 壳；只消费 transport，不持有 boringtun 密钥握手实现 |
| `sb-adapters/src/outbound/wireguard.rs` | registry outbound builder 构造；实现 Outbound/PacketConn 与 IR→transport 映射 | 保留 legacy outbound 壳；只消费同一 transport |
| `sb-adapters/src/endpoint/wireguard.rs` | endpoint registry adapter builder | 仅 thin builder，转交 core endpoint；非隧道重复 |

结论：三处不是三份隧道实现，而是 endpoint/outbound 两个产品壳 + 一个共享设备层；
底层已满足 D15，无协议行为改动。

## 2. Tailscale

| 层 | 消费证据 | 判定 |
|---|---|---|
| `sb-core/src/endpoint/tailscale.rs` | endpoint registry 在 `out_tailscale` 下注册；daemon LocalAPI 与 Endpoint 生命周期 | 保留 endpoint 壳 |
| `sb-adapters/src/outbound/tailscale.rs` | legacy Tailscale outbound builder；direct/SOCKS/WireGuard/managed 四模式 | 保留 outbound 壳 |
| `sb-adapters/src/tailscale_control/` | 仅 managed outbound 使用 Coordinator/Noise | 从 core `services/tailscale` 迁入唯一消费 crate；core service 影子删除 |
| `sb-transport/src/tailscale_dns.rs` | MagicDNS socket transport，供 outbound/DNS 路径消费 | 保留 transport；职责与 endpoint/control plane 不重叠 |
| `sb-adapters/src/endpoint/tailscale.rs` | thin endpoint builder | 保留；转交 core endpoint |

结论：endpoint、legacy outbound、MagicDNS 是不同产品面；唯一误放的 managed control
plane 已迁到 adapters。`snow` 依赖随 owner 迁移，core 不再因 Tailscale control plane
携带 Noise 实现。

## 3. Selector 家族

| 原对象 | 活跃消费方 | 处置 |
|---|---|---|
| `selector_group.rs` | adapter selector/urltest builders、app bootstrap、GUI group trait | 迁入 `sb-adapters/outbound/selector_group.rs`，成为唯一 Group/SelectorControl/UDP owner；测试随迁 |
| `selector.rs::Selector` | 仅 core bridge 的 unused import 与本文件自测 | 删除；功能与 canonical group 重复，且 `listen_packet` 含双重 `get(index)` 死路径 |
| `selector.rs::PoolSelector` | HTTP/SOCKS/Trojan/VLESS/VMess/SS/redirect/tproxy inbound pool | 迁入 `sb-adapters/outbound/pool_selector.rs`；它是 inbound endpoint-pool policy，不是 outbound Group |
| `selector_p3.rs` | 无生产构造方 | 删除 |
| `p3_selector.rs` | 仅 app 测试、bench、临时 CI task | 删除及连带 test/bench/task/feature |
| `feedback.rs` | 仅 `selector_p3` | 删除 |
| `observe.rs` | `with_observation` 仅死 Selector；pool helper 被 SOCKS UDP 使用 | 死 helper 删除；pool helper 迁 adapters |
| `health.rs` | HTTP/SOCKS fallback、runtime health task、smoke tests | 保留 core runtime health；删除无效 `MultiHealthView` marker/commented impl |
| `udp_balancer.rs` | 仅 core example/test；无生产构造 | 删除 example/test/module；真实 SOCKS UDP balancer 已在 adapters E2E 覆盖 |

终态：sb-core outbound 下 selector/p3/udp_balancer 实现文件为 0；canonical outbound
group 实现为 1。Clash API 继续只经 `sb_types::OutboundGroup` / `SelectorControl` 操作
`now/all/select`，无 concrete-type 依赖。

## 4. sb-core 影子模块

| 影子 | 消费审计 | 终态 |
|---|---|---|
| `core/transport/` | 无仓内消费；runtime transport 是独立模块 | 删除；协议传输继续用 sb-transport |
| `core/tls/` | danger/global 已是 sb-tls re-export；trust API 无消费；两处 core glue | 删除；所有 TLS 调用直指 sb-tls；CertificateStore marker 归 context，CertificateIR glue 归 supervisor |
| `core/subscribe/` | 仅 app `subs` CLI | 迁 `sb-subscribe::config_merge`，测试保留 |
| `core/config/` | 未从 lib 导出、无消费 | 删除；schema/config owner 仅 sb-config |
| `core/socks5/` | core examples/tests；生产 SOCKS5 已在 adapters | codec 迁 `sb-adapters::socks5_codec`，examples/tests/scripts 路径随迁 |
| `core/metrics/` | core registry/labels/metric definitions被 core 与 adapters 广泛消费；sb-metrics 提供 recorder/exporter façade | 按 D15 保留；契约清晰：core 负责领域指标定义，sb-metrics 负责全局 recorder/export helper |

TLS import 复核：core shadow path 为 0；Hysteria2/Trojan 等协议不再可能通过
`sb_core::tls` 访问 TLS。

## 5. Direct / Block

- outbound direct/block 唯一 concrete owner 是 sb-adapters registry；core 无 direct/block
  outbound fallback。
- core `inbound/direct.rs` 是 active forwarding engine；adapter `inbound/direct.rs` 是其
  lifecycle/registry wrapper，且 app legacy starter/专项 UDP 测试仍直接消费 core engine。
  D15 未授权删除该 active engine，本包保留并登记为分层，不认定为重复。
- 未发现 `direct_simple`、`block_simple` 或其它 orphan concrete variant。

## 6. 删除/迁移与行为边界

- 删除仅覆盖 D15 清单内、无生产构造方的实验 selector/影子模块/孤儿 helper。
- WireGuard/Tailscale 网络行为、配置字段、metrics 名称不变。
- selector manual/urltest/fallback/UDP 仍由原实现提供，只改变 owner crate 与 import。
- SOCKS5 probe 命令参数与输出不变；脚本只改 manifest 路径。
- 无 D18 冲突；无 parity/BHV、REALITY、packaging 数字移动。

## 7. 发现移交

- core active direct inbound engine 与 adapter wrapper 的进一步归位不在 D15 精确删除
  清单，留给后续独立迁移；本包不越权改变其 app legacy bootstrap 行为。
- feature 别名/legacy `out_*` 的剩余清理归 WP13。
