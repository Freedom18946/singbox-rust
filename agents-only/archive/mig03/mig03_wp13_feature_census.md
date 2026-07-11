<!-- tier: B -->
# MIG-03 WP13 feature census

Status: DONE（2026-07-11）

## 口径校正

规划文本把 sb-core 基线记为 103。按 `[features]` 段实际 Cargo 声明重放：MIG-03
立项提交 `54267796` 为 88，WP06/WP12 已先退役 `scaffold`、`selector_p3`，WP13
开工提交 `1f605e03` 为 86。本包继续使用原验收上限（feature ≤72、source cfg ≤807），
不借口径校正放宽门禁。最终为 65 feature、787 个 source `cfg(feature)`。

下游引用普查覆盖 app、workspace crates、Makefile、scripts、xtask/xtests、examples、
benches、fuzz、interop lab。判定无 TBD。

## 保留：65

| 分类 | feature（逐项） | 门控内容/依赖 | 下游结论 | 判定 |
|---|---|---|---|---|
| 默认聚合 | `default` | DNS transports、rustls、canonical inbound profile | sb-core 默认产品闭包 | 保留 |
| DNS | `dns_cache`, `dns_udp`, `dns_tailscale` | 纯能力门；无 optional dependency | app/profile 与 DNS tests 有效消费 | 保留 |
| DNS dependency | `dns_doh`, `dns_doh3`, `dns_dot`, `dns_doq`, `dns_dhcp`, `dns_resolved` | 分别门控 reqwest；h3/h3-quinn/quinn；rustls；quinn；notify；notify | app DNS profile/transport 有效消费 | 保留 |
| TLS | `tls_rustls`, `tls` | rustls/x509 optional dependency；legacy TLS compatibility branch | app/adapters/API 有效消费 | 保留 |
| inbound | `in_tun`, `in_socks`, `in_http`, `in_mixed`, `in_direct` | platform TUN 或 core inbound type registration；mixed 聚合 socks+http | app profiles 有效消费 | 保留 |
| router analysis | `analyze_json`, `dsl_analyze`, `dsl_derive`, `dsl_plus`, `explain`, `preview_route`, `rules_capture` | 分析、DSL、explain/preview/capture 代码面 | xtask/tests/app debug 有效消费 | 保留 |
| router compatibility | `sbcore_analyze_json`, `sbcore_rules_tool`, `schema-v2`, `json`, `rules_tool`, `socks`, `v2ray_transport` | 外部工具/schema/transport 兼容面 | 下游兼容名仍有消费或明确 API 责任 | 保留 |
| router cache/index | `cache_stats`, `cache_stats_hot`, `cache_stats_wire`, `router_cache_explain`, `router_cache_lru_demo`, `router_cache_wire`, `router_json`, `router_keyword_ac` | cache 观测/wire、JSON bridge、Aho-Corasick 加速 | tests/benches/tooling 有效消费；基础 router/suffix/keyword 已常驻 | 保留 |
| router data | `geoip_hot`, `geoip_mmdb`, `idna`, `platform`, `rand`, `rule_coverage` | hot reload、MMDB、IDNA dependency、平台输入、随机选择、coverage | app/tests/bench 有效消费 | 保留 |
| observability | `metrics`, `http_exporter` | metrics instrumentation；exporter 聚合 metrics | app/metrics 有效消费 | 保留 |
| test/dev | `bench`, `chaos`, `fuzzing`, `handshake_alpha`, `loom`, `failpoints` | benchmark、chaos/fuzz/handshake hooks、loom/fail optional deps | tests/benches/fuzz 有效消费；非产品默认 | 保留 |
| subscription | `subs_clash`, `subs_http`, `subs_singbox` | subscription compatibility helpers | app/sb-subscribe 有效消费 | 保留 |
| service | `service_ntp`, `service_ssmapi`, `service_clash_api`, `service_v2ray_api`, `service_derp`, `service_resolved`, `network_monitor` | core runtime hook/外部服务兼容 marker/resolved DNS/network monitor | app/sb-api/sb-service-derp 有效消费；不代表协议实现回流 core | 保留 |
| misc compatibility | `error-v2` | structured v2 error compatibility | schema/API compatibility | 保留 |

Cargo.toml 中以上每个声明均附同行 purpose comment；`default` 前置注释说明聚合目的。

## WP13 退役或常驻化：21

| feature | 原内容/依赖 | 下游处理 | 判定 |
|---|---|---|---|
| `router`, `routing` | 事实必选 router 栈/兼容聚合，制造双分支 | 删除 sb-core 转发；app `router` 仅保留外部 profile 名 | 按 D16 常驻化 |
| `router_keyword`, `suffix_trie` | 无真实 optional dependency 的 router 实现门 | keyword linear index 与 suffix trie 常驻；清理 tests/benches cfg | 常驻化 |
| `out_socks`, `out_http`, `out_shadowtls`, `out_ssh`, `out_ss`, `out_trojan`, `out_tuic`, `out_vless`, `out_vmess`, `out_wireguard` | 空 legacy marker，但仍激活 core 支撑 cfg | 删除 core marker/cfg/转发；协议 feature 归 sb-adapters/app | 退役 |
| `out_hysteria`, `out_hysteria2`, `out_naive`, `out_quic` | WP07 后遗留聚合及 hyper/quinn 边 | 删除 core marker；QUIC family 继续由 sb-adapters 所有 | 退役 |
| `out_tailscale` | legacy snow/协议边 | 删除 core marker；endpoint/adapter canonical 路径不变 | 退役 |
| `legacy_protocols` | 上述 legacy out 聚合 | 删除所有下游转发 | 退役 |
| `dev-cli` | CLI-only marker | xtask/工具改用实际能力 feature | 退役 |

## 立项后、WP13 前已退役：2

| feature | owner workpackage | 判定 |
|---|---|---|
| `scaffold` | WP06 | fallback/scaffold 删除 |
| `selector_p3` | WP12 | selector 影子实现删除/归位 |

## 依赖与边界结论

- sb-core production dependency `hyper` 已删除；DoH test mock 改为 raw Tokio HTTP server。
- sb-core 不再声明或消费 `out_*`、`router`、`routing`、`legacy_protocols`。
- app 外部兼容 profile 名可保留，但不得再转发已退役 sb-core feature。
- boundary V3 直接禁止协议实现进入 sb-core，不再依赖已失真的 legacy feature 名判断。
- 本包仅收敛结构与 feature 语义；不声明 parity/BHV/REALITY 分母变化。
