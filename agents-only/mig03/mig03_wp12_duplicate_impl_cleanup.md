<!-- tier: B -->
# MIG-03 WP12 — 重复实现与影子模块清理（WireGuard/tailscale/selector/影子模块）

Status: PLANNED
Priority: P2
Depends on: WP03（trait 已收敛）、WP06（scaffold 已删，direct/block 已归位）
Blocks: WP13

Primary evidence:

- **WireGuard 三处**：`sb-core/src/endpoint/wireguard.rs`(1,382)、
  `sb-adapters/src/outbound/wireguard.rs`(456)、
  `sb-transport/src/wireguard/`(mod 271 + netstack.rs 1,532)。
  Go 对照：endpoint/wireguard（endpoint 型）+ legacy outbound wireguard——
  三处 Rust 代码可能分别对应 endpoint / legacy outbound / netstack 设备层，
  **不一定是纯重复**，先审计再动手。
- **Tailscale 多处**：`sb-core/src/endpoint/tailscale.rs`(1,150)、
  `sb-adapters/src/outbound/tailscale.rs`(647)、`sb-core/src/services/tailscale/`、
  `sb-transport/src/tailscale_dns.rs`。
- **selector 家族 5 变体**（sb-core/src/outbound/）：`selector.rs`(475)、
  `selector_group.rs`(891)、`selector_p3.rs`(311)、`p3_selector.rs`(200)、
  `udp_balancer.rs`(238)；adapters 侧 `selector.rs`(46)/`urltest.rs`(60) 仅为 shim。
- **sb-core 影子模块**（与独立 crate 同名重复）：`transport/`(436：dialer/tcp/tls)、
  `tls/`(232：danger/global/trust)、`subscribe/`(144)、`config/`(512：schema_v2 等)、
  `socks5/`(181)、`metrics/`(2,292，与 sb-metrics crate 分工不明)。
- **direct/block 冗余变体**：WP06 已归位者除外的残留。

## Goal

每组重复实现收敛到唯一正典位置；影子模块逐个判定（合并入独立 crate / 删除 /
保留并登记理由）。删除与归并按 D15 预授权凭 census 证据直接执行，
超出 D15 清单的删除按 D18 升级。

## Current Gap

这些重复是历史并行开发与实验残留（p3 系列、direct_simple 等），trait 收敛
（WP03）后它们的合并才有安全前提。影子模块使"该 import 哪个"持续制造混乱
（如 hysteria2 用 core/tls 而非 sb-tls）。

## Non-goals

- 不改 WireGuard/tailscale 协议行为与配置面。
- 不动 sb-transport 内部实现质量问题（另行轨迹）。
- endpoint/ 框架本身（handler.rs/mod.rs 的 Endpoint trait 与生命周期）不动。

## Task Split

1. **WireGuard/Tailscale 职责切分审计**（产出 `mig03_wp12_dedup_census.md`）：
   - 三处 WireGuard 逐一测绘：各自的消费方、与 Go 的 endpoint/legacy-outbound
     对应关系、共享候选（密钥处理、netstack 接口）；
   - 判定形态（预期）：netstack/设备层唯一归 sb-transport；endpoint 型实现归
     core/endpoint（消费 transport 层）；adapters/outbound 版若为 legacy outbound
     对应物则消费同一 transport 层——**重复的是底层隧道逻辑，合并它**；
   - tailscale 同法（多一个 services/tailscale 的服务面判定）。
2. **selector 家族合并**：
   - 引用审计：5 个变体各自被谁构造（bridge？switchboard？测试？）；
     p3 系列疑似实验残留——无活跃构造方的列入删除清单；
   - 合并为一套 group 实现（selector + urltest + fallback 语义），实现 WP01
     ADR 钦定的 Group 契约；`selector_group_tests.rs` 等测试随迁；
   - GUI 组操作回归：Clash API 的 select/now/all 行为不变（sb-api 集成测试）。
3. **影子模块逐个判定**（每个模块一行结论进 census）：
   - `core/transport/` → 预期并入 sb-transport 或删除（dialer 语义先对比）；
   - `core/tls/` → 预期并入 sb-tls（danger/trust 的调用方改 import）；
   - `core/subscribe/` vs sb-subscribe、`core/config/` vs sb-config、
     `core/socks5/` vs adapters —— 同法；
   - `core/metrics/` vs sb-metrics：先测绘分工（core 侧疑似 registry+label 定义，
     crate 侧疑似 exporter），若分工合理则保留但在 census 写明契约，不强并。
4. **预授权执行（D15）**：census 完成后直接执行——
   - p3/实验 selector 变体：无活跃构造方即删（连带审计 observe/feedback/health
     三个疑似伴生文件）；
   - 影子模块归宿：`core/transport/`→sb-transport、`core/tls/`→sb-tls、
     `core/subscribe/`→sb-subscribe、`core/config/`→sb-config、
     `core/socks5/`→并入 adapters；`core/metrics/` 若 census 确认
     "registry 在 core / exporter 在 sb-metrics"分工清晰则保留并写明契约，
     分工不清则并入 sb-metrics；
   - WireGuard/Tailscale 按任务 1 判定形态合并重复层（netstack 唯一归
     sb-transport，endpoint/outbound 消费同一底层）；
   - 证据不足或超出此清单的删除按 D18 升级。
5. **执行与度量**：逐组执行；记录净删行数、模块数变化。

## Acceptance

- [ ] census 文档覆盖 evidence 全部条目，每条有消费方证据与判定结论。
- [ ] 执行范围与 D15 清单逐项对应；D18 升级项清零或已获用户答复。
- [ ] WireGuard 隧道核心逻辑全仓唯一（grep 密钥握手/netstack 关键符号仅一处定义）。
- [ ] selector 家族：sb-core/src/outbound/ 下 selector*/p3*/udp_balancer 文件数
      按 D15 收敛（目标 ≤2：一套实现 + 可能的 UDP 平衡策略），GUI 组操作
      集成测试绿。
- [ ] 影子模块按 D15 处置完毕；`hysteria2`/`trojan` 等协议的 TLS import 统一
      指向 sb-tls。
- [ ] 全局验收门禁五连全绿；wireguard/tailscale/selector 相关测试全绿。
- [ ] 双核回归：selector/urltest 维度 interop case 无新增差分。

## 验证命令

```bash
cargo fmt --all -- --check
cargo check --workspace --all-features
cargo clippy --workspace --all-targets --all-features
cargo test -p sb-core -p sb-adapters -p sb-transport
cargo test -p sb-api    # GUI 组操作契约
make boundaries
git diff --check
```

## Risks / known traps

- WireGuard "三处"最可能的真相是"两层架构 + 一份真重复"——审计前不要预设
  删哪个；boringtun 在 adapters 侧、netstack 在 transport 侧，密钥/配置逻辑
  才是重复热点。
- `endpoint/mod.rs`(1,035) 有 cfg(out_wireguard/out_tailscale) 门——与 WP13 的
  feature 拆除有次序耦合：本包先合并实现，feature 门移交 WP13。
- selector 的 `p3_selector.rs` vs `selector_p3.rs` 命名对撞暗示至少一个是
  死实验——但 `outbound/observe.rs`/`feedback.rs`/`health.rs` 可能只服务 p3
  系列，删除时连带审计这三个文件。
- GUI 对组的依赖走 Clash API `proxies` 端点——合并 selector 后
  `members_health` 的 rtt 语义保持不变（GUI 面板显示依赖它）。

## 发现移交

（执行时填写。）
