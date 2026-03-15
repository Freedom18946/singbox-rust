<!-- tier: S -->
# L23 Tier 1 实施计划

## 执行顺序：T3 → T2 → T1（简单到复杂）

---

## L23-T3: TUN sniff `override_destination` 补齐

**现状**: TUN TCP sniff 路径在 `tun/mod.rs:530-541` 处理 `Decision::Sniff { .. }` 时，
用 `matches!()` 匹配，没有解构出 `override_destination` 标志。sniff 完成后 re-decide
但即使 sniff 成功拿到域名，也从不覆盖原始 IP 目标。

**参考**: HTTP (`http.rs:429-499`) 和 SOCKS (`socks/mod.rs:547-618`) 已完成此逻辑。

**修改点** (1 个文件):

`crates/sb-adapters/src/inbound/tun/mod.rs` ~行 530:
```rust
// 当前:
if matches!(decision, Decision::Sniff { .. }) {
    if sniff_proto.is_some() {
        decision = self.router.decide(&route_ctx);
    }
    if matches!(decision, Decision::Sniff { .. }) {
        decision = Decision::Direct;
    }
}

// 改为:
if let Decision::Sniff { override_destination } = decision {
    if sniff_proto.is_some() {
        // Re-decide with sniffed protocol set → engine skips Sniff rules
        decision = self.router.decide(&route_ctx);
    }
    if matches!(decision, Decision::Sniff { .. }) {
        decision = Decision::Direct;
    }
    // Apply override_destination: replace IP target with sniffed hostname
    if override_destination {
        if let Some(ref h) = sniff_host {
            if !h.is_empty() {
                // Update dst for outbound dialing
                let (_, port) = pkt.dst_socket();
                dst = Address::Domain(h.clone(), port);
            }
        }
    }
}
```

还需更新 `host_str` 的使用位置，让后续的 outbound connect 使用覆盖后的目标地址。

**影响**: ~15 行改动。

---

## L23-T2: 废弃字段 `sniff: true` 自动注入

**现状**:
- Config 解析: `InboundIR.sniff: bool` 已解析 (v2.rs:1911)
- Bridge 映射: `InboundParam.sniff: bool` 已映射 (bridge.rs:378)
- 运行时: HTTP/SOCKS/TUN **从未读取** `InboundParam.sniff` / `param.sniff`

**Go 机制** (route.go:344-371):
```go
if metadata.InboundOptions.SniffEnabled {
    r.actionSniff(ctx, metadata, &RuleActionSniff{
        OverrideDestination: metadata.InboundOptions.SniffOverrideDestination,
    }, inputConn, inputPacketConn, nil, nil)
}
```
Go 在 `matchRule()` 的规则循环**之前**，如果 inbound 配置了 `sniff: true`，
就自动调用 `actionSniff()`，相当于在规则引擎之前插入一个隐式 sniff action。

**方案**: 在 `RouterHandle::decide()` 层注入（engine.rs）

在 `decide()` 开头加入：如果 `RouteCtx` 携带了 `inbound_sniff: true`（新字段），
且 `protocol.is_none()`（尚未 sniff），则返回 `Decision::Sniff { override_destination }`。

这样各 inbound 已有的 `Decision::Sniff` 处理逻辑自动生效，无需改动每个 inbound。

**修改点** (5 个文件):

1. **`sb-core/src/router/engine.rs`** — `RouteCtx` 增加 `inbound_sniff: bool` + `inbound_sniff_override: bool`；
   `decide()` 开头检查：if `inbound_sniff && protocol.is_none()` → return `Decision::Sniff { override_destination: inbound_sniff_override }`

2. **`sb-adapters/src/inbound/http.rs`** — `HttpProxyConfig` 加 `sniff: bool`, `sniff_override_destination: bool`；
   构造 `RouteCtx` 时设置 `inbound_sniff`

3. **`sb-adapters/src/inbound/socks/mod.rs`** — 同上，`SocksInboundConfig` 加 sniff 字段

4. **`sb-adapters/src/inbound/tun/mod.rs`** — `TunInboundConfig` 加 sniff 字段

5. **`sb-adapters/src/register.rs`** (或 `sb-core/src/adapter/bridge.rs`) — 传递 `InboundParam.sniff` → Config.sniff

**备选方案**: 不修改 RouteCtx，而是在各 inbound 的 `decide()` 调用前自行检查 sniff 字段。
但这意味着每个 inbound 都要重复逻辑。engine 层方案更集中、更干净。

**需要新增的字段**:
- `InboundIR` + V2 parser: `sniff_override_destination: Option<bool>` (目前 V2 路径没解析此字段)
- `InboundParam`: `sniff_override_destination: bool`
- `RouteCtx`: `inbound_sniff: bool`, `inbound_sniff_override: bool`

**影响**: ~60 行改动，5 个文件。

---

## L23-T1: TUN UDP 转发

**现状**: TUN 的 `run()` 方法在 macOS/Linux/Windows 所有三个平台分支中，
遇到 `L4::Udp` 包时直接 `trace!("drop")` 跳过。没有 UDP session 管理、
没有路由决策、没有 outbound 转发。

**Go 机制**: Go TUN 通过 sing-tun 库的网络栈 (gVisor/system) 接管 UDP，
回调 `NewPacketConnectionEx()` → `router.RoutePacketConnectionEx()` → `matchRule()` → outbound。
每个 UDP flow 是一个 `PacketConn`（N.PacketConn 接口）。

**Rust 现状**:
- smoltcp `TunStack` 已有 UDP socket 支持 (import `smoltcp::socket::udp`)
- 但 `TunStack` 没有暴露 `listen_udp()` / `udp_send()` / `udp_recv()` 方法
- `RouterHandle::decide()` 已支持 UDP 路由 (`decide_udp()`, `decide_udp_async()`)
- SOCKS5 UDP 有完整的 NAT/session 管理参考 (`socks/udp.rs`)

**方案**: 轻量 UDP NAT 表

1. `TunStack` 增加 `listen_udp()`, `udp_send()`, `udp_recv()` 方法
2. TUN 主循环遇到 `L4::Udp` 包时:
   - 解析 (src_ip:src_port, dst_ip:dst_port) 四元组
   - 查 UDP NAT 表 (DashMap<FourTuple, UdpSession>)
   - 如果已有 session → 转发到 outbound
   - 如果新 session → 路由决策 → sniff (datagram) → 建立 outbound UDP relay → 记录 NAT
3. 反向路径: outbound 收到 UDP 回包 → NAT 查表 → 构造 IP/UDP 包写回 TUN

**复杂度评估**:
- 需要 UDP session 管理 (~100 行)
- 需要 IP/UDP 包构造 (已有 TCP 包构造参考)
- 需要 outbound UDP relay (参考 socks/udp.rs)
- 需要超时清理
- 估计 ~250-350 行新增代码

**修改点** (3 个文件):
1. `tun/stack.rs` — 增加 UDP socket 方法
2. `tun/mod.rs` — UDP session manager + 主循环 UDP 分支
3. 可能新建 `tun/udp.rs` — UDP NAT 表和 relay 逻辑

**替代方案**: 直接在 raw IP 层面处理 UDP，不经过 smoltcp。
好处是更简单（直接解析 IP/UDP header），不依赖 smoltcp 的 UDP socket 栈。
坏处是需要自己组装响应 IP 包。但 TUN 已经有 TCP 的 IP 包构造代码可参考。

**推荐**: raw IP 方案，因为 smoltcp 的 UDP binding 需要固定本地端口，
而 TUN 需要处理任意目标地址的 UDP 流量。raw IP 方案更灵活。

**影响**: ~300 行新增，可能 2-3 个文件。

---

## 风险和依赖

| 风险 | 缓解 |
|------|------|
| T1 (TUN UDP) 工程量大 | T3/T2 先落地，T1 可以分阶段 |
| sniff auto-injection 可能影响现有 rule-action sniff | engine 层判断: 仅当 `protocol.is_none()` 时注入，不影响已 sniff 的连接 |
| UDP NAT 内存泄漏 | 超时清理 (5min default)，参考 SOCKS5 UDP 的清理模式 |

## 验收标准

- [x] T3: TUN TCP sniff 时如果 override_destination=true，outbound 使用 sniffed host 而非原始 IP
- [x] T2: 配置 `sniff: true` 的 HTTP/SOCKS/TUN inbound，自动触发 sniff，无需显式 sniff rule-action
- [x] T1: TUN 模式下 DNS-over-UDP 请求能被路由到正确 outbound；QUIC 流量不被 drop
- [x] 所有现有测试通过，clippy 无新 warning

> **全部完成**: 2026-03-16
