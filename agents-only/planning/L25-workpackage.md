<!-- tier: S -->
# L25 工作包：生产加固 + 跨平台补全 + 文档完善

> **阶段目标**: 解决 L22-L24 验收中 2 个 PARTIAL 项，推进安全加固、测试覆盖、功能补全和文档完善。
> **前置条件**: L1-L24 全部 Closed，parity 92.9%，综合验收 39/41 PASS。
> **约束**: 本文件为规划文档，任务实施时逐项更新状态。

---

## 任务总览

| 任务 | 描述 | 复杂度 | 批次 | 现有基础设施 |
|------|------|--------|------|-------------|
| T1 | TUN UDP Linux/Windows 补全 | L | B3 | macOS 实现为参考 |
| T2 | VMess fuzz 可见性修复 | S | B1 | 20 个 fuzz target 已存在 |
| T3 | WS e2e 测试隔离 | S | B1 | 测试已有，仅 flaky |
| T4 | 消除 transmute + Box::leak | M | B2 | 机械式重构 |
| T5 | sb-adapters 集成测试 | M | B2 | 26 个测试文件已存在 |
| T6 | Linux TUN 网络栈评估 | S | B1 | smoltcp 已集成 |
| T7 | Provider 热更新管线 | L | B3 | ProviderManager 骨架已有 |
| T8 | 跨平台发布加固 | S | B4 | release.yml 已完善 |
| T9 | 用户文档完善 | M | B4 | 文档结构已建立 |
| T10 | 性能回归 CI 增强 | S | B4 | bench-regression.yml 已有 |

---

## 执行批次

```
B1: [T2, T3, T6]  — 快速赢面 + 研究（并行，1-2 天）
B2: [T4, T5]      — 核心质量（并行，3-5 天）
B3: [T1, T7]      — 功能补全（并行，5-8 天）
B4: [T8, T9, T10] — 打磨收尾（并行，2-3 天）
```

## 依赖关系图

```
T6 ──informs──> T1
T4 ──simplifies──> T7
T2 ──helps──> T5 (VMess test)

B1: [T2, T3, T6]        (并行，无硬依赖)
B2: [T4, T5]             (并行，T5 可选等 T2)
B3: [T1, T7]             (并行，T1 参考 T6 评估，T7 受益于 T4)
B4: [T8, T9, T10]        (并行，无依赖)
```

---

## T1: TUN UDP Linux/Windows 补全 [L]

**目标**: 消除 L23-T1 PARTIAL — Linux/Windows 当前 `trace!("drop")` UDP 包

**关键文件**:
- `crates/sb-adapters/src/inbound/tun/mod.rs` — Linux UDP 路径 L766，Windows L842
- `crates/sb-adapters/src/inbound/tun/udp.rs` — `build_*_udp` 需去除 Linux/Win 的 4 字节 prefix
- `crates/sb-adapters/src/inbound/tun_session.rs` — `TunWriter` trait，需 Linux/Win 实现

**现状分析**:
- macOS：完整实现（UdpNatTable + NAT relay + IPv4/IPv6 包构建 + MacOsTunWriter）
- Linux：`parse_tun_packet()` 仅返回 `(L4, dst_ip, dst_port)`，缺 src_ip/src_port/payload
- Linux：TUN 以 `IFF_NO_PI` 模式打开（无 prefix），但 `build_*_udp` 添加了 PI header — 冲突
- Windows：使用 wintun `receive_blocking()` 同步模式，需 channel bridge
- 两者均无 TunWriter 实现

**方案**:
1. 重构 `build_ipv4_udp`/`build_ipv6_udp`：macOS 保留 AF prefix，Linux(IFF_NO_PI)/Windows 写裸 IP（无 prefix）
2. Linux：扩展 `parse_tun_packet` 返回完整五元组 + payload offset（参考 macOS `parse_frame` 的 `Parsed` 结构）
3. Linux：实现 `LinuxTunWriter`（共享 AsyncFd，类似 MacOsTunWriter 的 `Mutex<File>` 模式）
4. Linux：主循环 UDP 分支替换 `trace!("drop")` → 构造 `UdpFourTuple` + 调用 `udp_nat.forward()`
5. Windows：实现 `WintunTunWriter`（通过 `wintun::Session::allocate_send_packet` 写回）
6. Windows：同样接入 UDP NAT + 可能需要 `spawn_blocking` → mpsc channel bridge

**验证标准**:
- `cargo check --workspace --all-features --all-targets` 全平台通过
- `build_udp_ip_packet` 无 prefix 模式单元测试
- `parse_tun_packet_full` 返回完整五元组单元测试

**复杂度**: L | **依赖**: T6 评估结果 (soft)

---

## T2: VMess Fuzz 可见性 [S]

**目标**: 消除 T1-04 PARTIAL — fuzz_vmess 直接调用真实 VMess 解析

**关键文件**:
- `crates/sb-adapters/src/inbound/vmess.rs:499` — `fn parse_vmess_request`（private）
- `fuzz/targets/protocols/fuzz_vmess.rs` — 当前走 `parse_ss_addr` 替代

**现状分析**:
- `parse_vmess_request(data: &[u8]) -> Result<(String, u16, u8)>` 是同步纯解析器，适合 fuzz
- 其他可暴露的同步解析器：http.rs `parse_request_line`、naive.rs `parse_target`
- 异步解析器（Trojan/TUIC/Hysteria2）因 stream 依赖暂不处理

**方案**:
1. `parse_vmess_request` → `pub(crate) fn`
2. 同理处理：http.rs `parse_request_line`、naive.rs `parse_target`
3. 更新 `fuzz_vmess.rs` 直接调用 `parse_vmess_request`
4. 补充 VMess 格式 seed corpus（ATYP=0x01/0x02/0x03 各一条）

**验证标准**:
- `cargo +nightly fuzz build` 成功
- `cargo +nightly fuzz run fuzz_vmess corpus/seeds/vmess/ -- -runs=0` 通过
- `cargo check --workspace --all-features` 无回归

**复杂度**: S | **依赖**: 无

---

## T3: WS e2e 测试隔离 [S]

**目标**: 修复 `test_connections_ws_memory_remains_bounded_over_time` 并发 flaky

**关键文件**:
- `crates/sb-api/tests/clash_websocket_e2e.rs` — 全局 tracker race
- `crates/sb-api/Cargo.toml` — 添加 `serial_test` dev-dependency
- `crates/sb-common/src/conntrack.rs:312` — `GLOBAL_TRACKER` OnceLock 单例

**现状分析**:
- `global_tracker()` 是进程级 `OnceLock<ConnTracker>` 单例
- 测试在开头调用 `close_all()` 重置状态 — 并发时 race
- ClashApiServer 和 websocket handlers 直接硬编码 `global_tracker()`
- 仅 2/7 测试调用 `register_test_connection()`，flaky 风险集中

**方案**（Option A，快速修复）:
1. 添加 `serial_test = "3"` 到 `[dev-dependencies]`
2. 给调用 `register_test_connection()` 的 2 个测试加 `#[serial_test::serial]`
3. 审计其余测试是否也需要

**验证标准**:
- `cargo test -p sb-api -- --test-threads=8` 连跑 5 次零失败

**复杂度**: S | **依赖**: 无

---

## T4: 消除 transmute + Box::leak [M]

**目标**: 消除 `runtime/mod.rs:211` 的 unsafe transmute 和 5 处 `Box::leak` 内存泄漏

**关键文件**:
- `crates/sb-core/src/routing/engine.rs:69` — `Engine<'a>` 持有 `cfg: &'a ConfigIR`
- `crates/sb-core/src/runtime/mod.rs:211` — transmute；L173 — `Box::leak`
- `crates/sb-core/src/runtime/supervisor.rs:1376` — `Box::leak`
- `crates/sb-core/src/inbound/{socks5.rs:809, http_connect.rs:499, mixed.rs:182}` — 3 处 `Box::leak`

**现状分析**:
- `Engine<'a>` 需要 `'static` 才能 spawn 到 async task
- `clone_as_static()` 通过 transmute 强行扩展生命周期
- Supervisor 通过 `Box::leak` 泄漏 ConfigIR 来获得 `'static` 引用
- 3 个 inbound fallback 路径同样泄漏 ConfigIR

**方案**:
1. `Engine<'a>` → `Engine`，`cfg: &'a ConfigIR` → `cfg: Arc<ConfigIR>`
2. 删除 `clone_as_static()` 方法（Arc clone 天然 'static + Send）
3. `Runtime<'a>` → `Runtime`（移除生命周期参数）
4. 所有 `Box::leak(Box::new(ir))` → `Arc::new(ir)`
5. Supervisor `State.engine: Engine<'static>` → `State.engine: Engine`
6. `geoip`/`geosite` 字段（当前 `Option<&'a ClassifyIpFn>`，全处为 None）→ `Option<Arc<ClassifyIpFn>>`

**验证标准**:
- `grep -r "transmute" crates/sb-core/src/runtime/` 零命中
- `grep -r "Box::leak.*ConfigIR" crates/` 零命中
- `cargo test -p sb-core --lib` 全 509 tests pass
- `cargo clippy --workspace --all-features --all-targets -- -D warnings` 通过

**复杂度**: M | **依赖**: 无（但应在 T7 之前完成）

---

## T5: sb-adapters 集成测试 [M]

**目标**: 从 1 个非 ignored 测试提升到 ≥15 个真实协议 e2e 测试

**关键文件**:
- `crates/sb-adapters/tests/` — 26 个测试文件，多数 `#[ignore]`

**方案**:
1. 审计 26 个测试文件，分类：可直接启用 / 需 mock server / 需新写
2. 修复 6 个 `#[ignore]` 测试（使用 loopback mock server 替代外部依赖）
3. 新增：VMess round-trip、VLESS round-trip、Mixed 模式切换
4. 参考 `socks_udp_e2e_full.rs` 模式：启动 server → 连接 → 验证数据

**验证标准**:
- `cargo test -p sb-adapters` ≥15 个 non-ignored 测试通过

**复杂度**: M | **依赖**: T2 (VMess 可见性有助于测试，非硬依赖)

---

## T6: Linux TUN 网络栈评估 [S]

**目标**: 评估 smoltcp 是否满足需求，指导 T1 设计决策

**关键文件**:
- `crates/sb-adapters/src/inbound/tun/stack.rs` — smoltcp 包装（当前 TCP accept 返回 None，有 `#![allow(unused, dead_code)]`）
- `crates/sb-adapters/src/inbound/tun/device.rs` — TunDeviceDriver channel bridge

**方案**: 研究任务，输出评估文档
1. smoltcp 限制分析：连接数上限、TCP 拥塞控制算法、buffer 管理
2. 对比 Go gVisor netstack 能力矩阵
3. 评估 raw IP 直通方案（当前 macOS UDP 已是 raw IP，不经 smoltcp）
4. 输出 `agents-only/planning/L25-tun-stack-eval.md`
5. 决策树：(a) smoltcp 足够 (b) 需替换 (c) TCP 走 smoltcp + UDP 走 raw IP

**验证标准**:
- 评估文档含明确推荐和理由

**复杂度**: S | **依赖**: 无（输出指导 T1）

---

## T7: Provider 热更新管线 [L]

**目标**: 打通 ProviderManager 获取内容 → 解析 → 应用到运行中引擎的完整链路

**关键文件**:
- `crates/sb-api/src/managers.rs:510` — `ProviderManager`（已有 fetch + 后台循环 + health check）
- `crates/sb-subscribe/src/http.rs` — 最小 fetcher（10 行，无 retry/timeout/条件 GET）
- `crates/sb-subscribe/src/providers.rs` — placeholder stub（HashMap cache）
- `crates/sb-core/src/runtime/supervisor.rs` — 已有 `ReloadMsg::Apply(Box<ConfigIR>)`

**现状分析**:
- ProviderManager 完整：periodic fetch、failure marking、background sweep、health check
- 但 `Provider.content` 是 raw String — 未解析、未应用
- 无机制将更新后的 proxy/rule 列表推送到运行中引擎

**方案**:
1. 增强 HTTP fetcher（`sb-subscribe/src/http.rs`）：
   - timeout 30s、retry 3 次 exponential backoff
   - `If-Modified-Since` / `ETag` 条件 GET
   - `User-Agent` header
2. 实现 provider 内容解析（`sb-subscribe/src/providers.rs`）：
   - proxy-provider → `Vec<OutboundConfig>`（base64 proxy list / Clash YAML）
   - rule-provider → `Vec<RuleEntry>`（domain list / IP-CIDR list）
3. 新增 `ReloadMsg::UpdateProviders { proxies, rules }` 轻量热更新通道
4. ProviderManager 检测到内容变化后计算 diff → 发送到 Supervisor
5. 解析 config 中 `outbound_providers` 和 `rule_providers` 段落

**验证标准**:
- 单测：mock HTTP server fetch + parse 验证
- 单测：provider 更新触发 outbound 列表刷新
- 集成测试：引擎启动 + mock server 内容变更 → 新 outbound 可见

**复杂度**: L | **依赖**: T4 (Arc Engine 简化热更新，soft)

---

## T8: 跨平台发布加固 [S]

**目标**: 补全 release.yml 的边角功能

**关键文件**:
- `.github/workflows/release.yml` — 已有 6 targets
- `deployments/` — Docker/K8s/systemd 已有

**方案**:
1. 添加 ARM Windows target（`aarch64-pc-windows-msvc`）
2. 添加 Helm chart（`deployments/helm/singbox-rust/`）
3. 添加 SBOM 生成（`cargo auditable`）
4. 添加 release smoke test（`./run --version` + `./run check -c test-config.json`）
5. 固定 action 版本为精确 SHA

**验证标准**:
- `helm lint` 通过
- release workflow dry-run 通过
- SBOM artifact 生成

**复杂度**: S | **依赖**: 无

---

## T9: 用户文档完善 [M]

**目标**: 补全 Go→Rust 迁移指南和配置参考

**关键文件**:
- `docs/01-user-guide/configuration/schema-migration.md` — 18 行 stub

**已知配置差异**（来自 MEMORY.md）:
- `tag` → `name`
- `listen_port` → `port`
- URLTest interval: Go `"3s"` → Rust `3`（u64 秒）
- outbound members: Go `outbounds` → Rust `members`（Go alias 已支持）

**方案**:
1. 扩展 schema-migration.md：
   - 逐字段映射表
   - 完整 before/after 配置示例
   - 自动迁移命令说明
2. 新建配置参考文档（`docs/01-user-guide/configuration/field-reference.md`）：
   - 所有 inbound/outbound/route/dns 字段
3. 新建常见问题文档（`docs/01-user-guide/troubleshooting/common-issues.md`）

**验证标准**:
- markdown 渲染无错误
- 覆盖所有已知配置差异

**复杂度**: M | **依赖**: 无

---

## T10: 性能回归 CI 增强 [S]

**目标**: 补充定时 fuzz CI 和覆盖率报告

**关键文件**:
- `.github/workflows/bench-regression.yml` — 已有，PR 触发
- 新建：`.github/workflows/fuzz-nightly.yml`
- 新建：`.github/workflows/coverage.yml`

**方案**:
1. 新建 `fuzz-nightly.yml`：
   - `schedule: cron: '0 3 * * *'` + `workflow_dispatch`
   - 跑 20 个 fuzz target 各 60s
   - 使用 `fuzz/run_regression.sh` 回归验证
   - crash 时上传 artifact + 创建 GitHub issue
2. 新建 `coverage.yml`：
   - PR 触发，`cargo-llvm-cov` 生成 lcov
   - 上传 Codecov + PR comment
3. 增强 `bench-regression.yml`：
   - 支持 `workflow_dispatch` 手动触发
   - main 合并后自动更新 baseline

**验证标准**:
- `actionlint` 校验通过
- 手动触发 fuzz-nightly 零 crash

**复杂度**: S | **依赖**: 无

---

## 验证矩阵

| 类别 | 验证命令 |
|------|----------|
| 代码修改 | `cargo check --workspace --all-features --all-targets` + `cargo clippy ... -D warnings` + `cargo test -p <crate>` |
| Fuzz 任务 | `cargo +nightly fuzz build` + seed smoke test |
| CI 工作流 | `actionlint` 校验 |
| Helm | `helm lint` |
| 文档 | markdown 渲染检查 |

## 总量统计

| 复杂度 | 任务数 | 任务 |
|--------|--------|------|
| S | 5 | T2, T3, T6, T8, T10 |
| M | 3 | T4, T5, T9 |
| L | 2 | T1, T7 |
| **合计** | **10** | |

**估计总工作量**: 11-18 天，4 个批次
