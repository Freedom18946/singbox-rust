<!-- tier: S -->
# L24 工作包：性能 / 安全 / 质量 / 功能补全

> **阶段目标**: 从"功能完整"推向"生产就绪"，覆盖安全、Fuzz、质量、性能、功能补全五大领域。
> **前置条件**: L1-L23 全部 Closed，parity 92.9% (52/56)，构建绿色。
> **约束**: 本文件为规划文档，任务实施时逐项更新状态。

---

## Tier 1 — 必做 / 高价值（12 任务）

### T1-01 [安全] 修复 `sniff_quic.rs:71` `unreachable!()` → `return None`

**描述**: QUIC SNI 提取中，`quic_version_salt()` 对未知版本调用 `unreachable!()`，恶意/未知 QUIC 版本将 panic 整个进程。生产环境必须优雅降级。

**受影响文件**:
- `crates/sb-core/src/router/sniff_quic.rs:71`

**修改方案**:
- 将 `unreachable!()` 替换为 `return None`
- 调用方已处理 `None`（返回 `SniffResult::Unknown`）

**验证标准**:
- `cargo test -p sb-core --lib` 全过
- 构造 unknown version QUIC 包不触发 panic

**复杂度**: S | **依赖**: 无 | **被依赖**: T1-03

---

### T1-02 [Fuzz] 创建 `fuzz/targets/core/` + 3 个真实 fuzz target

**描述**: `fuzz/targets/core/` 目录缺失，core 模块（router/config/dns）无 fuzz 覆盖。需创建目录并实现 3 个基础 target。

**受影响文件**:
- `fuzz/targets/core/fuzz_config_parse.rs` (new) — 配置解析 fuzz
- `fuzz/targets/core/fuzz_route_decide.rs` (new) — 路由决策 fuzz
- `fuzz/targets/core/fuzz_dns_message.rs` (new) — DNS 消息解析 fuzz
- `fuzz/Cargo.toml` — 注册新 target

**修改方案**:
- 每个 target 使用 `libfuzzer-sys` 的 `fuzz_target!` 宏
- 输入为任意字节流，内部构造对应结构体并调用真实解析/处理函数
- 确保 panic 只在 bug 时发生（OOM/overflow 用 `#![no_main]` + libfuzzer 限制）

**验证标准**:
- `cargo fuzz build` 编译成功
- `cargo fuzz run <target> -- -max_total_time=60` 每个 target 不 panic

**复杂度**: M | **依赖**: 无 | **被依赖**: T1-03, T1-04

---

### T1-03 [Fuzz] Sniff 解析器 fuzz targets（TLS/HTTP/QUIC/Stream）

**描述**: sniff 解析器是攻击面最大的模块（直接解析不可信网络数据）。需要针对性 fuzz。

**受影响文件**:
- `fuzz/targets/core/fuzz_sniff_tls.rs` (new)
- `fuzz/targets/core/fuzz_sniff_http.rs` (new)
- `fuzz/targets/core/fuzz_sniff_quic.rs` (new)
- `fuzz/targets/core/fuzz_sniff_stream.rs` (new)
- `fuzz/Cargo.toml` — 注册

**修改方案**:
- TLS: 调用 `sniff_tls_client_hello()` 解析任意字节
- HTTP: 调用 `sniff_http_request()` 解析任意字节
- QUIC: 调用 `sniff_quic_sni()` / `sniff_quic_sni_multi()` 解析任意 UDP payload
- Stream: 调用 `sniff_stream()` 综合 sniff

**验证标准**:
- `cargo fuzz build` 编译成功
- 各 target 60s run 不 panic（T1-01 修复后 QUIC target 不触发 unreachable）

**复杂度**: M | **依赖**: T1-01, T1-02 | **被依赖**: T2-08

---

### T1-04 [Fuzz] 重写 11 个 simulated fuzz targets 为真实调用

**描述**: `fuzz/targets/protocols/` 下 11 个 target 目前是 simulated（仅打印 "would fuzz ..."），不调用任何真实代码。需逐个替换为真实 fuzz 调用。

**受影响文件**:
- `fuzz/targets/protocols/fuzz_shadowsocks.rs`
- `fuzz/targets/protocols/fuzz_vmess.rs`
- `fuzz/targets/protocols/fuzz_vless.rs`
- `fuzz/targets/protocols/fuzz_trojan.rs`
- `fuzz/targets/protocols/fuzz_hysteria2.rs`
- `fuzz/targets/protocols/fuzz_tuic.rs`
- `fuzz/targets/protocols/fuzz_wireguard.rs`
- `fuzz/targets/protocols/fuzz_naive.rs`
- `fuzz/targets/protocols/fuzz_ssh.rs`
- `fuzz/targets/protocols/fuzz_shadowtls.rs`
- `fuzz/targets/protocols/fuzz_socks5.rs`
- `fuzz/Cargo.toml`

**修改方案**:
- 每个 target 识别协议的最低级解析入口（如 `parse_request`, `decode_header`, `handshake_bytes`）
- 构造最小上下文（mock stream / config），调用真实解析函数
- 优先级：`fuzz_vmess` > `fuzz_shadowsocks` > `fuzz_trojan` > 其余

**验证标准**:
- `cargo fuzz build` 所有 target 编译成功
- 每个 target `cargo fuzz run -- -max_total_time=30` 不 panic

**复杂度**: L | **依赖**: T1-02 | **被依赖**: T2-08

---

### T1-05 [质量] 修复 `vmess.rs:211,218` 生产 `.unwrap()`

**描述**: VMess inbound handler 中两处 `.unwrap()` 直接作用于网络数据解析结果。恶意客户端可触发 panic。

**受影响文件**:
- `crates/sb-adapters/src/inbound/vmess.rs:211,218`

**修改方案**:
- 替换为 `ok_or(VmessError::InvalidRequest)?` 或 `.unwrap_or_default()` 视语义而定
- 确保错误路径返回合理的协议错误而非进程 crash

**验证标准**:
- `cargo test -p sb-adapters` 全过
- `cargo clippy -p sb-adapters --all-features -- -D warnings` 无 warning

**复杂度**: S | **依赖**: 无

---

### T1-06 [质量] 修复 `dsl_plus.rs:134` 空字符串 panic

**描述**: `DslPlus` 解析器在空字符串输入时 panic（`chars().next().unwrap()` 或类似模式）。配置文件中的空规则字段不应 crash。

**受影响文件**:
- `crates/sb-core/src/router/dsl_plus.rs:134`

**修改方案**:
- 添加空字符串 early return（返回空解析结果或合理错误）
- 添加单元测试覆盖空输入

**验证标准**:
- `cargo test -p sb-core --lib` 全过（含新测试）
- 空字符串输入不 panic

**复杂度**: S | **依赖**: 无

---

### T1-07 [质量] 消除 `runtime/mod.rs:211` transmute 生命周期扩展

**描述**: `unsafe { std::mem::transmute(…) }` 用于将 `'a` 生命周期扩展为 `'static`。这是 UB 风险极高的模式。

**受影响文件**:
- `crates/sb-core/src/runtime/mod.rs:211`

**修改方案**:
- 分析实际生命周期需求，改用 `Arc` / `'static` 所有权转移 / `Pin<Box<dyn Future>>` 等安全替代
- 如需运行时生命周期管理，使用 `tokio::task::spawn` + `Arc` 持有引用
- 完全消除该处 `transmute`

**验证标准**:
- `cargo test -p sb-core` 全过
- 该文件无 `unsafe` 块（或 `unsafe` 有充分注释说明安全性保证）
- `cargo clippy` 无 warning

**复杂度**: L | **依赖**: 无

---

### T1-08 [性能] Router `suffix_match()` 去除 per-check `format!()`

**描述**: `matcher.rs:118` 在每次域名后缀匹配时调用 `format!("."...)` 创建临时字符串。这是热路径（每个连接至少调用一次），分配开销不必要。

**受影响文件**:
- `crates/sb-core/src/router/matcher.rs:118`

**修改方案**:
- 预先在规则加载时将后缀规范化为 `.example.com` 格式存储
- 匹配时直接 `host.ends_with(&normalized_suffix)` 无分配

**验证标准**:
- `cargo test -p sb-core --lib` 全过
- T1-12 benchmark 验证改善（如可用）

**复杂度**: S | **依赖**: 无 | **被依赖**: T1-09（同文件合并 PR）

---

### T1-09 [性能] Router `matches_host()` 去除 per-call `to_string()`

**描述**: `matcher.rs:79` 在每次 host 匹配时调用 `.to_string()` 转换。与 T1-08 同文件，应合并优化。

**受影响文件**:
- `crates/sb-core/src/router/matcher.rs:79`

**修改方案**:
- 让 `matches_host()` 接受 `&str` 而非触发 `.to_string()`
- 或在上层缓存 string 表示

**验证标准**:
- `cargo test -p sb-core --lib` 全过
- 与 T1-08 合并验证

**复杂度**: M | **依赖**: T1-08

---

### T1-10 [功能] SOCKS5 outbound IPv6 (ATYP=0x04)

**描述**: SOCKS5 outbound 请求构建中仅处理 IPv4 (ATYP=0x01) 和域名 (ATYP=0x03)，缺少 IPv6 (ATYP=0x04)。纯 IPv6 网络下 SOCKS5 outbound 无法工作。

**受影响文件**:
- `crates/sb-core/src/outbound/socks5.rs:142`

**修改方案**:
- 添加 `SocketAddr::V6(v6)` 匹配分支
- 写入 `ATYP=0x04` + 16 字节 IPv6 地址 + 2 字节端口
- 参考 Go 实现 `transport/socks5/protocol.go`

**验证标准**:
- `cargo test -p sb-core --lib` 全过
- 新增单元测试覆盖 IPv6 SOCKS5 请求构建

**复杂度**: S | **依赖**: 无

---

### T1-11 [功能] TUN IPv6 UDP 响应包构建

**描述**: TUN UDP 反向路径仅构建 IPv4 UDP 包头（`tun/udp.rs:190`）。IPv6 UDP 响应被静默丢弃。

**受影响文件**:
- `crates/sb-adapters/src/inbound/tun/udp.rs:190`

**修改方案**:
- 添加 IPv6 分支：构建 IPv6 头（40 字节）+ UDP 头
- IPv6 伪头部校验和计算（next_header=17, 源/目标 128-bit）
- 测试覆盖 IPv6 UDP 回包

**验证标准**:
- `cargo test -p sb-adapters` 全过
- 新增测试覆盖 IPv6 UDP 包构建正确性

**复杂度**: M | **依赖**: 无

---

### T1-12 [性能] 端到端 TCP relay throughput benchmark

**描述**: 项目缺少性能基线。需要建立端到端 TCP 中继吞吐量 benchmark，用于量化后续优化效果。

**受影响文件**:
- `benches/benches/tcp_relay_e2e.rs` (new)
- `benches/Cargo.toml` — 如需修改

**修改方案**:
- 使用 `criterion` crate
- 构建 loopback TCP relay 管道：client → inbound → engine → outbound → server
- 测量不同 payload 大小 (1KB, 64KB, 1MB) 的吞吐量
- 输出 bytes/sec 和 latency 分位数

**验证标准**:
- `cargo bench --bench tcp_relay_e2e` 输出有意义数据
- 可在 CI 中重复运行

**复杂度**: M | **依赖**: 无 | **被依赖**: T2-05, T2-07, T2-09

---

## Tier 2 — 中价值（10 任务）

### T2-01 [性能] DNS cache `std::sync::Mutex` → `tokio::sync::Mutex`

**描述**: DNS 缓存使用 `std::sync::Mutex`，在 async 上下文中持锁期间可能阻塞 tokio 工作线程。应迁移到 async-aware 锁。

**受影响文件**:
- `crates/sb-core/src/dns/cache.rs`

**修改方案**:
- 替换 `std::sync::Mutex` 为 `tokio::sync::Mutex`
- 所有 `.lock()` 调用改为 `.lock().await`
- 注意：如果锁持有时间极短（无 await），可保留 std Mutex 并用 `parking_lot::Mutex` 替代

**验证标准**:
- `cargo test -p sb-core --lib` 全过
- DNS 解析功能正常

**复杂度**: M | **依赖**: 无

---

### T2-02 [质量] `register.rs` 12x `.unwrap()` defensive 化

**描述**: `register.rs` 3584-3823 行区域有 12 处 `.unwrap()`，用于注册表操作。注册失败应报错而非 panic。

**受影响文件**:
- `crates/sb-adapters/src/register.rs:3584-3823`

**修改方案**:
- 将 `.unwrap()` 替换为 `.expect("具体原因")` 或 `?` 传播
- 对于确定不会失败的场景（如静态字符串解析），使用 `.expect()` 附带说明
- 对于可能失败的场景，返回 `Result` 并传播

**验证标准**:
- `cargo test -p sb-adapters` 全过
- `cargo clippy -p sb-adapters --all-features -- -D warnings` 无 warning

**复杂度**: S | **依赖**: 无

---

### T2-03 [质量] `log/mod.rs` RwLock poison-tolerant 化

**描述**: `log/mod.rs:60,76` 处 RwLock `.read()` / `.write()` 在 panic 传播后会 poison，导致后续日志调用全部 panic（级联失败）。

**受影响文件**:
- `crates/sb-core/src/log/mod.rs:60,76`

**修改方案**:
- 使用 `.read().unwrap_or_else(|e| e.into_inner())` 模式忽略 poison
- 或迁移到 `parking_lot::RwLock`（无 poison 概念）

**验证标准**:
- `cargo test -p sb-core --lib` 全过
- 日志系统在 panic 后仍可用

**复杂度**: S | **依赖**: 无

---

### T2-04 [质量] 消除 5x `NonZeroUsize::new_unchecked()` 不必要 unsafe

**描述**: 多处使用 `unsafe { NonZeroUsize::new_unchecked(n) }` 但 `n` 是编译期常量（如 `1`, `4`）。Rust 1.83+ 提供 `const` 构造器，可安全替代。

**受影响文件**:
- `mmdb.rs` 中相关调用
- `multi.rs` 中相关调用
- `engine.rs` 中相关调用

**修改方案**:
- 替换为 `NonZeroUsize::new(n).unwrap()`（编译期求值）
- 或使用 `const { NonZeroUsize::new(n).unwrap() }` 明确编译期
- 确认 MSRV 支持

**验证标准**:
- `cargo check --workspace --all-features` 通过
- 消除所有不必要 `unsafe` 块

**复杂度**: S | **依赖**: 无

---

### T2-05 [性能] SS AEAD per-chunk 分配优化（`aead_in_place`）

**描述**: Shadowsocks AEAD 加解密路径每个 chunk 分配新 buffer。可使用 `aead_in_place` 就地加解密避免分配。

**受影响文件**:
- `crates/sb-adapters/src/outbound/shadowsocks.rs:485-553`

**修改方案**:
- 使用 `encrypt_in_place` / `decrypt_in_place` 替代 allocating 版本
- 预分配 buffer 复用（`Vec::with_capacity` + `clear()`/`truncate()`）
- 验证 tag 处理正确

**验证标准**:
- `cargo test -p sb-adapters` 全过
- T1-12 benchmark 量化改善

**复杂度**: M | **依赖**: T1-12

---

### T2-06 [功能] DNS over HTTP client 实现 (RFC 8484) ✅ DONE

**状态**: 已完成（2026-03-17）

**描述**: DoH 客户端目前仅有框架代码。需要实现完整 RFC 8484 wire-format HTTP 客户端。

**受影响文件**:
- `crates/sb-core/src/dns/http_client.rs`
- `crates/sb-core/Cargo.toml` (`dns_http` feature)

**实际修改**:
- 将 7 行 stub 替换为完整 RFC 8484 DoH 客户端（~200 行）
- `DohClient` struct: reqwest + HTTP/2 + 连接池 + adaptive GET/POST
- POST: `application/dns-message` 二进制（RFC 8484 §4.1）
- GET: `?dns=` base64url 编码（RFC 8484 §4.1）
- `dns_http` feature 从空数组改为 `["dns_udp", "dep:reqwest"]`
- 6 个测试（3 offline + 3 network `#[ignore]`）

**验证结果**:
- `cargo check -p sb-core --features dns_http` ✅
- `cargo check -p sb-core --features dns_doh` ✅（无回归）
- `cargo test -p sb-core --features dns_http --lib -- dns::http_client` ✅ 3/3

**复杂度**: L | **依赖**: 无

---

### T2-07 [性能] Benchmark 基线文档 + CI 集成

**描述**: 记录当前性能基线，建立 CI benchmark 回归检测机制。

**受影响文件**:
- `docs/benchmark-baseline.md` (new)
- CI 配置（如 `.github/workflows/bench.yml`）

**修改方案**:
- 运行 T1-12 benchmark，记录基线数据
- 配置 CI 在 PR 时运行 benchmark 并与基线比较
- 使用 `criterion` 的 JSON 输出 + `critcmp` 比较

**验证标准**:
- 文档包含当前平台的基线数据
- CI workflow 可运行

**复杂度**: M | **依赖**: T1-12

---

### T2-08 [Fuzz] Fuzz corpus 种子 + 回归测试框架

**描述**: Fuzz target 建立后需要种子 corpus 和回归测试框架，确保已发现的 crash 不再复现。

**受影响文件**:
- `fuzz/corpus/` (new) — 按 target 组织种子
- `fuzz/regression/` (new) — 触发过 crash 的输入

**修改方案**:
- 为每个 target 创建 10+ 合法种子文件（从测试配置/pcap/协议文档提取）
- 建立回归测试脚本：`fuzz/run_regression.sh`
- CI 集成：定期运行 fuzz 回归

**验证标准**:
- 每个 target 有 ≥5 个种子文件
- `fuzz/run_regression.sh` 全过

**复杂度**: M | **依赖**: T1-03, T1-04

---

### T2-09 [性能] TCP relay `pump()` buffer pool 化

**描述**: TCP relay 的 `pump()` 函数每次调用分配新 buffer。高并发时产生大量短命分配。

**受影响文件**:
- `crates/sb-core/src/net/metered.rs:154`

**修改方案**:
- 使用 `bytes::BytesMut` 池化（`thread_local!` 或 `crossbeam::queue`）
- 或使用 `tokio::io::copy_buf` 替代手动 pump
- 确保 buffer 大小适当（8KB-64KB）

**验证标准**:
- `cargo test -p sb-core --lib` 全过
- T1-12 benchmark 量化改善

**复杂度**: M | **依赖**: T1-12

---

### T2-10 [Fuzz] `parse_vmess_request` 优先改写为真实 fuzz target

**描述**: VMess 协议是攻击面最大的协议之一（复杂加密/认证握手）。`fuzz_vmess.rs` 应优先改为真实 fuzz。此任务可从 T1-04 中分离单独提前实施。

**受影响文件**:
- `fuzz/targets/protocols/fuzz_vmess.rs`

**修改方案**:
- 提取 VMess 请求解析的最底层函数
- 构造最小 mock 上下文（key/IV/config）
- 调用真实解密+解析路径

**验证标准**:
- `cargo fuzz build` 编译成功
- `cargo fuzz run fuzz_vmess -- -max_total_time=60` 不 panic

**复杂度**: S | **依赖**: 无

---

## Tier 3 — Nice-to-have（8 任务）

### T3-01 [质量] sb-core ~62 个空 feature flag 清理

**描述**: `sb-core/Cargo.toml` 中约 62 个 feature flag 是空数组 `[]`（L1 迁移遗留）。空 feature 仍会激活 `cfg` blocks，增加编译复杂度和认知负担。

**受影响文件**:
- `crates/sb-core/Cargo.toml`
- 所有引用这些 feature 的 `cfg(feature = "...")` 代码

**修改方案**:
- 审计每个空 feature 的 `cfg` 使用点
- 对于完全无效的 feature：删除 feature 定义 + 相关 cfg 代码
- 对于仍有语义的 feature：添加注释说明为何保留
- **高风险**：需逐个验证，防止误删有效 cfg 分支

**验证标准**:
- `cargo check --workspace --all-features --all-targets` 通过
- `cargo check --workspace` (默认 features) 通过

**复杂度**: L | **依赖**: 无

---

### T3-02 [质量] sb-types ~15 个公共类型补充 doc comments

**描述**: sb-types 中约 15 个核心 public trait/struct 缺少 doc comments。作为 API 边界层应有完整文档。

**受影响文件**:
- `crates/sb-types/src/*.rs`

**修改方案**:
- 为 `OutboundConnector`, `InboundHandler`, `Session`, `TargetAddr` 等核心类型添加 `///` doc comments
- 参考 Go 源码注释和架构文档

**验证标准**:
- `cargo doc -p sb-types --no-deps` 无 warning
- 核心类型有有意义的文档

**复杂度**: M | **依赖**: 无

---

### T3-03 [功能] Switchboard direct UDP 实现

**描述**: Switchboard 的 UDP 路径标记为 TODO，当前仅支持 TCP。

**受影响文件**:
- `crates/sb-core/src/runtime/switchboard.rs:367`

**修改方案**:
- 实现 UDP socket 池 + NAT 映射
- 处理 UDP 超时回收
- 参考 TUN UDP 实现

**验证标准**:
- `cargo test -p sb-core --lib` 全过
- 新增 UDP relay 单元测试

**复杂度**: M | **依赖**: 无

---

### T3-04 [功能] System proxy 设置实现（macOS）

**描述**: macOS 系统代理设置 API 标记为 TODO。需调用 `networksetup` 或 `SystemConfiguration` framework。

**受影响文件**:
- `crates/sb-adapters/src/inbound/http.rs:196`

**修改方案**:
- 使用 `std::process::Command` 调用 `networksetup -setwebproxy` / `-setsocksfirewallproxy`
- 进程退出时恢复原设置
- 仅 macOS 编译（`#[cfg(target_os = "macos")]`）

**验证标准**:
- macOS 上 `cargo test -p sb-adapters` 全过
- 手动验证系统代理设置正确

**复杂度**: M | **依赖**: 无

---

### T3-05 [功能] Endpoint sniff host mutation (消除 TODO)

**描述**: `endpoint/handler.rs:207` 标记 TODO，sniff 成功后未将 host 写回 endpoint。

**受影响文件**:
- `crates/sb-core/src/endpoint/handler.rs:207`

**修改方案**:
- sniff 成功后更新 `RouteCtx` 的目标地址为 sniff 得到的域名
- 遵循 `override_destination` 语义

**验证标准**:
- `cargo test -p sb-core --lib` 全过
- 已有 sniff 测试覆盖此路径

**复杂度**: S | **依赖**: 无

---

### T3-06 [功能] ShadowTLS v1 inbound 实现

**描述**: ShadowTLS inbound 仅实现了 v2/v3，v1 标记为 TODO。

**受影响文件**:
- `crates/sb-adapters/src/inbound/shadowtls.rs:140`

**修改方案**:
- v1 协议较简单：TLS handshake 转发 + 数据直通
- 参考 Go 实现 `transport/shadowtls/`

**验证标准**:
- `cargo test -p sb-adapters` 全过
- 新增 v1 握手单元测试

**复杂度**: M | **依赖**: 无

---

### T3-07 [质量] `tailscale.rs` raw pointer cast 安全性审计

**描述**: `tailscale.rs:756` 有 raw pointer 转换，需要审计其安全性并添加 SAFETY 注释或替代方案。

**受影响文件**:
- `crates/sb-core/src/endpoint/tailscale.rs:756`

**修改方案**:
- 审计 raw pointer 的来源、生命周期、对齐
- 如可用安全 API 替代，则替换
- 如必须保留，添加 `// SAFETY:` 注释说明不变量

**验证标准**:
- `cargo clippy` 无 unsafe 相关 warning
- SAFETY 注释完整说明

**复杂度**: M | **依赖**: 无

---

### T3-08 [质量] `context_pop.rs` `getpwuid` → `getpwuid_r` thread-safe

**描述**: `getpwuid()` 是非线程安全的 POSIX 函数。多线程并发调用可能产生 data race。

**受影响文件**:
- `crates/sb-core/src/router/context_pop.rs:96`

**修改方案**:
- 替换为 `getpwuid_r()`（thread-safe 版本）
- 或用 `nix` crate 的安全封装
- 仅 Unix 编译（`#[cfg(unix)]`）

**验证标准**:
- `cargo test -p sb-core --lib` 全过
- `cargo clippy` 无 warning

**复杂度**: S | **依赖**: 无

---

## 依赖关系图

```
T1-01 ──→ T1-03
T1-02 ──→ T1-03
T1-02 ──→ T1-04
T1-03 ──→ T2-08
T1-04 ──→ T2-08
T1-08 ──→ T1-09
T1-12 ──→ T2-05
T1-12 ──→ T2-07
T1-12 ──→ T2-09
```

所有其余任务无前置依赖，可按优先级自由排列。

## 执行批次

| 批次 | 周期 | 内容 | 并行任务 |
|------|------|------|----------|
| B1 | Week 1 | 安全修复 + Fuzz 基础设施 | T1-01,02,05,06 并行 → T1-03,04 → T2-08 |
| B2 | Week 2 | 性能热路径 + Benchmark | T1-08+09, T1-12 并行 → T2-05, T2-09, T2-07 |
| B3 | Week 3 | 功能补全 + 错误处理 | T1-10,11, T2-01,02,03,04,06 并行 |
| B4 | Week 4+ | T3 按需 | T3-05 → T3-01 → T3-06 → T3-02 → 其余 |

## 验证矩阵

| 类别 | 验证命令 |
|------|----------|
| 代码修改 | `cargo check --workspace --all-features --all-targets` + `cargo clippy ... -D warnings` + `cargo test -p <crate>` |
| Fuzz 任务 | `cargo fuzz build` + `cargo fuzz run <target> -- -max_total_time=60` |
| Benchmark | `cargo bench --bench <name>` 输出有意义数据 |
| 文档 | `cargo doc --no-deps` 无 warning |

## 总量统计

| Tier | 任务数 | S | M | L |
|------|--------|---|---|---|
| T1 | 12 | 5 | 5 | 2 |
| T2 | 10 | 3 | 5 | 2 |
| T3 | 8 | 2 | 5 | 1 |
| **合计** | **30** | **10** | **15** | **5** |
