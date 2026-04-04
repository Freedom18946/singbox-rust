<!-- tier: A -->
# 故障排查手册（Troubleshooting）

> **用途**：记录遇到过的怪异报错及解决方案
> **维护者**：AI Agent 遇到问题解决后主动记录

---

## 编译错误

### 链接器错误

| 错误 | 原因 | 解决方案 |
|------|------|---------|
| `linker 'cc' not found` | macOS 缺少 Xcode CLI | `xcode-select --install` |
| `aws-lc-sys build failed` | 缺少 cmake/go | `brew install cmake go` |

### 依赖错误

| 错误 | 原因 | 解决方案 |
|------|------|---------|
| `duplicate lang item` | 重复引入 std | 检查 `#![no_std]` 配置 |
| `version solving failed` | 依赖版本冲突 | `cargo update -p <crate>` |

---

## 运行时错误

### 网络相关

| 错误 | 原因 | 解决方案 |
|------|------|---------|
| `Address already in use` | 端口被占用 | `lsof -i :<port>` 检查 |
| `Permission denied (TUN)` | 缺少权限 | macOS 需要 root 或授权 |

### 配置相关

| 错误 | 原因 | 解决方案 |
|------|------|---------|
| `unknown field` | 配置字段名错误 | 检查 YAML/JSON 结构 |
| `invalid type` | 类型不匹配 | 检查配置值类型 |

---

## 测试相关

| 问题 | 原因 | 解决方案 |
|------|------|---------|
| 测试相互干扰 | 全局状态 | 使用 `serial_test` |
| 端口冲突 | 并行测试 | 使用随机端口 `:0` |

---

## 项目特定踩坑记录

### Feature / Cargo 相关

| # | 问题 | 原因 | 解决方案 |
|---|------|------|---------|
| 1 | 空 feature `out_trojan = []` 仍激活 `#[cfg(feature = "out_trojan")]` | cargo 认为 feature 已启用 | 清理 cfg blocks 中引用已删除类型的代码 |
| 2 | `--no-default-features` 编译失败 | snow/tun 引用在无 feature 时报错 | pre-existing，不阻塞默认构建 |
| 3 | `out_*` 空 feature 不能删除 | app/Cargo.toml 的 router feature 引用 | 保留空数组 `[]` |
| 4 | `adapter-wireguard` ≠ `adapter-wireguard-outbound` | 前者含 out_wireguard，后者独立 | 注意区分 |
| 5 | `cargo tree` 看到 tower 是传递依赖 | reqwest → hyper → tower | 删除直接 dep 即可 |

### 类型 / API 不匹配

| # | 问题 | 解决方案 |
|---|------|---------|
| 6 | vmess/vless adapter 用 `SocketAddr` 不支持域名 | parse 或 DNS resolve |
| 7 | `OutboundIR.transport` 是 `Option<Vec<String>>` 不是 `Option<String>` | 取首元素 |
| 8 | `alter_id`: IR 中 `u8`, vmess adapter 中 `u16` | `as u16` 转换 |
| 9 | `InboundIR` 类型字段叫 `ty` 不是 `inbound_type` | 直接用 `.ty` |
| 10 | ipnetwork 0.18 vs 0.21 类型不兼容 | 统一到 maxminddb 依赖的版本 |
| 11 | russh v0.49 API: `authenticate_publickey` 需要 `PrivateKeyWithHashAlg` | 非 `Arc<PrivateKey>` |
| 12 | maxminddb 0.27: `reader.lookup()` 不再有泛型参数 | 用 `.lookup()?.decode::<T>()?` |

### 架构 / 初始化

| # | 问题 | 解决方案 |
|---|------|---------|
| 13 | CryptoProvider 初始化时序 | L1.3 后需显式调用 `ensure_rustls_crypto_provider()` |
| 14 | `pub(crate)` mod 内的 `pub` items 触发 `unreachable_pub` | `#![allow(unreachable_pub)]` |
| 15 | reqwest 不能轻易可选化 | supervisor download_file() 无条件使用 → 用 HttpClient port 替代 |
| 16 | Hysteria/Hysteria2 inbound 依赖 out_* | 必须保留 sb-core feature forwarding |
| 17 | parse_listen_addr cfg 不匹配 router feature | 扩展 cfg 为 `any(feature = "adapters", feature = "router")` |

### 工具链

| # | 问题 | 解决方案 |
|---|------|---------|
| 18 | Task subagent 403 | haiku/sonnet 无权限，必须用 opus 或直接用工具 |
| 19 | check-boundaries.sh V1 grep 逻辑 | grep -B1 无法正确判断 cfg 保护，改用 sed -n |
| 20 | cfg(any(feature)) 需特殊匹配 | 用 `#\[cfg(.*feature` 而非 `#\[cfg(feature` |

### Clash API / sb-api 相关

| # | 问题 | 原因 | 解决方案 |
|---|------|------|---------|
| 21 | `InboundIR.listen` 不是 `Option<String>` | IR 定义为 `pub listen: String` | 用 `==` 直接比较而非 `.as_deref()` |
| 22 | `InboundIR` 没有 `enabled` 字段 | TUN 启用状态不在 IR 中 | 通过 type 匹配 `InboundType::Tun` 推断 |
| 23 | axum WS+HTTP 双模式端点 | Go 检查 Upgrade header 走 WS 或 HTTP | `Option<WebSocketUpgrade>` — None→HTTP, Some→WS |
| 24 | macOS 进程内存获取需 libc | `mach_task_basic_info` 需 libc crate | sb-api 不依赖 libc → 简化为返回 0 (Linux 用 /proc) |
| 25 | Go `badjson.JSONObject` vs Rust struct | Go 有序 KV 只输出 Put 过的字段，Rust struct 始终输出所有字段 | 用 skip_serializing_if 控制可选字段，多余字段不影响 GUI |

### Trait / 跨 Crate 模式

| # | 问题 | 原因 | 解决方案 |
|---|------|------|---------|
| 26 | `SelectorOutbound.as_any()` 返回 None | 未覆盖默认方法，`Arc<SelectorGroup>` 的 `as_any()` 不会自动转发 | 必须显式添加 `fn as_any(&self) -> Option<&dyn Any> { self.inner.as_any() }` |
| 27 | `OutboundGroup::select_outbound` lifetime 错误 | `&self` 和 `&str` 需要相同的生命周期才能返回 `Pin<Box<Future + '_>>` | 用显式 `'a` 生命周期: `fn select_outbound<'a>(&'a self, tag: &'a str) -> Pin<Box<..+'a>>` |
| 28 | downcast_ref 静默失败不报错 | 返回 None 而非 panic/error，所有 `if let Some(group) = ...downcast...` 分支静默跳过 | 优先用 trait 抽象 (`as_group()`) 替代 downcast，或在添加 wrapper 时检查是否需要转发 |

### 历史存储 / URLTest 相关

| # | 问题 | 原因 | 解决方案 |
|---|------|------|---------|
| 29 | `humantime` 不在 sb-api 依赖中 | 需要 RFC3339 时间格式化给 history | 在 sb-api/Cargo.toml 添加 `humantime = "2.1"` |
| 30 | E2E test `test_get_proxy_delay` 偶发失败 | 测试直连 gstatic.com，网络抖动导致超时 | 非代码 bug，重跑即可通过（transient network flake） |
| 31 | tolerance 对未测试代理 (rtt=0) 不应 sticky | rtt=0 意味着从未收到健康检查结果 | 在 tolerance 条件中加 `current_rtt > 0` guard |
| 32 | SelectorGroup 构造函数参数扩展影响 ~35 call sites | 新增 Option 字段导致所有 new_* 调用需改 | 用 agent 批量修改，测试代码全传 None |

### ConnectionTracker / L2.8 相关

| # | 问题 | 原因 | 解决方案 |
|---|------|------|---------|
| 33 | `balancer_socks5_ok` 测试偶发失败 | 全量 workspace 测试时资源竞争导致 SOCKS5 握手超时 | 非代码 bug，单独 `cargo test -p sb-core --test udp_balancer` 始终通过（flaky） |
| 34 | copy_with_recording 签名变更影响多处调用 | 新增 conn_counter 参数 | 所有调用点统一加 `None` 或 `Some(counter)`，tls_fragment 也需同步更新 |
| 35 | sb-core 需要 sb-common 依赖 | conn.rs 调用 global_tracker() 需要 sb-common | 在 sb-core/Cargo.toml 添加 `sb-common = { path = "../sb-common" }` |
| 36 | UDP cancel token 需 select! 包裹 timeout | 原代码用 `tokio::time::timeout(udp_timeout, recv)` 单层 | 改为 `select! { r = timeout(..) => r, _ = cancel.cancelled() => break }` |
| 37 | git stash 会恢复到 linter 修改前状态 | 系统提醒中显示旧代码导致误以为改动丢失 | git stash pop 恢复后验证文件状态即可 |

### Lifecycle / L2.9 相关

| # | 问题 | 原因 | 解决方案 |
|---|------|------|---------|
| 38 | Bridge 的 `Arc<dyn adapter::OutboundConnector>` 无法加入 OutboundManager | OutboundManager 用 `traits::OutboundConnector`，两个 trait 接口完全不同（connect vs connect_tcp） | 用 DirectConnector 占位注册，OutboundManager 此阶段仅做 tag 追踪 |
| 39 | tokio::sync::RwLock 没有 `try_read()` | std::sync::RwLock 有 try_read 但 tokio 版没有 | Startable::start() 是 sync 方法，不能 .await → 改用轻量日志，真正的统计信息放在 async 的 populate_bridge_managers 中 |
| 40 | populate_bridge_managers 签名改 Result 后 4 处调用需更新 | 原函数无返回值，新增 Result 后所有调用处需加 `?` 或 `.map_err()` | grep 所有调用处逐一加 `?`，含 reload 路径中的两处 |
| 41 | `balancer_socks5_ok` 仍偶发失败 | 全量测试环境下的端口竞争 | 与 L2.9 无关，是 #33 的重现，单独运行始终通过 |

### DNS 栈 / L2.10 相关

| # | 问题 | 原因 | 解决方案 |
|---|------|------|---------|
| 42 | `type_name_of_val()` 编译失败 | nightly-only API，stable 不可用 | 改用显式 `HashSet<String>` 追踪 FakeIP tags，config_builder 注册 `mark_fakeip_upstream(tag)` |
| 43 | DnsUpstream trait 方法名不匹配 | Plan 写 `tag()` 但实际是 `name()` | 使用 `name()` 方法 |
| 44 | DnsAnswer 构造 4 参数 | Plan 假设 struct literal，实际是 `DnsAnswer::new(ips, ttl, Source, Rcode)` | 用正确的构造函数 + `cache::Source::Static` / `cache::Rcode::NoError` |
| 45 | RecordType 有 5 个变体 | 无 `Any` 变体，但有 CNAME/MX/TXT | exchange() 中用 `_ => rcode=4 (NotImpl)` 通配 |
| 46 | Decision::HijackDns 导致 5+ 处 non-exhaustive match | 新增 enum variant 后所有 match 必须覆盖 | 逐一在 engine.rs, handler.rs, socks/{mod,udp}.rs, http.rs, anytls.rs 添加 arm |
| 47 | parity feature 编译额外文件 | `cargo check --workspace` 不编译 http.rs/anytls.rs，需 `--features parity` | 构建验证必须包含 `cargo check -p app --features parity` |
| 48 | DnsRoutingRule 新字段破坏 ~8 处测试 | 新增 disable_cache/rewrite_ttl/client_subnet 字段 | 所有测试构造处补 `None` 值 |
| 49 | rewrite_ttl 类型不匹配 u64 vs u32 | IR 定义为 u32，plan 写 u64 | 统一为 `Option<u32>` |
| 50 | Cache Key 新增 transport_tag 字段 | `Key { name, qtype }` → `Key { name, qtype, transport_tag }` | grep 所有 `Key {` 构造处加 `transport_tag: None` (~8 处) |
| 51 | Agent 403 配额错误中断 Task | opus agent token 配额用尽 | 验证 agent 已完成工作后标记任务完成，后续任务用新 agent |

### Interop-Lab / L5-L7 相关

| # | 问题 | 原因 | 解决方案 |
|---|------|------|---------|
| 52 | `cargo run -p interop-lab -- case list` 报 "missing field `kind`" | GuiStep 用 `kind:` tag 而非 `type:` | YAML 中 gui_sequence entry 必须用 `kind: http/ws_collect/sleep` |
| 53 | GuiStep 反序列化报 "missing field `name`" | 字段名是 `name` 不是 `label` | 所有 HTTP/WS gui step 必须有 `name:` 字段 |
| 54 | traffic_plan 报 "invalid type: map, expected a sequence" | `traffic_plan` 是平铺 `Vec<TrafficAction>` 而非嵌套 `{ steps: [] }` | 写 `traffic_plan: []` 而非 `traffic_plan: { steps: [] }` |
| 55 | assertions 报 "missing field `expected`" | assertions 用 `expected:` 不是 `value:` | `- key: errors.count, op: eq, expected: 0` |
| 56 | case 反序列化报 "missing field `bootstrap`" | CaseSpec 要求 `bootstrap:` 必填（含 `rust:` 子结构） | 必须包含 `bootstrap.rust.{command, args, api.base_url}` |
| 57 | `upstream_topology` vs `upstreams` | CaseSpec 字段名是 `upstream_topology` 不是 `upstreams` | 检查 case_spec.rs 确认字段名 |
| 58 | `description` vs `title` | CaseSpec 用 `title: Option<String>` 不是 `description` | 用 `title:` 字段 |
| 59 | 并行 case 运行端口冲突 | admin port 和 base_url port 全局不唯一 | 每个 case 分配唯一端口范围（19301-19309 for L11-L14 cases） |

### 弃用检测 / L12 相关

| # | 问题 | 原因 | 解决方案 |
|---|------|------|---------|
| 60 | migrate_to_v2() 签名变更破坏 7 处调用方 | 返回类型从 `Value` 改为 `(Value, Vec<MigrationDiagnostic>)` | grep 所有 `migrate_to_v2` 调用方，添加 `.0` 或解构 `let (val, diags) = ...` |
| 61 | check_cli 测试 `schema_v2_validate_flag_works` 失败 | v1 风格测试配置触发新增的弃用检测 | 更新测试配置为 v2 语法（`when: { domain_suffix: [...] }, to: "direct"`） |
| 62 | v2 rule validation 误报 "no match conditions" | `validate_rule()` 仅检查平铺属性，忽略 v2 `when` wrapper | 添加对 `when` 对象的检查，包括 v2 短格式 keys（`suffix`, `keyword`, `regex`） |

### 服务安全 / L13 相关

| # | 问题 | 原因 | 解决方案 |
|---|------|------|---------|
| 63 | sb-core/Cargo.toml 添加 tower dev-dependency 导致 boundary violation | check-boundaries.sh 扫描所有依赖（含 dev-dependencies）中的禁止 crate | 移除 tower dev-dependency（service.rs 测试不需要它） |
| 64 | `get_services_health` 无法访问 ServiceManager 实例 | sb-api 无法直接引用 sb-core 的 ServiceManager（跨 crate 架构限制） | 返回静态响应作为占位，后续通过 ApiState 扩展注入 |
| 65 | `balancer_socks5_ok` 在 `cargo test --workspace` 中 flaky 失败 | 全工作空间并行运行时端口冲突（SOCKS5 handshake error） | 已知预存问题，单独运行 `cargo test -p sb-core --test udp_balancer` 始终通过 |

### TLS / L14 相关

| # | 问题 | 原因 | 解决方案 |
|---|------|------|---------|
| 66 | rustls-native-certs 在 CI Linux 上可能失败 | 某些 CI 环境无系统证书库 | System 模式加载失败时自动回退 Mozilla 模式（`base_root_store()` fallback 逻辑） |
| 67 | notify crate 在 CI 中不触发事件 | CI 无真实文件变化 | CertificateWatcher 单元测试仅验证启动/停止/Drop，真实文件监听在集成测试验证 |
| 68 | CertificateIR 新字段破坏现有配置解析 | 新增 `store`/`certificate_directory_path` 字段 | 全部使用 `Option<T>` + `#[serde(default)]`，向后兼容 |

---

### 测试 Flaky / 全局静态污染

| # | 问题 | 原因 | 解决方案 |
|---|------|------|---------|
| 69 | `test_explicit_metrics_owner_tracks_prefetch_depth` 断言 `high_watermark == 3` 但得到 5 | `HIGH_WATERMARK` 是模块级 `AtomicU64`，CAS 只增不减；非 serial 测试 `test_enqueue_when_enabled` 通过 `enqueue()` → `observe_depth()` 累加 | 测试前 `HIGH_WATERMARK.store(0, Relaxed)` 重置 |
| 70 | `build_redactor_avoids_runtime_dependency_side_effects` 断言 security metrics 未安装但已安装 | `app_runtime_deps_exposes_owned_metrics_handle` 调用 `AppRuntimeDeps::new()` 安装全局 `DEFAULT_STATE` 后未清理；且缺 `#[serial]` | 添加 `#[serial]` + 前后 `clear_default_for_test()` |

---

*最后更新：2026-03-24（新增 #69-#70 测试 flaky 全局静态污染）*
