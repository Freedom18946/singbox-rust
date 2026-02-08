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

---

*最后更新：2026-02-08*
