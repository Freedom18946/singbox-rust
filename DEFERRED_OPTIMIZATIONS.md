# Deferred Optimizations

本文档记录暂不实施的优化建议，需在未来评估收益后决定是否实施。

---

## 1. run.rs 信号处理重构

**文件**: `app/src/bin/run.rs`

**当前问题**:
- 信号处理逻辑（SIGINT/SIGTERM/SIGHUP）分散在 `main` 函数的 `tokio::select!` 块中
- SIGINT 和 SIGTERM 的关闭逻辑重复
- SIGHUP 处理器包含无限循环，控制流不够清晰

**建议改进**:
1. 使用 `tokio::signal::unix::signal` 为所有信号创建独立的流
2. 使用 `tokio_stream::StreamExt::merge` 合并为单一信号流
3. 在主循环中监听合并流，通过单一处理函数根据信号类型分发到 `handle_reload` 或 `handle_shutdown`
4. 消除代码重复，简化主循环结构

**暂不实施原因**:
- 信号处理是关键路径，重构可能引入微妙的 bug
- 当前代码运行稳定，收益 < 风险
- 可推迟到有大规模重构需求时一并处理

**优先级**: 低

---

## 2. engine.rs 路由性能优化

**文件**: `crates/sb-core/src/routing/engine.rs`

**当前问题**:
- `decide` 函数使用线性扫描查找匹配规则（O(N) 复杂度）
- 对于包含数千条规则的配置，可能成为性能瓶颈

**建议改进**:
1. **IP CIDR 匹配**: 使用 Radix Tree（PATRICIA trie，如 `ip_network_table-deps-treebitmap` crate）实现 O(log N) 查找
2. **域名后缀匹配**: 使用 Suffix Trie 优化域名匹配
3. **GeoSite 规则**: 使用 Aho-Corasick 算法进行多模式匹配

**暂不实施原因**:
- 这是典型的"过早优化"
- 引入复杂数据结构会显著增加代码复杂度和依赖
- **必须先做性能基准测试**，证明当前 O(N) 确实是瓶颈

**实施前提**:
1. 使用实际配置（如 3000+ 条规则）进行基准测试
2. 如果 99 百分位延迟 < 1ms，则无需优化
3. 仅在确认为瓶颈时才引入复杂数据结构

**优先级**: 需要先评估（基准测试）

**评估方法**:
```bash
# 创建包含 3000 条规则的测试配置
# 使用 criterion 进行路由决策的基准测试
# 目标阈值：p99 < 1ms 则无需优化
```

---

## 3. dialer.rs Happy Eyeballs 交错优化

**文件**: `crates/sb-transport/src/dialer.rs`

**当前实现**:
- 立即启动第一个 IPv6 连接
- 延迟 50ms 后启动第一个 IPv4 连接
- 批量启动其余所有 IPv6 地址
- 批量启动其余所有 IPv4 地址

**建议改进**:
- 更严格的 RFC 8305 交错策略：IPv6 → 延迟 → IPv4 → 延迟 → 下一个 IPv6 → 延迟 → 下一个 IPv4...
- 在多个地址都无响应的极端网络场景下，理论上能更快找到可用路径

**暂不实施原因**:
1. **当前实现已是合理的 Happy Eyeballs**：优先 IPv6，并发尝试所有地址，返回首个成功连接
2. **性价比低**：
   - 实现复杂度显著增加（需要精细的任务调度逻辑）
   - 在正常网络环境下性能提升微乎其微（首个或前几个地址通常可用）
   - 仅在极端场景（大量失败地址 + 高延迟）下才有价值
3. **缺乏实际证据**：无用户报告连接性能问题，无基准测试证明当前实现是瓶颈

**优先级**: 极低（除非有实际性能投诉）

---

## 4. tls_secure.rs 代码重复问题

**文件**: `crates/sb-transport/src/tls_secure.rs`

**审稿意见**:
> SecureTlsDialer::connect 方法与 TlsDialer::connect 有代码重复（建立连接、配置 SNI、ALPN），建议重构为先调用 `self.inner.connect()` 完成 TLS 握手，再进行 pinning 检查。

**实际问题分析**:
该建议**从设计上无法实现**，原因如下：

1. **类型擦除导致信息丢失**:
   - `TlsDialer::connect()` 返回 `Box<dyn AsyncReadWrite>`（trait object）
   - 返回类型已擦除具体的 `TlsStream` 类型信息
   - 无法从 trait object 访问 `peer_certificates()` 等 TLS 特定方法

2. **当前实现的必要性**:
   ```rust
   // 必须调用 inner.inner 绕过 TLS 层，获得原始流
   let stream = self.inner.inner.connect(host, port).await?;
   // 手动执行 TLS 握手，保留对 TlsStream 的访问
   let tls_stream = connector.connect(server_name, stream).await?;
   // 访问 TLS 连接内部状态进行 pinning 验证
   tls_stream.get_ref().1.peer_certificates()
   ```

3. **重构的代价**:
   要消除代码重复，需要：
   - 修改 `Dialer` trait 设计，添加返回具体类型的方法
   - 或引入新的 trait 用于访问 TLS 元数据
   - 大规模重构整个拨号器架构

**暂不实施原因**:
- **当前设计是合理的权衡**：代码重复是为了访问底层 TLS 状态而付出的必要代价
- **重构成本过高**：需要修改核心 trait 设计，影响所有拨号器实现
- **收益有限**：仅减少约 20 行重复代码，但破坏了 API 的简洁性

**优先级**: 不推荐（设计权衡，非缺陷）

**替代方案**:
如果未来需要支持更多 TLS 增强特性（OCSP Stapling、Session Resumption 等），可考虑引入专门的 `TlsMetadata` trait，届时再统一重构。

---

## 5. sb-config 反序列化错误信息增强

**文件**: `crates/sb-config/src/de.rs`

**当前实现**:
- `listen_addr::deserialize` 使用自定义反序列化器解析 ListenAddr（支持字符串 "ip:port" 或对象形式）
- `parse_from_string` 函数在解析失败时返回 `Result<ListenAddr, String>`
- 错误处理已使用 `D::Error::custom` 将字符串错误转换为 serde 错误

**建议改进**:
- 将 `parse_from_string` 的返回类型改为 `Result<ListenAddr, impl DeError>`
- 在内部解析错误点直接使用 `D::Error::custom` 构造更具体的错误信息
- 示例：`port.parse().map_err(|_| D::Error::custom("invalid port number in listen address"))`

**当前错误信息示例**:
```
invalid listen addr, expect 'host:port'
invalid port
```

**改进后错误信息示例**:
```
Error at line 5, column 12: invalid port number in listen address
Expected a valid port (1-65535), got: "badport"
```

**暂不实施原因**:
1. **当前实现已基本够用**：
   - `de.rs:28` 已经使用 `D::Error::custom` 将错误传递给 serde
   - 用户能看到解析失败的原因（"invalid port" 等）
   - serde 已经提供行号信息

2. **收益有限**：
   - 改进仅优化错误消息的可读性
   - 不影响功能正确性
   - ListenAddr 解析错误通常在开发/配置阶段一次性修复，不是高频问题

3. **维护成本**：
   - 需要为每个解析错误点编写详细错误信息
   - 增加测试覆盖范围以验证错误信息准确性

**优先级**: 低（polish 级别优化）

**实施建议**:
如果决定实施，可在以下场景中改进：
- 端口超出范围（0 或 > 65535）：显示实际解析到的值
- IPv6 地址格式错误：提示正确的括号语法 `[::1]:port`
- 缺少冒号：显示完整的输入字符串以便调试

---

## 说明

这些优化建议来自代码审查，但经评估后认为：
- **信号处理重构**: 稳定性风险 > 代码整洁收益
- **路由性能优化**: 需要证据支持（基准测试）才能决定是否实施
- **Happy Eyeballs 交错优化**: 实现复杂度高，性能提升微乎其微
- **TLS 代码重复问题**: 当前设计是合理权衡，重构需修改核心 trait

如果未来出现以下情况，应重新评估：
1. 信号处理出现 bug 需要重构
2. 用户报告大规模路由规则下性能问题
3. 基准测试显示路由决策是热点路径
4. 用户报告 Happy Eyeballs 连接性能问题
5. 需要支持更多 TLS 增强特性（届时可统一重构拨号器架构）
