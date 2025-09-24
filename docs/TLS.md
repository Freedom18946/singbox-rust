# TLS 客户端（rustls 0.23 / tokio-rustls 0.26）

## 架构

- 统一入口：`sb_core::transport::tls::TlsClient`
- 默认 **WebPKI 根** 校验；可通过环境变量切换 **NoVerify**（仅测试）
- 指标：`outbound_connect_seconds_bucket{kind="tls",phase="tls_handshake"}`、`outbound_error_total{kind="tls",phase="tls_handshake",class}`

## 环境变量

- `SB_TLS_NO_VERIFY=1`：关闭证书校验（**仅测试**）

## 兼容性

- 未启用 `tls_rustls` feature 时，`TlsClient` 退化为桩（透传），**不改变既有行为**。
- `dns_dot` 需与 `tls_rustls` **共同启用**。

## 使用方式

### 基本用法

```rust
use sb_core::transport::tls::TlsClient;

// 从环境变量创建客户端
let tls = TlsClient::from_env();

// 连接并完成 TLS 握手
let stream = tls.connect("example.com", tcp_stream).await?;
```

### 自定义配置

```rust
use sb_core::transport::tls::{TlsClient, ClientAuth};

let tls = TlsClient::builder()
    .verified_default_roots()  // 或 .no_verify() 用于测试
    .build();

let stream = tls.connect("example.com", tcp_stream).await?;
```

## Feature 控制

- `tls_rustls`：启用真实 TLS 实现（rustls 0.23）
- 未启用时：TLS 客户端为桩实现，直接透传流量（不加密）

## 指标监控

启用 `metrics` feature 时，TLS 握手会产生以下指标：

- `outbound_connect_seconds_bucket{kind="tls",phase="tls_handshake"}`: 握手耗时分布
- `outbound_connect_total{kind="tls",phase="tls_handshake",result="ok"}`: 成功握手计数
- `outbound_error_total{kind="tls",phase="tls_handshake",class="..."}`: 错误分类计数

### 错误分类

TLS 错误会根据类型分类为：
- `tls_cert`: 证书错误
- `tls_verify`: 证书验证失败
- `handshake`: 握手协议错误
- `timeout`: 超时
- `io`: I/O 错误

## 安全注意事项

⚠️ **重要**：`SB_TLS_NO_VERIFY=1` 会跳过所有证书验证，仅应用于：
- 测试环境
- 内网自签证书场景
- **绝不应在生产环境使用**

默认行为使用 WebPKI 根证书进行严格验证，这是生产环境的推荐配置。

## 示例与测试

### 运行示例

```bash
# 基本 TLS 握手测试
cargo run --example tls_handshake --features tls_rustls -- example.com 443

# 使用自定义主机和端口
HOST=httpbin.org PORT=443 cargo run --example tls_handshake --features tls_rustls

# 跳过证书验证（仅测试）
SB_TLS_NO_VERIFY=1 cargo run --example tls_handshake --features tls_rustls -- badssl.com 443
```

### 运行烟雾测试

```bash
# 完整的 TLS 烟雾测试（包括指标检查）
./scripts/e2e_tls_smoke.zsh

# 自定义测试目标
HOST=httpbin.org PORT=443 ./scripts/e2e_tls_smoke.zsh
```

## DoT 集成

DNS over TLS (DoT) 已集成使用统一的 TLS 客户端：

- DoT 需要同时启用 `dns_dot` 和 `tls_rustls` features
- DoT 查询会自动使用 `TlsClient::from_env()` 配置
- 支持通过 `SB_TLS_NO_VERIFY=1` 跳过证书验证（测试）

## 故障排除

### 编译错误

如果遇到 TLS 相关编译错误：
1. 确保启用了 `tls_rustls` feature
2. 检查 rustls 版本兼容性（应为 0.23.x）
3. 确保 tokio-rustls 版本为 0.26.x

### 运行时错误

- **证书验证失败**：检查系统时间，确认目标证书有效
- **连接超时**：检查网络连接和防火墙设置
- **TLS 协议错误**：目标服务器可能不支持 TLS 1.2/1.3

### 调试

启用详细日志：
```bash
RUST_LOG=debug cargo run --example tls_handshake --features tls_rustls
```

## 版本信息

- rustls: 0.23.x
- tokio-rustls: 0.26.x
- webpki-roots: 0.26.x

这些版本确保与 sing-box-rust 生态系统的兼容性。