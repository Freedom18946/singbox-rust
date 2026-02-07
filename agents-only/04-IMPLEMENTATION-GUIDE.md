# 实现指南（Implementation Guide）

> **整合自 singbox_archspec_v2 和根目录文档**：提供迁移计划、开发规范和参考模板。

---

## 1. 迁移计划（Migration Plan）

### 1.1 Phase 0：立法（必须先做）

**目标**：建立依赖边界检查机制

**任务**：
- [x] 落地依赖边界检查（CI）
- [x] 建立 crate 宪法
- [x] 冻结新增越界依赖

**验收**：
```bash
# 任意新 PR 不能增加 sb-core 对 Web/TLS/QUIC 的依赖
cargo tree -p sb-core | grep -E "axum|tonic|tower|hyper|rustls|quinn"
# 预期：无输出
```

### 1.2 Phase 1：迁出协议实现

**目标**：sb-core 不包含任何协议实现

**任务**：
- [ ] 将 `sb-core/src/outbound/*` 移至 `sb-adapters/src/outbound/*`
- [ ] 将 `sb-core/src/inbound/*` 协议实现移至 `sb-adapters/src/inbound/*`
- [ ] sb-core 只保留 Outbound 选择与调度

**验收**：
```bash
# sb-core 不包含协议握手/加密代码
grep -r "vmess\|vless\|trojan\|shadowsocks" crates/sb-core/src/ --include="*.rs"
# 预期：只有类型引用，无实现
```

### 1.3 Phase 2：迁出平台服务

**目标**：sb-core 不包含平台服务实现

**任务**：
- [ ] 将 `sb-core/src/services/*` 迁到 `sb-platform/src/...`
- [ ] 对外以 Ports 形式提供

**验收**：
```bash
# sb-core 不包含 systemd-resolved/NTP/DERP 实现
grep -r "resolved\|ntp\|derp" crates/sb-core/src/ --include="*.rs"
# 预期：只有 trait 定义
```

### 1.4 Phase 3：控制面解耦

**目标**：控制面与数据面完全隔离

**任务**：
- [ ] sb-core 暴露 `AdminPort/StatsPort`
- [ ] sb-api 注入 Ports

**验收**：
```bash
# sb-api 不依赖 sb-adapters
cargo tree -p sb-api | grep "sb-adapters"
# 预期：无输出

# sb-core 不依赖 web 框架
cargo tree -p sb-core | grep -E "axum|tonic|tower|hyper"
# 预期：无输出
```

---

## 2. 开发规范（Development Standards）

### 2.1 Async 模型

```rust
// ✅ 正确：使用 tokio 原语
async fn handle_connection(conn: TcpStream) -> Result<()> {
    // ...
}

// ❌ 错误：阻塞操作
fn handle_connection_blocking(conn: TcpStream) -> Result<()> {
    std::thread::sleep(Duration::from_secs(1)); // 不要在 async 中这样做
}
```

### 2.2 错误处理

```rust
// 使用 thiserror 定义错误类型
#[derive(Debug, thiserror::Error)]
pub enum RouterError {
    #[error("rule not found: {0}")]
    RuleNotFound(String),
    
    #[error("connection failed: {source}")]
    ConnectionFailed {
        #[from]
        source: std::io::Error,
    },
}
```

### 2.3 Feature 策略

```toml
# app/Cargo.toml
[features]
default = []
parity = [
    "adapters",
    "dns_udp", "dns_doh", "dns_dot", "dns_doq", "dns_doh3",
    "dns_dhcp", "dns_resolved", "dns_tailscale",
    "service_ntp", "service_resolved", "service_ssmapi", "service_derp",
    "clash_api", "v2ray_api",
]

# 只在 app 聚合 features
# 其他 crate 不要用 feature 当"隐式依赖开关"
```

### 2.4 测试策略

```rust
// 单元测试：使用 mock
#[cfg(test)]
mod tests {
    use super::*;
    use mockall::mock;

    mock! {
        pub OutboundConnector {}
        impl OutboundConnector for OutboundConnector {
            async fn connect(&self, addr: &str) -> Result<Connection>;
        }
    }

    #[tokio::test]
    async fn test_router_with_mock() {
        let mut mock = MockOutboundConnector::new();
        mock.expect_connect().returning(|_| Ok(Connection::mock()));
        // ...
    }
}

// 集成测试：使用真实组件
#[tokio::test]
async fn test_shadowsocks_e2e() {
    let server = start_test_server().await;
    let client = create_client(&server.addr()).await;
    // ...
}
```

---

## 3. 代码模板（Templates）

### 3.1 Enum Dispatch 模板

```rust
// sb-types/src/outbound.rs
pub trait OutboundConnector: Send + Sync {
    fn connect(&self, ctx: &ConnectContext) -> BoxFuture<'_, Result<Connection>>;
}

// sb-adapters/src/outbound/mod.rs
pub enum OutboundDispatch {
    Direct(DirectOutbound),
    Shadowsocks(ShadowsocksOutbound),
    VMess(VMessOutbound),
    // ...
}

impl OutboundConnector for OutboundDispatch {
    fn connect(&self, ctx: &ConnectContext) -> BoxFuture<'_, Result<Connection>> {
        match self {
            Self::Direct(o) => o.connect(ctx),
            Self::Shadowsocks(o) => o.connect(ctx),
            Self::VMess(o) => o.connect(ctx),
        }
    }
}
```

### 3.2 错误类型模板

```rust
// 每个 crate 定义自己的错误类型
#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    #[error("protocol error: {0}")]
    Protocol(String),
    
    #[error("connection error")]
    Connection(#[from] std::io::Error),
    
    #[error("config error: {0}")]
    Config(String),
}

// 在 crate 边界转换错误
impl From<AdapterError> for CoreError {
    fn from(e: AdapterError) -> Self {
        CoreError::Adapter(e.to_string())
    }
}
```

### 3.3 Object-Safe Wrapper 模板

```rust
// 当需要 object-safety 时
pub trait OutboundConnectorDyn: Send + Sync {
    fn connect_dyn(&self, ctx: &ConnectContext) -> BoxFuture<'_, Result<Connection>>;
}

impl<T: OutboundConnector> OutboundConnectorDyn for T {
    fn connect_dyn(&self, ctx: &ConnectContext) -> BoxFuture<'_, Result<Connection>> {
        self.connect(ctx)
    }
}
```

---

## 4. 工具链配置（Toolchain）

### 4.1 rust-toolchain.toml

```toml
[toolchain]
channel = "1.92"
components = ["rustfmt", "clippy"]
```

### 4.2 clippy.toml

```toml
msrv = "1.92"
```

### 4.3 deny.toml

```toml
[advisories]
vulnerability = "deny"
unmaintained = "warn"

[licenses]
allow = ["MIT", "Apache-2.0", "BSD-3-Clause", "BSD-2-Clause", "ISC"]
```

### 4.4 CI 检查脚本

```bash
#!/bin/bash
# scripts/ci/check.sh

set -e

# Format
cargo fmt --check

# Lint
cargo clippy --workspace --all-features -- -D warnings

# Test
cargo test --workspace

# Security
cargo deny check

# Build parity
cargo build -p app --features parity --release
```

---

## 5. 性能指南（Performance Guidelines）

### 5.1 热路径优化

```rust
// ✅ 优先使用 enum 静态分发
match outbound {
    Outbound::Direct(o) => o.connect(ctx).await,
    Outbound::Shadowsocks(o) => o.connect(ctx).await,
}

// ❌ 避免在热路径使用 dyn Trait
let outbound: Box<dyn OutboundConnector> = ...;
outbound.connect(ctx).await; // 有虚表查找开销
```

### 5.2 内存分配

```rust
// ✅ 预分配 buffer
let mut buf = vec![0u8; 4096];
stream.read(&mut buf).await?;

// ❌ 避免频繁小分配
loop {
    let buf = vec![0u8; 64]; // 每次循环都分配
}
```

### 5.3 Metrics 最佳实践

```rust
// ✅ 使用 Atomic 计数器
static CONNECTIONS: AtomicU64 = AtomicU64::new(0);
CONNECTIONS.fetch_add(1, Ordering::Relaxed);

// ❌ 避免在热路径加锁
let mut guard = metrics.lock().await;
guard.connections += 1;
```

---

## 6. 日志与监控（Logging & Monitoring）

### 6.1 日志级别

| 级别 | 用途 |
|------|------|
| ERROR | 不可恢复错误 |
| WARN | 可恢复异常 |
| INFO | 重要状态变化 |
| DEBUG | 调试信息 |
| TRACE | 详细调试 |

### 6.2 Tracing 使用

```rust
use tracing::{info, debug, span, Level};

pub async fn handle_connection(conn: Connection) -> Result<()> {
    let span = span!(Level::INFO, "connection", id = %conn.id());
    let _guard = span.enter();
    
    info!("connection established");
    // ...
    debug!(bytes = %n, "data transferred");
}
```

---

## 7. 安全指南（Security Guidelines）

### 7.1 凭证处理

```rust
use sb_security::{redact_token, redact_key};

// ✅ 正确：脱敏日志
info!("auth token: {}", redact_token(token));

// ❌ 错误：明文日志
info!("auth token: {}", token); // 敏感信息泄露！
```

### 7.2 密钥管理

```rust
// 优先使用环境变量
let key = std::env::var("JWT_SIGNING_KEY")?;

// 文件方式需检查权限
let metadata = std::fs::metadata(&path)?;
let permissions = metadata.permissions();
if permissions.mode() & 0o077 != 0 {
    return Err(Error::InsecurePermissions);
}
```

---

*本文档为 AI Agent 开发参考，请结合具体任务使用。*
