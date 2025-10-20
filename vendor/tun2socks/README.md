# tun2socks Build Stub

**⚠️ 警告：这是一个构建时 stub，不提供实际功能**

## 概述

这是 `tun2socks` crate 的最小化 stub 实现，仅用于编译时类型检查和特性门控。

## 为什么需要这个 stub？

真实的 `tun2socks` crate 存在以下问题：

1. **复杂的构建依赖**
   - 需要 Go 工具链（用于构建底层 C 绑定）
   - 需要平台特定的 TUN 设备驱动支持
   - 需要网络访问下载外部依赖

2. **跨平台兼容性问题**
   - 在某些 CI 环境中无法构建
   - 在容器化环境中需要特殊权限
   - Windows/macOS/Linux 需要不同的构建配置

3. **工作区全特性构建**
   - 项目使用 `cargo build --all-features` 进行测试
   - 即使不使用 TUN 功能，也会触发编译
   - stub 允许编译通过而不需要实际依赖

## API 表面

此 stub 提供以下 API，与真实 crate 兼容：

```rust
/// 使用 YAML 配置和 TUN 文件描述符启动 tun2socks
pub fn main_from_str(_yaml: &str, _tun_fd: i32) -> Result<(), i32>

/// 请求 tun2socks 运行时终止
pub fn quit()
```

**实现行为**：
- `main_from_str`: 立即返回 `Ok(())`，不执行任何操作
- `quit`: 无操作（no-op）

## 在生产环境使用真实实现

### 方法 1: 移除 patch（推荐用于开发）

编辑根目录 `Cargo.toml`，注释掉 patch：

```toml
[patch.crates-io]
# tun2socks = { path = "vendor/tun2socks" }  # 注释掉这行
```

然后安装必要的系统依赖并重新构建。

### 方法 2: 使用独立的 tun2socks 进程（推荐用于生产）

不直接集成 tun2socks crate，而是：

1. 单独编译和部署 tun2socks 二进制
2. 通过 Unix socket 或命名管道通信
3. 在 `sb-adapters` 中通过进程管理集成

这种方式的优势：
- 隔离构建依赖
- 更好的进程隔离和安全性
- 更容易调试和监控
- 支持热重启 TUN 组件

### 方法 3: 条件特性门控

为真实实现创建专门的 feature：

```toml
[features]
tun-real = []  # 启用真实 tun2socks
```

在代码中：

```rust
#[cfg(feature = "tun-real")]
use tun2socks_real as tun2socks;

#[cfg(not(feature = "tun-real"))]
use tun2socks;  // stub 版本
```

## 相关模块

- `sb-adapters/src/inbound/tun.rs` - TUN 入站适配器
- `sb-adapters/src/inbound/tun_macos.rs` - macOS 特定实现
- `sb-platform` - 平台抽象层

## 维护说明

如果 tun2socks 上游更新 API：

1. 更新 `src/lib.rs` 中的函数签名
2. 确保所有函数返回成功值
3. 添加适当的文档注释
4. 运行 `cargo check --all-features` 验证兼容性

## 许可证

与上游 tun2socks crate 保持一致：MIT OR Apache-2.0
