# Vendored Dependencies

本目录包含项目所需的特殊依赖项，这些依赖无法直接从 crates.io 获取或需要特殊处理。

## 目录结构

### tun2socks/

**用途**: 编译时 stub，用于替代真实的 `tun2socks` crate

**为什么需要**:
- 真实的 `tun2socks` crate 依赖特定的构建环境和工具链
- 需要网络访问和外部 Go 工具链支持
- 在 CI/CD 或离线环境中难以构建
- 使用稳定工具链编译所有特性时需要此 stub

**工作原理**:
通过 `Cargo.toml` 中的 `[patch.crates-io]` 机制，将 crates.io 上的 `tun2socks` 替换为本地 stub 实现：

```toml
[patch.crates-io]
tun2socks = { path = "vendor/tun2socks" }
```

**限制**:
- ⚠️ 此 stub **仅供编译使用**，不提供运行时功能
- 所有函数调用立即返回成功，不执行实际操作
- 生产环境必须使用真实的 tun2socks 实现或外部进程

## 切换到真实实现

如果你需要实际的 TUN 设备功能：

1. **方式一：使用外部 tun2socks 进程**（推荐）
   - 单独编译和运行 tun2socks
   - 通过 IPC 或配置文件与本项目集成

2. **方式二：移除 patch**
   - 从 `Cargo.toml` 中注释或删除 `[patch.crates-io]` 部分
   - 确保构建环境具备必要的工具链和依赖
   - 重新构建项目

3. **方式三：条件编译**
   - 为生产构建创建单独的 feature flag
   - 使用 `cfg` 属性选择性启用真实实现

## 添加新的 vendored 依赖

如果需要添加其他 vendored 依赖：

1. 在此目录下创建新的子目录
2. 添加完整的 Cargo.toml 和实现代码
3. 在根 Cargo.toml 的 `[patch.crates-io]` 中添加对应条目
4. 更新本 README 说明新依赖的用途和限制

## 相关文档

- [Cargo Patch 机制](https://doc.rust-lang.org/cargo/reference/overriding-dependencies.html#the-patch-section)
- [TUN 设备适配器实现](../crates/sb-adapters/src/inbound/tun.rs)
- [平台抽象层](../crates/sb-platform/)
