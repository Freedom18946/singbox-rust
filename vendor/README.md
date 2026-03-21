# Vendored Dependencies

本目录包含通过 `[patch.crates-io]` 或直接 `path` 引用的本地依赖源码。

## 目录

| 目录 | 引用方式 | 用途 |
|------|----------|------|
| `anytls-rs/` | `[patch.crates-io]` | AnyTLS 协议实现（定制 fork） |
| `rustls/` | `[patch.crates-io]` | 定制版 rustls（ECH / 协议扩展） |
| `tun2socks/` | sb-adapters 直接 `path =` 依赖 | macOS TUN shim（默认 stub，`real` feature 启用真实实现） |

## 注意事项

- `anytls-rs` 和 `rustls` 的 patch 声明在根 `Cargo.toml` 的 `[patch.crates-io]` 段
- `tun2socks` 由 `crates/sb-adapters/Cargo.toml` 直接引用，不经 patch
- `tun2socks` 的 stub 模式仅供编译，所有函数调用返回成功不执行实际操作
