# Cross Compilation

Lightweight notes on cross-target builds.

## Examples

```bash
cargo build --target x86_64-unknown-linux-gnu --release
cargo build --target aarch64-apple-darwin --release
cargo build --target x86_64-pc-windows-msvc --release
```

## Notes

- Install targets with `rustup target add <target>`
- Some features are platform-specific (TUN, process matching)
