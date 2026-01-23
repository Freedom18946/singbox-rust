# 🚀 Getting Started with singbox-rust

Get up and running with singbox-rust in **5 minutes**!

---

## What is singbox-rust?

**singbox-rust** is a high-performance, memory-safe proxy platform written in Rust. It provides:

- **Universal Proxy**: SOCKS5, HTTP, TUN, VMess, VLESS, Trojan, Shadowsocks, Hysteria, TUIC, and more
- **Smart Routing**: Route traffic based on domain, IP, protocol, process, and more
- **Anti-Censorship**: REALITY and ECH protocols for enhanced privacy
- **Production-Ready**: 100% feature parity with upstream sing-box, with better performance

**Use Cases**:

- Privacy-focused browsing
- Bypassing network restrictions
- Load balancing and failover
- Development and testing proxies
- Self-hosted VPN alternatives

---

## Installation

### From Pre-built Binaries (Recommended)

Download the latest release for your platform:

```bash
# Linux x86_64
curl -LO https://github.com/your-repo/releases/download/v0.2.0/singbox-rust-linux-x86_64.tar.gz
tar xzf singbox-rust-linux-x86_64.tar.gz
sudo mv app /usr/local/bin/singbox-rust

# macOS (Apple Silicon)
curl -LO https://github.com/your-repo/releases/download/v0.2.0/singbox-rust-macos-arm64.tar.gz
tar xzf singbox-rust-macos-arm64.tar.gz
sudo mv app /usr/local/bin/singbox-rust

# Verify installation
singbox-rust version
```

### From Source

**Requirements**: Rust 1.90+

```bash
# Clone repository
git clone https://github.com/your-repo/singbox-rust.git
cd singbox-rust

# Build with all features
cargo build -p app --features "acceptance,manpage" --release

# Binary will be at: target/release/app
sudo cp target/release/app /usr/local/bin/singbox-rust
```

### Using Docker

```bash
# Pull image
docker pull your-registry/singbox-rust:latest

# Run with config
docker run -d \
  -v $PWD/config.yaml:/etc/singbox/config.yaml \
  -p 1080:1080 \
  -p 18088:18088 \
  your-registry/singbox-rust:latest \
  run -c /etc/singbox/config.yaml
```

### Package Managers

```bash
# Homebrew (macOS/Linux)
brew install singbox-rust

# Cargo (Rust package manager)
cargo install singbox-rust

# AUR (Arch Linux)
yay -S singbox-rust
```

---

## Build from Source

### Build with Acceptance Features

Build the full-featured binary for testing and release candidates:

```bash
# Build with all acceptance features enabled
cargo +1.90 build -p app --features "acceptance,manpage" --release

# Binary will be at: target/release/app
```

### Essential CLI Examples

```bash
# 1) Validate configuration (exit codes: 0=ok, 1=warnings, 2=errors)
./target/release/app check -c config.json --format json

# 2) Explain routing decision for a destination
./target/release/app route -c config.json --dest example.com:443 --explain --format json

# 3) Display version with build metadata
./target/release/app version --format json

# 4) Generate shell completions for all shells
./target/release/app gen-completions --all --dir completions/
```

### Full Development Workflow

```bash
cargo check --workspace --all-features
bash scripts/ci/local.sh
scripts/e2e/run.sh   # optional e2e summary → .e2e/summary.json

# Run comprehensive E2E tests (auth + rate limiting)
cargo run -p xtask -- e2e

# Run app with adapter bridge (HTTP/SOCKS/Mixed/TUN via sb-adapters)
cargo run -p app --features "adapters,router" -- --config config.json
```

---

## Quick Start: Your First Proxy

### 1. Create a Minimal Configuration

Create `config.yaml`:

```yaml
schema_version: 2

# Local SOCKS5 proxy listening on port 1080
inbounds:
  - type: socks
    tag: socks-in
    listen: 127.0.0.1
    port: 1080

# Route all traffic directly (no upstream proxy)
outbounds:
  - type: direct
    tag: direct-out

# Simple routing: everything goes to direct-out
route:
  rules:
    - outbound: direct-out
  default: direct-out
```

### 2. Validate Configuration

```bash
singbox-rust check -c config.yaml
# ✓ Configuration is valid
```

### 3. Run the Proxy

```bash
singbox-rust run -c config.yaml
# [INFO] Starting singbox-rust v0.2.0
# [INFO] Listening on socks://127.0.0.1:1080
```

### 4. Test the Proxy

In another terminal:

```bash
# Test with curl
curl -x socks5h://127.0.0.1:1080 https://ifconfig.me

# Or configure your browser to use SOCKS5 proxy:
# Host: 127.0.0.1
# Port: 1080
```

**Congratulations!** 🎉 You've set up your first proxy!

---

## Next Steps

### 📖 Learn More

- **[Basic Configuration Guide](basic-configuration.md)** - Understand the config structure
- **[Add an Upstream Proxy](first-proxy.md)** - Connect to a remote proxy server
- **[User Guide](../01-user-guide/)** - Deep dive into features

### 🔧 Common Configurations

- **[SOCKS5 + HTTP on One Port](../08-examples/basic/mixed-proxy.md)** - Mixed inbound
- **[TUN Mode (System-wide Proxy)](../08-examples/basic/tun-mode.md)** - Transparent proxy
- **[Load Balancing](../08-examples/advanced/load-balancing.md)** - Multiple upstreams

### 🎓 Advanced Topics

- **[REALITY Protocol](../01-user-guide/protocols/reality.md)** - Anti-censorship TLS
- **[Smart Routing](../01-user-guide/configuration/routing.md)** - Route by domain, IP, process
- **[DNS Configuration](../01-user-guide/configuration/dns.md)** - FakeIP, DoH, DoT

---

## Command Cheat Sheet

```bash
# Validate configuration
singbox-rust check -c config.yaml

# Run proxy server
singbox-rust run -c config.yaml

# Test routing decision
singbox-rust route -c config.yaml --dest example.com:443 --explain

# Format configuration file
singbox-rust format -c config.yaml -w

# Generate REALITY keypair
singbox-rust generate reality-keypair

# Show version
singbox-rust version

# Enable debug logging
RUST_LOG=debug singbox-rust run -c config.yaml
```

See [CLI Reference](../02-cli-reference/) for all commands.

---

## FAQ

### Q: What's the difference between singbox-rust and sing-box (Go)?

**A**: singbox-rust is a complete Rust rewrite with:

- **Better performance**: 149x faster process matching on macOS
- **Memory safety**: No null pointer crashes, use-after-free, or data races
- **Drop-in compatible**: Use the same configuration files
- **Modern tooling**: Better error messages, stricter validation

### Q: Can I use my existing sing-box configuration?

**A**: Yes! singbox-rust supports V1 (Go sing-box) configs and automatically migrates them to V2 format:

```bash
singbox-rust check -c old-config.json --migrate --write-normalized --out new-config.json
```

### Q: Which protocols are supported?

**A**: All major protocols are fully supported - **100% of Go protocol coverage achieved!**

- **Inbounds (18/18)**: SOCKS5, HTTP, Mixed, Direct, DNS, TUN, Redirect, TProxy, Shadowsocks, VMess, VLESS, Trojan, Naive, ShadowTLS, AnyTLS, Hysteria v1, Hysteria v2, TUIC
- **Outbounds (19/19)**: Direct, Block, DNS, HTTP, SOCKS5, SSH, Shadowsocks, VMess, VLESS, Trojan, ShadowTLS, TUIC, Hysteria v1, Hysteria v2, Tor, AnyTLS, WireGuard, Selector, URLTest

See [Migration Guide](../docs/MIGRATION_GUIDE.md) for full protocol matrix and feature parity details.

### Q: How do I enable TUN mode on Linux?

**A**: TUN requires `CAP_NET_ADMIN` capability:

```bash
# Option 1: Run as root (not recommended)
sudo singbox-rust run -c config.yaml

# Option 2: Grant capability (recommended)
sudo setcap cap_net_admin+ep $(which singbox-rust)
singbox-rust run -c config.yaml

# Option 3: Use systemd with AmbientCapabilities
# See docs/03-operations/deployment/systemd.md
```

### Q: How do I update to the latest version?

**A**:

```bash
# From binaries
curl -LO https://github.com/your-repo/releases/latest/download/singbox-rust-linux-x86_64.tar.gz
tar xzf singbox-rust-linux-x86_64.tar.gz
sudo mv app /usr/local/bin/singbox-rust

# From source
cd singbox-rust
git pull
cargo build -p app --features "acceptance,manpage" --release
sudo cp target/release/app /usr/local/bin/singbox-rust

# Using package managers
brew upgrade singbox-rust
# or
cargo install singbox-rust --force
```

### Q: Where can I find example configurations?

**A**: See [`docs/08-examples/`](../08-examples/) for ready-to-use examples, or check out:

- `examples/configs/` in the repository
- [Configuration Gallery](../08-examples/README.md)
- [User Guide](../01-user-guide/configuration/overview.md)

### Q: How do I troubleshoot connection issues?

**A**:

1. **Enable debug logging**:

   ```bash
   RUST_LOG=debug singbox-rust run -c config.yaml
   ```

2. **Test routing**:

   ```bash
   singbox-rust route -c config.yaml --dest example.com:443 --explain --format json
   ```

3. **Validate config**:

   ```bash
   singbox-rust check -c config.yaml --format json
   ```

4. **Check metrics** (if admin enabled):
   ```bash
   curl http://127.0.0.1:18088/metrics
   ```

See [Troubleshooting Guide](../01-user-guide/troubleshooting.md) for common issues.

---

## Getting Help

- **Documentation**: You're here! Browse [docs/](../)
- **GitHub Issues**: [Report bugs](https://github.com/your-repo/issues)
- **Discussions**: [Ask questions](https://github.com/your-repo/discussions)
- **Examples**: [Configuration examples](../08-examples/)

---

## What's Next?

Now that you have singbox-rust running, explore:

1. **[Basic Configuration Guide](basic-configuration.md)** - Understand config structure in depth
2. **[Add Your First Proxy](first-proxy.md)** - Connect to an upstream VMess/VLESS/Trojan server
3. **[User Guide](../01-user-guide/)** - Learn all features
4. **[Operations Guide](../03-operations/)** - Deploy to production

Happy proxying! 🎉
