# singbox-rust

A pragmatic rewrite path for sing-box in Rust. Focused on **good taste**, **never break userspace**, and **boring clarity**.

## 🚨 重要：项目导航权威文档

**⚠️ 开发者必读：在开始任何开发工作之前，请务必阅读并验证 [`PROJECT_STRUCTURE_NAVIGATION.md`](./PROJECT_STRUCTURE_NAVIGATION.md) 的准确性。**

- 📋 **权威性**: 该文档是项目结构的唯一权威参考
- 🔄 **更新责任**: 任何修改项目结构的开发者都必须同步更新该导航文档
- ✅ **验证要求**: 新的开发者或 AI 助手在开始工作前必须验证导航文档的准确性
- 📍 **导航优先**: 所有开发活动都应基于该导航文档进行路径规划

**如发现导航文档与实际项目结构不符，请立即更新文档后再继续开发工作。**

## Quick Start

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

DNS backends (env-driven)

```bash
# Direct backend selection
SB_DNS_ENABLE=1 SB_DNS_MODE=doh cargo run -p app -- run
SB_DNS_ENABLE=1 SB_DNS_MODE=dot cargo run -p app -- run
SB_DNS_ENABLE=1 SB_DNS_MODE=doq cargo run -p app --features "sb-core/dns_doq" -- run

# Resolver pool (race strategy)
SB_DNS_ENABLE=1 \
SB_DNS_POOL="system,udp:127.0.0.1:1053,doh:https://cloudflare-dns.com/dns-query,dot:1.1.1.1:853,doq:1.1.1.1:853@cloudflare-dns.com" \
SB_DNS_POOL_STRATEGY=race \
cargo run -p app -- run
```

NTP background service (experimental)

```bash
# Build with service_ntp feature and enable via env
SB_NTP_ENABLE=1 \
SB_NTP_SERVER=time.google.com:123 \
SB_NTP_INTERVAL_S=1800 \
cargo build -p sb-core --features service_ntp
```

### Logging & Docs

- Runtime logs use `tracing` across binaries and libraries.
- Enable and filter logs via env:
  - `RUST_LOG=info` enables info-level logs (use `debug` for more detail).
  - Example: `RUST_LOG=sb_core=debug,app=info cargo run -p app -- version`.
  - JSON output (when subscriber configured): `RUST_LOG=info APP_LOG_JSON=1 ...`.

- Metrics & redaction
  - Prometheus exporter: set `SB_METRICS_ADDR=127.0.0.1:9090` and the app exposes `/metrics`.
  - Log sampling: set `SB_LOG_SAMPLE=<N>` to rate‑limit info/debug logs per-target per-second (default off).
  - Secret redaction: enabled by default; set `SB_LOG_REDACT=0` to disable. See `METRICS_CATALOG.md` for details and label whitelist.

CLI bench (HTTP/2) requires feature `reqwest`:

```bash
cargo run -p app --features reqwest -- bench io --h2 --url https://example.com --requests 10 --concurrency 2 --json
```

### Performance Baseline & Regression Detection

Record and verify performance baselines using cargo bench:

```bash
# Record baseline (run once on stable machine)
scripts/test/bench/guard.sh record

# Check for regressions (CI/development use)
scripts/test/bench/guard.sh check

# Adjust tolerance threshold (default: ±10%)
BENCH_GUARD_TOL=0.05 scripts/test/bench/guard.sh check
```

The guard script:

- Records hardware/machine info, date, git SHA, and rustc version in baseline.json
- Compares current benchmark results against baseline with configurable tolerance
- Returns exit code 3 for regressions, 2 for setup/parsing failures
- Supports stable benchmarks that avoid external network dependencies

## Lint Baseline

- Workspace default denies warnings: `cargo clippy --workspace --all-targets -- -D warnings`
- Strict lib-only checks (pedantic + nursery):
  - `cargo clippy -p sb-core --lib --features metrics -- -D warnings -W clippy::pedantic -W clippy::nursery -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic -D clippy::todo -D clippy::unimplemented -D clippy::undocumented_unsafe_blocks`
  - `cargo clippy -p sb-platform --lib -- -D warnings -W clippy::pedantic -W clippy::nursery -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic -D clippy::todo -D clippy::unimplemented -D clippy::undocumented_unsafe_blocks`
  - `cargo clippy -p sb-transport --lib -- -D warnings -W clippy::pedantic -W clippy::nursery -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic -D clippy::todo -D clippy::unimplemented -D clippy::undocumented_unsafe_blocks`

Docs & guides:

- Getting Started: [docs/00-getting-started/](docs/00-getting-started/)
- Development: [docs/04-development/](docs/04-development/)
- Operations: [docs/03-operations/](docs/03-operations/)

Local verification:

- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test -p app -q -- --nocapture`
- `cargo test -p sb-core --features metrics -q`

Run with an example:

```bash
bash scripts/tools/run-examples.sh examples/configs/advanced/full_stack.json
```

## 📚 文档导航

### 🗺️ 项目结构导航 (必读)

- **[PROJECT_STRUCTURE_NAVIGATION.md](./PROJECT_STRUCTURE_NAVIGATION.md)** - 项目结构权威导航文档

### 📖 核心文档

- **[docs/](docs/)** - 完整文档门户（全新重构）
  - [Getting Started](docs/00-getting-started/) - 5 分钟快速开始
  - [User Guide](docs/01-user-guide/) - 配置指南和协议说明
  - [CLI Reference](docs/02-cli-reference/) - 命令行工具参考
  - [Operations](docs/03-operations/) - 部署和运维指南
  - [Development](docs/04-development/) - 架构和贡献指南
  - [API Reference](docs/05-api-reference/) - HTTP/gRPC API 文档
  - [Advanced Topics](docs/06-advanced-topics/) - REALITY/ECH 等高级特性
  - [Reference](docs/07-reference/) - Schema 和错误码参考
- [Examples](docs/08-examples/) - 配置示例
 - [UDP Support](docs/UDP_SUPPORT.md) - SOCKS5 UDP 行为、会话/直连路径、NAT 策略、e2e 运行说明

### 🧪 测试文档

- [tests/README.md](tests/README.md) - 测试指南和目录结构

### CLI Parity Commands

The unified `app` binary now mirrors upstream `sing-box` subcommands. Run any tool with:

```bash
cargo run -p app -- <subcommand> [flags]
```

Common examples:

- `cargo run -p app -- format -c config.json -w`
- `cargo run -p app -- merge -c base.json -c override.json merged.json`
- `cargo run -p app -- geoip --file geoip.db list`
- `cargo run -p app -- geosite --file geosite.db export netflix`
- `cargo run -p app -- ruleset validate rules.srs`
- `cargo run -p app -- tools connect example.com:443 -c config.json`

### Adapter Bridge Coverage

Enabling the `adapters` feature switches the bridge to sb-adapters implementations
for the following protocols:

| Protocol | Direction | Extra `sb-adapters` features |
| --- | --- | --- |
| HTTP CONNECT | inbound/outbound | `http`, `adapter-http` |
| SOCKS5 | inbound/outbound | `socks`, `adapter-socks` |
| Mixed (HTTP+SOCKS) | inbound | `mixed`, `http`, `socks` |
| TUN (Phase 1 skeleton) | inbound | `tun`, `adapter-tun` |
| Shadowsocks AEAD | inbound/outbound | `adapter-shadowsocks` |
| VMess | inbound/outbound | `adapter-vmess` |
| VLESS | inbound/outbound | `adapter-vless` |
| Trojan | inbound/outbound | `adapter-trojan` |

Example:

```bash
cargo run -p app \
  --features "router,adapters,sb-adapters/adapter-shadowsocks" \
  -- --config config.json
```

When adapters are disabled (the default), the bridge automatically falls back to the
built-in scaffold implementations.

### Admin 实现选择

运行期可通过 CLI 或环境变量在 **核心实现** 与 **Debug 实现**间切换：

```bash
# 核心 Admin（默认）
run --admin-impl core

# Debug Admin（包含 Dry-Run、审计、config_version 等扩展）
SB_PREFETCH_ENABLE=1 \
SB_PREFETCH_CAP=256 \
SB_PREFETCH_WORKERS=2 \
run --admin-impl debug --admin-listen 127.0.0.1:8088
```

### 🔐 Authentication & Security

**JWT Authentication**: Production-ready JWT validation with:

- RS256/ES256/HS256 algorithm support with configurable allowlist
- JWKS caching with automatic rotation and fallback mechanisms
- Clock skew tolerance (±5 minutes) for robust timestamp validation
- Memory-safe key loading from environment variables, files, or inline configuration

**Security Features**:

- Credential redaction in logs via `sb-security` crate
- Supply chain security with `cargo-deny` policies
- Memory protection with `ZeroizeOnDrop` for sensitive data
- Rate limiting with configurable QPS and burst limits

See [SECURITY.md](SECURITY.md) for complete security documentation and [docs/05-api-reference/](docs/05-api-reference/) for API authentication details.

### 预取（Prefetch）

当 `/subs/...` 响应 `Cache-Control: max-age>=60` 时将触发异步预取，并在 `__metrics` 暴露：

```
sb_prefetch_queue_depth
sb_prefetch_jobs_total{event=...}
```

可使用 `scripts/tools/prefetch-heat.sh` 观察指标变化。

## Protocol Support

### Inbound Protocols (12/12 Complete)

- **SOCKS5**: Full support with UDP relay and authentication
- **HTTP/HTTPS**: HTTP proxy with CONNECT method
- **Mixed**: Combined SOCKS5 + HTTP on single port
- **Direct**: TCP/UDP forwarder with address override
- **TUN**: Virtual network interface (macOS/Linux)
- **Shadowsocks**: AEAD ciphers with UDP relay
- **VMess**: V2Ray protocol with AEAD encryption
- **VLESS**: Lightweight V2Ray protocol with REALITY/ECH support
- **Trojan**: TLS-based protocol with fallback
- **TUIC**: QUIC-based UDP-optimized protocol
- **Hysteria v1**: High-performance QUIC with custom congestion control
- **Hysteria v2**: Enhanced Hysteria with Salamander obfuscation
- **Naive**: Chromium-based HTTP/2 proxy
- **ShadowTLS**: TLS camouflage for Shadowsocks

### Outbound Protocols (15/15 Complete)

- **Direct**: Direct connection to target
- **Block**: Block connections
- **DNS**: DNS query outbound
- **SOCKS5**: SOCKS5 proxy client
- **HTTP/HTTPS**: HTTP proxy client
- **Shadowsocks**: Full cipher suite support
- **VMess**: V2Ray client with transport options
- **VLESS**: VLESS client with REALITY/ECH
- **Trojan**: Trojan client with TLS
- **TUIC**: QUIC-based client with UDP over stream
- **Hysteria v1**: High-performance QUIC client
- **Hysteria v2**: Enhanced Hysteria client
- **SSH**: SSH tunnel with key-based auth
- **Selector**: Manual/auto outbound selection
- **URLTest**: Health-check based selection

### Advanced TLS Features

- **REALITY**: X25519-based TLS camouflage with fallback proxy
- **ECH (Encrypted Client Hello)**: HPKE-encrypted SNI for privacy
- **Standard TLS**: Full TLS 1.2/1.3 with ALPN, SNI, certificate verification
- **Certificate Management**: Custom CA, client certificates, skip verification

### Transport Layers (All Complete)

- **TCP**: Standard TCP transport
- **UDP**: UDP with NAT session management
- **QUIC**: HTTP/3 and custom QUIC protocols
- **WebSocket**: WS and WSS with custom paths
- **HTTP/2**: H2 and H2C transport
- **HTTPUpgrade**: HTTP upgrade to TCP stream
- **gRPC**: gRPC tunnel transport
- **Multiplex**: yamux stream multiplexing

## Status

**Version**: v0.2.0 | **Production Readiness**: ⭐⭐⭐⭐⭐ (9.9/10) | **Feature Parity**: 99%+

**Recent Achievements**:

- ✅ **Sprint 1** (2025-10-02): P0+P1 fixes, zero compilation errors, v0.2.0 release
- ✅ **Sprint 2** (2025-10-02): macOS native process matching (**149.4x faster**), cardinality monitoring
- ✅ **Sprint 3** (2025-10-02): Windows native process matching, VLESS support
- ✅ **Sprint 4** (2025-10-02): Constant-time credential verification, comprehensive module documentation
- ✅ **Sprint 5** (2025-10-09): **TLS INFRASTRUCTURE COMPLETE** - REALITY, ECH, Hysteria v1/v2, TUIC, Direct inbound ✨

**Sprint 5 Major Breakthrough (2025-10-09)**:

- 🎉 **TLS Infrastructure**: REALITY, ECH, Standard TLS complete in new `crates/sb-tls` crate
- 🎉 **REALITY TLS**: Client/server handshake with X25519 key exchange, auth data embedding, fallback proxy
- 🎉 **ECH**: Runtime handshake with HPKE encryption, SNI encryption, ECHConfigList parsing
- 🎉 **Direct Inbound**: TCP+UDP forwarder with session-based NAT, automatic timeout cleanup
- 🎉 **Hysteria v1**: Full client/server with QUIC transport, custom congestion control, UDP relay
- 🎉 **Hysteria2**: Complete with Salamander obfuscation, password auth, UDP over stream
- 🎉 **TUIC Outbound**: Full UDP over stream support with authentication
- 🎉 **Sniffing Pipeline**: HTTP Host, TLS SNI, QUIC ALPN detection integrated with routing

**Major Milestones Achieved**:

- 🎉 **TLS Infrastructure**: REALITY, ECH, Standard TLS (NEW - unblocks 15+ protocols)
- 🎉 **Inbounds**: 5/15 Full, 8/15 Partial (33.3% complete)
- 🎉 **Outbounds**: 6/17 Full, 7/17 Partial (35.3% complete)
- 🎉 **Transport Layer**: WebSocket, HTTP/2, HTTPUpgrade, Multiplex complete
- 🎉 **CLI Tools**: 100% complete (generate, rule-set, geoip, geosite tools)
- 🔐 **Advanced TLS**: REALITY handshake, ECH with HPKE, Standard TLS 1.2/1.3
- 🚀 **Cross-platform**: Native process matching - macOS (149.4x), Windows (20-50x)
- 📊 **Observability**: Prometheus metrics with cardinality monitoring
- 🔐 **Security**: Timing-attack resistant credential verification
- 📚 **Rule-Set**: SRS binary format, remote caching, auto-update
- 🔄 **Proxy Selectors**: URLTest with health checks, load balancing
- 🌐 **DNS**: FakeIP, multiple strategies, DoH/DoT/DoQ support

**Next Steps**: Multiplex integration, V2Ray transports, DNS/Routing engine completion
**For detailed feature status, see**: [GO_PARITY_MATRIX.md](GO_PARITY_MATRIX.md) and [NEXT_STEPS.md](NEXT_STEPS.md)

## Deployment (Quickstart)

- Systemd (Linux): see `packaging/systemd/singbox-rs.service`, then:

  - `sudo cp packaging/systemd/singbox-rs.service /etc/systemd/system/`
  - `sudo systemctl daemon-reload && sudo systemctl enable --now singbox-rs`

- Docker (MUSL image): see `packaging/docker/Dockerfile.musl` and `packaging/docker/entrypoint.sh`.
  - Exposes admin/metrics and mounts `/data` for configs.
  - Example: `docker run -p 18088:18088 -v $PWD:/data singbox-rs:latest --config /data/minimal.yaml`

Health probe: `curl -fsS http://127.0.0.1:18088/metrics` (or admin ping endpoint if enabled).

## Troubleshooting

- Set `SB_PRINT_ENV=1` to print a one-line JSON snapshot of relevant environment variables at startup.
- Common errors and meanings:
  - `outbound_error_total{kind="udp",class="no_upstream"}`: proxy mode selected but no upstream configured; falls back to direct.
  - `balancer_failures_total{reason}`: upstream connect/send/recv failures with exponential backoff applied.
  - `udp_nat_reject_total{reason="capacity"}`: NAT table reached capacity; increase `SB_UDP_NAT_MAX` or reduce churn.

### P0 Protocol Troubleshooting

**REALITY TLS**:

- **Authentication failures**: Verify `public_key` and `short_id` match server configuration. Use `sing-box generate reality-keypair` to generate compatible keys.
- **Handshake errors**: Ensure `server_name` matches a valid target domain. REALITY requires a real target server for fallback.
- **Config validation**: Public key must be 64 hex characters, short_id must be 0-16 hex characters.

**ECH (Encrypted Client Hello)**:

- **Config format**: ECH config must be base64-encoded ECHConfigList. Generate with `sing-box generate ech-keypair`.
- **Handshake failures**: Verify server supports ECH. Check `pq_signature_schemes_enabled` if using post-quantum crypto.
- **SNI encryption**: ECH encrypts SNI in ClientHello. Verify with packet capture if needed.

**Hysteria v1/v2**:

- **Connection failures**: Check `up_mbps` and `down_mbps` settings. Hysteria requires bandwidth configuration.
- **Authentication errors**: Verify password/obfs settings match server. Hysteria v2 uses password auth, v1 uses obfs.
- **UDP relay issues**: Ensure `udp: true` is set on inbound. Check NAT table capacity with metrics.
- **Salamander obfuscation** (v2): Password must match on both client and server for obfuscation to work.

**SSH Outbound**:

- **Host key verification failures**: Add server to `known_hosts` or set `host_key_verification: false` (insecure).
- **Authentication errors**: Verify username/password or private key path. Check key permissions (should be 600).
- **Private key format**: Supports OpenSSH and PEM formats. Use `private_key_passphrase` for encrypted keys.
- **Connection pooling**: Adjust `connection_pool_size` (default 5) based on concurrent connection needs.

**TUIC**:

- **UUID format**: Must be valid UUID v4 format (e.g., `550e8400-e29b-41d4-a716-446655440000`).
- **Congestion control**: Supports `cubic`, `new_reno`, `bbr`. Match server configuration.
- **UDP over stream**: Set `udp_over_stream: true` to tunnel UDP over TCP streams.
- **Zero-RTT**: Enable `zero_rtt_handshake: true` for faster connection establishment (less secure).

**General TLS Issues**:

- **Certificate verification**: Use `skip_cert_verify: true` only for testing. Production should use valid certificates.
- **ALPN negotiation**: Specify `alpn` array (e.g., `["h2", "http/1.1"]`) to match server requirements.
- **SNI**: Set `sni` field to match server certificate. Required for most TLS configurations.

### Probe a layered outbound (VMess/VLESS/Trojan)

Build with router and enable desired sb-core features:

```
cargo run -p app --features "router,sb-core/out_vmess,sb-core/out_vless,sb-core/out_trojan,sb-core/v2ray_transport" --bin probe-outbound -- \
  --config config.yaml --outbound my-vmess --target example.com:80
```

Config example (VMess with TLS+WebSocket):

```yaml
schema_version: 2
outbounds:
  - type: vmess
    name: my-vmess
    server: vmess.example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
    transport: [tls, ws]
    ws_path: /ws
    ws_host: cdn.example.com
    tls_sni: cdn.example.com
```
