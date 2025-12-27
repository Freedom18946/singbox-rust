# Fuzz Testing for singbox-rust

This directory contains comprehensive fuzz testing infrastructure for the singbox-rust project, targeting protocol parsers, network layers, and core functionality.

## Quick Start

```bash
# From project root
make -f Makefile.fuzz fuzz-help        # Show all available commands
make -f Makefile.fuzz fuzz-list        # List all fuzz targets
make -f Makefile.fuzz fuzz-corpus      # Generate corpus seeds
make -f Makefile.fuzz fuzz-quick       # Quick smoke test (30s each)
make -f Makefile.fuzz fuzz-all         # Run all targets (5min each)
```

## Fuzz Targets (15 total)

### Core Functionality (3 targets)
- **fuzz_config** - Configuration file parsing (JSON/YAML)
- **fuzz_config_structured** - Structured config fuzzing with arbitrary
- **fuzz_dns_message** - DNS message parsing

### Protocol Parsers (9 targets)
- **fuzz_vmess** - VMess protocol parsing (simulated)
- **fuzz_vmess_structured** - Structured VMess fuzzing with arbitrary
- **fuzz_vless** - VLESS protocol parsing (simulated)
- **fuzz_trojan** - Trojan protocol parsing (simulated)
- **fuzz_shadowsocks** - Shadowsocks AEAD packet parsing (simulated)
- **fuzz_hysteria** - Hysteria protocol parsing (simulated)
- **fuzz_tuic** - TUIC protocol parsing (simulated)
- **fuzz_socks5** - SOCKS5 UDP datagram parsing ✅ (uses real production code)
- **fuzz_http_connect** - HTTP CONNECT request parsing (simulated)

### Network Layer (2 targets)
- **fuzz_tun_packet** - TUN packet parsing (IPv4/IPv6, simulated)
- **fuzz_mixed_protocol** - Mixed protocol detection (TLS/SOCKS5/HTTP, simulated)

### API (1 target)
- **fuzz_v2ray_api** - V2Ray API request parsing (simulated)

## Implementation Status

### ✅ Using Real Production Code
- **SOCKS5 UDP**: Uses `sb_adapters::inbound::socks::udp::parse_udp_datagram()` and `encode_udp_datagram()`
- Includes roundtrip encoding/decoding tests
- Full boundary testing for all address types (IPv4, domain, IPv6)

### ⚠️ Using Simulated Parsing Logic
Most other protocol targets currently use **simulated parsing logic** that mimics the protocol structure but doesn't call the actual production code. This is because:

1. **Async-only interfaces**: Most protocol handlers are embedded in `async fn serve()` functions without exposing synchronous parsing functions
2. **Stream-based design**: Parsers often read from `TcpStream` directly rather than accepting byte slices
3. **Private functions**: Key parsing logic is not exposed via `pub fn`

**Example (VMess):**
- Current: Hand-coded protocol structure simulation
- Ideal: Call `sb_adapters::inbound::vmess::parse_request(data)` (doesn't exist as pub fn)

## Future Improvements

### Priority 1: Expose Parsing Functions
To improve fuzz testing effectiveness, the following functions should be exposed:

```rust
// Recommended additions to sb-adapters

// VMess
pub fn parse_vmess_auth_header(data: &[u8]) -> Result<AuthHeader>;
pub fn parse_vmess_request(data: &[u8]) -> Result<VMessRequest>;

// VLESS
pub fn parse_vless_header(data: &[u8]) -> Result<VlessHeader>;

// Trojan
pub fn parse_trojan_request(data: &[u8]) -> Result<TrojanRequest>;
pub fn validate_trojan_password_hash(hash: &[u8]) -> bool;

// Shadowsocks
pub fn parse_shadowsocks_aead_packet(data: &[u8]) -> Result<(Vec<u8>, Tag)>;

// HTTP
pub fn parse_http_request_line(data: &[u8]) -> Result<(Method, Target)>;
pub fn parse_host_port(target: &str) -> Result<(Host, Port)>;

// TUN
pub fn parse_tun_frame(data: &[u8]) -> Result<IpPacket>;
pub fn parse_ipv4_packet(data: &[u8]) -> Result<Ipv4Packet>;
pub fn parse_ipv6_packet(data: &[u8]) -> Result<Ipv6Packet>;
```

### Priority 2: Structured Fuzzing
Use the `arbitrary` crate for structured fuzzing:

```rust
#[derive(Arbitrary, Debug)]
struct VMessRequest {
    version: u8,
    iv: [u8; 16],
    key: [u8; 16],
    // ...
}

fuzz_target!(|req: VMessRequest| {
    let data = req.to_bytes();
    let _ = sb_adapters::inbound::vmess::parse_request(&data);
});
```

### Priority 3: Coverage Tracking
Add coverage reporting to identify untested code paths:

```bash
cargo +nightly fuzz coverage fuzz_vmess
cargo cov -- export ... -format=lcov > coverage.lcov
```

## Directory Structure

```
fuzz/
├── Cargo.toml                 # Fuzz workspace configuration
├── targets/                   # Fuzz targets organized by category
│   ├── core/                  # Core functionality (config, DNS)
│   ├── protocols/             # Protocol parsers (VMess, VLESS, etc.)
│   ├── network/               # Network layer (TUN, mixed protocol)
│   └── api/                   # API endpoints
├── corpus/                    # Seed data for fuzzing
│   ├── seeds/                 # Protocol-specific seeds
│   └── generated/             # Auto-generated edge cases
├── scripts/
│   └── generate_corpus.sh     # Corpus generation script
└── README.md                  # This file
```

## Corpus Statistics

The corpus includes **79 files (11MB)** covering:

| Protocol      | Files | Size  | Coverage                          |
|---------------|-------|-------|-----------------------------------|
| VMess         | 6     | 28KB  | Auth headers, IPv4/IPv6/domain    |
| VLESS         | 5     | 24KB  | Version, UUID, address types      |
| Trojan        | 5     | 24KB  | Password hash, command parsing    |
| Shadowsocks   | 6     | 28KB  | AEAD packets, address encoding    |
| Hysteria      | 6     | 28KB  | v1/v2 handshake                   |
| TUIC          | 5     | 24KB  | Handshake, commands               |
| SOCKS5        | 6     | 28KB  | UDP datagrams, all address types  |
| HTTP          | 6     | 28KB  | CONNECT, GET requests             |
| TUN           | 6     | 28KB  | IPv4/IPv6 packets                 |
| Mixed         | 7     | 32KB  | TLS, SOCKS5, HTTP detection       |
| Config        | 6     | 28KB  | JSON/YAML configs                 |
| Edge Cases    | 15    | 10MB  | Empty, large, malformed data      |

## Testing Categories

### Quick Smoke Test (30s each)
```bash
make -f Makefile.fuzz fuzz-quick
```
Tests: config, vmess, vless, trojan, http_connect

### Category-Specific
```bash
make -f Makefile.fuzz fuzz-core        # Core functionality
make -f Makefile.fuzz fuzz-protocols   # All protocols
make -f Makefile.fuzz fuzz-network     # Network layer
make -f Makefile.fuzz fuzz-api         # API endpoints
```

### Individual Protocols
```bash
make -f Makefile.fuzz fuzz-vmess
make -f Makefile.fuzz fuzz-socks5
make -f Makefile.fuzz fuzz-http
# ... etc
```

## Expected Results

### Security Benefits
- **Buffer overflow detection**: Find bounds-checking issues
- **Panic prevention**: Discover unwrap/expect failures
- **Authentication bypass**: Test edge cases in auth logic
- **Resource exhaustion**: Identify allocation issues

### Known Limitations
1. **Not testing real code paths**: Most targets simulate protocols rather than calling actual parsers
2. **No async testing**: Current fuzzing doesn't test async state machines
3. **Limited integration**: Individual component fuzzing, not full protocol flows
4. **No stateful fuzzing**: Each fuzz iteration is independent

## CI Integration

### Current
- Basic smoke test in `.github/workflows/fuzz-smoke.yml`
- Runs on push/PR
- Limited duration (quick sanity check)

### Recommended Enhancement
```yaml
# .github/workflows/fuzz-extended.yml
name: Extended Fuzz Testing
on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM
  workflow_dispatch:

jobs:
  fuzz:
    strategy:
      matrix:
        target: [fuzz_vmess, fuzz_vless, fuzz_trojan, ...]
    steps:
      - run: cargo +nightly fuzz run ${{ matrix.target }} -- -max_total_time=600
      - uses: actions/upload-artifact@v3
        if: failure()
        with:
          name: fuzz-crashes-${{ matrix.target }}
          path: fuzz/artifacts/${{ matrix.target }}/
```

## Troubleshooting

### Build Errors
```bash
# Ensure nightly toolchain is installed
rustup install nightly
rustup component add llvm-tools-preview --toolchain nightly

# Install cargo-fuzz
cargo install cargo-fuzz
```

### Missing Corpus
```bash
# Regenerate corpus seeds
make -f Makefile.fuzz fuzz-corpus
```

### Slow Fuzzing
```bash
# Use fewer iterations for quick testing
cargo +nightly fuzz run TARGET -- -max_total_time=30 -runs=10000
```

## References

- [Rust Fuzz Book](https://rust-fuzz.github.io/book/)
- [cargo-fuzz Documentation](https://github.com/rust-fuzz/cargo-fuzz)
- [LibFuzzer Tutorial](https://llvm.org/docs/LibFuzzer.html)
- [Protocol Fuzzing Best Practices](https://github.com/google/fuzzing/blob/master/docs/good-fuzz-target.md)

## Contributing

When adding new fuzz targets:

1. **Use real code**: Prefer calling actual parsing functions over simulated logic
2. **Document limitations**: If using simulated logic, add a note explaining what should be exposed
3. **Generate corpus**: Add appropriate seeds to `scripts/test/fuzz/generate-corpus.sh`
4. **Update Makefile**: Add the new target to `Makefile.fuzz`
5. **Test compilation**: Run `make -f Makefile.fuzz fuzz-build` to verify

## License

Same as parent project (GPL-3.0).
