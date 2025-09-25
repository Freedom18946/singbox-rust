# Examples

## Minimal v2 configs
- `examples/v2_minimal.json`: HTTP inbound + direct outbound + route.default.
- `examples/config.min.{json,yaml}`: SOCKS inbound on port 0 (ephemeral), direct outbound.

Run a quick check:
```bash
cargo run -q -p app -- check --config examples/v2_minimal.json --format json
```

## HTTP inbound demo (legacy)
```bash
RUST_LOG=info cargo run -p app --example http_inbound_demo
```

## SOCKS5 UDP probe (if enabled)
```bash
SB_SOCKS_UDP_ENABLE=1 cargo run -p sb-adapters --example socks5_udp_probe -- \
  127.0.0.1:11080 127.0.0.1:19090 example.com
```

## TCP connect helper
```bash
cargo run -q --example tcp_connect -- example.com 80
```

