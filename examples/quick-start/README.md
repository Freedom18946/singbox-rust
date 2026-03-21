# Quick Start Examples

All files in this directory are kept in sync with the current validator.

## Files

- `01-minimal.yaml` / `01-minimal.json`: mixed inbound on `127.0.0.1:1080`, direct outbound
- `02-socks5-direct.yaml` / `02-socks5-direct.json`: SOCKS inbound with direct outbound
- `03-http-proxy.yaml`: HTTP inbound on `127.0.0.1:8080`
- `04-mixed-inbound.yaml`: mixed inbound on a single port
- `05-basic-routing.yaml`: current rule syntax with `when`, `to`, and `default`
- `explain_minimal.yaml`: minimal config for `app route`

## Commands

Validate:

```bash
cargo run -p app -- check -c examples/quick-start/01-minimal.yaml
```

Run:

```bash
cargo run -p app -- run -c examples/quick-start/01-minimal.yaml
```

Test the default mixed inbound:

```bash
curl --proxy http://127.0.0.1:1080 https://example.com
```
