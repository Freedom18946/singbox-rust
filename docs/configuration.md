# Configuration Reference

Current high-level config areas:

- `log`
- `inbounds`
- `outbounds`
- `route`
- `dns`
- protocol-specific nested `tls` and `transport` blocks where supported

Validation command:

```bash
cargo run -p app -- check -c /path/to/config.json
```

Route inspection command:

```bash
cargo run -p app -- route -c /path/to/config.json --dest example.com:443 --explain --with-trace
```

Current examples live under `examples/quick-start/` and `examples/configs/`.
