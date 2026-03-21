# Developer Transport Examples

This directory is for transport-planning and developer inspection only.

Use it when you want to inspect derived transport chains with:

```bash
cargo run -p app --features router --bin transport-plan -- --config docs/examples/vmess_ws_tls.yaml
```

These files are not curated as end-user deployment examples. For runnable user-facing configs, use:

- `examples/quick-start/`
- `examples/configs/`
