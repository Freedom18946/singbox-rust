# `route` Command

This page keeps its historical filename, but the live command is `route`.

Example:

```bash
cargo run -p app -- route -c examples/quick-start/explain_minimal.yaml --dest example.com:443 --explain --with-trace
```

Important options:

- `--dest <DEST>`
- `--udp`
- `--format <human|json|sarif>`
- `--explain`
- `--with-trace`
