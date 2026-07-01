# Code Examples

This directory contains Rust examples and test fixture data.

- `network/`, `proxy/`, `dns/`: Rust source examples
- `testing/scenarios/`: fixture inputs for test tooling, not runnable `app` configs

Build all Rust examples from this directory:

```bash
cargo build --manifest-path examples/code-examples/Cargo.toml --bins
```

Run one example:

```bash
cargo run --manifest-path examples/code-examples/Cargo.toml --bin udp_echo -- 127.0.0.1:19090
```

The JSON files under `testing/scenarios/` are scenario descriptors. They are not expected to pass `app check`.
