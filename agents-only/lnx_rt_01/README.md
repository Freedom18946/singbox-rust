<!-- tier: B -->
# LNX-RT-01 Linux runtime dual-kernel acceptance

Status and volatile result counts live only in `../active_context.md`.

This directory owns task-scoped Linux runtime evidence, result tables, and reproduction
instructions. It does not change the dual-kernel BHV denominator.

- `acceptance.md`: findings, attribution, and remaining closure gates.
- `results.md`: per-case dual-kernel Linux outcome table.
- `reproduction.md`: repeatable build, replay, and inbound-smoke commands.

## Container entrypoint

`../06-scripts/run-linux-runtime.sh` builds and runs a pinned Debian toolchain containing
Rust 1.92.0 and Go 1.24.7. Cargo, Go, target, and raw interop artifacts use a host bind-cache
under `/private/tmp` by default so Docker's project cache volume is not expanded by runtime
replay.

```bash
agents-only/06-scripts/run-linux-runtime.sh \
  'uname -m && rustc --version && go version && protoc --version'
```

Set `SINGBOX_LINUX_PLATFORM=linux/arm64` for the best-effort arm64 lane. Set
`SINGBOX_LINUX_CAP_NET_ADMIN=1` only for Linux inbound smoke that needs transparent-socket
capabilities.
