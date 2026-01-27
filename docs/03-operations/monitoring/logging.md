# Logging

## Overview

Logging uses `tracing` with env-based filters.

## Common usage

```bash
RUST_LOG=info singbox-rust run -c config.yaml
RUST_LOG=debug,sb_tls=debug singbox-rust run -c config.yaml
```

## JSON logs

```bash
SB_LOG_FORMAT=json singbox-rust run -c config.yaml
```

## Related

- [Monitoring](README.md)
