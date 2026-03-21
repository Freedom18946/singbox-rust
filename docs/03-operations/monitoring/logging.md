# Logging

## Overview

Logging uses `tracing` with env-based filters.

## Common usage

```bash
RUST_LOG=info cargo run -p app -- run -c config.yaml
RUST_LOG=debug,sb_tls=debug cargo run -p app -- run -c config.yaml
```

## JSON logs

```bash
SB_LOG_FORMAT=json cargo run -p app -- run -c config.yaml
```

## Related

- [Monitoring](README.md)
