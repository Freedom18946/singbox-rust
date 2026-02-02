# Config Schema v2

## Overview

Configuration uses `schema_version: 2` at the top level.

## Validation

```bash
singbox-rust check -c config.yaml
```

## Compatibility aliases

The validator accepts several Go-compatible aliases and normalizes them in the IR:

- `user` → `username` (SSH/HTTP/SOCKS credentials)
- `auth_str` → `auth` (Hysteria v1)
- URLTest timing: `interval`/`timeout`/`tolerance` accept seconds or duration strings; `interval_ms`/`timeout_ms`/`tolerance_ms` accept milliseconds
- Selector/URLTest member list: `outbounds` is accepted as an alias for `members`

## Notes

Schema docs are evolving. Use validation output and examples as guidance.
