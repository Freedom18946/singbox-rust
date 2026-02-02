# Schema Migration (V1 → V2)

## Overview

Use the `check` command to migrate legacy configs.

## Example

```bash
singbox-rust check -c old-config.json --migrate --write-normalized --out config.v2.yaml
```

## Notes

- Always validate the migrated config.
- Review TLS and transport sections after migration.
- Go-compatible aliases (for example `user`, `auth_str`, URLTest timing keys, and `outbounds` as a selector/urltest member alias) are accepted and normalized during validation.
