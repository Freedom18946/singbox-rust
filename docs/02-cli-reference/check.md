# `check` Command

Validate configuration files and optionally migrate V1 → V2.

## Usage

```bash
singbox-rust check -c config.yaml
```

## Common Options

- `--format <text|json>`: output format
- `--migrate`: migrate V1 config to V2
- `--write-normalized`: write normalized config
- `--out <FILE>`: output file for normalized config

## Examples

```bash
singbox-rust check -c config.yaml
singbox-rust check -c old.json --migrate --write-normalized --out config.v2.yaml
```

## Related

- [Exit Codes](exit-codes.md)
