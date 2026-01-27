# `run` Command

Start the proxy server with a configuration file.

## Usage

```bash
singbox-rust run -c config.yaml
```

## Common Options

- `-c, --config <FILE>`: configuration file path
- `--admin-impl <IMPL>`: `core` or `debug`
- `--admin-listen <ADDR>`: admin API listen address

## Examples

```bash
singbox-rust run -c config.yaml
RUST_LOG=info SB_ADMIN_ENABLE=1 singbox-rust run -c config.yaml
```

## Related

- [Environment Variables](environment-variables.md)
- [Exit Codes](exit-codes.md)
