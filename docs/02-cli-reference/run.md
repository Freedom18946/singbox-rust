# `run` Command

Current help summary:

```bash
cargo run -p app -- run --help
```

Important options:

- `-c, --config <CONFIG>`
- `-C, --config-directory <CONFIG_DIRECTORY>`
- `-i, --import <IMPORT_PATH>`
- `-D, --directory <DIRECTORY>`
- `-w, --watch`
- `--check`
- `--http <HTTP_LISTEN>`
- `--admin-listen <ADMIN_LISTEN>`
- `--admin-token <ADMIN_TOKEN>`
- `--no-banner`
- `--disable-color`

Example:

```bash
ADMIN_LISTEN=127.0.0.1:19090 \
cargo run -p app -- run -c examples/quick-start/01-minimal.yaml
```
