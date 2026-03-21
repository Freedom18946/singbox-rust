# `completion` Command

The current command name is `completion`, not `gen-completions`.

Examples:

```bash
cargo run -p app -- completion --shell bash
cargo run -p app -- completion --all --dir ./completions
```

Important options:

- `--shell <bash|zsh|fish|power-shell|elvish>`
- `--dir <DIR>`
- `--all`
