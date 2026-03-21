# `merge` Command

Merge multiple configuration files into one.

## Usage

```bash
cargo run -p app -- merge -c base.yaml -c override.yaml output.yaml
```

## Notes

- Later files override earlier files.
- For upstream behavior details, see the sing-box documentation.
