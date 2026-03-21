# Getting Started

The current verified path is source-first. Older release-download snippets and placeholder repository URLs were removed because they were not maintained.

## Build

```bash
git clone https://github.com/Freedom18946/singbox-rust.git
cd singbox-rust
cargo build -p app
```

## Validate A Known-Good Example

```bash
cargo run -p app -- check -c examples/quick-start/01-minimal.yaml
```

## Run A Local Proxy

```bash
cargo run -p app -- run -c examples/quick-start/01-minimal.yaml
```

The default quick-start config listens on `127.0.0.1:1080`. Test it with:

```bash
curl --proxy http://127.0.0.1:1080 https://example.com
```

## Useful Follow-Ups

- `basic-configuration.md`
- `first-proxy.md`
- `../02-cli-reference/README.md`
- `../03-operations/README.md`
