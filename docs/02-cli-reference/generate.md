# `generate` Command

Generate key material and helper artifacts.

## Usage

```bash
cargo run -p app -- generate reality-keypair
cargo run -p app -- generate ech-keypair
cargo run -p app -- generate wireguard-keypair
cargo run -p app -- generate uuid
cargo run -p app -- generate tls-cert --domain example.com --out-cert cert.pem --out-key key.pem
```
