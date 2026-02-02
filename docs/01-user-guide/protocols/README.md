# Protocol Guides

Protocol-specific notes for singbox-rust.

## Index

- [REALITY](reality.md)
- [ECH](ech.md)
- [Shadowsocks](shadowsocks.md)
- [Trojan](trojan.md)
- [VMess](vmess.md)
- [VLESS](vless.md)
- [Hysteria](hysteria.md)
- [TUIC](tuic.md)

## How to use this section

Each page includes:
- A short overview
- Minimal inbound/outbound examples
- Links to TLS and transport docs

Note: Config validation accepts select Go-compatible aliases (for example `user`, `auth_str`, URLTest timing `*_ms` fields, and selector/urltest `outbounds` as an alias for `members`). See the configuration guide for details.

## Related

- [TLS Configuration](../configuration/tls.md)
- [Transport Defaults](../../04-development/transport-defaults.md)
- [Advanced Topics](../../06-advanced-topics/README.md)
