# Upstream Connectors (Scaffold)

## Credentials
- IR fields: `credentials.username|password|username_env|password_env`
- Environment values override literals when provided.

This document describes the scaffold implementations for:
- **SOCKS5 upstream** (`outbound.type="socks"`)
- **HTTP CONNECT upstream** (`outbound.type="http"`)
- **HTTP CONNECT inbound** (`inbound.type="http"`)

> Production implementations should be provided by `sb-adapter`. These scaffold
> connectors exist to complete the end-to-end path for CI and GUI integration.

## Configuration (IR)

```json
{
  "inbounds": [
    {"type":"http","listen":"127.0.0.1","port":19084,
     "basicAuth":{"username_env":"IN_HTTP_USER","password_env":"IN_HTTP_PASS"}}
  ],
  "outbounds": [
    {"type":"socks","name":"A","server":"127.0.0.1","port":19180,
     "credentials":{"username":"u","password":"p"}},
    {"type":"http","name":"B","server":"127.0.0.1","port":19181,
     "credentials":{"username_env":"UP_USER","password_env":"UP_PASS"}},
    {"type":"selector","name":"S","members":["A","B"]}
  ],
  "route": {"rules":[{"domain":["*"],"outbound":"S"}]}
}
```

## Contracts
- CLI/Explain/metrics **unchanged**.
- `Adapter Bridge` prioritizes `sb-adapter`; scaffold only when missing or forced via `ADAPTER_FORCE=scaffold`.
- Health (`outbound_up`) works regardless of connector kind.

## Security Notes
- Basic auth is supported for HTTP CONNECT inbound/outbound; credentials should be supplied via your normal configuration pipeline. Scaffold versions keep parsing minimal and do not do TLS termination.