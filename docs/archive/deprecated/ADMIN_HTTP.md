# Admin HTTP (Minimal, Opt-in)

## Security
- Default: loopback/private networks allowed without token.
- Set token to require `X-Admin-Token`:
  - CLI: `--admin-token topsecret`
  - ENV: `ADMIN_TOKEN=topsecret`
- GUI/CI should send `X-Admin-Token: <token>` header when token is configured.

> Contract remains stable. Endpoints and JSON fields unchanged.

## Enable
- CLI: `run --admin-listen 127.0.0.1:19095`
- ENV: `ADMIN_LISTEN=127.0.0.1:19095 run ...`

## Endpoints
### `GET /healthz`
Response:
```json
{"ok":true,"pid":12345,"fingerprint":"0.1.0"}
```

### `GET /outbounds`
Response:
```json
{"items":[{"name":"direct","kind":"direct"}, {"name":"S","kind":"selector"}]}
```

### `POST /explain`
Body:
```json
{"dest":"example.com:443","network":"tcp","protocol":"socks"}
```
Response:
```json
{"dest":"example.com:443","outbound":"direct"}
```

> Contract: 字段集固定且稳定，便于 GUI/自动化集成。错误以 404/405/400 形式返回简洁 JSON。

## IR Examples
```json
{
  "inbounds":[
    {"type":"http","listen":"127.0.0.1","port":19084,
     "basicAuth":{"username_env":"IN_HTTP_USER","password_env":"IN_HTTP_PASS"}}
  ],
  "outbounds":[
    {"type":"http","name":"up1","server":"127.0.0.1","port":19181,
     "credentials":{"username":"u","password":"p"}}
  ]
}
```

## Scope
- 不提供 `/metrics`（保留给 Prom 导出器）
- 不提供热重载（后续版本提供）