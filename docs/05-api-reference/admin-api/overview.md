# Admin API Overview

## Overview

The Admin API is an HTTP interface for runtime control and inspection.

## Base URL

- Default: `http://127.0.0.1:18088`

## Common endpoints

- `GET /__health` — health check
- `GET /__metrics` — Prometheus metrics
- `GET /__config` — fetch admin-debug runtime config
- `PUT /__config` — update admin-debug runtime config
- `GET /router/geoip/*` — geoip tools (feature-dependent)
- `GET /router/rules/normalize` — normalize rules
- `GET /subs/*` — subscription endpoints (feature-dependent)
- `GET /router/analyze` — rule analysis (feature-dependent)
- `POST /route/dryrun` — routing dry-run (feature-dependent)

## Response envelope

All responses use a JSON envelope:

```json
{ "ok": true, "data": {} }
```

## Authentication

When enabled, pass credentials via `Authorization` header (Bearer token or HMAC scheme).

## Example

```bash
curl http://127.0.0.1:18088/__health
```

## Notes

- `/__config` manages admin-debug parameters, not the full proxy config file.

## Related

- [Authentication](authentication.md)
- [API Reference](../README.md)
