# Load Balancing Example

## Use case

Select between multiple outbounds either automatically or manually.

## URLTest (auto selection)

```yaml
outbounds:
  - type: shadowsocks
    tag: proxy-us
    server: us.example.com
    port: 8388
    method: aes-256-gcm
    password: ${SS_PASSWORD}

  - type: shadowsocks
    tag: proxy-jp
    server: jp.example.com
    port: 8388
    method: aes-256-gcm
    password: ${SS_PASSWORD}

  - type: urltest
    tag: auto-select
    outbounds: [proxy-us, proxy-jp]
    url: https://www.google.com/generate_204
    interval: 300s
    timeout_ms: 3000
    tolerance: 50ms
```

Use `interval_ms`/`timeout_ms`/`tolerance_ms` for millisecond precision if needed.

`members` is accepted as an alias for `outbounds` in selector/urltest configs.

## Related

- [Node Selection](../../06-advanced-topics/node-selection.md)

## Selector (manual selection)

```yaml
outbounds:
  - type: selector
    tag: manual-select
    outbounds: [proxy-us, proxy-jp]
    default: proxy-us
```
