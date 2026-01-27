# `geoip` and `geosite` Commands

Manage GeoIP and Geosite databases.

## GeoIP

```bash
singbox-rust geoip --file geoip.db list
singbox-rust geoip --file geoip.db lookup 8.8.8.8
singbox-rust geoip --file geoip.db export cn --out cn.srs
```

## Geosite

```bash
singbox-rust geosite --file geosite.db list
singbox-rust geosite --file geosite.db lookup netflix.com
singbox-rust geosite --file geosite.db export netflix --out netflix.srs
```
