# `geoip` and `geosite` Commands

Manage GeoIP and Geosite databases.

## GeoIP

```bash
cargo run -p app -- geoip --file geoip.db list
cargo run -p app -- geoip --file geoip.db lookup 8.8.8.8
cargo run -p app -- geoip --file geoip.db export cn --out cn.srs
```

## Geosite

```bash
cargo run -p app -- geosite --file geosite.db list
cargo run -p app -- geosite --file geosite.db lookup netflix.com
cargo run -p app -- geosite --file geosite.db export netflix --out netflix.srs
```
