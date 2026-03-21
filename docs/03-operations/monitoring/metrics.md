# Metrics

Expose the admin HTTP surface before scraping metrics.

```bash
ADMIN_LISTEN=0.0.0.0:19090 \
cargo run -p app -- run -c /etc/singbox/config.json
```

Then scrape:

```bash
curl http://127.0.0.1:19090/metricsz
```

Health check:

```bash
curl http://127.0.0.1:19090/healthz
```

If you configured `ADMIN_TOKEN`, include:

```bash
curl -H 'X-Admin-Token: change-me' http://127.0.0.1:19090/metricsz
```
