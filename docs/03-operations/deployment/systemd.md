# systemd

Use `deployments/systemd/singbox-rust.service` as the maintained unit file.

The unit starts:

```bash
/usr/local/bin/app run -c /etc/singbox/config.json
```

It also uses:

- `ADMIN_LISTEN=127.0.0.1:19090`
- optional `ADMIN_TOKEN`
- health endpoint `http://127.0.0.1:19090/healthz`
