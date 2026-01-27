# Systemd Deployment

## Overview

Use systemd for long-running service management on Linux.

## Quick start

```bash
sudo install -m 0755 target/release/app /usr/local/bin/singbox-rust
sudo install -d /etc/singbox
sudo install -m 0644 config.yaml /etc/singbox/config.yaml
sudo install -m 0644 deployments/systemd/singbox-rust.service /etc/systemd/system/singbox-rust.service
sudo systemctl daemon-reload
sudo systemctl enable --now singbox-rust
```

## Notes

- See `deployments/systemd/singbox-rust.service` for a baseline unit.
- Use `Environment=` or drop-in files for secrets.

## Related

- [Deployment Guide](../../DEPLOYMENT_GUIDE.md)
- [Deployment Checklist](../../DEPLOYMENT_CHECKLIST.md)
