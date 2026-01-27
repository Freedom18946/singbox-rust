# Docker Deployment

## Overview

Container deployment for singbox-rust.

## Quick start

```bash
docker build -t singbox-rust:latest -f deployments/docker/Dockerfile .

docker run -d \
  --name singbox-rust \
  -v /etc/singbox/config.yaml:/etc/singbox/config.yaml:ro \
  -p 1080:1080 -p 18088:18088 \
  singbox-rust:latest run -c /etc/singbox/config.yaml
```

## Notes

- Sample compose files live in `deployments/docker-compose/`.
- Use read-only config mounts for safety.

## Related

- [Deployment Guide](../../DEPLOYMENT_GUIDE.md)
