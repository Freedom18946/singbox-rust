# Kubernetes Deployment

## Overview

Kubernetes deployment notes and pointers.

## Quick start

```bash
kubectl apply -f deployments/kubernetes/deployment.yaml
```

## Notes

- Use ConfigMaps or Secrets for config and credentials.
- Add probes for `/metrics` if admin API is enabled.

## Related

- [Deployment Guide](../../DEPLOYMENT_GUIDE.md)
