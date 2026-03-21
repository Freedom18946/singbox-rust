# Kubernetes

The maintained manifest lives at `deployments/kubernetes/deployment.yaml`.

Conventions used there:

- config mounted at `/etc/singbox/config.json`
- process started as `app run -c /etc/singbox/config.json`
- admin port `19090`
- liveness and readiness probes use `GET /healthz`

For Helm users, see `deployments/helm/singbox-rust/`.
