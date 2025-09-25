# Operations & Deployment

## Systemd (Linux)
- Unit file: `packaging/systemd/singbox-rs.service`
  ```bash
  sudo cp packaging/systemd/singbox-rs.service /etc/systemd/system/
  sudo systemctl daemon-reload && sudo systemctl enable --now singbox-rs
  ```
- Environment:
  - `SB_METRICS_ADDR=0.0.0.0:18088` exposes `/metrics` for probing.
  - Logs via journald (use `journalctl -u singbox-rs -f`).

## Docker (musl)
- Dockerfile: `packaging/docker/Dockerfile.musl`
  ```bash
  docker build -t singbox-rs:latest -f packaging/docker/Dockerfile.musl .
  docker run --rm -p 18088:18088 -v $PWD:/data singbox-rs:latest --config /data/minimal.yaml
  ```
- Health probe: `curl -fsS http://127.0.0.1:18088/metrics` (or admin ping when enabled).

## Platform notes (TUN/process)
- TUN operations may require elevated privileges or capabilities on Linux/macOS.
- Process matching relies on `/proc` (Linux) or tooling fallbacks (macOS/Windows). Ensure necessary permissions where applicable.

