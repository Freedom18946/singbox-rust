# Packaging

- Systemd unit: `systemd/singbox-rs.service`
  - Copy to `/etc/systemd/system/` and enable.
- Docker (musl): `docker/Dockerfile.musl` + `docker/entrypoint.sh`
  - Build: `docker build -t singbox-rs:latest -f packaging/docker/Dockerfile.musl .`
  - Run: `docker run --rm -p 18088:18088 -v $PWD:/data singbox-rs:latest --config /data/minimal.yaml`

Artifacts include README/LICENSE and version info (see release workflow).
