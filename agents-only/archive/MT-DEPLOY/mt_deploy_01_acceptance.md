<!-- tier: B -->
# MT-DEPLOY-01: Deployment Acceptance Baseline

**Date**: 2026-04-10
**HEAD**: post-9c6add56 (on main, after MT-DEPLOY-01 fixes)
**Card type**: deployment-acceptance / release-readiness quality work. NOT parity completion.

---

## 1. Scope

This card validates whether the current repository is ready for real deployment:
buildable, startable, config-checkable, and packageable.

---

## 2. Blockers Found and Fixed

### 2.1 `app/src/tracing_init.rs` — missing `#[cfg(feature = "sb-metrics")]`

**Problem**: `init_metrics_exporter_once` at line 214 was defined without a `#[cfg(feature = "sb-metrics")]` gate, while a second definition at line 220 had `#[cfg(not(feature = "sb-metrics"))]`. Under the `parity` feature (which does NOT include `sb-metrics`), this caused:
- `E0428`: duplicate definition of `init_metrics_exporter_once`
- `E0433`: unresolved crate `sb_metrics`
- `E0425`: unresolved function `install_compat_metrics_exporter`

**Fix**: Added `#[cfg(feature = "sb-metrics")]` to the first definition (line 214).

### 2.2 `app/Cargo.toml` — `tokio-util` missing from `router` feature

**Problem**: `app/src/run_engine_runtime/watch.rs` (gated behind `#[cfg(feature = "router")]`) uses `tokio_util::sync::CancellationToken`. But `tokio-util` was only pulled in by the `admin_debug` feature, not by `router`. Under the `parity` feature (which includes `router` but not `admin_debug`), this caused `E0433: unresolved crate tokio_util`.

**Fix**: Added `"tokio-util"` to the `router` feature list in `app/Cargo.toml`.

---

## 3. Deployment Acceptance Verification Results

### 3.1 Build

| Check | Command | Result |
|-------|---------|--------|
| Debug build (parity) | `cargo build -p app --features parity` | **PASS-STRICT** |
| Release build (parity) | `cargo build -p app --features parity --release` | **PASS-STRICT** |
| Clippy (all features) | `cargo clippy -p app --all-features --all-targets -- -D warnings` | **PASS-STRICT** |

### 3.2 Tests

| Check | Command | Result |
|-------|---------|--------|
| App lib tests | `cargo test -p app --all-features --lib -- --test-threads=1` | **PASS-STRICT** (286 passed, 0 failed) |

### 3.3 Version Output

| Check | Command | Result |
|-------|---------|--------|
| Debug version | `cargo run -p app --features parity -- version` | **PASS-STRICT** — outputs `sing-box version 0.1.0 (9c6add56dfcf)` with env/tags |
| Release version | `./target/release/app version` | **PASS-STRICT** — same output |

### 3.4 Config Check

| Check | Command | Result |
|-------|---------|--------|
| `check` subcommand | `cargo run -p app --features parity -- check -c deployments/config-template.json` | **PASS-STRICT** (exit 0, outbound 'direct' registered) |
| `run --check` (zero side-effect) | `cargo run -p app --features parity -- run --check -c deployments/config-template.json` | **PASS-STRICT** (exit 0, runtime init verified) |
| Release binary check | `./target/release/app check -c deployments/config-template.json` | **PASS-STRICT** |

### 3.5 Near-Startup (Real Bind)

| Check | Command | Result |
|-------|---------|--------|
| Standalone `run` binary | `cargo run -p app --features parity --bin run -- -c deployments/config-template.json` (3s timeout) | **PASS-STRICT** — binds `0.0.0.0:1080`, registers mixed inbound + direct outbound, graceful shutdown on SIGTERM |

Output evidence:
```
Mixed (HTTP+SOCKS5) inbound bound addr=0.0.0.0:1080 actual=0.0.0.0:1080
started pid=63524 fingerprint=0.1.0
beginning graceful shutdown deadline_ms=1499
all inbound connections drained
shutdown summary event={"event":"shutdown","fingerprint":"0.1.0","ok":true,"wait_ms":0}
```

### 3.6 Package Script

| Check | Command | Result |
|-------|---------|--------|
| `package_release.sh` | `bash scripts/package_release.sh --version 0.1.0 --target aarch64-apple-darwin --os macos --arch arm64 --binary ./target/release/app --out-dir /tmp/... --config-template deployments/config-template.json --readme README.md` | **PASS-STRICT** |

Package artifact structure:
```
singbox-rust-0.1.0-macos-arm64.tar.gz (16M)
├── bin/singbox-rust
├── config/config-template.json
└── docs/README.md
```
SHA256 checksum generated in `checksums.txt`.

---

## 4. Deployment Entry Point Consistency Audit

### 4.1 Recommended Primary Entry Point

**Binary**: `app` (default binary of the `app` crate)
**Production build command**: `cargo build -p app --features parity --release`
**Production run command**: `app run -c /path/to/config.json`

### 4.2 Consistency Check Across Deployment Manifests

| Manifest | Command Used | Consistent? |
|----------|-------------|-------------|
| `deployments/docker/Dockerfile` | `app run -c /etc/singbox/config.json` | **YES** |
| `deployments/docker/docker-compose.yml` | `app run -c /etc/singbox/config.json` | **YES** |
| `deployments/kubernetes/deployment.yaml` | `app run -c /etc/singbox/config.json` | **YES** |
| `deployments/systemd/singbox-rust.service` | `/usr/local/bin/app run -c /etc/singbox/config.json` | **YES** |
| `deployments/helm/singbox-rust/` | Uses same pattern via templates | **YES** |

All deployment manifests use the same entry point: `app run -c <config-path>`.

### 4.3 Config Template Consistency

`deployments/config-template.json` is embedded identically in:
- Kubernetes ConfigMap (`deployments/kubernetes/deployment.yaml`)
- Used by `package_release.sh` as `config/config-template.json`
- Docker Compose expects it mounted at `/etc/singbox/config.json`

Template content (minimal viable config):
```json
{
  "schema_version": 2,
  "log": { "level": "info" },
  "inbounds": [{ "type": "mixed", "name": "mixed-in", "listen": "0.0.0.0:1080" }],
  "outbounds": [{ "type": "direct", "name": "direct" }],
  "route": { "default": "direct" }
}
```

### 4.4 Feature Profile for Production

The `parity` feature is the recommended production profile:
- Includes: router, all protocol adapters, all DNS backends, NTP/resolved/DERP services, Clash/V2Ray API
- Excludes: observe, admin_debug, dev-cli, bench-cli (opt-in for diagnostics)
- Docker builds default to `BUILD_FEATURES=parity`

---

## 5. Deployment Command Reference

### Build
```bash
cargo build -p app --features parity --release
```

### Version
```bash
./target/release/app version
```

### Config Check (static validation only)
```bash
./target/release/app check -c config.json
```

### Config Check (runtime init, zero side-effect)
```bash
./target/release/app run --check -c config.json
```

### Run (production)
```bash
./target/release/app run -c config.json
```

### Package
```bash
bash scripts/package_release.sh \
  --version <VER> --target <TRIPLE> --os <OS> --arch <ARCH> \
  --binary ./target/release/app \
  --out-dir ./dist \
  --config-template deployments/config-template.json \
  --readme README.md
```

---

## 6. Overall Verdict

### Does the repository have a deployment acceptance baseline?

**YES.**

| Criterion | Status |
|-----------|--------|
| Buildable (debug + release, parity features) | **PASS-STRICT** |
| Version output works | **PASS-STRICT** |
| Config check works with deployment template | **PASS-STRICT** |
| Near-startup (real bind + graceful shutdown) | **PASS-STRICT** |
| Package script produces correct artifact | **PASS-STRICT** |
| Deployment manifests use consistent entry point | **PASS-STRICT** |
| Config template consistent across manifests | **PASS-STRICT** |
| Clippy clean | **PASS-STRICT** |
| App lib tests pass | **PASS-STRICT** |

### Environment Limitations

- Full network proxy E2E (client → inbound → outbound → target) not tested — requires real upstream server. Recorded as **PASS-ENV-LIMITED** for E2E proxy path.
- Docker image build not tested in this session (requires Docker daemon). Recorded as **PASS-ENV-LIMITED** for container path.
- systemd/k8s/helm deployment not tested (requires target infrastructure). Recorded as **PASS-ENV-LIMITED** for orchestration path.

### Remaining Non-Blocking Items

These are inherited from MT-AUDIT-01 and are NOT deployment blockers:
- 21 stale boundary assertions (script targets, not code)
- 4 mega-files (structural debt)
- `tun_enhanced.rs` 112 production expect() (panic surface)
- Lifecycle-aware compat shells (future boundary)

---

## 7. Blockers Fixed in This Card

| Issue | File | Fix | Impact |
|-------|------|-----|--------|
| Missing `#[cfg(feature = "sb-metrics")]` | `app/src/tracing_init.rs` | Added cfg gate to `init_metrics_exporter_once` | Unblocked `parity` feature build |
| Missing `tokio-util` in `router` feature | `app/Cargo.toml` | Added `"tokio-util"` to `router` feature list | Unblocked `parity` feature build |
