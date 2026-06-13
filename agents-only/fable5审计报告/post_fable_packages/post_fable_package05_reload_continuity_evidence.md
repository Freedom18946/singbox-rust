<!-- tier: B -->
# post_fable_package05_reload_continuity_evidence

Date: 2026-06-13
Implementation commit: `a9236205` (`fix(sb-core): make reload activation atomic`)

## Result

package05 is closed as a conservative atomic reload fix. Reload now commits only
after the new runtime builds, starts, reports supported inbound readiness, and
finishes PostStart/Started. Failed reloads keep the old listener set and runtime
registries alive.

## Coverage

- Router path: `reload_atomicity` supervisor tests pass under default features.
- No-router path: same `reload_atomicity` tests pass with `--no-default-features`.
- Supported readiness: HTTP, SOCKS, and MIXED report `Ok(())` after bind and
  `Err(AddrInUse)` on occupied ports.
- Registry atomicity: failed reload preserves old runtime tags and does not expose
  failed new inbound/outbound tags.
- Same-port policy: old/new overlapping listen endpoint is rejected before old
  listener shutdown; wildcard overlap (`0.0.0.0:port` vs `127.0.0.1:port`) is covered.

## Verification

- `cargo test -p sb-core --lib --features service_v2ray_api rollback` PASS
- `cargo test -p sb-core --lib supervisor` PASS
- `cargo test -p sb-core --lib reload_atomicity --no-default-features -- --test-threads=1` PASS
- `cargo test -p sb-adapters --lib` PASS
- `cargo test -p sb-adapters --lib --features http,socks readiness_reports` PASS
- `cargo build -p app --bin app --features adapters,clash_api` PASS
- `cargo check -p app --features parity` PASS
- `cargo check --workspace --all-features` PASS
- `WORK=/tmp/pf07-after-reload bash agents-only/fable5审计报告/post_fable_packages/post_fable_package07_probe_harness.sh` PASS (14/0)
- `git diff --check` PASS before implementation commit and before checkpoint.

## Boundary

Same-port in-process handoff is not implemented. This is now a documented safe
rejection because fd handoff/reuseport semantics are outside package05. GUI restart
uses process stop/start and remains unaffected.

Readiness is strong only for HTTP, SOCKS, and MIXED. Other inbound services remain
best-effort until package06 liveness/observability work.
