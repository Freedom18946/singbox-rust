<!-- tier: B -->
# LNX-RT-01 acceptance report

Status and aggregate result counts live only in `../../active_context.md` after archival.

## Environment

- Debian bookworm container, Linux x86_64.
- Rust 1.92.0, Go 1.24.7, protobuf compiler with `PROTOC_INCLUDE=/usr/include`.
- Go reference built from `go_fork_source/sing-box-1.13.13/` with `with_clash_api`.
- Raw logs and normalized interop artifacts remain outside Git under the task bind-cache.

## Scope decision

- `decision_request.md` is resolved. The canonical Go-compatible VMess AEAD implementation in
  `vmess_canonical_plan.md` replaced the former bespoke Rust dialect.
- Closure stays limited to VMess TCP AEAD dataplane. Legacy `aes-128-cfb`, canonical CommandMux,
  UDP/packet VMess, and redirect/tproxy app composition remain explicit non-goals.
- No skip, weakened assertion, expected-failure declaration, or static S4 label was added.

## T1 findings

- Linux amd64 `multiplex_vmess_e2e` passed with every real assertion enabled.
- Workspace all-feature tests, all-target/all-feature check, repository-policy clippy, and
  formatting passed in the pinned runtime.
- Linux portability fixes make custom `CARGO_TARGET_DIR` authoritative for app/xtest binary
  discovery, use compile-time Cargo binary paths where available, and invoke `python3` for the
  Prometheus helper.
- Environment-mutating rate-limit tests are serialized. High-load accounting includes the
  preflight request. Trojan inbound routing now uses its injected router and canonical `RouteCtx`,
  with boundary rules forbidding process-global router reuse.
- Trojan pooling expectations stay below the production connection limit. These changes close
  deterministic workspace failures instead of masking them.

## T2 findings

- Go oracle was rebuilt from `go_fork_source/sing-box-1.13.13/` with `with_clash_api`; the
  interop runner was rebuilt in the same pinned Linux runtime.
- Committed `p2_vmess_dual_dataplane_local.yaml` is strict, has no environment-limit declarations,
  and retains its complete positive, wrong-UUID, and zero-error assertions.
- Committed case passed with `--kernel both`; evidence run
  `20260717T142243Z-34b05275-47aa-41ff-bcfa-39220788da3d`.
- Both snapshots show the valid UUID round-trip succeeding, wrong UUID failing, and empty error
  arrays. `summary.json` records `PASS` with no covered divergence, environment attribution,
  expected environment failure, or failure.
- Cold acceptance-app compilation exceeded one startup budget before assertions ran. The exact
  committed case passed after the dedicated target finished building; this is build warm-up
  evidence, not a protocol classification.

## T3 findings

- Storage permitted the arm64 best-effort lane. A native arm64 pinned image was built and the
  focused VMess multiplex suite passed without skips.

## Closure

- `results.md` contains per-case Linux evidence; aggregate state remains only in
  `../../active_context.md`.
- Raw logs and normalized snapshots remain under `/private/tmp/singbox-rust-lnx-rt-01/` and are
  not tracked by Git.
- Scope decision and task-local remaining items are closed. Repository-wide gate state and next
  step are recorded in active context, not duplicated here.
