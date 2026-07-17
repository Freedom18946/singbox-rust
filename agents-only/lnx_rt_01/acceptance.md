<!-- tier: B -->
# LNX-RT-01 acceptance report

Status and aggregate result counts live only in `../active_context.md`.

## Environment

- Debian bookworm container, Linux x86_64.
- Rust 1.92.0, Go 1.24.7, protobuf compiler with `PROTOC_INCLUDE=/usr/include`.
- Go reference built from `go_fork_source/sing-box-1.13.13/` with `with_clash_api`.
- Raw logs and normalized interop artifacts remain outside Git under the task bind-cache.

## T1 findings

- VLESS multiplex E2E: all five Linux cases passed.
- `sb-adapters`, `sb-core`, and `sb-transport` all-feature suites passed after fixing three
  test portability/isolation defects.
- Linux exposed two supervisor tests that incorrectly assumed `resolved` was unavailable and
  one DNS forwarder test that raced the process-global resolver. Tests now use a portable
  invalid UDP configuration and a shared resolver guard that restores prior state.
- Linux `service_resolved` exposed a stale integration-test expectation: the no-rule resolver
  is wrapped by the default answer cache and correctly reports `cached_resolver`.
- The approved task-only Cargo target cache was removed. Docker Desktop was restarted once to
  release deleted bind-share inodes; Cargo/Go download caches, logs, binaries, interop artifacts,
  images, and volumes were preserved.
- Workspace all-feature execution then reached `app/tests/multiplex_vmess_e2e.rs`: all six cases
  failed with `early eof`; an isolated single-case replay failed identically, excluding test
  concurrency as the cause.
- This is not a Linux runtime regression. The VMess outbound writes a 31-byte plaintext auth
  record and plaintext request, while the inbound has always expected a 24-byte timestamp/HMAC
  record plus an AEAD request and a different response tag. Inbound mux also explicitly remains
  unimplemented. macOS classified the resulting `early eof` as a constrained-environment skip,
  masking this pre-existing implementation/test gap.
- Repair would expand LNX-RT-01 into the separately excluded VMess canonical/multiplex frontier.
  `decision_request.md` records the required scope choice. No skip or static label was added.

## T2 findings

- Every repository case with `kernel_mode: both` has Linux evidence in `results.md`.
- Priority order was preserved: strict P0, GUI critical path, SS/Trojan/VLESS dataplane, then
  lifecycle and DNS.
- Two Linux harness assumptions were fixed:
  - service isolation no longer relies on privileged port binding, because Docker permits
    unprivileged low ports when `net.ipv4.ip_unprivileged_port_start=0`;
  - chain-proxy process cleanup no longer uses `pkill -f` against a pattern embedded in its own
    shell command line.
- No new S4 entry or BHV-ID was created. FakeIP and VMess retain their existing classifications.
- Generic diff reports may flag Linux RSS magnitude differences in cases that sample `/memory`;
  this maps to the existing BHV-PF-003 performance axis and does not suppress any assertion or
  change the four-state case outcome.

## T3 findings

- Redirect listener bind/shutdown passed on Linux.
- TProxy `IP_TRANSPARENT` listener bind/shutdown passed with effective `CAP_NET_ADMIN`.
- These are direct adapter runtime smokes. App composition still reports redirect/tproxy as
  unsupported and should be handled by a separate wiring card; LNX-RT-01 did not expand into
  product composition work.

## Remaining before closure

- Resolve `decision_request.md`; the task is paused before VMess scope expansion.
- After that decision, rerun workspace all-feature test/check/clippy and remaining repository
  gates.
- Attempt the arm64 best-effort lane if storage permits.
- Update authoritative active context, red-team final diff, commit, and push main.
