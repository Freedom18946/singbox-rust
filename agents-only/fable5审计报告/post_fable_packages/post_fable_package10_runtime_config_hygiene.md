<!-- tier: B -->
# post_fable_package10_runtime_config_hygiene

## Status

DONE.

## Source Findings

- CAL-11: production paths still contain `eprintln!`.
- CAL-20: `ServiceManager::close` is a structural footgun despite current explicit
  compensation.
- CAL-21: invalid FakeIP masks are silently dropped.
- CAL-22: malformed `experimental` blocks are silently dropped.
- CAL-23: unsupported-platform `system_proxy` can report success.
- CAL-24: `serve_http` heartbeat leaks on the shared-runtime legacy path.
- CAL-25: multiple runtime entrypoints remain, including legacy/dead paths.

## Objective

Reduce runtime/config surprise without changing the main product direction.

## Implementation Contract

- Replace production `eprintln!` calls with structured tracing at appropriate levels.
- Add visible validation issues for malformed FakeIP masks and malformed
  `experimental` blocks.
- Make unsupported `system_proxy` behavior honest: return an explicit unsupported
  result or document why warn-plus-ok is retained.
- Decide whether `ServiceManager::close` should remain no-op with stronger comments
  or become structurally aligned with `stop_services`.
- Either cancel the shared-runtime `serve_http` heartbeat task or make the legacy path
  impossible to call in production.
- Mark legacy runtime entrypoints as deprecated/dead or route callers to the live
  supervisor path.

## Out Of Scope

- Reload atomicity and continuity.
- Sidecar liveness policy.
- Public documentation calibration, which package 11 owns.

## Acceptance Criteria

- No production hot path writes directly to stderr through the identified `eprintln!`
  calls.
- FakeIP and `experimental` malformed config cases are observable.
- `system_proxy` unsupported-platform behavior is explicit.
- Runtime entrypoint ownership is easier to understand and less likely to mislead
  future agents.

## Tests / Verification

- Add config validation tests for FakeIP mask and malformed `experimental` behavior.
- Run relevant platform/system_proxy tests where available.
- Run affected inbound/http tests.
- Run `cargo check --workspace --all-features`.
- Run `git diff --check`.

## Docs To Update

- Runtime/config hygiene evidence note under `agents-only/`.
- This package file, under Completion Notes.
- `agents-only/active_context.md` if runtime entrypoint posture changes.

## Dependencies

- None.

## Completion Notes

Closed by package10 runtime/config hygiene patch.

- CAL-11: remaining production stderr writes in HTTP stop/shutdown paths now use `tracing`.
- CAL-20: `ServiceManager::close` remains a compatibility no-op; supervisor `stop_services`
  ownership is documented and tested.
- CAL-21/CAL-22: malformed FakeIP masks and malformed typed `experimental` blocks now emit
  validation errors and fail the full config load path.
- CAL-23: unsupported-platform `SystemProxyManager` paths return explicit `Unsupported`.
- CAL-24: HTTP heartbeat task is bound to `serve_http` lifecycle through an abort-on-drop guard.
- CAL-25: live runtime entrypoint remains `run_engine::run_supervisor`; bootstrap is documented
  and pinned as legacy compatibility.
- Evidence and command results: `post_fable_package10_runtime_config_hygiene_evidence.md`.
- Scope review: no package11 external-doc calibration, no package05/06 reload/liveness reopening,
  no `.github/workflows/*`, no `agents-only/a0_reality_spike/`, and no original fable5 audit body
  edits.
