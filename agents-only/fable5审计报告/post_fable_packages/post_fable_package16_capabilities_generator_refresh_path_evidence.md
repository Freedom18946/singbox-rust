<!-- tier: B -->
# post_fable_package16_capabilities_generator_refresh_path_evidence

## Scope

Package16 is a docs/tooling repair package. It restores trust in the capability
snapshot generator and refreshes tracked docs/report artifacts as docs-only
snapshots. It changes no product runtime behavior and does not close package03
or package07.

## Generator Entry

```bash
python3 scripts/capabilities/generate.py --out reports/capabilities.json
```

Validation helper:

```bash
python3 scripts/capabilities/test_generate.py
```

## Root Cause

The generator's `locate_line()` helper returned line `1` when an evidence path
did not exist or a configured needle could not be found. That made stale static
anchors look successful, including:

- `tls.ech.quic -> crates/sb-config/src/validator/v2.rs:1`
- `tls.ech.tcp` provider evidence pointing at the old runtime entry file
- `acceptance_closure` evidence pointing at an unavailable planning file

## Fix Strategy

- Evidence generation now fails fast when an anchor path is missing or the needle
  is absent.
- Static anchors were updated to existing semantic files:
  - `tls.ech.quic`: `crates/sb-config/src/validator/v2/outbound.rs`
  - `tls.ech.tcp` provider decision:
    `app/src/run_engine_runtime/supervisor.rs`
  - `acceptance_closure`: `docs/capabilities.md` and
    `reports/L18_REPLACEMENT_CERTIFICATION.md`
- The tracked report now carries package16 `staleness` metadata with
  `status=refreshed_docs_only_snapshot`.
- Historical `reports/` references to the removed `validator/v2.rs` file were
  calibrated to current module paths so the stale-anchor scan is reproducible.

## Tracked Refresh

Tracked artifacts refreshed:

- `reports/capabilities.json`
- `docs/capabilities.md`

The refreshed report remains docs-only. Live project state, gates, and next step
remain delegated to `agents-only/active_context.md`; package states remain in
the post-FABLE package map.

## Verification Results

| Command | Result |
|---|---|
| `python3 scripts/capabilities/generate.py --out /tmp/capabilities.package16.json` | PASS. |
| `python3 -m json.tool /tmp/capabilities.package16.json >/tmp/capabilities.package16.json.check` | PASS. |
| `python3 scripts/capabilities/test_generate.py` | PASS. |
| `python3 scripts/capabilities/generate.py --out reports/capabilities.json` | PASS. |
| `python3 -m json.tool reports/capabilities.json >/tmp/capabilities.package16.tracked.json.check` | PASS. |
| `bash scripts/check_claims.sh` | PASS. |
| `rg -n "crates/sb-config/src/validator/v2.rs:1\|crates/sb-config/src/validator/v2.rs\|tls\\.ech\\.quic" docs reports scripts app crates` | PASS after review: `tls.ech.quic` remains as capability id text; stale `validator/v2.rs` anchors are absent. |
| `cargo test -p app --test gui_runtime_profile --features gui_runtime` | PASS. |
| `cargo check --workspace --all-features` | PASS. |
| `cargo clippy --workspace --all-features --all-targets` | PASS. |
| `git diff --check` | PASS. |

## Residual Limits

- This package repairs the capability snapshot refresh path only; it does not
  prove GUI readiness, drop-in readiness, or full runtime parity.
- `reports/capabilities.json` records the generator run's `source_commit`; the
  package16 implementation commit is recorded by git history and final package
  handoff.
- package03 remains PARTIAL until privileged TUN dataplane proof passes.
- package07 remains PARTIAL until real interactive Wails desktop-window E2E is
  performed and documented.
