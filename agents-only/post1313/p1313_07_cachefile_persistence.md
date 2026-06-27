<!-- tier: B -->
# P1313-07 CacheFile Persistence

Priority: P0

Primary evidence:

- `agents-only/reference/GO_PARITY_MATRIX.md` PX-013
- `go_fork_source/sing-box-1.13.13/experimental/cachefile/cache.go`
- `go_fork_source/sing-box-1.13.13/experimental/cachefile/fakeip.go`
- `go_fork_source/sing-box-1.13.13/experimental/cachefile/rdrc.go`
- `go_fork_source/sing-box-1.13.13/option/experimental.go`
- `GUI_fork_source/GUI.for.SingBox-1.25.1/frontend/src/utils/generator.ts`

## Goal

Decide and implement a Go-compatible enough CacheFile strategy for selector mode,
selected proxy, group expansion, rule-set cache, FakeIP metadata, and RDRC behavior.

## Status

Closed locally on 2026-06-27. This package does not claim any dual-kernel parity
number movement.

## Decision

Use Option B. Rust keeps the existing sled backing store and implements Go-compatible
CacheFile behavior at the adapter/service level. It does not read or write Go bbolt
`cache.db` files.

Migration posture:

- `experimental.cache_file.enabled=true` with no `path` now opens `cache.db` as a sled
  directory, matching the GUI default name but not the Go bbolt file format.
- If `path` points at a regular file, startup fails with an explicit error asking the
  user to move that file or choose another Rust cache path.
- If an existing sled directory fails to open and the error is not a lock conflict, Rust
  renames it to `.corrupt.<timestamp>` and rebuilds a fresh sled directory.
- Legacy Rust v1 `rulesets` tree entries remain readable as content-only rule-set payloads.
  New writes use a typed v2 payload with `content`, `last_updated`, and `last_etag`.
- No import/export CLI was added.

## Implemented

- `CacheFileService::try_new(&CacheFileIR) -> anyhow::Result<Self>` is the production
  constructor. `new()` remains a convenience wrapper, and `memory()` is the explicit
  in-memory test/ephemeral constructor.
- Clash mode, selected outbound, group expansion, RDRC, and rule-set payloads are
  scoped by `cache_id`; FakeIP mappings and FakeIP allocation metadata remain global.
- FakeIP domain lookups are split by family (`domain4` / `domain6`) while preserving the
  reverse IP-to-domain map and allocation cursor metadata.
- RDRC rejection keys include transport, qtype, and qname without ambiguous concatenation;
  expired entries are deleted on read, and `store_rdrc=false` disables reads and writes.
- Rule-set remote loading writes typed CacheFile payloads after successful downloads and
  can restore from CacheFile when network or file-cache recovery fails.
- Supervisor startup/reload and app bootstrap propagate cache initialization errors rather
  than falling back to memory. Equivalent supervisor reloads reuse the existing sled handle.
- API/runtime wiring restores persisted Clash mode, validates invalid persisted modes with
  warnings, and keeps `/configs` aligned with persisted mode state.

## Verification

PASS:

- `cargo test -p sb-core cache_file`
- `cargo test -p sb-core dns`
- `cargo test -p sb-core --test supervisor_reload_state`
- `cargo test -p sb-core --test adapter_surface_contract`
- `cargo test -p sb-api clash`
- `cargo test -p sb-core --test router_ruleset_integration test_remote_ruleset_cachefile_fallback_preserves_metadata`
- `cargo check -p sb-core --features router`
- `cargo check --workspace --all-features`
- `./agents-only/06-scripts/verify-consistency.sh`
- `make boundaries`
- `cargo fmt --check`

## Non-Goals

- No GUI desktop test.
- No public rule-set download requirement; use local/mock fixtures.
- No hidden fallback that reports persistence success while dropping writes.
