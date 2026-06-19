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

## Current Gap

PX-013 says Rust cache is JSON-only/sled-oriented and lacks Go BoltDB buckets/cache_id
scoping, mode/selected/group_expand/rule_set storage, FakeIP metadata async paths, and RDRC
reject-cache semantics. GUI 1.25.1 still models `cache_file` but suppresses `store_rdrc` in
generated output.

## Task Split

1. Persistence posture decision.
   - Option A: implement BoltDB-compatible file format.
   - Option B: keep Rust backing store but implement Go-equivalent adapter behavior and a
     documented migration/import/export story.
   - Record the chosen posture before code work.

2. Cache identity and path.
   - `enabled`, `path`, `cache_id`.
   - Ensure multiple cache IDs do not cross-contaminate.
   - Respect GUI path override to `cache.db`.

3. Clash mode and selector state.
   - Store/read mode.
   - Store/read selected outbound per group.
   - Store/read group expansion state.
   - Ensure selector/urltest startup restores state before `/proxies` response.

4. Rule-set storage.
   - Remote rule-set metadata.
   - Binary/source freshness and update interval metadata.
   - Failure behavior when cache is corrupt.

5. FakeIP storage.
   - Address to domain mapping.
   - Domain to address mapping.
   - Expiry and capacity.
   - Integration with DNS reverse mapping.

6. RDRC storage.
   - Reject cache key and timeout.
   - Query before upstream.
   - Save after address-limit rejection.
   - Ensure GUI-generated `store_rdrc` omission has a documented default.

7. Tests.
   - Round-trip persistence tests.
   - Cross-version read tests if legacy Rust cache exists.
   - Corrupt cache recovery tests.

## Acceptance

- `cargo test -p sb-core cache_file`
- `cargo test -p sb-core dns`
- `cargo test -p sb-api clash`
- A documented migration posture in `agents-only/post1313/` evidence or updated active docs.

## Non-Goals

- No GUI desktop test.
- No public rule-set download requirement; use local/mock fixtures.
- No hidden fallback that reports persistence success while dropping writes.
