<!-- tier: B -->
# post1313 Package Index

## Package Map

| ID | Title | Status | Priority | Primary PX | Depends on | Deliverable type |
|---|---|---|---:|---|---|---|
| P1313-01 | Config schema and GUI fixtures | DONE and verified locally | P0 | PX-002 | none | schema/tests/fixtures |
| P1313-02 | DNS transport manager | DONE | P0 | PX-004 | P1313-01 | core DNS |
| P1313-03 | DNS rule actions and cache semantics | DONE | P0 | PX-003/PX-004/PX-013 | P1313-02 | core DNS + config |
| P1313-04 | Route rule engine and network strategy | DONE locally | P1 | PX-003/PX-005 | P1313-01/P1313-03 | router |
| P1313-05 | Lifecycle managers and start order | DONE | P0 | PX-006 | P1313-01 | core lifecycle |
| P1313-06 | Adapter surface contracts | DONE | P1 | PX-007/PX-008/PX-009 | P1313-05 | cross-crate API |
| P1313-07 | CacheFile persistence | Closed locally | P0 | PX-013 | P1313-03/P1313-06 | cache + migration |
| P1313-08 | Clash API and GUI channel contract | DONE | P0 | PX-010 | P1313-05/P1313-07 | API/e2e |
| P1313-09 | UDP NAT and packet dataplane | Closed locally | P1 | PX-005 | P1313-04/P1313-06 | dataplane |
| P1313-10 | V2Ray stats and router tracker | DONE locally | P1 | PX-012 | P1313-06/P1313-09 | service/API |
| P1313-11 | Service regression closeout | DONE locally | P1 | PX-011/PX-014/PX-015 | P1313-05/P1313-06 | service tests |
| P1313-12 | GUI 1.25.1 low-priority contract | DONE locally | P2 | GUI diff | P1313-01/P1313-08 | fixtures/API probes |

## Historical Execution Waves

### Wave A: Freeze The Shape

- P1313-01
- Output: a current fixture/test baseline for Go 1.13.13 and GUI 1.25.1 generated configs.
- Reason: every later package needs an unambiguous config acceptance target.

### Wave B: DNS And Runtime Core

- P1313-02
- P1313-03
- P1313-05
- Reason: DNS, cache, and lifecycle are high-fanout surfaces.

### Wave C: Adapter/Route Integration

- P1313-06
- P1313-04
- P1313-09
- Reason: adapter interfaces and route execution should move after the core container is
  stable.

### Wave D: Control Plane And Persistence

- P1313-07
- P1313-08
- P1313-10
- Reason: user-visible API behavior depends on cache, selectors, connection tracking, and
  route metadata.

### Wave E: Tails And Low-Priority GUI Refresh

- P1313-11
- P1313-12
- Reason: revalidate service edges and keep GUI 1.25.1 shape current without resuming Wails
  automation.

## Common Definition Of Done For Reopened Or Future Implementation Packages

- Add or adapt tests before claiming closure.
- Run the narrow package tests plus the relevant broader gate.
- Re-review the diff against the source anchors named in the package file.
- Update `agents-only` status docs without duplicating volatile counts outside their source
  of truth.
- Commit only relevant tracked changes and push to `main`.

## Common Verification Commands

Use the package-specific commands first, then select from this common local gate set:

```bash
./agents-only/06-scripts/verify-consistency.sh
make boundaries
cargo check -p sb-config
cargo check -p sb-core
cargo check -p sb-adapters
cargo check -p app --features parity
cargo check --workspace --all-features
```

Do not add workflow automation. Do not treat a green check-only run as behavior parity unless
the package-specific acceptance proves the behavior.
