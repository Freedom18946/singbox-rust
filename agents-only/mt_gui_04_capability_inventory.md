<!-- tier: B -->
# MT-GUI-04: Declared-Complete Capability Inventory

**Date**: 2026-04-12
**Purpose**: Enumerates every kernel capability declared as complete/supported/verifiable,
with the authoritative source for each declaration.

> This is the **source list** for the exhaustive acceptance sweep.
> It is NOT a parity completion claim. The golden spec remains the authoritative parity口径.

---

## 1. Inventory Sources

| Source | What it declares | Authority level |
|--------|-----------------|-----------------|
| `dual_kernel_golden_spec.md` §S3 | 56 BHVs (behavioral capabilities) | **Primary** — authoritative behavioral alignment standard |
| `GO_PARITY_MATRIX.md` | 209/209 closed items (code-level parity) | **Primary** — code-level closure |
| `ACCEPTANCE-CRITERIA.md` | Verification procedures and tri-state model | **Primary** — acceptance methodology |
| GUI source `kernel.ts` | 7 REST endpoints + 4 WS streams = 11 GUI API surfaces | **Primary** — GUI contract ground truth |
| MT-DEPLOY-01 | 9 deployment chain items | **Primary** — deployment baseline |
| MT-GUI-01/02/03 | 35 scenarios + 10 divergence classifications | **Secondary** — existing evidence base |

---

## 2. Capability Categories

### A. Startup / Lifecycle (5 capabilities)

| ID | Capability | BHV Ref | Source |
|----|-----------|---------|--------|
| CAP-A-01 | Kernel starts and serves API | BHV-LC-002, BHV-PF-005 | golden_spec §S3 LC.1 |
| CAP-A-02 | Config validate via `check` subcommand | BHV-LC-001 | golden_spec §S3 LC.1 |
| CAP-A-03 | Auth enforcement — valid token accepted | BHV-CP-012 | golden_spec §S3 CP.3 |
| CAP-A-04 | Auth enforcement — wrong token rejected | BHV-CP-013 | golden_spec §S3 CP.3 |
| CAP-A-05 | Auth enforcement — missing token rejected | BHV-CP-014 | golden_spec §S3 CP.3 |

### B. Clash / GUI Control-Plane API (21 capabilities)

| ID | Capability | BHV Ref | Source |
|----|-----------|---------|--------|
| CAP-B-01 | GET /configs returns runtime config | BHV-CP-001 | golden_spec §S3 CP.1 + GUI kernel.ts |
| CAP-B-02 | PATCH /configs updates mode | BHV-CP-002, BHV-LC-004 | golden_spec §S3 CP.1 + GUI kernel.ts |
| CAP-B-03 | GET /proxies lists groups+members | BHV-CP-003 | golden_spec §S3 CP.1 + GUI kernel.ts |
| CAP-B-04 | GET /proxies/{group} returns group detail | BHV-CP-003 (sub) | GUI kernel.ts |
| CAP-B-05 | PUT /proxies/{group} switches active | BHV-CP-004 | golden_spec §S3 CP.1 + GUI kernel.ts |
| CAP-B-06 | GET /proxies/{name}/delay tests latency | BHV-CP-005 | golden_spec §S3 CP.1 + GUI kernel.ts |
| CAP-B-07 | GET /connections lists active conns | BHV-CP-006 | golden_spec §S3 CP.1 + GUI kernel.ts |
| CAP-B-08 | DELETE /connections/{id} closes conn | BHV-CP-007 | golden_spec §S3 CP.1 + GUI kernel.ts |
| CAP-B-09 | GET /rules returns rule list | BHV-CP-019 | golden_spec §S3 CP.4 |
| CAP-B-10 | GET /providers/proxies returns provider list | BHV-CP-018 | golden_spec §S3 CP.4 |
| CAP-B-11 | GET /providers/rules returns rule providers | BHV-CP-018 (sub) | golden_spec §S3 CP.4 |
| CAP-B-12 | GET /dns/query resolves domain (resolvable) | BHV-CP-021 | golden_spec §S3 CP.4 |
| CAP-B-13 | GET /dns/query non-resolvable domain handling | BHV-CP-021 (axis 2) | DIV-M-010 |
| CAP-B-14 | WS /traffic streams bandwidth | BHV-CP-008 | golden_spec §S3 CP.2 + GUI kernel.ts |
| CAP-B-15 | WS /memory streams RSS | BHV-CP-009 | golden_spec §S3 CP.2 + GUI kernel.ts |
| CAP-B-16 | WS /connections streams updates | BHV-CP-010 | golden_spec §S3 CP.2 + GUI kernel.ts |
| CAP-B-17 | WS /logs streams log entries | BHV-CP-011 | golden_spec §S3 CP.2 + GUI kernel.ts |
| CAP-B-18 | WS auth valid token accepted | BHV-CP-015 | golden_spec §S3 CP.3 |
| CAP-B-19 | WS auth wrong token rejected | BHV-CP-016 | golden_spec §S3 CP.3 |
| CAP-B-20 | WS auth missing token rejected | BHV-CP-017 | golden_spec §S3 CP.3 |
| CAP-B-21 | GET /version returns version info | BHV-CP-020 | golden_spec §S3 CP.4 |

### C. Proxy / Traffic Plane (17 capabilities)

| ID | Capability | BHV Ref | Source |
|----|-----------|---------|--------|
| CAP-C-01 | SOCKS5 TCP CONNECT relays HTTP | BHV-DP-001 | golden_spec §S3 DP.1 |
| CAP-C-02 | SOCKS5 HTTP GET JSON echo | BHV-DP-005 | golden_spec §S3 DP.2 |
| CAP-C-03 | Selector group switch affects traffic routing | BHV-DP-006 | golden_spec §S3 DP.2 |
| CAP-C-04 | HTTP status codes pass through | BHV-DP-005 | golden_spec §S3 DP.2 |
| CAP-C-05 | HTTPS (self-signed -k) through SOCKS5 | BHV-DP-005 | golden_spec §S3 DP.2 |
| CAP-C-06 | HTTPS strict (no -k) client TLS verification | BHV-DP-005 | golden_spec §S3 DP.2 |
| CAP-C-07 | Redirect chain follow through proxy | BHV-DP-005 | golden_spec §S3 DP.2 |
| CAP-C-08 | Chunked transfer-encoding relay | BHV-DP-005 | golden_spec §S3 DP.2 |
| CAP-C-09 | Large body (1 MiB) relay | BHV-DP-005 | golden_spec §S3 DP.2 |
| CAP-C-10 | SSE stream relay | BHV-DP-005 | golden_spec §S3 DP.2 |
| CAP-C-11 | Slow upstream relay | BHV-DP-005 | golden_spec §S3 DP.2 |
| CAP-C-12 | RFC 6455 WebSocket through SOCKS5 | BHV-DP-001 | MT-GUI-02 DP-12 |
| CAP-C-13 | Raw TCP echo through SOCKS5 | BHV-DP-001 | MT-GUI-02 DP-11 |
| CAP-C-14 | Early-close fault handling | BHV-DP-005 | MT-GUI-02 DP-13 |
| CAP-C-15 | RST (no reply) fault handling | BHV-DP-005 | MT-GUI-02 DP-14 |
| CAP-C-16 | Dead port connection refusal | BHV-DP-008 | MT-GUI-02 DP-15 |
| CAP-C-17 | Client timeout behavior | BHV-DP-005 | general proxy semantics |

### D. Subscription / Remote Config / Refresh (5 capabilities)

| ID | Capability | BHV Ref | Source |
|----|-----------|---------|--------|
| CAP-D-01 | Subscription fetch (public, no auth) | — | MT-GUI-02 SUB-01 |
| CAP-D-02 | Subscription auth rejection (wrong bearer) | — | MT-GUI-02 SUB-02 |
| CAP-D-03 | Subscription auth acceptance (correct bearer) | — | MT-GUI-02 SUB-03 |
| CAP-D-04 | ETag / If-None-Match / 304 caching | — | MT-GUI-02 SUB-04 |
| CAP-D-05 | Downloaded config parseable by both kernels | — | MT-GUI-02 SUB-05 |

### E. Observability / State Plane (5 capabilities)

| ID | Capability | BHV Ref | Source |
|----|-----------|---------|--------|
| CAP-E-01 | /connections returns array of active connections | BHV-CP-006 | golden_spec §S3 CP.1 |
| CAP-E-02 | /connections.downloadTotal presence | BHV-CP-006 | DIV-M-011 axis |
| CAP-E-03 | /traffic WS real-time bandwidth observable | BHV-CP-008 | golden_spec §S3 CP.2 |
| CAP-E-04 | /memory WS RSS observable | BHV-CP-009 | golden_spec §S3 CP.2 |
| CAP-E-05 | /logs WS log stream observable | BHV-CP-011 | golden_spec §S3 CP.2 |

### F. Graceful Shutdown (2 capabilities)

| ID | Capability | BHV Ref | Source |
|----|-----------|---------|--------|
| CAP-F-01 | Rust kernel graceful shutdown on SIGTERM | BHV-LC-007 | golden_spec §S3 LC.3 |
| CAP-F-02 | Go kernel graceful shutdown on SIGTERM | BHV-LC-007 | golden_spec §S3 LC.3 |

---

## 3. Totals

| Category | Count |
|----------|-------|
| A. Startup / Lifecycle | 5 |
| B. Clash / GUI Control-Plane API | 21 |
| C. Proxy / Traffic Plane | 17 |
| D. Subscription / Remote Config | 5 |
| E. Observability / State Plane | 5 |
| F. Graceful Shutdown | 2 |
| **Total declared capabilities** | **55** |

---

## 4. Capabilities NOT in this inventory (and why)

### Golden spec BHVs not mapped here

| BHV Range | Reason not in this inventory |
|-----------|------------------------------|
| BHV-SV-001..004 | Reclassified as harness-only (SV.1); not kernel behavior |
| BHV-SV-005..007 | STRUCTURAL: Go provider endpoints return stubs; cannot dual-kernel test (DIV-H-005) |
| BHV-LC-003 | NOT-FEASIBLE: concurrent service failure isolation; Rust `/services/health` is a static stub (DIV-H-006) |
| BHV-DP-002 | SOCKS5 UDP: requires UDP ASSOCIATE support; not exercised by GUI API surface |
| BHV-DP-003 | HTTP CONNECT proxy: tested in interop-lab but not in GUI-shape config |
| BHV-DP-004 | Mixed inbound: tested in interop-lab (both); GUI config uses SOCKS-only |
| BHV-DP-007 | URLTest auto-select: tested in interop-lab; GUI config has selector only |
| BHV-DP-009 | Chain proxy: tested in interop-lab; not in GUI-shape config |
| BHV-DP-010..014 | Routing rules: tested in interop-lab; GUI-shape config has no explicit rules |
| BHV-DP-015..018 | DNS data-plane: tested in interop-lab; partially covered by B-12/B-13 |
| BHV-PF-001..005 | Performance: covered by interop-lab perf cases; not GUI-surface-specific |
| BHV-LC-005..006 | Reload/state preservation: covered by interop-lab lifecycle cases |
| BHV-LC-008..009 | WS close notification + resource cleanup: covered by interop-lab |

These BHVs are covered by the interop-lab's `kernel_mode: both` cases (52/56 BHV coverage
per golden spec §S6), not by this GUI-surface inventory. They are NOT gaps — they are
capabilities verified through a different channel.

### GO_PARITY_MATRIX items not mapped here

The 209 code-level closure items cover implementation presence (files, modules, feature gates),
not behavioral verification. This inventory focuses on **behavioral evidence in GUI context**,
not code-level closure. The parity matrix is a complementary, not competing, evidence source.
