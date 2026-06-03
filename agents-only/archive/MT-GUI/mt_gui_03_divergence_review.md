<!-- tier: B -->
# MT-GUI-03: GUI Dual-Kernel Divergence Classification & Oracle Reconciliation

**Date**: 2026-04-12
**HEAD**: `47b2a8f2` (post-MT-GUI-02 close, on `main`)
**Card type**: Classification / oracle reconciliation / audit-evidence work.
**NOT**: a dual-kernel parity completion card, an internal refactor, a new maintenance line, a
blocker-hunting card, a code-change card, or a rewrite of prior parity conclusions.

> **Authoritative parity口径仍以** `labs/interop-lab/docs/dual_kernel_golden_spec.md` **为准**.
> 本卡只归类 MT-GUI-01 / MT-GUI-02 已取得的差异证据，并决定差异该如何落入 oracle / golden
> spec / accepted-limitation 文档体系。
> 不新增新的双内核测试，不改内核实现，不升级任何差异为 blocker。

---

## 1. Scope

MT-GUI-03 ingests the existing evidence produced by MT-GUI-01 and MT-GUI-02 and answers the
following questions, one divergence at a time:

1. Is this divergence already covered by `dual_kernel_golden_spec.md §S4`?
2. If covered, is it an **extension** of an accepted limitation (same endpoint, new axis) or a
   **direct** match (same axis)?
3. If not covered, is it
   - a **New Finding, Non-Blocking** (record in acceptance docs only), or
   - an **Environment-Limited** observation (test harness artifact), or
   - a **Needs Oracle Decision** item (insufficient evidence to classify)?
4. Does the spec / oracle / accepted-limitation doc need to be updated?
5. Should any of these become new maintenance cards? (Pre-committed answer: **no** unless the
   observation has repeated across multiple agents or directly breaks a GUI user flow.)

### Explicitly out of scope

- Running a new full dual-kernel test sweep (the MT-GUI-02 evidence from `2026-04-12T05:30Z` is
  fresh and reused as-is).
- Writing new `kernel_mode: both` interop cases for any of these findings.
- Modifying Rust kernel code to close any of these gaps.
- Restoring any removed `.github/workflows/*`.
- Public `RuntimePlan` / `PlannedConfigIR` / generic query API work.

---

## 2. Evidence inventory (inputs to this classification)

| Source | What it contributes |
|--------|---------------------|
| [mt_gui_01_acceptance.md](./mt_gui_01_acceptance.md) | First observation of §5 `downloadTotal` delta (Go=2454, Rust=0); 4× existing DIV-M-* confirmations |
| [mt_gui_01_matrix.md](./mt_gui_01_matrix.md) | Per-scenario disposition for 15 scenarios |
| [mt_gui_02_acceptance.md](./mt_gui_02_acceptance.md) | 35-scenario run with CP-13 NEW FINDING + DP-16 CONFIRMED FINDING |
| [mt_gui_02_matrix.md](./mt_gui_02_matrix.md) | Per-scenario matrix with divergence reconciliation table |
| [mt_gui_02_mock_public_infra.md](./mt_gui_02_mock_public_infra.md) | Mock design; confirms `mock-public.local` is deliberately non-resolvable |
| [mt_gui_02_evidence/control_plane.txt](./mt_gui_02_evidence/control_plane.txt) | Raw status codes for CP-13 (Rust=500, Go=200) |
| [mt_gui_02_evidence/data_plane.txt](./mt_gui_02_evidence/data_plane.txt) | Raw delta counters for DP-16 (Rust=0, Go=1055032) |
| [mt_gui_02_evidence/extra_shape_probe.txt](./mt_gui_02_evidence/extra_shape_probe.txt) | Pretty-printed bodies for `/rules`, `/providers/rules`, `/dns/query`, `/configs`, `/connections` |
| `labs/interop-lab/docs/dual_kernel_golden_spec.md §S4` | Authoritative DIV registry as of this card |
| `labs/interop-lab/cases/p1_gui_connections_tracking.yaml` | Existing dual-kernel case for `/connections` live counter semantics (reveals what is already asserted and what is not) |
| `labs/interop-lab/cases/p1_dns_query_endpoint_contract.yaml` | Existing dual-kernel case for `/dns/query` (resolvable only, status-assertion axis) |
| `go_fork_source/sing-box-1.12.14/experimental/clashapi/dns.go` | Confirms Go's `/dns/query` returns 500 on router.Exchange error — so the CP-13 divergence is not at the HTTP handler level but at the internal DNS router's behavior on an unconfigured resolver |

No new reproduction was necessary: the MT-GUI-02 evidence files are dated `Apr 12 05:30–05:31`
(this morning's re-run) and already contain the raw strings this card is classifying.

---

## 3. Category definitions (used consistently below)

| Class | Meaning | Oracle/spec action |
|-------|---------|--------------------|
| **Covered by Existing Divergence** | The observation maps 1:1 onto an existing `DIV-*` entry with the same axis (status code, body shape, WS frame count, etc.). | None — already handled by `ignore_http_paths` / `ignore_ws_paths` / tolerance rules. |
| **Extension of Existing Accepted Limitation** | Same endpoint as an existing `DIV-*` entry, but a distinct behavioral axis (e.g. DIV covers body shape, observation is about status code). | Update existing entry's description to cover both axes, OR add a new sibling `DIV-M-*` entry on the same endpoint. |
| **New Finding, Non-Blocking** | Not on any path currently covered by `DIV-*`; does not affect any real GUI user flow; both kernels return syntactically valid responses. | Record in acceptance doc only. Do NOT add to golden spec unless signal repeats. |
| **Environment-Limited** | Observation is bounded by a test-harness limitation (curl not being a real WS client, self-signed cert, unbound port, …). | None — tri-state `PASS-ENV-LIMITED` already handles it. |
| **Needs Oracle Decision** | Insufficient evidence to tell which of the above applies; the review explicitly holds judgment instead of guessing. | Hold. Record as open question. |

Every observation in the MT-GUI-01 / MT-GUI-02 record lands in exactly one of the first four
classes below. None land in **Needs Oracle Decision** — all have enough evidence to classify.

---

## 4. Per-divergence classification

### 4.1 `/configs` payload normalization (mode casing, exposed ports)

**Observed** (MT-GUI-01 Scenario 2 + MT-GUI-02 CP-02 + extra_shape_probe):

| Field | Rust | Go |
|-------|------|------|
| `mode` | `"rule"` | `"Rule"` |
| `mode-list` | `["rule","global","direct"]` | `["Rule"]` |
| `socks-port` | `11810` | `0` |
| `tun` | `{}` | `null` |
| `log-level` | `"info"` | `"warn"` |

**Class**: **Covered by Existing Divergence** (`DIV-M-006`).
**Evidence**: `dual_kernel_golden_spec.md §S4 DIV-M-006` + oracle action `ignore_http_paths: ["/configs"]`.
**Action**: None. DIV-M-006 text already covers "mode casing, mode-list, and exposed port
fields under strict self-managed configs".

---

### 4.2 `/proxies` inventory

**Observed**: Rust keys `[DIRECT, GLOBAL, REJECT, alt-direct, direct, my-group]`, Go keys
`[GLOBAL, alt-direct, direct, my-group]`.

**Class**: **Covered by Existing Divergence** (`DIV-M-007`).
**Evidence**: `DIV-M-007` explicitly calls out "Rust injects synthetic entries and richer
group metadata than Go" with oracle `ignore_http_paths: ["/proxies"]`.
**Action**: None.

---

### 4.3 `/proxies/direct/delay` exact millisecond value

**Observed**: Rust=`{"delay":1}` (MT-GUI-02 CP-07), Rust=`{"delay":4}` (MT-GUI-01), Rust=`{"delay":0}` (MT-GUI-02 re-run); Go=`{"delay":502|510|602}`.

**Class**: **Covered by Existing Divergence** (`DIV-M-009`).
**Evidence**: `DIV-M-009` covers "exact millisecond values are timing-sensitive across kernels
even when status is consistent"; oracle is path-specific ignore for delay.
**Action**: None.

---

### 4.4 `/connections` body `memory` field shape/magnitude

**Observed**: Rust `memory≈17–21 MiB`, Go `memory≈4–5 MiB`; body schema is otherwise
identical; `connections` list empty; `uploadTotal` / `downloadTotal` present on both.

**Class**: **Covered by Existing Divergence** (`DIV-M-008`).
**Evidence**: `DIV-M-008` is scoped to "runtime/platform-specific `memory` values; Rust
returns 0 on non-Linux" with oracle `ignore_http_paths: ["/connections"]`.
**Action**: None.

---

### 4.5 `/dns/query?name=example.com` body shape (resolvable baseline)

**Observed** (MT-GUI-02 CP-12 + extra_shape_probe):

- Rust: `{"addresses":["198.18.1.30"],"name":"example.com","ttl":300,"type":"A"}`
- Go: `{"AD":false,"Answer":[{"TTL":1,"data":"198.18.1.30",…}],"Question":[…],"Server":"internal",…}`

Both 200. Same answer IP. Different body shape.

**Class**: **Covered by Existing Divergence** (`DIV-M-005`).
**Evidence**: `DIV-M-005` already reads "Rust returns simplified JSON vs Go's full dig-style
output" with oracle `ignore_http_paths: ["/dns/query*"]`.
**Action**: None.

> **Note**: both kernels returning `198.18.1.30` for `example.com` is synthetic — neither
> kernel has outbound DNS configured in the mock run, and both fall back to some internal
> deterministic answer. This is a property of the *test configuration*, not a kernel
> divergence, and is NOT re-classified here.

---

### 4.6 `/rules` list vs null (within-envelope shape diff)

**Observed** (MT-GUI-02 CP-09 + extra_shape_probe):

- Rust: `{"rules":[{"type":"MATCH","proxy":"my-group","payload":"","order":9999}]}`
- Go: `{"rules":null}`

Both 200. Route behavior identical (`route.final = my-group` terminates dispatch on both
kernels — already verified by DP-01..DP-15 PASS-STRICT across HTTP/HTTPS/WS/SSE/chunked/large).

**Class**: **New Finding, Non-Blocking**.
**Rationale**:
- Not an existing DIV-M-* entry's axis (no DIV entry currently covers `/rules`).
- Both bodies are syntactically valid JSON; both represent the same underlying route dispatch
  (Rust surfaces the implicit final-rule sentinel, Go leaves it implicit).
- The GUI consumer of `/rules` is a rule-list panel that accepts both `null` and `[]` shapes
  — it iterates defensively.
- No GUI user flow is broken by this divergence: the selector, delay probe, and data plane
  all behave identically.

**Action**: Do NOT elevate to `DIV-M-*`. Do NOT create a new dual-kernel case. Keep recorded
in `mt_gui_02_acceptance.md §4.4` and this review only. Elevating would flood the registry
without changing any oracle behavior, because no strict case currently diffs `/rules` and any
future case should just add the endpoint to `ignore_http_paths`.

---

### 4.7 `/providers/rules` object vs array (empty-set shape diff)

**Observed** (MT-GUI-02 CP-11 + extra_shape_probe):

- Rust: `{"providers":{}}`
- Go: `{"providers":[]}`

Both 200, both empty, both GUI-parseable.

**Class**: **New Finding, Non-Blocking**.
**Rationale**:
- `/providers/proxies` returns `{"providers":{}}` on both kernels (matches) — proving the
  divergence is narrow, affecting only the rule-provider path.
- GUI source (`frontend/src/api/kernel.ts`) uses `Object.keys` on the providers response for
  iteration; both a `{}` object and an `[]` array are safe for `Object.keys` iteration.
- No GUI user flow is broken.

**Action**: Do NOT elevate to `DIV-M-*`. Do NOT create a new dual-kernel case. Same rationale
as §4.6. Keep recorded in `mt_gui_02_acceptance.md §4.4` and this review only.

---

### 4.8 WS handshake via curl

**Observed**: `/traffic`, `/memory`, `/connections`, `/logs` all return data via curl
`--http1.1` Upgrade probe on both kernels.

**Class**: **Environment-Limited**.
**Rationale**: curl is not a real RFC 6455 client. MT-GUI-02 DP-12 already covers real WS
through a hand-rolled Python client over SOCKS5 with PASS-STRICT. `p0_clash_api_contract*`
covers real WS framing against the Clash API directly. Both kernels are proven to handshake
correctly — this scenario adds nothing a real WS case does not cover.
**Action**: None. Tri-state `PASS-ENV-LIMITED` already handles it.

---

### 4.9 `/dns/query?name=mock-public.local` on NON-RESOLVABLE domain — **deferred finding #1**

**Observed** (MT-GUI-02 CP-13 + extra_shape_probe):

| Field | Rust | Go |
|-------|------|------|
| HTTP status | **500** | **200** |
| Body (abbreviated) | `{"message":"Failed to resolve mock-public.local: …nodename nor servname provided, or not known"}` | `{"Answer":[{"data":"198.18.1.29","name":"mock-public.local.","type":1,"TTL":6}], "Server":"internal", "Status":0, …}` |

**Class**: **Extension of Existing Accepted Limitation** — same endpoint as `DIV-M-005`,
distinct axis.

**Why this is a distinct axis from DIV-M-005**:

- `DIV-M-005` is scoped to **body shape of a successful DNS answer** (Rust flat Clash-ish JSON
  vs Go dig-style `Answer[]` envelope). That axis is already ignored by
  `ignore_http_paths: ["/dns/query*"]`.
- CP-13 is about **what status and what body each kernel returns when the internal DNS router
  cannot resolve the name**. This is a different diff dimension (status code + semantics of
  the response).

**Root-cause reading** (from Go source at
`go_fork_source/sing-box-1.12.14/experimental/clashapi/dns.go:22-48`):

1. Go's `queryDNS` handler would return 500 if `router.Exchange(ctx, &msg, …)` returns an
   error. So the CP-13 divergence is **not** in the Clash API layer — it is in Go's internal
   DNS router deciding to synthesize an answer for an unconfigured resolver instead of
   propagating a lookup error. That synthesized answer comes from the fake-IP-style pool
   (`198.18.x.x`).
2. Rust's `/dns/query` handler faithfully propagates the OS resolver error (`nodename nor
   servname provided`) as an HTTP 500 with the error text.

So the categorical description is:
- **Go**: "internal DNS router synthesizes a fake-IP-shaped answer for names the real
  resolver cannot handle, and returns 200".
- **Rust**: "internal DNS router surfaces the underlying lookup error as HTTP 500".

This is a **design divergence**, not a parity bug on either side. Both behaviors are
internally consistent with their project's philosophy: Go errs on "keep the GUI chart happy";
Rust errs on "tell the truth about resolution failure".

**Impact on real GUI user flow**:

- GUI.for.SingBox's resolver panel is invoked by user action (user types a name, clicks
  "query"). Users typically type a name they believe is resolvable. When the name IS
  resolvable, both kernels return 200 (already verified by CP-12).
- When the user types a non-resolvable name:
  - On Go: GUI shows a fake `198.18.x.x` answer, which is misleading but not an error.
  - On Rust: GUI gets an HTTP 500 and would show an error message.
- Neither outcome corrupts GUI state. This is a UX difference, not a functional gap.

**Disposition**:

- **Add a new DIV entry**: `DIV-M-010` in `dual_kernel_golden_spec.md §S4`, tagged
  `COSMETIC`, description: "`/dns/query` on non-resolvable name: Rust propagates lookup error
  as 500; Go synthesizes a fake-IP-shaped answer via internal resolver fallback and returns
  200. Design divergence, not a parity gap."
- **Oracle action**: Already satisfied — `ignore_http_paths: ["/dns/query*"]` exists in the
  DIV-M-005 row, and the existing `p1_dns_query_endpoint_contract` dual-kernel case asserts
  status on a **resolvable** name (`localhost`), which avoids this axis entirely. No existing
  case needs editing.
- **New case recommendation**: None. If a future agent wants to exercise this axis, the
  correct pattern is a new `kernel_mode: both` case asserting
  `http.dns_query.status in {200, 500}` on `mock-public.local`. This card does NOT create it.
- **New maintenance card**: None. Neither side is broken.
- **Code change**: None. Specifically, Rust should **not** adopt Go's fake-IP fallback; the
  Rust behavior is the semantically honest one, and the Go behavior is best read as a
  historical artifact of the fake-ip strategy being on by default.

---

### 4.10 Cumulative `/connections.downloadTotal` after close — **deferred finding #2**

**Observed** (MT-GUI-01 §5 + MT-GUI-02 DP-16, two independent runs, different scales):

| Observation | Rust | Go |
|-------------|------|------|
| MT-GUI-01 (1× curl, ~2454 B) | `delta=0` | `delta=2454` |
| MT-GUI-02 (full 15-scenario sweep, >1 MiB) | `delta=0` | `delta=1055032` |
| `uploadTotal` (MT-GUI-02) | `0` | `2186` |
| `connections` (active) at capture | `[]` | `[]` |

Both kernels successfully relayed all 15 data-plane scenarios (HTTP/HTTPS/SSE/chunked/1 MiB/
slow/early-close/RST/TCP-echo/RFC-6455-WS) — the data plane works identically. The divergence
is **exclusively** in whether the process-lifetime counter accumulates across closed
connections or resets to zero.

**Is it on DIV-M-008's axis?** No:

- `DIV-M-008` is "`/connections` HTTP snapshot includes runtime/platform-specific `memory`
  values; Rust returns 0 on non-Linux". That is a memory-field axis.
- `DP-16` is about the top-level `downloadTotal` / `uploadTotal` fields on the same endpoint.
  These are different fields with different semantics.

**Does any existing dual-kernel case exercise this axis?**

Checked: `labs/interop-lab/cases/p1_gui_connections_tracking.yaml`. It asserts:

```yaml
- key: connections.uploadTotal
  op: gt
  expected: 0
```

…on a **live in-flight connection** (the case starts a slow 4-second request via SOCKS5,
sleeps 300ms, then captures `/connections` while the request is still running). This confirms
that **Rust DOES track bytes per active connection** — the per-connection `uploadTotal` is
non-zero and the case is strict-mode `both`. The thing that does NOT happen on Rust is
**summing closed connections' bytes into a process-lifetime counter**.

So the finding has two halves, and only one is a divergence:
- **Per-connection live counter** (works on both): no divergence. Covered by
  `p1_gui_connections_tracking` with strict oracle.
- **Process-lifetime cumulative counter after close** (diverges): no case covers it, no DIV
  entry describes it.

**Root-cause reading** (no code change attempted in this card): Rust's `/connections`
handler likely zeroes the top-level totals when the active `connections` list is empty, or
only surfaces totals from currently-open connection trackers. Go accumulates independently.
We do not dig deeper in this card because the card's mandate is classification, not repair.

**Impact on real GUI user flow**:

- GUI bandwidth chart (`WS /traffic`) uses live per-tick delta from the traffic stream, not
  the cumulative totals. So the primary GUI chart is **unaffected**.
- GUI connection list panel shows a small "total transferred this session" stat at the bottom,
  derived from the HTTP `/connections.downloadTotal` field. On Rust this would read 0 whenever
  no connections are currently active — a real UX difference, but not a functional break.
- No other GUI surface consumes these fields.

**Disposition**:

- **Add a new DIV entry**: `DIV-M-011` in `dual_kernel_golden_spec.md §S4`, tagged
  `COSMETIC`, description: "`/connections` top-level `downloadTotal`/`uploadTotal` semantics
  differ: Rust scopes byte counters per-active-connection and does not retain accumulated
  totals after connections close; Go accumulates across the process lifetime. Per-connection
  live counters (`connections[].upload`/`.download`) match; only the top-level aggregate
  differs."
- **Oracle action**: Already satisfied. `DIV-M-008` already contributes
  `ignore_http_paths: ["/connections"]`, which prevents any diff engine from flagging the
  cumulative field mismatch on that path. The existing `p1_gui_connections_tracking` case
  asserts a per-connection field (`connections.uploadTotal` on the live connection), not a
  top-level field, so it is not impacted.
- **New case recommendation**: None. If a future agent wants a dual-kernel case that
  tolerates the divergence, the correct pattern is a `kernel_mode: both` case that asserts
  `http.connections.status == 200` AND `connections.len >= 0`, with
  `ignore_http_paths: ["/connections"]`. This card does NOT create it.
- **New maintenance card**: None. Neither side is broken.
- **Code change**: None. Closing this gap would require Rust to maintain a process-lifetime
  byte counter across connection-close events. That is a scope decision, not a bug fix, and
  this card is explicitly not a repair card.

> **Note on whether the repeated observation should force escalation**: Per the card's
> pre-committed rule ("do not open a follow-up card unless the finding has repeated across
> multiple agents or directly breaks a GUI user flow"): the finding HAS repeated (MT-GUI-01
> §5 → MT-GUI-02 DP-16), but it does NOT break any GUI user flow (the bandwidth chart uses
> live WS data). Escalation criteria are not met. Spec annotation is the correct response;
> a maintenance card is not.

---

## 5. Summary table

| # | Observation | Endpoint(s) | Class | Spec change | Oracle change | New case | New card |
|---|-------------|-------------|-------|-------------|---------------|----------|----------|
| 1 | `/configs` mode casing + exposed ports | `/configs` | Covered by DIV-M-006 | — | — | — | — |
| 2 | `/proxies` synthetic Rust entries | `/proxies` | Covered by DIV-M-007 | — | — | — | — |
| 3 | `/proxies/{name}/delay` ms | `/proxies/direct/delay` | Covered by DIV-M-009 | — | — | — | — |
| 4 | `/connections.memory` shape/magnitude | `/connections` | Covered by DIV-M-008 | — | — | — | — |
| 5 | `/dns/query?name=example.com` body shape | `/dns/query` | Covered by DIV-M-005 | — | — | — | — |
| 6 | `/rules` list vs null | `/rules` | New Finding, Non-Blocking | — | — | — | — |
| 7 | `/providers/rules` `{}` vs `[]` | `/providers/rules` | New Finding, Non-Blocking | — | — | — | — |
| 8 | WS handshake via curl | `/traffic /memory /connections /logs` | Environment-Limited | — | — | — | — |
| 9 | **`/dns/query` non-resolvable status 500 vs 200** | `/dns/query` | Extension of DIV-M-005 (new axis) | **+DIV-M-010** | already in place | — | — |
| 10 | **Cumulative `downloadTotal` after close** | `/connections` | Extension of DIV-M-008 (new axis) | **+DIV-M-011** | already in place | — | — |

**Class totals**: 5 Covered, 2 New-Finding-Non-Blocking, 1 Environment-Limited, 2 Extension-of-Existing. 0 Needs-Oracle-Decision. 0 Blockers.

---

## 6. Golden spec update (the only `dual_kernel_golden_spec.md` edit this card makes)

Added to `§S4 Cosmetic (Format Differences)`:

| DIV ID | Tag | Description | Affected BHV | Oracle Action |
|--------|-----|-------------|--------------|---------------|
| `DIV-M-010` | COSMETIC | `/dns/query` on non-resolvable name: Rust propagates lookup error as HTTP 500; Go's internal DNS router synthesizes a fake-IP-shaped answer and returns 200. Design divergence, not a parity gap. Distinct axis from DIV-M-005 (which covers body shape of successful answers). | BHV-CP-021 | Already covered by `ignore_http_paths: ["/dns/query*"]` from DIV-M-005 |
| `DIV-M-011` | COSMETIC | `/connections` top-level `downloadTotal`/`uploadTotal`: Rust scopes byte counters per-active-connection only; Go accumulates across process lifetime. Per-connection live counters match; only the top-level aggregate diverges after connections close. Distinct axis from DIV-M-008 (which covers the `memory` field). | BHV-CP-006 | Already covered by `ignore_http_paths: ["/connections"]` from DIV-M-008 |

Both entries are **documentation-only additions**. They introduce no new oracle action, no
new case, no new maintenance card, and no code change. Their purpose is to make
`§S4` self-contained: future agents staring at a diff report on these paths can locate the
classification in the spec without cross-referencing MT-GUI-01 / MT-GUI-02 evidence.

### Why a new DIV-ID instead of editing DIV-M-005 / DIV-M-008

- DIV-M-005 and DIV-M-008 have narrow, crisp descriptions that are directly cited by existing
  interop cases. Expanding their text to include the new axes would blur the match between
  a case's "known divergence" comment and the DIV entry it points at.
- Adding `DIV-M-010` / `DIV-M-011` is a cheap, additive change — it preserves the existing
  case comments and cleanly adds two new entries to the registry that future agents can
  reference by ID.
- Neither new entry changes the oracle action (both reuse the existing `ignore_http_paths`
  rules contributed by their sibling DIVs). The registry grows by 2 rows; nothing else moves.

### Why `GO_PARITY_MATRIX.md` is NOT updated

`GO_PARITY_MATRIX.md` records code-level closure (209/209) and historic capability tri-state,
not behavioral-axis divergences. The two new findings are not unimplemented features: both
sides implement the endpoint and return valid responses. There is nothing to move from
"aligned" to "partial" or from "partial" to "not aligned". The correct place for both is the
behavior registry (`dual_kernel_golden_spec.md §S4`), which is already the authoritative
divergence口径 as declared in `AGENTS.md`.

### Why `ACCEPTANCE-CRITERIA.md` is NOT updated

The tri-state `PASS-STRICT / PASS-ENV-LIMITED / FAIL` with the MT-GUI-02 extensions for
`NEW FINDING` / `CONFIRMED FINDING` already covers the review's outputs. No acceptance axis
changes.

---

## 7. Verdict

Does the GUI-driven dual-kernel acceptance path leave any unclassified divergences?

**NO — everything observed in MT-GUI-01 and MT-GUI-02 now falls into a clearly labelled class,
and the two deferred findings have explicit, non-repair dispositions in the golden spec.**

| Categorical answer | Status |
|--------------------|--------|
| All existing DIV-M-* entries confirmed by MT-GUI-01/02 evidence | **YES** |
| Deferred findings from MT-GUI-01 §5 / MT-GUI-02 CP-13 + DP-16 now classified | **YES** |
| New DIV-IDs added: `DIV-M-010` (`/dns/query` non-resolvable status) + `DIV-M-011` (`/connections` cumulative counter) | **YES** |
| New oracle action required | **NO** — existing `ignore_http_paths` rules already cover both new axes |
| New dual-kernel interop cases added | **NO** — out of scope for this card |
| New maintenance cards opened | **NO** — neither finding meets the escalation bar |
| Rust kernel code changes | **NO** — both divergences are semantic/design, not defects |
| Blockers discovered | **NO** |

This card is a **classification / oracle reconciliation / audit-evidence** result, not a
parity completion claim. The dual-kernel behavioral alignment story remains:

- 52 / 56 BHVs covered by at least one `kernel_mode: both` case (unchanged).
- 5 MIG-02-era DIVs (`DIV-M-005..009`) cover all GUI-visible cosmetic differences on the
  control-plane REST surface.
- 2 new COSMETIC DIVs (`DIV-M-010`, `DIV-M-011`) document the new axes revealed by MT-GUI-02
  without changing any oracle behavior.
- The data-plane SOCKS5 relay works identically across HTTP / HTTPS / SSE / chunked / large
  body / slow / WS / TCP echo / early-close / RST / dead port on both kernels.

---

## 8. Reproduction

No new reproduction work is part of this card. To re-run the underlying dual-kernel evidence
sweep that this card classifies:

```bash
cd /Users/bob/Desktop/Projects/ING/sing/singbox-rust
bash agents-only/mt_gui_02_evidence/run_acceptance.sh
```

To verify the spec update this card made:

```bash
grep -n 'DIV-M-010\|DIV-M-011' labs/interop-lab/docs/dual_kernel_golden_spec.md
```

Expected: two rows in `§S4 Cosmetic` with the descriptions above.

---

## 9. What this card is NOT

- Not a parity completion update.
- Not a promotion of any finding to `kernel_mode: both`.
- Not a new maintenance card.
- Not a Rust kernel code change.
- Not a replacement for `mt_gui_01_acceptance.md` / `mt_gui_02_acceptance.md` — those remain
  the primary evidence documents; this card is the classification-and-oracle-reconciliation
  layer over them.
- Not a rewrite of `dual_kernel_golden_spec.md` — the spec is extended by exactly two new
  rows in `§S4`, and the rest of the spec (§S1..§S3, §S5..§S8) is untouched.
