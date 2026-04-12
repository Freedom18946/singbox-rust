<!-- tier: B -->
# MT-GUI-04: Exhaustive Declared-Complete Kernel Acceptance Sweep

**Date**: 2026-04-12
**HEAD**: `ac5741a1` (post-MT-GUI-03, on `main`)
**Card type**: Exhaustive declared-complete capability acceptance / evidence / release-readiness work.
**NOT**: a parity completion card, a new maintenance line, a code-change card, or a blocker-hunting card.

> **Authoritative parity口径仍以** `labs/interop-lab/docs/dual_kernel_golden_spec.md` **为准**.
> 本卡对所有"声明完成"的内核能力逐条验收，不重写 parity 结论.

---

## 1. Scope

MT-GUI-04 answers a single question: **have ALL declared-complete kernel capabilities been
individually verified with real dual-kernel evidence in GUI context?**

Prior cards (MT-GUI-01/02/03) proved the system works through broad scenario-based acceptance.
This card drills down to **per-capability granularity** — each capability gets its own ID,
its own test, its own evidence line, and its own status.

### What "declared-complete" means here

A capability is "declared-complete" if it appears in at least one of:
- `dual_kernel_golden_spec.md` §S3 (behavioral registry)
- GUI source `kernel.ts` (API contract the GUI actually uses)
- MT-DEPLOY-01 (deployment baseline)
- MT-GUI-01/02 (existing acceptance evidence)

### Deliverables

| Deliverable | File |
|-------------|------|
| Capability inventory (source list) | `mt_gui_04_capability_inventory.md` |
| Per-item verification matrix | `mt_gui_04_matrix.md` |
| This acceptance report | `mt_gui_04_acceptance.md` |
| Gap analysis | `mt_gui_04_gap_list.md` |
| Raw evidence | `mt_gui_04_evidence/raw_sweep.txt` |
| Test script | `mt_gui_04_evidence/exhaustive_sweep.sh` |

### Explicitly out of scope

- Building or running the GUI binary itself (Wails desktop)
- Real upstream proxy chains
- Restoring `.github/workflows/*`
- Public `RuntimePlan` / `PlannedConfigIR` / generic query API
- Promoting results to parity completion claims

---

## 2. Method

### 2.1 Capability enumeration

55 capabilities extracted from authoritative sources, organized into 6 categories:
- A. Startup / Lifecycle (5)
- B. Clash / GUI Control-Plane API (21)
- C. Proxy / Traffic Plane (17)
- D. Subscription / Remote Config (5)
- E. Observability / State Plane (5)
- F. Graceful Shutdown (2)

Full enumeration: `mt_gui_04_capability_inventory.md`.

### 2.2 Test infrastructure

Reuses MT-GUI-02's mock public infrastructure (`mock_public_infra.py`) with both kernels
running simultaneously against the same GUI-shape configs.

### 2.3 Execution

Single automated script (`exhaustive_sweep.sh`) tests every capability individually:
- Each capability has a unique test ID (A-01 through F-02)
- Each test produces an explicit PASS/FAIL determination
- Each test records Rust and Go observations
- Divergences are mapped to specific DIV-M-* entries

### 2.4 Status classification

| Status | Definition |
|--------|-----------|
| **PASS-STRICT** | Both kernels behave identically on this capability |
| **PASS-DIV-COVERED** | Both work, difference is already attributed to a specific DIV-M-* entry |
| **PASS-ENV-LIMITED** | Observation limited by test harness; covered by interop-lab real tests |
| **NEW FINDING** | Observation not categorized by golden spec |
| **FAIL** | Capability does not work |

---

## 3. Results

### 3.1 Aggregate

| Status | Count | Percentage |
|--------|-------|------------|
| PASS-STRICT | 35 | 63.6% |
| PASS-DIV-COVERED | 7 | 12.7% |
| PASS-ENV-LIMITED | 13 | 23.6% |
| NEW FINDING | 0 | 0% |
| FAIL | **0** | **0%** |
| **Total** | **55** | **100%** |

**Zero failures. Zero new findings.**

### 3.2 By category

| Category | Total | STRICT | DIV-COV | ENV-LIM | FAIL |
|----------|-------|--------|---------|---------|------|
| A. Startup/Lifecycle | 5 | 5 | 0 | 0 | 0 |
| B. Control-Plane API | 21 | 7 | 6 | 7 | 0 |
| C. Traffic Plane | 17 | 15 | 0 | 2 | 0 |
| D. Subscription | 5 | 5 | 0 | 0 | 0 |
| E. Observability | 5 | 1 | 1 | 3 | 0 |
| F. Shutdown | 2 | 2 | 0 | 0 | 0 |

### 3.3 Divergence accounting

All 7 PASS-DIV-COVERED items map to specific DIV-M entries:

| Cap ID | DIV ID | Tag | Axis |
|--------|--------|-----|------|
| B-01 | DIV-M-006 | COSMETIC | /configs mode casing |
| B-03 | DIV-M-007 | COSMETIC | /proxies synthetic entries |
| B-06 | DIV-M-009 | COSMETIC | delay ms timing |
| B-07 | DIV-M-008 | COSMETIC | /connections memory field |
| B-12 | DIV-M-005 | COSMETIC | /dns/query body shape |
| B-13 | DIV-M-010 | COSMETIC | /dns/query non-resolvable status |
| E-02 | DIV-M-011 | COSMETIC | downloadTotal cumulative |

All are COSMETIC. No new divergences discovered.

### 3.4 ENV-LIMITED accounting

13 items are PASS-ENV-LIMITED. All are WebSocket probes using curl (not a real RFC 6455 client):

| Cap IDs | What's limited | Why it's still covered |
|---------|---------------|----------------------|
| B-14..B-20 | WS stream + auth via curl | Real WS covered by `p0_clash_api_contract_strict`, `p1_gui_full_boot_replay`, `p1_clash_api_auth_enforcement` — all `kernel_mode: both` in interop-lab |
| C-12 | WS through SOCKS5 | PASS-STRICT in MT-GUI-02 DP-12 with inline Python WS client |
| C-13 | TCP echo through SOCKS5 | PASS-STRICT in MT-GUI-02 DP-11 with inline Python TCP client |
| E-03..E-05 | WS observability | Same as B-14..B-17 — real WS in interop-lab |

**No ENV-LIMITED item lacks real coverage elsewhere.** The limitation is purely in this
sweep's curl-based probe — the capability itself has been verified through real WS clients
in other test runs.

---

## 4. Comparison with prior cards

| Card | Scenarios | Granularity | Findings |
|------|-----------|-------------|----------|
| MT-GUI-01 | 15 | Broad scenario | 1 NEW FINDING (downloadTotal) |
| MT-GUI-02 | 35 | Scenario + mock public | 1 NEW + 1 CONFIRMED FINDING |
| MT-GUI-03 | — (classification only) | Per-divergence | 2 new DIV entries (M-010, M-011) |
| **MT-GUI-04** | **55** | **Per-capability** | **0 new findings, 0 failures** |

MT-GUI-04 is more granular than MT-GUI-01/02 (55 individual capability checks vs 15/35 scenarios)
and confirms that the MT-GUI-03 divergence classification is complete — no new issues surfaced
when testing at finer granularity.

---

## 5. Uncovered BHVs (outside GUI-surface scope)

The golden spec defines 56 BHVs. This sweep covers capabilities corresponding to the GUI API
surface (the 11 endpoints the GUI actually uses + surrounding lifecycle). The following BHVs
are verified through interop-lab `kernel_mode: both` cases, not through this GUI-surface sweep:

| BHV Range | Domain | Covered by |
|-----------|--------|-----------|
| BHV-DP-002 | SOCKS5 UDP | `p1_rust_core_udp_via_socks` (both) |
| BHV-DP-003 | HTTP CONNECT | `p1_http_connect_via_http_proxy` (both) |
| BHV-DP-004 | Mixed inbound | `p1_mixed_inbound_dual_protocol` (both) |
| BHV-DP-007 | URLTest auto | `p1_urltest_auto_select_replay` (both) |
| BHV-DP-009 | Chain proxy | `p2_dataplane_chain_proxy` (both) |
| BHV-DP-010..014 | Routing rules | Various `p1_*_rule_via_socks` (both) |
| BHV-DP-015..018 | DNS data | `p1_dns_*` cases (both) |
| BHV-LC-005..006 | Reload | `p1_inbound_hot_reload_sighup`, `p1_selector_switch_traffic_replay` (both) |
| BHV-LC-008..009 | Shutdown WS + cleanup | `p1_gui_ws_reconnect_behavior`, `p1_lifecycle_restart_reload_replay` (both) |
| BHV-PF-001..005 | Performance | Various `p1_*`, `p2_*` perf cases (both) |

4 BHVs remain structurally uncoverable:
- **BHV-SV-005..007** (DIV-H-005): Go provider endpoints return stubs
- **BHV-LC-003** (DIV-H-006): Service failure isolation requires runtime health plumbing

These 4 are the same gap as documented in golden spec §S6 (52/56 BHV coverage).

---

## 6. Verdict

### Does every declared-complete kernel capability have per-item verification evidence?

**YES.**

| Question | Answer |
|----------|--------|
| Total capabilities enumerated | 55 |
| Capabilities verified PASS-STRICT | 35 (63.6%) |
| Capabilities verified PASS-DIV-COVERED | 7 (12.7%) — all mapped to specific DIV-M-* |
| Capabilities verified PASS-ENV-LIMITED | 13 (23.6%) — all have real coverage in interop-lab |
| Capabilities FAIL | **0** |
| New findings | **0** |
| New divergences | **0** |
| New blockers | **0** |
| Items left "粗颗粒已过、细项未清" | **0** — every item has its own row |

### Remaining structural gaps (unchanged from golden spec)

- 4 BHVs (SV.2 provider + LC.3 service isolation) are structurally uncoverable due to
  Go-side limitations (DIV-H-005, DIV-H-006)
- These are NOT new; they are the same 4/56 gap documented since golden spec creation

### Categorical conclusion

This sweep confirms that the exhaustive per-capability verification is complete:
- **No capability was left at "coarse-grained pass, fine-grained unverified"**
- **No new blocker was discovered**
- **No new divergence was found beyond what MT-GUI-03 already classified**
- **The 7 known COSMETIC divergences (DIV-M-005..011) account for 100% of observed differences**

---

## 7. Reproduction

```bash
cd /Users/bob/Desktop/Projects/ING/sing/singbox-rust

# Confirm prerequisites
ls target/release/app
ls go_fork_source/sing-box-1.12.14/sing-box

# Run the exhaustive sweep
bash agents-only/mt_gui_04_evidence/exhaustive_sweep.sh

# Inspect raw evidence
cat agents-only/mt_gui_04_evidence/raw_sweep.txt
```

---

## 8. What this card is NOT

- Not a parity completion update
- Not a replacement for `dual_kernel_golden_spec.md`
- Not a new interop case
- Not a maintenance card
- Not a code change
