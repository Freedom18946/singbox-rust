<!-- tier: B -->
# T3-1C — Coordinated per-ClientHello GREASE selector (checkpoint)

Replaces the five fixed Chrome GREASE constants in the Rust REALITY client with a
per-ClientHello `ChromeGreaseProfile` drawn from an **independent OsRng source**, so Rust
draws fresh GREASE values for every handshake (as Go `utls.HelloChrome_Auto` does) while
every other ClientHello property is preserved. **Tracked change is confined to a single file
(`crates/sb-tls/src/reality/handshake.rs`, incl. its in-file test module). No golden_spec /
Cargo / Cargo.lock / harness / fixture / Makefile / L18 / CI change. No public network.**
golden_spec amendment is deferred to T3-2.

Prereqs: T3-1B harness committed (`052d4392`) + checkpoint (`50a74350`).

## A. Initial `from_seed(u16)` coupling risk (T3-1C.1 — REJECTED)

The first implementation derived all five GREASE slots deterministically from the
per-handshake `randomization_seed` via the GF(2)-linear `mix_randomization_seed` mixer
(distinct salts per slot). The exhaustive 65,536-seed audit showed this is **structurally
unsafe**:

- **Only 16 distinct GREASE profiles** over the whole seed space (each profile shared by
  exactly 4096 seeds).
- **Every pairwise slot relation is a perfect bijection** (all 8 audited pairs:
  fwd_functional = bwd_functional = true, joint-support 16/256) — knowing one GREASE value
  reveals all four others with certainty.
- **Unrelated slots never collide naturally** (cipher==group / cipher==versions /
  group==versions counts all 0), unlike Chrome.
- marginals were uniform (16 distinct/slot, 4096 each), but uniform marginals do not fix the
  cross-slot dependence.

Root cause: `mix(seed, salt) % 16` is GF(2)-linear in the seed, so for fixed salts
`idx_i ⊕ idx_j` is a constant — the slots differ by fixed XORs (affine lockstep). Reusing the
extension-order seed also tied GREASE to the order/ECH axes. This **fails §4** ("no
unnecessary functional cross-slot relationship", "reasonable unique-profile space", "no
stable mapping vs extension-order / ECH bucket"), so `from_seed` was rejected.

## B. Exhaustive seed-space audit (current → rejected design)

All 65,536 u16 seeds, `from_seed`: marginal per slot distinct=16, min=max=4096 (uniform);
all 8 pairwise pairs support=16/256, fwd+bwd functional=true; **unique_profiles=16**;
ext_head==ext_tail=0; natural collisions (cipher==group etc.)=0; distinct ext-order
perms=459; distinct ECH buckets=4; ext_order_perm_determines_GREASE_profile=false but
profiles_per_ext_order_perm min=1 (some perms uniquely reveal the profile);
distinct (profile,perm,bucket) tuples=492. Q1: yes — the single seed drove extension order,
ECH payload bucket, padding, and (in the rejected design) the GREASE selector. Q2: a perfect
affine cross-slot relationship existed. Q3: ext_tail re-draw was a non-issue numerically
(0 collisions reachable since slots were always distinct), but the whole construction was
unsound regardless.

## C. Go reference sample (256 HelloChrome_Auto, sanitized — limited-sample)

`group==key_share` 256/256; `ext_head != ext_tail` 256/256; per-slot distinct=16 (all);
pairwise joint-support 148–170/256 (sample-bounded) with **fwd_functional=false** on every
pair; natural collisions present (cipher==group 15, cipher==versions 22, group==versions 21
≈ 256/16); distinct ext-order classes=256; ECH buckets {186,218,250,282}; distinct GREASE
profiles=256. (`grease_profile_determines_ext_order/ech=true` here is a small-sample artifact
— 256 distinct profiles seen once each — NOT evidence of coupling.) Caveat: limited-sample
observation, not a strict distribution proof.

## D. Final RNG design (independent OsRng — ADOPTED)

`ChromeGreaseProfile` keeps the testable core `from_index_source(impl FnMut() -> usize)`
(draws cipher / supported_versions / group / ext_head / ext_tail; ext_tail re-drawn while it
equals ext_head, bounded by the table length with a deterministic `(head_idx+1)%16`
fallback). Production now uses `ChromeGreaseProfile::random(rng: &mut impl RngCore)`, which
pulls each slot from `rng.next_u32() & 0x0f` — unbiased because 16 divides 2^32. The
fingerprint builder is split into `build_chrome_client_hello_fingerprint_with_seed(seed)`
(production: draws `ChromeGreaseProfile::random(&mut OsRng)`, then delegates) and
`build_chrome_client_hello_fingerprint_with_seed_and_grease(seed, grease)` (GREASE supplied
as a parameter, for deterministic structural tests). Result (sampled 262,144 draws): all 5
marginals 16 distinct (≈16,384 each); all 8 pairwise pairs **support 256/256** (ext_head ×
ext_tail 240/256, the off-diagonal) with **fwd_functional=false**; **unique profiles 230,242**
(vs 16 before); ext_head==ext_tail 0; natural collisions present. This matches Go's structure.

### Why not reuse the extension-order seed

The extension order, ECH bucket, and padding are functions of `randomization_seed`. Deriving
GREASE from the same 16-bit seed (a) collapses the GREASE space (GF(2)-linear → 16 profiles)
and (b) ties GREASE to the order/ECH axes, a fingerprinting distinguisher Go does not have
(Go draws GREASE from independent entropy). `random` takes only an RNG — no seed parameter —
so it structurally cannot reuse the seed.

### Selector lifecycle

`perform_stream` (per-connection handshake entry) rebuilds `build_client_config` per
connection → `build_chrome_client_hello_fingerprint` → `ChromeGreaseProfile::random(&mut
OsRng)` fresh each time. Nothing is cached on `RealityHandshake` or the rustls `ClientConfig`
(which is local to `perform_stream` and dropped after). So GREASE is genuinely
per-ClientHello, no global mutable state, no timestamp seed, no static counter.

## E. Correlation rules (all enforced & matched to Go)

groups GREASE == key_share GREASE (one shared `group`; Go 256/256); ext_head != ext_tail
(rejection sampling + bounded fallback; Go 256/256); five slots drawn independently; no
six-slot dedup beyond ext_head≠ext_tail; unrelated slots may collide naturally; ECH GREASE
type/payload unchanged; normalized profile structure / extension set / cipher tail / groups /
sigalgs / ALPN / versions / key-share shape / record-length ladder unchanged (u16→u16).

## F. Unit tests

`exhaustive_or_table_driven_slot_membership`, `group_and_key_share_share_exactly_one_draw`,
`ext_tail_collision_path_is_bounded_and_distinct`, `unrelated_slots_can_collide`,
`deterministic_sequences_produce_expected_profiles`, `no_duplicate_grease_extension_type`,
`production_selector_does_not_reuse_extension_order_seed` (structural: same seed + different
grease → identical middle order, different GREASE; different seed + same grease → different
order, identical GREASE), `selector_is_rebuilt_per_clienthello`. Deterministic `SeqRng`
injects controlled draws into `random`. No probabilistic gate. `cargo test -p sb-tls
--all-features`: **201 passed, 0 failed** + 1 doctest. `cargo clippy -p sb-tls --all-features
--all-targets -- -D warnings`: **clean**. `cargo fmt --check`: clean. Existing in-file tests
remain on GREASE-membership + correlation checks (incl. key_share GREASE == supported_groups
GREASE).

Note: `cargo test ... grease` (name filter) surfaces a **pre-existing** isolation quirk —
`test_chrome_baseline_ech_outer_matches_utls_boring_grease_family` needs another test to
install the process-level rustls `CryptoProvider` first. Unrelated to GREASE; the full suite
is green.

## G. Harness before / after (`run_check.py --runs 20`, rebuilt `target/debug/app`)

| advisory | before (T3-1B) | after (T3-1C) |
|---|---|---|
| Rust GREASE entropy | FIXED (1/slot) | **RANDOMIZED** (10–20 distinct/slot) |
| Go GREASE entropy | RANDOMIZED | RANDOMIZED |
| Rust groups vs key_share | correlated | correlated (equal distinct counts, vary together) |
| from_spec JA4 (Go==Rust) | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | unchanged (GREASE-robust) |
| ext-order distribution | advisory | advisory (Go 20/20, Rust 20/20) |
| snapshot drift | false | false |

Blocking (unchanged, PASS): `EXIT=0`, blocking_pass=true, token Go 20/20 + Rust 20/20,
normalized_profile_digest Go==Rust==`bc002612a968fae0`, required field-set parity PASS
(record-length ladder residue [25], span 96 = 3×32), redaction guard PASS. GREASE
randomization does not move the digest / field-set (GREASE-as-category). Rust entropy is run
evidence only; the correctness gate is the deterministic selector unit tests.

## H. Known boundaries / still OPEN

- official FoxIO JA4 cross-check still **DEFERRED** (no public network); from_spec JA4 stays a
  non-blocking diagnostic; official JA4 parity NOT claimed.
- extension-order **distribution** equivalence vs Chrome still **OPEN** (both randomize
  per-hello; statistical-shape parity not asserted).
- tier-2 real-network camouflage sufficiency / active-probing resistance / L4 raw-byte
  equality remain **OUT OF SCOPE / OPEN**.

## I. golden_spec → T3-2

Amending golden_spec S4 DEV-REALITY-01 to record the now-randomized, decorrelated Rust
GREASE is **T3-2**, not this card (no golden_spec edit here).

## Disposition

Saved: this report. Tracked change staged-ready: `crates/sb-tls/src/reality/handshake.rs`
only (uncommitted). Temporary audit tests were run via `--ignored` and removed before commit;
their /tmp outputs are not committed. `agents-only/a0_reality_spike/` untouched untracked.
