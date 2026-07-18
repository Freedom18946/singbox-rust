<!-- tier: C -->
# R92 External Public Observation — INCONCLUSIVE, Probe Flow Parity Fixed

Date: 2026-07-18

## Scope

- Source snapshot: `ebrasha/free-v2ray-public-list` main commit
  `b71c46b3ad86a13bbd92df9936ecb957451b7782`; downloaded VLESS list SHA-256
  `816013afde2a1e9415734ef5620e237501acf9b73b50bfd6e1350bfb2f02a0be`.
- Public credentials stayed in exact `/tmp` inputs and were never committed.
- Admission: three fresh-ready REALITY/VLESS plain-TCP nodes; production config parse passed;
  R81 subset-schema gate passed with zero violations.
- Formal post-fix observation: three nodes x three runs, target `example.com:80`.

## Finding And Repair

One no-flow candidate first produced repeatable `app_minimal_diverged` and
`bridge_io_diverged`. Root cause was probe-tool drift, not product behavior:
`reality_vless_env_from_config.py` omitted outbound `flow`, while
`vless_reality_phase_probe` hard-coded `xtls-rprx-vision`. App correctly used
`FlowControl::None`; minimal probe tested a different protocol shape.

The extractor now exports `SB_VLESS_FLOW`; the minimal probe validates and uses the exact
configured mode (`none`, `xtls-rprx-vision`, or `xtls-rprx-direct`) and reports it in JSON.
Same no-flow node replay moved from two mismatches to zero. Explicit Vision replay retained zero
mismatches.

## Formal Observation

- 9/9 matrices completed; matrix status zero; no matrix timeout.
- 0 app/minimal mismatches after the fix.
- One node: REALITY/VLESS dial 3/3 passed; payload ended `post_dial_eof` in both paths.
- One node: REALITY 3/3 passed; config-faithful no-flow VLESS/payload timed out in both paths.
- One node: uniform `reality_dial_eof` across all phases, classified infrastructure-dead and
  excluded from client verdict.
- Healthy all-phase nodes: zero. Verdict: **INCONCLUSIVE**, not banked.

Machine-readable record:
`agents-only/mt_real_02_evidence/round92_external_public_observation.json`.

## Verification

- `python3 scripts/tools/test_reality_probe_tools.py` — 214 PASS.
- `cargo test -p sb-adapters --example vless_reality_phase_probe --features adapter-vless,tls_reality`
  — 6 PASS.
- No-flow live replay — 0 mismatches; `flow=""`.
- Explicit Vision live replay — 0 mismatches; `flow="xtls-rprx-vision"`.
- R92 formal post-fix public replay — 9/9 completed, 0 mismatches.
- External-observation validator, local REALITY gate, formatting, clippy, boundaries,
  consistency, and diff check are recorded in the accepting commit.

## Non-Claims

- Tier-2 healthy-cohort observation remains open: no all-phase healthy node was admitted.
- Real-network camouflage sufficiency remains open.
- No success-path ServerHello byte-borrowing claim.
- No dual-kernel BHV movement.
