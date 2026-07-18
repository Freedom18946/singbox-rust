<!-- tier: C -->
# R94 External Camouflage Observation — Observable Minimum Subset Seen

Date: 2026-07-19

## Scope And Provenance

- Input: same user-supplied, three-node fixed cohort banked in R93. Source snapshot SHA-256:
  `0f40004fc36a6ab17cb664f30f7a205b5330b7396d66002d1866c7e07e94b6b9`.
- Upstream authority: XTLS/REALITY `README.en.md` commit
  `9234c772ba8f181f31c3e81dc2b4177322e5a9a9`, file SHA-256
  `5658a983b4335f8af1e0e24edba51fc1f50f57b0e6826660f14b65b5c5800c13`.
- Upstream general-proxy guidance also includes GFW/deployment location. R94 cannot classify that
  from one vantage; it observes only TLS 1.3, H2, and disallowed-domain-redirect behavior.
  Proximity/latency, record shape, OCSP, port forwarding, and target rarity remain unscored.
- Probe sends ordinary unauthenticated TLS ClientHello to the REALITY endpoint and to configured
  SNI via public DNS:443. Client config does not reveal server's actual `target`; the latter is an
  oracle candidate only. Both paths require normal WebPKI validation. Credentials are never used.

## Observation

| Node | Complete pairs | Proxy/oracle TLS 1.3 + H2 | No disallowed domain redirect | Exact leaf/profile |
|---|---:|---:|---:|---:|
| `cam-001` (`r93u_006`) | 3/3 | 3/3 + 3/3 | 3/3 + 3/3 | 3/3 + 3/3 |
| `cam-002` (`r93u_009`) | 3/3 | 3/3 + 3/3 | 3/3 + 3/3 | 3/3 + 3/3 |
| `cam-003` (`r93u_014`) | 3/3 | 3/3 + 3/3 | 3/3 + 3/3 | 3/3 + 3/3 |

- 9/9 proxy/oracle pairs completed with verified certificates.
- 9/9 pairs observed TLS 1.3, H2, and no disallowed domain redirect on both paths.
- Final record matched exact leaf certificate and TLS version/cipher/ALPN for all three nodes.
- An earlier self-review repetition gave `cam-001` 0/3 exact leaf/profile matches while its
  WebPKI/TLS/H2/redirect subset remained 3/3. This observed instability is consistent with
  CDN/target-route variance and proves exact matching must remain descriptive, not gating.
- Recorded timing is descriptive only; no latency threshold was invented.

Machine record:
`agents-only/mt_real_02_evidence/round94_external_camouflage_observation.json`.

## Tool And Verification

- `scripts/tools/reality_camouflage_probe.py` emits only neutral IDs, booleans, protocol facts,
  timing, and error classes. It excludes endpoint, SNI, UUID, public key, short ID, certificate
  bytes/hash, and raw exception text.
- Twelve offline unit tests cover GUI/v2 config admission, unambiguous index/name selection,
  plain-TCP filtering, dry-run secret redaction, aggregation, redirect scope, and error sanitization.
- Live output passed credential/endpoint secret scan. Boundaries, consistency, Python compile,
  diff check, and focused tests are recorded in the accepting commit.

## Interpretation And Remaining Blocker

Observation: **UPSTREAM_OBSERVABLE_MINIMUM_OBSERVED**. Camouflage sufficiency verdict:
**NOT_ASSESSED**.

Public-DNS oracle is not proof of server's private target. These public endpoints also do not
establish a controlled externally reachable Rust REALITY server, multi-vantage censor observation,
traffic-distribution equivalence, or censorship resistance.
Closing real-network camouflage sufficiency still requires external deployment/measurement;
R94 closes the local tooling and redaction gap, not the external research claim. No merge gate,
ServerHello borrowing, Rust regression, or `52/56` BHV movement is claimed.
