<!-- tier: A -->
# REALITY External Camouflage Observation

Read-only, credential-redacting observation of ordinary TLS fallback on real REALITY endpoints.

## What It Measures

For each selected plain-TCP VLESS+REALITY outbound, the probe sends an ordinary unauthenticated
TLS ClientHello to:

1. the REALITY endpoint, which should reject REALITY authentication and relay to its target; and
2. the configured SNI through public DNS on TCP/443 (`direct_sni_oracle`).

Client config does not reveal server's actual REALITY `target` address. Public-DNS SNI is only an
oracle candidate; exact certificate/profile mismatch can reflect CDN edge or target routing and is
never a failure by itself.

Both paths use normal WebPKI verification. The record contains TLS version, cipher, ALPN, HTTP
domain-redirect state, neutral-node comparisons, and timing. It never contains endpoint, SNI, UUID,
public key, short ID, certificate bytes/hash, or raw exception text.

## Upstream Basis

XTLS/REALITY `README.en.md` at commit
`9234c772ba8f181f31c3e81dc2b4177322e5a9a9` (file SHA-256
`5658a983b4335f8af1e0e24edba51fc1f50f57b0e6826660f14b65b5c5800c13`) states the minimum
general-proxy guidance including GFW/deployment location, TLS 1.3, H2, and no disallowed domain
redirect (main-domain to `www` is explicitly allowed). R94 observes only the network-visible
TLS/H2/redirect subset; it cannot classify GFW location or discover private target routing.
Upstream also lists proximity/latency, post-ServerHello record shape, OCSP stapling, TCP/80 and
UDP/443 forwarding, and target rarity as bonus/deployment properties rather than numeric thresholds.

Therefore tool emits only:

- `UPSTREAM_OBSERVABLE_MINIMUM_OBSERVED`;
- `UPSTREAM_OBSERVABLE_MINIMUM_NOT_FULLY_OBSERVED`; or
- `INCONCLUSIVE`.

`camouflage_sufficiency_verdict` is always `NOT_ASSESSED`. One network vantage point cannot prove
censorship resistance, traffic-distribution equivalence, or production camouflage sufficiency.

## Usage

```bash
python3 scripts/tools/reality_camouflage_probe.py \
  --config /path/to/local-config.json \
  --source-index 6 \
  --source-index 9 \
  --runs 3 \
  --output-json /tmp/reality-camouflage.json
```

`--source-index` is 1-based and keeps source tags out of process arguments. `--outbound` remains
available for already-neutral tags. Selection modes (`--source-index`, `--outbound`, `--limit`)
are mutually exclusive.

Dry-run admission/redaction check:

```bash
python3 scripts/tools/reality_camouflage_probe.py \
  --config /path/to/local-config.json \
  --limit 3 \
  --dry-run \
  --output-json /tmp/reality-camouflage-plan.json
```

This remains external, observational, and non-gating. It adds no GitHub workflow and no `52/56`
BHV movement.
