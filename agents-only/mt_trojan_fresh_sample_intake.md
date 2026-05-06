<!-- tier: A -->
# MT-TROJAN-FRESH-01 Trojan Fresh Sample Intake

> Separate quality line. This is not MT-REAL-02 REALITY/VLESS work and
> does not promote dual-kernel parity. BHV remains 52/56.

## Scope

The R72c input is valid JSON but belongs to the Trojan protocol family.
It cannot feed MT-REAL-02 R73 REALITY live probe. It may be useful as a
future bounded Rust-only Trojan realworld sanity sample, after a
non-live dry-run/probe runner exists.

## Safety Rules

- Do not commit `/tmp` configs or intake outputs.
- Do not write raw server, password, TLS server_name, or other node
  material to git, reports, or chat.
- Do not run live probes during intake.
- Do not treat Trojan sanity as dual-kernel parity completion.

## Safe Field Summary

Input summary, counted without printing values:

- `outbounds_len`: 90
- `type_counts`: `trojan=90`
- `has_password`: 90
- `has_tls`: 90
- `has_server`: 90
- `has_server_port`: 90
- `tls_enabled`: 90
- `tls_server_name`: 90
- `transport_type_counts`: `<absent>=90`

## Intake Tool

`scripts/tools/trojan_sample_intake.py` performs offline classification
and writes only redacted fingerprints:

- `trojan_ready`: required Trojan fields are present and TLS fields are
  interpretable.
- `duplicate`: repeated tag or repeated redacted fingerprint.
- `not_ready`: missing server, server_port, password, or invalid TLS
  shape.
- `unsupported`: non-Trojan outbound.

Fingerprint output contains only:

- `server_hash`
- `password_hash`
- `server_name_hash`
- `port`

## MT-TROJAN-FRESH-01 Result

Command:

```bash
python3 scripts/tools/trojan_sample_intake.py \
  --candidate-config /tmp/mt_real_02_fresh_config_wrapped.json \
  --output-json /tmp/trojan_fresh_intake.json \
  --redacted-md /tmp/trojan_fresh_intake.md
```

Redacted counts:

- `trojan_ready`: 88
- `duplicate`: 2
- `not_ready`: 0
- `unsupported`: 0
- `ready_for_trojan_sanity`: true

## Dry-Run Gate

No live probe was run. The repository currently has no bounded Trojan
realworld sanity dry-run/probe runner equivalent to the REALITY/VLESS
batch tooling, so the gate stops at **C: tooling gap**.

Next implementation step: add a Trojan-specific bounded runner that can
produce a non-live plan/dry-run summary before any live authorization.

## Verification

- `python3 -B -m unittest scripts/tools/test_reality_probe_tools.py scripts/tools/test_reality_clienthello_family.py scripts/tools/test_dual_kernel_verification.py`
  -> 82 PASS.
- `cargo check --workspace` -> PASS.

## Classification

**C - Tooling gap.** Trojan intake is redacted and ready, but the next
bounded Rust-only sanity probe needs dedicated dry-run/probe tooling
before live authorization.
