# Capability Ledger

This is the authoritative human-readable entry for capability states.
Machine source of truth: [`reports/capabilities.json`](../reports/capabilities.json) (schema: [`scripts/capabilities/schema.json`](../scripts/capabilities/schema.json)).

## Metadata Contract

`reports/capabilities.json` top-level fields:

- `schema_version` (`1.0.0`)
- `generated_at` (RFC3339)
- `source_commit` (git sha)
- `profile` (`docs-only` in Batch A)
- `capabilities[]`
- `runtime_probe` (optional, present when runtime probe report is available)
- `claims[]`

Generate command:

```bash
python3 scripts/capabilities/generate.py --out reports/capabilities.json
```

Optional runtime probe (Batch B):

```bash
SB_CAPABILITY_PROBE_ONLY=1 \
SB_CAPABILITY_PROBE_OUT=reports/runtime/capability_probe.json \
cargo run -q -p app --features parity --bin run -- \
  -c examples/quick-start/01-minimal.json

python3 scripts/capabilities/generate.py \
  --out reports/capabilities.json \
  --probe-report reports/runtime/capability_probe.json
```

Clash API contract endpoint (L19.5.1):

```bash
curl -s http://127.0.0.1:9090/capabilities | jq
```

Response contract includes:

- `schema_version`
- `compat_version`
- `clash_api_compat_version`
- `contract_version` (`2.0.0`)
- `required_by_gui` (`status/min_contract_version/min_clash_api_compat_version/required_top_level_fields/blockers?`)
- `breaking_changes` (array, empty means no active breaking change gate)
- `tls_provider` (`status/requested/effective/source/install/fallback_reason/evidence_capability_ids`)
- `capability_matrix[]`

Provider selection for startup probe/runtime:

- `SB_TLS_PROVIDER=ring|aws-lc|auto` (default `auto` -> `ring`)
- If `aws-lc` is requested without build feature `tls-provider-aws-lc`, startup falls back to `ring` and logs fallback reason.
- Probe details for `tls.ech.{tcp,quic}` include provider keys:
  `tls_provider`, `tls_provider_source`, `tls_provider_install`, `tls_provider_requested`, `tls_provider_fallback_reason`.

## State Model

Capability fields:

- `compile_state`: `supported | gated_off | stubbed | absent`
- `runtime_state`: `verified | unverified | unsupported | blocked`
- `verification_state`: `e2e_verified | integration_verified | compile_only | no_evidence`
- `overall_state`: `implemented_verified | implemented_unverified | scaffold_stub`
- `runtime_probe` (optional): startup probe snapshot `{compile_state,runtime_state,requested,summary,details}`

`overall_state` priority rules:

1. `compile_state in {stubbed, absent}` -> `scaffold_stub`
2. `runtime_state in {unsupported, blocked}` -> `scaffold_stub`
3. `verification_state in {e2e_verified, integration_verified}` and `runtime_state=verified` -> `implemented_verified`
4. otherwise runnable but evidence-limited -> `implemented_unverified`

Minimum evidence rule:

- each capability must contain at least one evidence item `{kind,path,line,note}`.

## Capability Index

| capability id | overall_state | accepted_limitation |
| --- | --- | --- |
| [`project.acceptance.baseline`](#capability-project-acceptance-baseline) | `implemented_verified` | `true` |
| [`tun.macos.tun2socks`](#capability-tun-macos-tun2socks) | `scaffold_stub` | `true` |
| [`inbound.redirect`](#capability-inbound-redirect) | `scaffold_stub` | `true` |
| [`inbound.tproxy`](#capability-inbound-tproxy) | `scaffold_stub` | `true` |
| [`tls.utls`](#capability-tls-utls) | `implemented_unverified` | `true` |
| [`tls.utls.chrome`](#capability-tls-utls-chrome) | `implemented_unverified` | `true` |
| [`tls.utls.firefox`](#capability-tls-utls-firefox) | `implemented_unverified` | `true` |
| [`tls.utls.randomized`](#capability-tls-utls-randomized) | `implemented_unverified` | `true` |
| [`tls.ech.tcp`](#capability-tls-ech-tcp) | `implemented_unverified` | `true` |
| [`tls.ech.quic`](#capability-tls-ech-quic) | `scaffold_stub` | `true` |

## Capability Details

### <a id="capability-project-acceptance-baseline"></a>`project.acceptance.baseline`

- `compile_state`: `supported`
- `runtime_state`: `verified`
- `verification_state`: `integration_verified`
- `overall_state`: `implemented_verified`
- Evidence anchor: `agents-only/02-reference/GO_PARITY_MATRIX.md`

### <a id="capability-tun-macos-tun2socks"></a>`tun.macos.tun2socks`

- `compile_state`: `stubbed`
- `runtime_state`: `unsupported`
- `verification_state`: `compile_only`
- `overall_state`: `scaffold_stub`
- Evidence anchors: `crates/sb-adapters/Cargo.toml`, `vendor/tun2socks/src/lib.rs`
- Build switch: `--features tun2socks-stub` (default parity path) or `--features tun2socks-real`

### <a id="capability-inbound-redirect"></a>`inbound.redirect`

- `compile_state`: `gated_off`
- `runtime_state`: `unsupported`
- `verification_state`: `no_evidence`
- `overall_state`: `scaffold_stub`
- Evidence anchors: `docs/07-reference/platform-io.md`, `app/src/inbound_starter.rs`

### <a id="capability-inbound-tproxy"></a>`inbound.tproxy`

- `compile_state`: `gated_off`
- `runtime_state`: `unsupported`
- `verification_state`: `no_evidence`
- `overall_state`: `scaffold_stub`
- Evidence anchors: `docs/07-reference/platform-io.md`, `app/src/inbound_starter.rs`

### <a id="capability-tls-utls"></a>`tls.utls`

- `compile_state`: `supported`
- `runtime_state`: `unverified`
- `verification_state`: `integration_verified`
- `overall_state`: `implemented_unverified`
- Evidence anchors: `crates/sb-tls/src/utls.rs`, `crates/sb-tls/README.md`
- Sub-capabilities: `tls.utls.chrome`, `tls.utls.firefox`, `tls.utls.randomized`
- Runtime probe details include: `requested_profile`, `effective_profile`, `fallback_reason`, `utls_request_count`

### <a id="capability-tls-utls-chrome"></a>`tls.utls.chrome`

- `parent_capability_id`: `tls.utls`
- `compile_state`: `supported`
- `runtime_state`: `unverified`
- `verification_state`: `integration_verified`
- `overall_state`: `implemented_unverified`
- Evidence anchors: `crates/sb-tls/src/utls.rs`, `reports/security/tls_fingerprint_baseline.json`

### <a id="capability-tls-utls-firefox"></a>`tls.utls.firefox`

- `parent_capability_id`: `tls.utls`
- `compile_state`: `supported`
- `runtime_state`: `unverified`
- `verification_state`: `integration_verified`
- `overall_state`: `implemented_unverified`
- Evidence anchors: `crates/sb-tls/src/utls.rs`, `reports/security/tls_fingerprint_baseline.json`

### <a id="capability-tls-utls-randomized"></a>`tls.utls.randomized`

- `parent_capability_id`: `tls.utls`
- `compile_state`: `supported`
- `runtime_state`: `unverified`
- `verification_state`: `integration_verified`
- `overall_state`: `implemented_unverified`
- Evidence anchors: `crates/sb-tls/src/utls.rs`, `reports/security/tls_fingerprint_baseline.json`
- Current behavior note: Rust `randomized` maps to stable template; Go `randomized` is seed-driven randomized spec.

### <a id="capability-tls-ech-tcp"></a>`tls.ech.tcp`

- `compile_state`: `supported`
- `runtime_state`: `unverified`
- `verification_state`: `integration_verified`
- `overall_state`: `implemented_unverified`
- Evidence anchors: `crates/sb-transport/src/tls.rs`, `crates/sb-tls/docs/ech_usage.md`

### <a id="capability-tls-ech-quic"></a>`tls.ech.quic`

- `compile_state`: `supported`
- `runtime_state`: `unsupported`
- `verification_state`: `no_evidence`
- `overall_state`: `scaffold_stub`
- Evidence anchors: `crates/sb-config/src/validator/v2.rs`, `crates/sb-transport/src/quic.rs`, `crates/sb-tls/docs/ech_usage.md`
- Guardrail: QUIC+ECH defaults to `experimental.quic_ech_mode=reject` (hard error); explicit `experimental` mode downgrades to warning for controlled interop tests.
- Suggested path: use TCP-based TLS ECH outbounds (`vless`/`vmess`/`trojan` over `tcp+tls`).

## Claims Contract

`claims[]` fields:

- `source_path`
- `line`
- `text`
- `risk_level` (`high|medium|low`)
- `linked_capability_ids[]`

High-risk claims must link to at least one capability id and must only target `implemented_verified` capabilities.
