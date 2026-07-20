<!-- tier: C -->
# REALITY Production Server Configuration Acceptance

Date: 2026-07-20

## Decision

Production Rust `app` can now load and serve a VLESS+REALITY+Vision inbound from V2 JSON/YAML.
The prior reverse interop result proved adapter behavior only: A1 launched
`vless_reality_server_fixture`, while production config lowering rejected or discarded VLESS
inbound identity and REALITY server options.

## Closed Defects

- V2 inbound dispatch now preserves `type: vless`, canonical one-user UUID/flow (plus documented
  `users_vless` compatibility), nested `tls.server_name`, and `tls.reality` server fields.
- Strict validation requires TLS enablement, server name, X25519 private key, handshake target,
  valid short IDs, and a positive timeout. Canonical Go `handshake` and `short_id` are primary;
  published `fallback_server`/`fallback_port`/`short_ids` aliases remain accepted.
- `InboundRealityIR` crosses both production builders into `RealityServerConfig`; active-probing
  fallback remains mandatory.
- Registry-managed VLESS now creates a Tokio runtime on its blocking worker thread instead of
  panicking at `Handle::current()`, and reports bind/config readiness before startup succeeds.
- Client and server X25519 keys accept 64-hex, base64url, and key-generator standard base64.
- A1 reverse lane now launches production `app run -c rust_server.json`, not an adapter example.

Current Rust VLESS inbound remains single-user. Strict config validation rejects zero or multiple
`users` entries instead of silently selecting one.

## Acceptance

- `run_fixture.py --runs 20`: `local_deterministic_gate=PASS`.
- Go client -> production Rust server: 20/20 HTTP token matches with Vision.
- Go -> Go and Rust -> Go dataplanes: 20/20 each.
- Rust four-phase probe: 20/20 all phases; bad-key, bad-UUID, dead-target, and occupied-port
  negative controls all PASS.
- Go server/client/reverse-client and Rust client/server config checks: all exit 0.
- Focused config, starter, key-decoding, blocking-driver, and render tests PASS.
- Committed `round-summary.json` SHA-256:
  `3f8abd144afc9a8f87d219000c4221e54c839c2c0422bb1a5ab017092ad1807f`.

Committed point-in-time machine evidence remains under
`labs/interop-lab/reality_local_fixture/evidence/`. The accepting run does not prove public
reachability, real-network camouflage sufficiency, multi-vantage censor behavior, or success-path
ServerHello byte borrowing. REALITY has no S3 BHV-ID; parity remains unchanged.
