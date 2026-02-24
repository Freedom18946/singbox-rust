# Migration From Go sing-box (L17 Entry)

This entry file provides the current migration path from Go `sing-box 1.12.14` to `singbox-rust` and links to detailed compatibility references.

## Current Parity Baseline

- Baseline date: 2026-02-24
- Current parity: `100% acceptance baseline (209/209 closed)`
- Remaining open item: none
- Authority: `agents-only/02-reference/GO_PARITY_MATRIX.md`

## Migration Checklist

1. Validate existing config:

```bash
cargo run -p app -- check -c ./config.json
```

2. Normalize config format:

```bash
cargo run -p app -- format -c ./config.json -w
```

3. Verify route behavior:

```bash
cargo run -p app -- route-explain -c ./config.json --dest example.com:443
```

4. Run parity feature build:

```bash
cargo check -p app --features parity
```

## Accepted Limitations (Must Know)

- Linux `systemd-resolved` runtime/system-bus real-machine evidence (`PX-015`) is accepted as non-blocking and no longer tracked as an open gap.
- Tailscale endpoint remains de-scoped in Rust path (documented limitation).
- WireGuard endpoint userspace behavior differs from Go's full stack in some platform/runtime details.
- Chrome certificate store mode currently uses `webpki-roots` equivalence path.

## Detailed References

- Existing full guide: `docs/MIGRATION_GUIDE.md`
- Schema migration: `docs/01-user-guide/configuration/schema-migration.md`
- Tailscale decision: `docs/TAILSCALE_LIMITATIONS.md`
- TLS decisions: `docs/TLS_DECISION.md`
