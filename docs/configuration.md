# Configuration Reference (L17 Entry)

This entry file is the L17 top-level configuration guide. It maps every top-level configuration domain to the existing detailed docs.

## Top-Level Domains

1. `log`
- Purpose: runtime logging level/format/output.
- Details: `docs/01-user-guide/configuration/overview.md`

2. `dns`
- Purpose: resolver transports, strategy, fakeip, cache controls.
- Details: `docs/01-user-guide/configuration/dns.md`

3. `inbounds`
- Purpose: listener protocols and local entry points.
- Details: `docs/01-user-guide/configuration/inbounds.md`

4. `outbounds`
- Purpose: upstream protocols and outbound groups.
- Details: `docs/01-user-guide/configuration/outbounds.md`

5. `route`
- Purpose: matching rules and final dispatch behavior.
- Details: `docs/01-user-guide/configuration/routing.md`

6. `tls`
- Purpose: certificates, store mode, verification strategy, advanced options.
- Details: `docs/01-user-guide/configuration/tls.md`

7. `experimental` / services
- Purpose: admin/service integration such as Clash API, SSMAPI, DERP, resolved.
- Details: `docs/05-api-reference/admin-api/overview.md`, `docs/DERP_USAGE.md`

8. `endpoints`
- Purpose: endpoint-side capabilities (e.g., WireGuard endpoint path).
- Details: `docs/wireguard-endpoint-guide.md`, `docs/TAILSCALE_LIMITATIONS.md`

9. Migration/deprecation compatibility
- Purpose: V1→V2 field migration and deprecated-key governance.
- Details: `docs/01-user-guide/configuration/schema-migration.md`, `docs/migration-from-go.md`

## Recommended Validation Flow

```bash
cargo run -p app -- check -c /path/to/config.json
cargo run -p app -- format -c /path/to/config.json
cargo run -p app -- route-explain -c /path/to/config.json --dest example.com:443
```

## Compatibility Notes

- Current parity / closure review context is tracked in `agents-only/reference/GO_PARITY_MATRIX.md`.
- Linux `systemd-resolved` runtime/system-bus real-machine evidence (`PX-015`) is accepted as non-blocking and is not tracked as an open item.
