# L5 Oracle Rules

## Normalization principles

1. Compare semantic outcomes, not raw field order.
2. For HTTP responses, compare `status` and `body_hash`.
3. For WS streams, compare `(frame_count, frame_hash)` by path.
4. Counters may drift; allow jitter when `oracle.tolerate_counter_jitter=true`.
5. Missing route on either side is a mismatch unless explicitly ignored.

## Diff output

`case diff <id>` produces:

- `diff.json` structured mismatch payload.
- `diff.md` human-readable summary.

Mismatch classes:

- `http_mismatches`
- `ws_mismatches`
- `subscription_mismatches`
- `traffic_mismatches`
