# Selector Outbound Policy (Design Contract)

## Purpose
A virtual outbound that selects one of named outbounds at request time using a stable scoring policy.

## Inputs
- IR outbounds item with `"type":"selector"`, `"name":"S"`, `"members":["A","B",...]`.
- Members must be resolvable from Bridge (could come from sb-adapter or scaffold).

## Policy (v1)
- Score = EMA_RTT(ms) + 400 * FailRatio + jitter(0..8ms).
- Cold start: round-robin sampling for `min_samples=2`.
- Circuit breaker: open for `cb_open_ms=1500` on failure.

## Metrics
- `proxy_select_total{outbound="S",member="A"}` counter.
- `proxy_select_score{outbound="S",member="A"}` gauge (current score snapshot).
- RTT is observed via `tcp_connect_duration_seconds` indirectly.

## Backward compatibility
- No changes to CLI/Explain/Run JSON contracts.
- Works with both adapter-backed and scaffold-backed outbounds.

## Future extensions
- Weighted preference per member; health-aware exclusion; time-sliced stickiness.