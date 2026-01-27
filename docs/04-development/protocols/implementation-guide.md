# Protocol Implementation Guide

Outline for adding a new inbound or outbound protocol.

## Steps

1. Add adapter in `crates/sb-adapters`
2. Wire feature flag in `Cargo.toml`
3. Register adapter in the app wiring
4. Add tests (unit + integration)
5. Update documentation and examples

## References

- Adapter bridge: `adapter-bridge.md`
- Upstream parity: `upstream-compat.md`
