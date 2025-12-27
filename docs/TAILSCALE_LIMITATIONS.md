# Tailscale Integration: Limitations and Architecture Decision

> **Status**: De-scoped (Short Term) | **Date**: 2025-12-22

This document describes the architectural differences between the Go `sing-box` Tailscale implementation and the Rust `singbox-rust` implementation, and documents the decision to use a daemon-only approach in the short term.

## TL;DR

The Rust implementation uses **daemon-only mode** which requires an external `tailscaled` daemon, rather than embedding the full Tailscale stack. This is a deliberate architectural decision due to FFI complexity and build constraints.

## Architecture Comparison

```
┌─────────────────────────────────────────────────────────────────┐
│                         Go sing-box                              │
├─────────────────────────────────────────────────────────────────┤
│  protocol/tailscale/endpoint.go                                  │
│  ┌──────────────────────────────────────────────────────────────┤
│  │ tsnet.Server (embedded control plane)                        │
│  │  ├── Tailscale control protocol                              │
│  │  ├── WireGuard key management                                │
│  │  └── Node authentication                                     │
│  ├──────────────────────────────────────────────────────────────┤
│  │ gVisor netstack (embedded data plane)                        │
│  │  ├── Virtual TCP/UDP sockets                                 │
│  │  ├── Userspace packet processing                             │
│  │  └── DNS hook integration                                    │
│  ├──────────────────────────────────────────────────────────────┤
│  │ dns_transport.go                                             │
│  │  └── LookupHook for DNS resolution                           │
│  ├──────────────────────────────────────────────────────────────┤
│  │ protect_android.go / protect_nonandroid.go                   │
│  │  └── Socket protection for VPN bypass                        │
│  └──────────────────────────────────────────────────────────────┤
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    Rust singbox-rust                             │
├─────────────────────────────────────────────────────────────────┤
│  sb-core/src/endpoint/tailscale.rs                               │
│  ┌──────────────────────────────────────────────────────────────┤
│  │ DaemonControlPlane (external daemon)                         │
│  │  ├── Connects to tailscaled via Local API                    │
│  │  ├── Unix socket (Linux/macOS) / Named pipe (Windows)        │
│  │  └── Queries status, IPs, auth state                         │
│  ├──────────────────────────────────────────────────────────────┤
│  │ Host network stack (data plane)                              │
│  │  ├── Uses system sockets after tailscaled sets routes        │
│  │  └── No userspace packet processing                          │
│  ├──────────────────────────────────────────────────────────────┤
│  │ DNS Hook: NOT IMPLEMENTED                                    │
│  │ Socket Protect: NOT IMPLEMENTED                              │
│  └──────────────────────────────────────────────────────────────┤
└─────────────────────────────────────────────────────────────────┘
```

## Feature Comparison

| Feature | Go sing-box | Rust singbox-rust | Gap |
|---------|-------------|-------------------|-----|
| Control plane | Embedded `tsnet.Server` | External `tailscaled` | Architecture |
| Data plane | gVisor netstack (userspace) | Host network stack | Architecture |
| DNS resolution | `LookupHook` integration | System resolver | Missing |
| Socket protection | `protect_*.go` | Not implemented | Missing |
| Auth URL callback | Embedded | Via Local API | ✅ Equivalent |
| Tailscale IPs | Embedded | Via Local API | ✅ Equivalent |
| WireGuard keys | Auto-managed | Managed by daemon | ✅ Equivalent |
| Build complexity | Single binary | Requires daemon | Operational |

## Functional Impact

### What Works

1. **Authentication**: Users can authenticate via the auth URL returned from the Local API
2. **IP allocation**: Tailscale IPs are correctly retrieved and usable
3. **Routing**: Traffic to Tailscale IPs routes through the daemon-configured tunnel
4. **Status monitoring**: Connection state is observable

### What Doesn't Work

1. **Standalone operation**: Cannot run without `tailscaled` daemon
2. **DNS hook**: Cannot intercept DNS queries for MagicDNS resolution
3. **Socket protection**: Cannot protect sockets from routing loops on Android
4. **Netstack features**: No userspace TCP/UDP processing

## Why Not Port tsnet?

| Approach | Feasibility | Issues |
|----------|-------------|--------|
| **tsnet CGO FFI** | ❌ Failed | ARM64 darwin build failures; CGO complexity |
| **Pure Rust port** | ⏳ High effort | 10,000+ LOC in tailscale/tsnet; gVisor dependency |
| **smoltcp + boringtun** | ⏳ Possible | Significant engineering; different trust model |

## Decision

**Short term (current)**: Accept daemon-only mode with documented limitations.

**Rationale**:
- 90%+ of use cases work with daemon mode
- Avoids 2-4 weeks of high-risk integration work
- `tailscaled` is well-maintained and stable
- Focus engineering effort on other parity gaps

**Medium term**: Re-evaluate if:
- gVisor gains stable darwin/arm64 support
- Pure Rust Tailscale control client emerges (e.g., `tailscale-control` crate)
- Significant user demand for embedded mode

## Usage

### Prerequisites

```bash
# Install Tailscale
# macOS
brew install tailscale

# Linux
curl -fsSL https://tailscale.com/install.sh | sh

# Windows
# Download from https://tailscale.com/download
```

### Running

```bash
# Start the daemon
sudo tailscaled

# Authenticate (one-time)
tailscale up

# singbox-rust will automatically connect to the daemon
```

### Configuration

```yaml
endpoints:
  - tag: "tailscale"
    type: "tailscale"
    auth_key: "tskey-auth-..."  # Optional: for headless auth
    hostname: "singbox-node"     # Node hostname in Tailnet
    ephemeral: true              # Don't persist node
```

## Files

| File | Purpose |
|------|---------|
| `sb-core/src/endpoint/tailscale.rs` | Endpoint implementation with `DaemonControlPlane` |
| `sb-core/src/endpoint/mod.rs` | Endpoint trait definitions |
| `docs/TAILSCALE_LIMITATIONS.md` | This document |

## See Also

- [GO_PARITY_MATRIX.md](../GO_PARITY_MATRIX.md) - Overall parity status
- [TAILSCALE_DECISION.md](TAILSCALE_DECISION.md) - Original decision document
- [Tailscale tsnet docs](https://pkg.go.dev/tailscale.com/tsnet) - Go embedded library
