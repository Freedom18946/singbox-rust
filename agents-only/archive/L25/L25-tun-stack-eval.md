<!-- tier: A -->
# TUN Network Stack Evaluation — smoltcp Fitness for singbox-rust

**Date**: 2026-03-17
**Author**: L25 T6 evaluation
**Status**: COMPLETE

---

## 1. Current State Analysis

### 1.1 Architecture Overview

The TUN inbound (`sb-adapters/src/inbound/tun/`) uses a **hybrid approach**:

| Component | Implementation | Status |
|-----------|---------------|--------|
| TCP sessions | Manual IP/TCP packet parsing + `TcpSessionManager` (DashMap) | WIP/skeleton |
| UDP sessions | `UdpNatTable` (DashMap) + raw IP/UDP packet construction | Working (macOS) |
| smoltcp `TunStack` | `stack.rs` — wraps `smoltcp::Interface` + `SocketSet` | **Unused in practice** |

**Key finding**: The current code does NOT actually use smoltcp for TCP session management. Instead, it manually:
1. Parses raw IP packets from the TUN fd (`sys_macos::parse_frame`)
2. Extracts TCP payload by calculating IP header + TCP header offsets
3. Tracks sessions via `TcpSessionManager` (DashMap of `FourTuple` -> `TcpSession`)
4. Builds response packets with manual IP/TCP header construction (`tun_packet.rs`, `tun_session.rs`)

The `stack.rs` file exists but has critical issues:
- `accept_tcp()` **always returns `None`** (line 178-182, comment says "This is a simplification")
- `TunStack` is instantiated in `TunInbound::new()` but the main packet loop in `run()` never feeds packets to it
- The manual approach in `mod.rs` handles TCP SYN/data/FIN directly at the IP level

### 1.2 smoltcp Configuration

```toml
# sb-adapters/Cargo.toml
smoltcp = { version = "0.11", features = [
    "std", "async", "medium-ethernet", "medium-ip",
    "proto-ipv4", "proto-ipv6",
    "socket-tcp", "socket-udp", "socket-icmp"
]}
```

**Missing features**:
- `socket-tcp-cubic` / `socket-tcp-reno` — no congestion control enabled
- No compile-time tuning (`SMOLTCP_IFACE_MAX_ADDR_COUNT`, etc.)

### 1.3 TCP Session Management Issues

The manual TCP implementation in `tun_session.rs` has fundamental problems:
- **No TCP state machine**: Hardcoded seq/ack values (`seq = 1000, ack = 1000`) — no tracking of actual TCP sequence numbers
- **No flow control**: No window size tracking, no backpressure
- **No retransmission**: Packet loss = data loss
- **No congestion control**: Can flood the network
- **No SYN/FIN handshake**: Session lifecycle is incomplete
- **IPv6 TCP not implemented** (returns `Unsupported` error)

### 1.4 UDP Implementation

The UDP path (`udp.rs`) is better architected:
- Clean NAT table with DashMap + TTL eviction
- Direct socket relay (no userspace TCP/IP stack needed for UDP)
- Raw IP/UDP packet construction for return path
- **macOS-only**: Linux/Windows return path packets are constructed but untested
- 4096 max NAT entries (hardcoded)

---

## 2. smoltcp Limitation Analysis

### 2.1 What smoltcp Does Well

- **Correctness**: Full TCP state machine (SYN, ESTABLISHED, FIN-WAIT, etc.)
- **No heap required**: Compile-time buffer sizing
- **Mature**: Active development since 2017, v0.11 is stable
- **Rust-native**: No FFI, no unsafe in core
- **Feature flags**: Modular — only pay for what you use

### 2.2 What smoltcp Lacks for Proxy Use

| Limitation | Impact | Severity |
|-----------|--------|----------|
| **Single-threaded poll model** | Must hold `&mut` to poll; cannot share across tasks without `Mutex` | HIGH |
| **No built-in async** | `async` feature exists but the core `Interface::poll()` is synchronous | MEDIUM |
| **Connection count scales linearly** | Each socket = 128KB (64KB rx + 64KB tx buffers as currently configured) — 1000 connections = 128MB | HIGH |
| **No GSO/GRO** | Cannot coalesce packets for high throughput | LOW |
| **No splice/zero-copy** | All data passes through user buffers | MEDIUM |
| **TCP accept is manual** | Must iterate `SocketSet` and check states — no listener abstraction | MEDIUM |

### 2.3 Congestion Control

smoltcp 0.11 **does** support CUBIC and Reno, but the project has **not enabled** the feature flags:
- `socket-tcp-cubic` — CUBIC (Linux/macOS/Windows default)
- `socket-tcp-reno` — Classic Reno

Without congestion control, smoltcp TCP can flood links and cause packet loss cascades. This is the single most critical missing configuration for proxy use.

### 2.4 Memory Budget

At current buffer sizes (64KB rx + 64KB tx per socket):

| Connections | Memory (buffers only) |
|------------|----------------------|
| 100 | 12.5 MB |
| 500 | 62.5 MB |
| 1000 | 125 MB |
| 5000 | 625 MB |

For a desktop/mobile proxy, 500-1000 concurrent connections is typical. This is manageable but not elegant. Buffer sizes could be reduced to 16KB-32KB for most proxy traffic.

---

## 3. Comparison with Alternatives

### 3.1 Go sing-box Stack Architecture

Go sing-box offers three modes via `sing-tun`:

| Mode | TCP | UDP | Description |
|------|-----|-----|-------------|
| **system** | Kernel TCP (via dialer) | Kernel UDP | L3->L4 via OS socket API; fastest TCP |
| **gvisor** | gVisor netstack | gVisor netstack | Full userspace; best UDP NAT |
| **mixed** (default) | Kernel TCP | gVisor UDP | Best of both worlds |

The **mixed** mode is the default and recommended mode. This is a critical insight: Go sing-box does NOT use a userspace TCP/IP stack for TCP by default. The system stack creates real kernel TCP connections for each intercepted flow.

### 3.2 Comparison Table

| Feature | smoltcp 0.11 | gVisor netstack | netstack-smoltcp | System stack (kernel) |
|---------|-------------|-----------------|------------------|-----------------------|
| **Language** | Rust | Go | Rust (wraps smoltcp) | N/A (kernel) |
| **TCP state machine** | Yes | Yes | Yes (via smoltcp) | Yes (kernel) |
| **Congestion control** | CUBIC/Reno (feature flag) | CUBIC + SACK + timestamps | Via smoltcp | Full (kernel) |
| **Connection scalability** | ~1000s (memory-bound) | ~10000s (goroutine-per-conn) | ~1000s | Kernel limits (~100K) |
| **Async Rust integration** | Manual (Mutex around poll) | N/A (Go) | Tokio AsyncRead/AsyncWrite | Native tokio::net |
| **UDP handling** | Socket-based | Full stack | Socket-based | Direct |
| **GSO/GRO** | No | Yes (Linux) | No | Yes (kernel) |
| **Zero-copy** | No | Partial | No | splice/sendfile |
| **Maintenance** | Active, Rust community | Google-backed | Small team, active | Kernel (always maintained) |
| **Maturity for proxy** | Low (embedded focus) | High (used by sing-box, Coder, WireGuard-go) | Medium (purpose-built for this) | Highest |
| **Binary size** | ~200KB | N/A (Go-only) | ~200KB + smoltcp | 0 (kernel) |

### 3.3 netstack-smoltcp Deep Dive

`netstack-smoltcp` (crate) is the most relevant option. It wraps smoltcp specifically for TUN-to-TCP/UDP use:

**API**:
```rust
let (stack, runner, udp_socket, tcp_listener) = StackBuilder::default()
    .stack_buffer_size(512)
    .tcp_buffer_size(4096)
    .enable_udp(true)
    .enable_tcp(true)
    .build();

// tcp_listener provides AsyncRead/AsyncWrite TcpStreams
// udp_socket provides Stream/Sink for datagrams
```

**Advantages over raw smoltcp**:
- Solves the `accept_tcp()` problem — provides a proper `TcpListener` abstraction
- Handles the poll loop internally (the "runner")
- Returns `TcpStream` with `AsyncRead`/`AsyncWrite` — drops into tokio ecosystem
- Cross-platform: Linux, macOS, Windows, iOS, Android

**Disadvantages**:
- Another dependency layer
- Still limited by smoltcp's core throughput
- Small maintainer team

---

## 4. Recommendation

### 4.1 Primary Recommendation: **Adopt the "mixed" pattern from Go sing-box**

The singbox-rust TUN inbound should implement two modes:

#### Mode A: System Stack (TCP) — DEFAULT for TCP
- Intercept TCP SYN packets from TUN
- Extract destination (IP:port) from packet headers
- Create a **real kernel TCP connection** to the outbound via `tokio::net::TcpStream`
- Relay data bidirectionally between the TUN-side virtual connection and the real outbound connection
- This is exactly what the current `tun_session.rs` attempts, but it needs a proper TCP state machine for the TUN side

#### Mode B: Userspace Stack (UDP) — DEFAULT for UDP
- Keep the current `UdpNatTable` approach — it is already correct
- UDP does not need a full TCP/IP stack; the NAT table + raw packet construction is sufficient
- Fix Linux/Windows return packet construction (the AF header logic)

#### Why NOT full smoltcp for TCP:
1. **The OS kernel's TCP is strictly better** for proxy forwarding: congestion control, SACK, timestamps, ECN, window scaling — all battle-tested
2. smoltcp adds complexity without benefit when the goal is just to relay TCP data to an outbound connection
3. Memory overhead of per-connection buffers in smoltcp is unnecessary when the kernel manages the real connection
4. Go sing-box proved this pattern works: their default "mixed" mode uses kernel TCP + userspace UDP

### 4.2 Implementation Path

**Phase 1: Fix the TCP side (replaces current skeleton)**
- Use smoltcp (or netstack-smoltcp) ONLY for the TUN-side L3->L4 translation: accept the incoming TCP SYN, complete the 3-way handshake in userspace, then extract the TCP byte stream
- Once we have a byte stream from the TUN side, relay it to a real `TcpStream` (kernel connection) to the outbound
- This is the "system stack" pattern: smoltcp handles the client-facing half, kernel handles the server-facing half

**Phase 2: Consider netstack-smoltcp as the L3->L4 bridge**
- `netstack-smoltcp` already solves the `accept_tcp() -> None` problem
- It provides `TcpStream` with `AsyncRead`/`AsyncWrite` — perfect for relay
- Evaluate if its performance is sufficient; if not, the raw smoltcp path with proper accept logic is also viable

**Phase 3: Enable congestion control**
- Add `socket-tcp-cubic` to smoltcp features regardless of which approach is chosen
- The TUN-side TCP connection (client to proxy) needs congestion control to avoid overwhelming the TUN device

### 4.3 What to Do with `stack.rs`

**Option A (recommended)**: Replace `stack.rs` with `netstack-smoltcp` dependency — it does what `stack.rs` was trying to do, but correctly.

**Option B**: Fix `stack.rs` to implement proper TCP accept by iterating the `SocketSet` and checking socket states. This is more work but avoids the extra dependency.

Either way, the current `stack.rs` with `accept_tcp() -> None` is dead code and should not remain as-is.

### 4.4 smoltcp Feature Flag Fix (immediate)

Regardless of architecture decision, add congestion control to `Cargo.toml`:

```toml
smoltcp = { version = "0.11", features = [
    "std", "async", "medium-ip",
    "proto-ipv4", "proto-ipv6",
    "socket-tcp", "socket-udp", "socket-icmp",
    "socket-tcp-cubic"   # <-- ADD THIS
]}
```

Also remove `"medium-ethernet"` — TUN devices operate at L3 (IP), not L2 (Ethernet).

---

## 5. Impact on T1 (TUN UDP Linux/Windows)

### Current Blocker
The UDP return path (`udp.rs` `build_udp_ip_packet`) constructs raw IP/UDP packets. On macOS this works because:
- macOS utun uses a 4-byte AF_INET/AF_INET6 prefix
- The code correctly generates this prefix

On Linux, the issue is the packet info (PI) header format:
- `IFF_NO_PI` mode: no prefix needed, raw IP packets
- `IFF_PI` mode: 4-byte header (flags[2] + protocol[2])
- The current code uses PI mode format but the TUN device may be opened in NO_PI mode

On Windows (wintun):
- wintun delivers raw IP packets (no prefix)
- The current code adds a 4-byte prefix unconditionally — this breaks on Windows

### Recommended Fix
1. Abstract the packet framing behind a platform trait (already partially done with `TunWriter`)
2. Make the AF/PI prefix conditional on platform and TUN device configuration
3. The UDP NAT table architecture itself is sound — only the packet construction needs platform fixes

### This evaluation does NOT block T1
T1 can proceed with platform-specific packet framing fixes. The TCP stack architecture decision is orthogonal to UDP return path fixes.

---

## 6. Summary

| Question | Answer |
|----------|--------|
| Keep smoltcp? | **Yes**, but only for TUN-side L3->L4 translation |
| Replace smoltcp? | **No** — no better Rust alternative exists |
| Augment smoltcp? | **Yes** — consider `netstack-smoltcp` crate for proper TCP listener |
| Use smoltcp for full TCP relay? | **No** — use kernel TCP for the outbound half (Go's "mixed" pattern) |
| Immediate action | Enable `socket-tcp-cubic`, remove `medium-ethernet` |
| Architecture model | Follow Go sing-box: system TCP + userspace UDP ("mixed" stack) |
