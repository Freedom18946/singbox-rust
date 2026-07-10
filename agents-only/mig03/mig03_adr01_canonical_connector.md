<!-- tier: B -->
# ADR-01 — Canonical Adapter Contracts in `sb-types`

| Item | Value |
|---|---|
| Date | 2026-07-10 |
| Decision ID | MIG-03 ADR-01 |
| Status | ✅ Approved — directly authorized by D1–D8 |
| Scope | Exact internal Rust contract target for WP02/WP03; no implementation is changed by this ADR. |

## Context

The WP01 census shows that the workspace has six-plus incompatible meanings of
“outbound connector”. The actively used adapter trait returns an erased stream,
but the core adapter trait returns `tokio::net::TcpStream`; `register.rs` then
contains protocol-specific wrappers to bridge the mismatch. UDP has at least
five shapes, while inbound lifecycle is split between unused ports and a
blocking core service trait. The result is parallel implementations and an
unusable nominal port layer.

The Go 1.13.13 reference contracts are the intended semantic shape:

```go
// adapter/outbound.go
type Outbound interface {
    Type() string
    Tag() string
    Network() []string
    Dependencies() []string
    N.Dialer                 // DialContext + ListenPacket
}

// adapter/inbound.go + lifecycle.go
type Inbound interface { Lifecycle; Type() string; Tag() string }
type Lifecycle interface { Start(stage StartStage) error; Close() error }
```

This ADR records the exact Rust target before WP02 modifies any implementation.
It is an internal contract migration, not a public RuntimePlan/query API.

## Decision

### 1. Canonical supporting types

The traits and I/O aliases below live in `sb-types::ports`. The request-context
types `ResolveMode`, `RetryPolicy`, `ConnectOptions`, `PacketOptions`, and their
duration codecs live beside `Session` in `sb-types::session` (and may be
re-exported at crate root). `NetworkKind`, `Session`, `TargetAddr`,
`OutboundTag`, `InboundTag`, `StartStage`, and `BoxFuture` are existing
sb-types types. `Session.target` is the one routed destination; canonical
connection methods do **not** take a second independent target argument.

```rust
// sb-types gains the lightweight `futures` crate, but not Tokio/hyper/axum.
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

pub trait AsyncStream:
    futures::io::AsyncRead + futures::io::AsyncWrite + Unpin + Send + 'static {}
impl<T> AsyncStream for T
where
    T: futures::io::AsyncRead + futures::io::AsyncWrite + Unpin + Send + 'static,
{}
pub type BoxedStream = Box<dyn AsyncStream>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ResolveMode {
    Local,
    #[default]
    Remote,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicy {
    pub max_retries: u32,
    pub base_delay_ms: u64,
    pub jitter: f32,
    pub max_delay_ms: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 2,
            base_delay_ms: 100,
            jitter: 0.1,
            max_delay_ms: 5_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectOptions {
    #[serde(with = "duration_serde")]
    pub connect_timeout: Duration,
    #[serde(with = "duration_serde")]
    pub read_timeout: Duration,
    pub retry_policy: RetryPolicy,
    pub resolve_mode: ResolveMode,
}

impl Default for ConnectOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(30),
            retry_policy: RetryPolicy::default(),
            resolve_mode: ResolveMode::Remote,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketOptions {
    #[serde(default)]
    pub udp_connect: bool,
    #[serde(with = "duration_serde")]
    pub idle_timeout: Duration,
    #[serde(default)]
    pub udp_disable_domain_unmapping: bool,
}

impl Default for PacketOptions {
    fn default() -> Self {
        Self {
            udp_connect: false,
            idle_timeout: Duration::from_secs(5 * 60),
            udp_disable_domain_unmapping: false,
        }
    }
}

// Session gains `#[serde(default)] pub connect: ConnectOptions` and
// `#[serde(default)] pub packet: PacketOptions`. Connect defaults preserve the
// present DialOpts values: 10 s/30 s, RetryPolicy(2,100,0.1,5000), and Remote.
// Packet default is Go UDPTimeout (5m), but a finalized routed Session MUST
// overwrite `idle_timeout` using the current precedence: route `udp_timeout`
// -> inbound `udp_timeout` -> port/protocol timeout -> UDPTimeout. Move the
// current private `errors.rs` duration serializer into accessible
// `sb_types::session::duration_serde` (same millisecond format) before deriving
// Session serialization.

pub trait PacketConn: Send + Sync + std::fmt::Debug + 'static {
    fn send_to<'a>(
        &'a self,
        data: &'a [u8],
        destination: &'a TargetAddr,
    ) -> BoxFuture<'a, Result<usize, CoreError>>;

    fn recv_from<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> BoxFuture<'a, Result<(usize, TargetAddr), CoreError>>;

    fn close(&self) -> BoxFuture<'_, Result<(), CoreError>>;

    fn local_addr(&self) -> Option<TargetAddr>;
    fn set_deadline(&self, deadline: Option<Instant>) -> Result<(), CoreError>;
    fn set_read_deadline(&self, deadline: Option<Instant>) -> Result<(), CoreError>;
    fn set_write_deadline(&self, deadline: Option<Instant>) -> Result<(), CoreError>;
}
pub type BoxedPacketConn = Box<dyn PacketConn>;

```

`PacketConn::recv_from` deliberately returns `TargetAddr`, not `SocketAddr`, so
an unresolved peer and an IP peer follow the same cross-crate representation.
`Session.target` remains the routed destination, while `Session.connect`
preserves every legacy `DialOpts` field and `Session.packet` carries the live
route controls `udp_connect`, effective `idle_timeout`, and
`udp_disable_domain_unmapping`. Each `PacketConn` retains immutable snapshots
of both option structures from the finalized `Session` that created it:
`udp_connect` chooses connected-UDP operation, `idle_timeout` preserves the
existing route -> inbound -> protocol/port -> Go-5-minute fallback precedence,
and domain-unmapping behavior remains visible to UDP NAT. The deadline methods
are required (not silent no-op defaults); adapters that cannot delegate to an
OS socket implement the same semantics in their wrapper state. This is the
runtime-neutral equivalent of the Go packet connection’s address/deadline
surface.

### 2. Canonical outbound and group

Rust uses the raw identifier `r#type` for Go `Type()`. Every protocol outbound
implements this one trait exactly once.

```rust
pub trait Outbound: Send + Sync + std::fmt::Debug + 'static {
    fn r#type(&self) -> &str;
    fn tag(&self) -> OutboundTag;
    fn network(&self) -> &[NetworkKind];

    fn dependencies(&self) -> &[OutboundTag] {
        &[]
    }

    fn dial<'a>(&'a self, session: &'a Session)
        -> BoxFuture<'a, Result<BoxedStream, CoreError>>;

    fn listen_packet<'a>(&'a self, session: &'a Session)
        -> BoxFuture<'a, Result<BoxedPacketConn, CoreError>>;

    fn as_group(&self) -> Option<&dyn OutboundGroup> {
        None
    }
}

pub trait OutboundGroup: Outbound {
    fn now(&self) -> OutboundTag;
    fn all(&self) -> Vec<OutboundTag>;

    fn as_selector_control(&self) -> Option<&dyn SelectorControl> {
        None
    }

}

pub trait SelectorControl: Send + Sync + std::fmt::Debug + 'static {
    fn select<'a>(&'a self, tag: &'a str) -> BoxFuture<'a, Result<(), CoreError>>;
}
```

This is D1/D3/D4/D5 in executable-signature form:

- `network()` expresses the Go TCP/UDP capability declaration.
- `dependencies()` gives the supervisor’s startup ordering input without
  teaching protocols about the manager.
- `dial()` uses a stream rather than `TcpStream`; there is no `connect_io`
  escape hatch.
- `listen_packet()` is the sole UDP creation method. `PacketConn` carries both
  send and receive, so a SOCKS/QUIC association has one owner.
- `as_group()` is the base group capability hook; there is no generic
  `as_any()`. `OutboundGroup::r#type()` supplies the group type. The finite
  optional `SelectorControl` hook is the explicit Rust equivalent of Go’s
  concrete-selector assertion, so GUI mutation does not assert that every
  group is selectable. The old `members_health` method has zero consumers and
  is deleted with the legacy core group trait rather than preserved as a new
  unconsumed contract.

### 3. Canonical inbound

Socket acceptance and router dispatch are implementation details of the
registry/builder context. The one public inbound contract represents the Go
adapter lifecycle and preserves currently observable readiness/connection
metrics without exporting handler/acceptor subtraits.

```rust
pub trait Inbound: Send + Sync + std::fmt::Debug + 'static {
    fn r#type(&self) -> &str;
    fn tag(&self) -> InboundTag;

    fn start(&self, stage: StartStage) -> Result<(), CoreError>;
    fn close(&self) -> Result<(), CoreError>;

    fn supports_startup_readiness(&self) -> bool {
        false
    }

    fn active_connections(&self) -> Option<u64> {
        None
    }

    fn udp_sessions_estimate(&self) -> Option<u64> {
        None
    }
}
```

`serve`, `serve_with_ready`, `request_shutdown`, `InboundHandler`, and
`InboundAcceptor` are not retained as public contract methods. Implementations
may spawn/listen internally at the appropriate `StartStage`; `close()` is the
only teardown request. That preserves lifecycle semantics while eliminating the
current unconsumed handler/acceptor split.

Required behavioral invariant for WP03: `start(StartStage::Start)` does not
return `Ok(())` until the inbound has either bound its listener and published
the equivalent of the current readiness signal, or returned its structured
failure. `close()` requests shutdown, ends accept loops, waits for their owned
workers as appropriate, and releases listener resources. This preserves the
supervisor’s current `serve_with_ready(Some(oneshot))` and
`request_shutdown()` behavior without carrying those old methods forward.

### 4. Structured error boundary

All canonical methods return `CoreError`; no `anyhow::Error`, `io::Error`,
`AdapterError`, `SbError`, or `ProtoError` crosses this boundary. WP02 extends
the existing base error with a structured connection category, then adapters
map at their outer implementation edge:

```rust
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConnectErrorKind {
    Refused,
    Reset,
    Unreachable,
    Unsupported,
    InvalidConfig,
}

pub enum CoreError {
    // Existing variants unchanged …
    #[error("connect {kind:?}: {message}")]
    Connect {
        kind: ConnectErrorKind,
        message: String,
    },
}

impl CoreError {
    pub fn class(&self) -> ErrorClass {
        match self {
            // Existing arms unchanged …
            Self::Connect { kind: ConnectErrorKind::Refused
                | ConnectErrorKind::Reset
                | ConnectErrorKind::Unreachable, .. } => ErrorClass::Io,
            Self::Connect { kind: ConnectErrorKind::Unsupported, .. }
                => ErrorClass::Protocol,
            Self::Connect { kind: ConnectErrorKind::InvalidConfig, .. }
                => ErrorClass::Configuration,
        }
    }
}

pub enum ErrorClass {
    // Existing variants unchanged …
    Configuration,
}

// Add `Self::Configuration => "configuration"` to ErrorClass::Display's
// exhaustive match at the same time.
```

| Existing error at a migration seam | Canonical result |
|---|---|
| `io::ErrorKind::{ConnectionRefused}` | `CoreError::Connect { kind: Refused, .. }` |
| `io::ErrorKind::{ConnectionReset, ConnectionAborted}` | `CoreError::Connect { kind: Reset, .. }` |
| `io::ErrorKind::{NotConnected, AddrNotAvailable, NetworkUnreachable}` | `CoreError::Connect { kind: Unreachable, .. }` |
| Socket / DNS I/O not above | `CoreError::Io { class: ErrorClass::Io, message }` or `CoreError::Dns` |
| `AdapterError::Timeout` or timed-out dial/listen I/O | `CoreError::Timeout { operation, duration: session.connect.connect_timeout }` |
| Proxy/TLS framing or handshake | `CoreError::Protocol { message }` |
| Credentials | `CoreError::Auth { message }` |
| Block/routing denial | `CoreError::Policy { reason }` |
| Unsupported protocol/transport or `NotImplemented` | `CoreError::Connect { kind: Unsupported, .. }` |
| Invalid adapter configuration | `CoreError::Connect { kind: InvalidConfig, .. }` |

This follows D2: `CoreError` remains the base, gains structured connection
subcategories without exposing adapter/raw errors, and does not introduce a
competing top-level `ConnectError`.

For a packet operation, `PacketConn` uses its finalized creation snapshot’s
`packet.idle_timeout`/current explicit deadline and reports that duration in
`CoreError::Timeout`. `Inbound::start`/`close` have no connection session:
their owning supervisor applies the configured lifecycle timeout and emits
`CoreError::Timeout { operation: "inbound-start" | "inbound-close", duration }`.
The inbound trait itself never guesses a transport timeout.

### 5. Runtime dependency boundary

`sb-types` may add direct `futures = "0.3"` for `futures::io::{AsyncRead,
AsyncWrite}`. It does not add Tokio, tokio-util, hyper, axum, or anyhow.
Tokio implementations are adapted at the adapter/core boundary with the
existing workspace compatibility facilities (for example, tokio-util’s
`compat` extension in the owning crate). This obeys D7 and fixes the current
marker-only `BoxedStream` without leaking a runtime into the contract crate.

### 6. Direct cutover rule

WP02/WP03 use a direct cutover: implement canonical traits, switch every
consumer, delete old traits and wrappers in the same package scope. A single
concentrated internal conversion module is allowed only during WP02 and must
be gone by WP03/WP06. No deprecated public compatibility trait, type alias, or
dual registry is permitted. This is D8.

## Migration map

The file counts are the current source-file blast radius observed by the WP01
commands. They are planning counts, not claims that each occurrence is a
runtime implementation. Every row has an explicit destination; none is left
unresolved.

| Existing surface | Snapshot scope / affected files | Destination | WP | Risk |
|---|---:|---|---|---|
| `sb-types::ports::OutboundConnector` (O1) | 1 definition; 0 adopters | Replace its definition in place with canonical `Outbound`; delete `send_datagram`. | WP02 | Low |
| `sb-types::ports::adapter::UpstreamConnectorPort` (O10) | 1 definition plus port references | Merge metadata into `Session`; delete as a second connector port. | WP02 | Medium |
| `sb-adapters::traits::OutboundConnector` + `Target` + `DialOpts` (O2) | 16 implementation files / 17 direct protocol impls | Each adapter implements canonical `Outbound`; move options into `Session.connect`; delete trait/types. | WP02 | High |
| `register.rs` connector bridge | 1 file / generic bridge plus 4 explicit adapter-dial bridges | Delete after callers use adapter canonical trait directly; do not introduce replacement wrappers. | WP02 | High |
| `sb-core::adapter::OutboundConnector` (O3) | 33 direct implementation blocks (23 non-test) | Replace holders with `Arc<dyn sb_types::Outbound>`; delete concrete-TCP trait and `connect_io`. | WP03 | High |
| `sb-core::adapter::OutboundGroup` (O15) | 1 implementation plus control-plane callers | Replace with canonical `OutboundGroup`; expose selection only through `SelectorControl`; delete legacy health/type hooks. | WP03 | Medium |
| `sb-core::outbound::manager::OutboundAdapter` / `OutboundHandler` (O16) | Dynamic manager holder plus test implementation | Store canonical outbound objects directly; delete duplicate lifecycle connector supertrait and alias. | WP03 | Medium |
| `sb-core::adapter::OutboundFactory` (O17) | 1 definition; 0 implementations/callers | Delete as dead error-erasing factory. | WP03 | Low |
| `sb-core::outbound::traits::{OutboundConnector, OutboundConnectorIo, UdpTransport}` (O4/O5/O14) | 25 core/adapter/app source files | Fold into canonical `Outbound` + `PacketConn`; delete all three. | WP03 | High |
| `runtime::switchboard::OutboundConnector` (O6) | 10 source files | Switchboard registry consumes canonical outbound; delete local trait and local target/options. | WP03 | High |
| `pipeline::{Inbound, Outbound, DynOutbound}` (I4/O7) | 4 source files | Convert direct/block to canonical adapters, then delete pipeline traits/alias. | WP03 | Medium |
| `outbound/types::{Outbound, OutboundTcp}` (O8/O11) | 8 source files | Convert active Hysteria/Naive paths to canonical stream/packet operations; delete legacy types. | WP03 | High |
| `outbound/crypto_types::{OutboundTcp, OutboundUdp}` (O12/O13) | 1 legacy file, no active impl | Compile-confirmed deletion. | WP03 | Low |
| `sb-proto::connector::OutboundConnector` / `Target` / `ProtoError` (O9) | 6 source/test files | Move needed protocol helper into adapter-private code or sb-types, then delete sb-proto under D15. | WP03 | Medium |
| `sb-types::{InboundHandler, InboundAcceptor}` (I1/I2) | 1 definition file, no adopters | Delete; builder internals own dispatch. | WP03 | Low |
| `sb-core::adapter::InboundFactory` (I6) | 1 definition; 0 implementations/callers | Delete as dead error-erasing factory. | WP03 | Low |
| `sb-core::InboundAdapter` (I7) | 1 test implementation; no production holder | Delete rather than promote its non-canonical lifecycle error boundary. | WP03 | Low |
| `sb-core::adapter::InboundService` (I3) | 30 impls (19 adapter / 11 core) | Adapters/core inbounds implement canonical `Inbound`; preserve status hooks, remove blocking serve/downcast. | WP03 | High |
| `sb-adapters` direct `InboundService` implementations | 19 adapter modules | Direct canonical `Inbound` implementation; no adapter bridge trait. | WP03 | High |
| `UdpOutboundFactory` / `UdpOutboundSession` | 8 lexical factory + 8 session impls (5/4 production, including endpoint facade) | `Outbound::listen_packet` + `PacketConn`; delete both. | WP03 | High |
| `Endpoint::listen_packet` / `EndpointUdpOutboundFactory` | Endpoint trait, one facade factory, WireGuard/Tailscale implementations | Keep endpoint lifecycle; adapt endpoint UDP facade to canonical `PacketConn`, then remove parallel factory/session exposure. | WP03 | High |
| `sb-adapters::OutboundDatagram` | 4 protocol UDP socket impls | Implement `PacketConn` directly; delete local trait. | WP03 | High |

## Alternatives rejected

### A. Keep the current sb-types `OutboundConnector` as-is

Rejected. It has no adopters, a marker-only `BoxedStream`, no type/network/
dependency metadata, and a send-only UDP method. Preserving it would create
the seventh nominal connector rather than achieve D1/D4.

### B. Make `sb-core::adapter::OutboundConnector` canonical

Rejected. Its `TcpStream` return is exactly what forces protocol wrappers and
the `v2ray_transport` `connect_io` side channel. It also brings Tokio and bare
I/O errors across a contract boundary, violating D2/D7.

### C. Retain old traits as deprecated adapters for one migration cycle

Rejected by D8. This repository’s existing disease is layers of “temporary”
bridges that never disappear. WP02 may have one concentrated conversion module
while it changes callers, but the old trait definitions and registries do not
survive a package boundary.

## D1–D8 consistency check

| Decision | ADR implementation | Result |
|---|---|---|
| D1 | `Outbound` has type/tag/network/dependencies, stream `dial`, and packet `listen_packet`; no concrete socket type. | Aligned |
| D2 | All canonical methods use expanded `CoreError`; conversions happen inside implementations. | Aligned |
| D3 | `Session` + `TargetAddr` are the sole connection context/address carriers; no `Target`/`DialOpts`. | Aligned |
| D4 | `PacketConn` plus `listen_packet` is the one UDP model with send and receive. | Aligned |
| D5 | `OutboundGroup` is in sb-types and exposed only by `as_group()`. | Aligned |
| D6 | One staged-lifecycle `Inbound` replaces handler/acceptor/service splitting. | Aligned |
| D7 | `futures` only in sb-types; Tokio-compatible conversion stays outside. | Aligned |
| D8 | Direct cutover; no deprecated compatibility traits. | Aligned |

No census evidence conflicts with D1–D8. D18 escalation is therefore not
needed for WP01.

## Consequences and verification handoff

Positive consequences: protocol implementations get one contract, group GUI
functions remain explicit, and UDP has a complete ownership/receive model.
The migration cost is deliberately front-loaded into WP02/WP03, where it is
validated by focused adapter/inbound/UDP tests plus the all-feature workspace
gates specified in `mig03_00_overview.md`.

WP01 itself makes no source change; its validation is document scope and clean
worktree verification. WP02 must add compile-time trait-object tests for
`Outbound`, `PacketConn`, `OutboundGroup`, and `Inbound`, then add behavior
tests for an encrypted stream and a bidirectional UDP association before
deleting any adapter wrapper.
