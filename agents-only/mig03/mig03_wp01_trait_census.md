<!-- tier: B -->
# MIG-03 WP01 — Trait Contract Census

Status: COMPLETE
Snapshot: 2026-07-10 (working tree `main`, before WP02)
Scope: documentation-only evidence for the contracts named in
`mig03_wp01_trait_census_and_adr.md`; no production source was changed.

## 1. Method and reproducibility

This is a source census, not a claim that identically named Rust traits are the
same trait. Rust imports make a bare `impl OutboundConnector` ambiguous, so all
counts below are scoped by the defining module and accompanied by a command
that prints the evidence. Counts include tests when a test is an implementation
or a caller; this is intentional because WP02 must migrate its fixtures too.

```bash
# List every contract definition that the census considers.
rg -n --glob '*.rs' \
  '^\s*(pub )?trait (InboundService|InboundHandler|InboundAcceptor|OutboundConnector|OutboundGroup|OutboundDatagram|UdpOutboundSession|UdpOutboundFactory|OutboundTcp|OutboundUdp|UdpTransport|Outbound)\b' \
  crates/sb-types crates/sb-core crates/sb-adapters crates/sb-proto

# Reproduce the implementation and dynamic-holder evidence by module.  Inspect
# the import at each hit before treating a bare trait name as a particular trait.
rg -n --glob '*.rs' 'impl .*OutboundConnector for' crates/sb-adapters
rg -n --glob '*.rs' 'impl .*OutboundConnector for' crates/sb-core
rg -n --glob '*.rs' 'impl .*InboundService for' crates/sb-core crates/sb-adapters
rg -n --glob '*.rs' 'impl .*UdpOutbound(Session|Factory) for' crates/sb-core crates/sb-adapters
rg -n --glob '*.rs' 'impl .*OutboundDatagram for' crates/sb-adapters
rg -n --glob '*.rs' 'dyn (OutboundConnector|InboundService|UdpTransport)' crates app
```

The first command finds 19 trait definitions in the four relevant crates. The
Primary-evidence list describes the nine public/legacy families; the remaining
definitions are recorded in §2.3 so a forgotten side interface cannot become a
seventh connector contract during WP02.

## 2. Outbound contract families

### 2.1 Primary definitions

| ID | Location | Exact shape / defaults | Error and async model | Implementers and callers at snapshot | Object shape / migration disposition |
|---|---|---|---|---|---|
| O1 | `sb-types/src/ports/outbound.rs:11` | `tag() -> OutboundTag`; `connect_stream(&Session, &TargetAddr) -> BoxFuture<Result<BoxedStream, CoreError>>`; `send_datagram(&Session, &TargetAddr, &[u8]) -> BoxFuture<Result<(), CoreError>>` | Hand-written object-safe `BoxFuture`; `CoreError`; no defaults. | **0 implementations and 0 runtime consumers** of this trait. `rg -n 'sb_types(::ports)?::OutboundConnector|connect_stream\(' crates app` only finds the declaration or unrelated TLS methods. | `Send + Sync + Debug + 'static`; technically object-safe, but its `BoxedStream` is a marker and is not a usable byte-I/O contract. **Replace in-place** with the ADR canonical `Outbound`; do not keep this name as a compatibility facade. |
| O2 | `sb-adapters/src/traits.rs:535` | `async start() -> Result<()>` default `Ok(())`; `async dial(Target, DialOpts) -> Result<BoxedStream>`; `name() -> &'static str` default `"unknown"`. | `#[async_trait]`; crate-local `AdapterError` via `Result<T>`; `Target`/`DialOpts` are adapter-local. | **17 direct protocol implementations in 16 files**: hysteria, trojan, socks5, socks4, tor, vless, http, ssh, vmess, shadowsocks, wireguard ×2, dns, shadowsocksr, hysteria2, tuic, shadowtls. `AdapterIoBridge<A>` and four explicit `OutboundConnector::dial` calls in `register.rs` are the actual bridge; no `dyn crate::traits::OutboundConnector` holder was found. | Object-safe after `async_trait`, `Send + Sync + Debug` but no explicit `'static`. **Implement canonical directly** in WP02; remove `Target`, `DialOpts`, this trait, and all per-protocol bridge use. |
| O3 | `sb-core/src/adapter/mod.rs:120` | `async connect(&str, u16) -> io::Result<TcpStream>`; under `v2ray_transport`, default `connect_io` boxes the preceding `TcpStream`; default `as_any() -> None`; default `as_group() -> None`. | `#[async_trait]`; concrete `tokio::net::TcpStream` and bare `io::Error`. | **33 direct `connect` implementation blocks**: 23 non-test (11 in `register.rs`, AnyTLS, and core adapter/bridge/outbound/endpoint paths) plus 10 fixtures. It is the live registry/bridge contract: `Bridge.outbounds`, adapter registry, `OutboundImpl::Connector`, selector/group and app fixtures hold it dynamically. | Object-safe but is the direct cause of wrappers: a TLS/proxy stream cannot satisfy a `TcpStream` return. **Delete** in WP03 after WP02 gives adapters the canonical implementation. |
| O4 | `sb-core/src/outbound/traits.rs:16` | `async connect_tcp(&ConnCtx) -> SbResult<TcpStream>` and `async connect_udp(&ConnCtx) -> SbResult<Box<dyn UdpTransport>>`. | `#[async_trait]`; core-local `SbResult`; concrete TCP half plus a different UDP trait. | **6 implementations**: live `DirectConnector`, live `ManagerConnectorBridge`, and four test dummies. Dynamic `UdpTransport` is used by `net/datagram.rs`, SOCKS/TUN UDP paths, `outbound/mod.rs`, manager, and supervisor tests. | Object-safe after macro, `Send + Sync + Debug`; no `'static` bound. **Fold into canonical** `Outbound`/`PacketConn`; delete the module trait and `UdpTransport` in WP03. |
| O5 | `sb-core/src/outbound/traits.rs:42` | Feature-gated `async connect_tcp_io(&ConnCtx) -> SbResult<sb_transport::IoStream>`. | `#[async_trait]`; `v2ray_transport` only; core-local error. | No production implementer found outside the declaration/test surface (`rg -n 'impl .*OutboundConnectorIo for' crates app`). | Object-safe when enabled. **Delete**, because canonical `dial()` always returns a stream and needs no feature-only parallel trait. |
| O6 | `sb-core/src/runtime/switchboard.rs:149` | `async start()` default `Ok(())`; `async dial(Target, DialOpts) -> AdapterResult<BoxedStream>`; `name()` default `"unknown"`. | `#[async_trait]`; local `AdapterError`, local `Target`/`DialOpts`, local Tokio stream alias. | Three local implementation sites: `DirectPassthroughConnector`, `BlockRejectConnector`, `DegradedConnector`; held in `OutboundSwitchboard` registry/default fields. Its confirmed live dynamic dial is the TUN path. | Object-safe, `Send + Sync + Debug`. **Delete** with the switchboard’s legacy connector registry; it must hold `Arc<dyn sb_types::Outbound>` instead. |
| O7 | `sb-core/src/pipeline.rs:14` | `async connect(Address) -> io::Result<TcpStream>`; default `connect_ex(&ConnectParams)` delegates to `connect`; `DynOutbound = Arc<dyn Outbound>`. | `#[async_trait]`; concrete Tokio stream and bare `io::Error`. | **2 production implementations**: `sb_adapters::outbound::{direct::DirectOutbound, block::BlockOutbound}`; three `register.rs` uses convert through it. The generic `pipeline::Inbound` only has its unit-test implementation. | Object-safe after macro. **Delete** in WP03: the two implementations become canonical adapters, not a core-owned compatibility trait. |
| O8 | `sb-core/src/outbound/types.rs:158` | `async tcp_connect(TcpConnectRequest) -> anyhow::Result<TcpStream>`; `async tcp_connect_tls(...) -> anyhow::Result<TlsStream<TcpStream>>`; `async udp_bind(UdpBindRequest) -> anyhow::Result<UdpSocket>`; `name() -> &'static str`. | `#[async_trait]`; `anyhow`, concrete Tokio streams/sockets. | **0 active implementation/caller**. Four textual implementation files are orphaned: their modules are not declared by `outbound/mod.rs`; their stale fields do not match the current trait. | Object-safe after macro but invalid across the desired boundary due to `anyhow`/Tokio. **Delete as dead/legacy surface** in WP03 after compile-confirmed removal. |
| O9 | `sb-proto/src/connector.rs:116` | `async connect(&Target) -> Result<Box<dyn IoStream>, ProtoError>`. | `#[async_trait]`; `ProtoError`; Tokio I/O trait alias. | **1 generic production implementation**: `sb_proto::trojan_connector::TrojanConnector<D>`; API tests exercise its public types. | Object-safe after macro. D15 already authorizes deletion of `sb-proto`; **move the still-used protocol helper/type need into sb-types or adapter-private code in WP03**, then delete this trait/crate rather than leaving an adapter bridge. |

### 2.2 Call and holder evidence

The decisive ownership evidence is not a raw bare-name count:

| Surface | Reproducible evidence | What it proves |
|---|---|---|
| Adapter implementations | `rg -n --glob '*.rs' 'impl .*OutboundConnector for' crates/sb-adapters` | All protocol adapters currently implement O2, while `register.rs` translates them to O3. This is the wrapper seam WP02 must remove. |
| Core concrete return | `rg -n --glob '*.rs' 'async fn connect\(&self, .*\) -> .*TcpStream|connect_io' crates/sb-core/src/adapter crates/sb-core/src/outbound` | O3/O4/O7/O8 expose a concrete `TcpStream` on at least one method; encrypted streams need a second method or wrapper. |
| Dynamic holders | `rg -n --glob '*.rs' 'Arc<dyn .*OutboundConnector>|Box<dyn .*OutboundConnector>|DynOutbound' crates app` | Registries, groups, bridges, tests, and the switchboard all dispatch dynamically. The canonical trait must stay object-safe. |
| Existing sb-types port adoption | `rg -n --glob '*.rs' 'sb_types(::ports)?::OutboundConnector|impl .*sb_types.*OutboundConnector' crates app` | No implementation/adoption exists. WP02 can replace it without a public compatibility layer. |

### 2.3 Additional discovered definitions (must not be omitted)

| ID | Location | Exact shape | Current use and destination |
|---|---|---|---|
| O10 | `sb-types/src/ports/adapter.rs:70` `UpstreamConnectorPort` | `tag() -> OutboundTag`; `connect_stream(TargetAddr, RouteMetadata) -> BoxFuture<Result<BoxedStream, CoreError>>`; default `supports_udp() -> false`. | A second sb-types connector port. Its consumers must be enumerated as part of the WP02 implementation sweep; **merge its metadata into `Session` and delete it**, not retain a second connector trait. |
| O11 | `sb-core/src/outbound/types.rs:45` | `OutboundTcp` with associated `IO`, `connect(&HostPort) -> io::Result<IO>`, default `protocol_name() -> "unknown"`. | Used by `naive_h2`, Hysteria v1/v2 and outbound factory paths. A trait object would have to bind its associated `IO`, so it cannot be the one erased common stream port. **Replace** with canonical `dial()` in WP03. |
| O12 | `sb-core/src/outbound/crypto_types.rs:33` | A second `OutboundTcp`: associated Tokio `IO`, `connect(&HostPort) -> io::Result<IO>`, required `protocol_name()`. | No active implementation/reference outside this legacy file was found. **Delete** with its dead module after compiler confirmation in WP03. |
| O13 | `sb-core/src/outbound/crypto_types.rs:45` | `OutboundUdp::bind() -> io::Result<UdpSocket>`; default `connect_addr(&SocketAddr) -> Ok(())`; `protocol_name()`. | No active implementation/reference found. **Delete** in WP03; its bind model is not Go `ListenPacket`. |
| O14 | `sb-core/src/outbound/traits.rs:26` | `UdpTransport::send_to(&[u8], &Endpoint) -> SbResult<usize>` and `recv_from(&mut [u8]) -> SbResult<(usize, SocketAddr)>`. | Active through `DirectUdpTransport`, `UdpFactoryTransport`, manager tests, and `net/datagram.rs`. **Replace** with canonical `PacketConn`. |

## 3. Inbound census

### 3.1 Definitions, obligations, and adoption

| ID | Location | Exact shape / defaults | Implementers / callers | Object shape and disposition |
|---|---|---|---|---|
| I1 | `sb-types/src/ports/inbound.rs:29` `InboundHandler` | `on_stream(Session, BoxedStream) -> BoxFuture<Result<(), CoreError>>`; `on_datagram(Session, Datagram) -> BoxFuture<Result<(), CoreError>>`. | **0 implementations and 0 external adopters**; its only trait-object use is the `Arc<dyn InboundHandler>` parameter declared by I2’s `accept_loop`. Reproduce: `rg -n --glob '*.rs' 'impl .*InboundHandler for|dyn InboundHandler|\.on_stream\(|\.on_datagram\(' crates app`. | Object-safe, `Send + Sync + 'static`; currently dormant. **Delete** rather than promote: dispatch belongs inside the inbound builder/runtime context under D6. |
| I2 | `sb-types/src/ports/inbound.rs:49` `InboundAcceptor` | `tag() -> InboundTag`; `accept_loop(Arc<dyn InboundHandler>) -> BoxFuture<Result<(), CoreError>>`. | **0 implementations, 0 holders/callers**; reproduce with `rg -n --glob '*.rs' 'impl .*InboundAcceptor for|dyn InboundAcceptor|accept_loop' crates app`. | Object-safe, `Send + Sync + 'static`; dormant and splits lifecycle from dispatch. **Delete** in favor of one canonical `Inbound`. |
| I3 | `sb-core/src/adapter/mod.rs:76` `InboundService` | Required `serve() -> io::Result<()>`; defaults: `supports_startup_readiness() -> false`, `serve_with_ready(..)` delegates to `serve`, `request_shutdown()` no-op, `active_connections()/udp_sessions_estimate()/as_any()` return `None`. | **30 implementations**: 19 adapter sources and 11 core sources (four core test stubs), so 19 adapter + seven scaffold production implementations. `Bridge`, `InboundBuilder`, `InboundRegistryHandle`, supervisor, and `app/inbound_starter.rs` actively hold/start/stop it. | Object-safe, `Send + Sync + Debug + 'static`. **Replace** with canonical `Inbound`; preserve readiness and observability methods but delete blocking `serve*`, `request_shutdown`, and generic downcast. |
| I4 | `sb-core/src/pipeline.rs:9` `Inbound` | `async serve() -> anyhow::Result<()>`. | Only the unit-test `MockInbound`; no production holder/caller. | Object-safe after macro but has `anyhow`; **delete as dead legacy** in WP03. |
| I5 | `sb-adapters` inbound surface | There is **no adapter-local inbound lifecycle trait**. 19 adapter implementations (HTTP, mixed, redirect, tproxy, Hysteria, Hysteria2, TUIC, Naive, AnyTLS, ShadowTLS, Trojan, VLESS, VMess, Shadowsocks, SOCKS, direct, TUN, DNS, SSH) implement I3 directly. A separate Tokio-only `InboundStream` is an I/O helper, not a lifecycle contract. | `rg -n --glob '*.rs' 'impl[[:space:]]+(sb_core::adapter::)?InboundService[[:space:]]+for' crates/sb-adapters/src` prints the direct adapter implementations. | Confirms the canonical inbound must be implemented directly by adapters; no adapter compatibility trait is needed. |
| I6 | `sb-core/src/adapter/mod.rs` `InboundFactory` | `create(&InboundParam) -> Option<Arc<dyn InboundService>>`. | **0 implementations and 0 callers**. Its `Option` erases an error. | Object-safe but dormant; **delete** in WP03 rather than translate an error-losing factory. |
| I7 | `sb-core` `InboundAdapter: Lifecycle` | `tag() -> &str`, `inbound_type() -> &str`; inherited `Lifecycle::start/close` returns `Box<dyn Error + Send + Sync>`. | **1 test implementation**, not connected to the production manager. | Object-safe but violates D2 error boundary; **delete** in WP03 rather than use as a supertrait. |
| I8 | `sb-adapters/src/transport_config.rs:436` `InboundStream` | Tokio `AsyncRead + AsyncWrite + Unpin + Send`; `InboundListener::accept() -> io::Result<(Box<dyn InboundStream>, SocketAddr)>`. | Seven executable/type uses in transport listener/Trojan/VLESS; a raw `rg` finds nine including two comments. | Object-safe I/O helper, but Tokio-bound; keep adapter-private and do not lift it into `sb-types`. |

The present responsibility split is therefore artificial: I1/I2 model a
handler/acceptor handoff that nothing uses, while I3 combines socket lifecycle,
readiness, shutdown request, and metrics in core. The canonical trait in the
ADR retains lifecycle and observable status, and treats socket acceptance plus
connection dispatch as an implementation detail of the registry builder.

## 4. UDP census and required unification

| Surface | Send destination | Receive path | Lifecycle / ownership | Error / async | Snapshot evidence | Canonical mapping |
|---|---|---|---|---|---|---|
| O1 `sb-types::OutboundConnector::send_datagram` | Explicit `&TargetAddr`; session supplied separately. | **None.** | No packet/session object. | `BoxFuture<Result<(), CoreError>>`. | Zero implementers. | Remove: unable to represent NAT association or receive semantics. |
| O2 `sb-adapters::OutboundDatagram` | Socket is pre-associated; `send_to(&[u8])`. | `recv_from(&mut [u8]) -> Result<usize>`; source address is lost. | Default async `close() -> Ok(())`. | `#[async_trait]`, `AdapterError`. | **4 impls**: SOCKS, Shadowsocks, Trojan, VLESS UDP sockets. | Adapt into `PacketConn`; retain bidirectional behavior, restore `TargetAddr` source. |
| Core `UdpOutboundFactory` / `UdpOutboundSession` | Factory `open_session() -> Future<Arc<dyn Session>>`; session `send_to(&[u8], host, port)`. | `recv_from() -> io::Result<(Vec<u8>, SocketAddr)>`. | Factory owns association creation; session is an `Arc`. | Hand-written boxed future / `#[async_trait]`, `io::Error`. | **8 lexical factory and 8 session implementations**; production is five factories (Direct, WireGuard, Hysteria2, SelectorGroup, Endpoint) and four sessions (Direct, WireGuard, Hysteria2, WireGuardEndpoint), with the rest tests/wrappers. | Fold both into `Outbound::listen_packet(&Session)` returning an owned `PacketConn`. |
| O14 `UdpTransport` | Explicit `&Endpoint`. | `recv_from(&mut [u8]) -> SbResult<(usize, SocketAddr)>`. | No close or per-association factory. | `#[async_trait]`, `SbResult`. | **3 implementations**: `DirectUdpTransport`, `UdpFactoryTransport`, and a test mock; production SOCKS/TUN UDP NAT consumes it. | Fold into `PacketConn`; `Endpoint`/`SocketAddr` become `TargetAddr`. |
| O13 `crypto_types::OutboundUdp` | `bind()` then optional peer connect. | Implied socket receiver, not on trait. | Owns concrete Tokio `UdpSocket`. | `#[async_trait]`, `io::Error`; no active impl. | Dead legacy. | Delete. |
| Endpoint UDP facade | `Endpoint::listen_packet(Socksaddr) -> Future<Arc<UdpSocket>>`; optional `supports_udp_outbound()` + `open_udp_outbound_session() -> Future<Arc<dyn UdpOutboundSession>>`; bridge registers `EndpointUdpOutboundFactory`. | Socket/session dependent. | Endpoint lifecycle remains separate from outbound registry. | Tokio socket / `io::Error`; default is explicit unsupported. | `endpoint/mod.rs:248-275`, `:700-704`; WireGuard/Tailscale implement the surface, and `adapter/bridge.rs:95-101` wires it. | Keep endpoint lifecycle, but adapt its UDP facade to canonical `PacketConn`; do not leave a parallel endpoint UDP contract. |

The only canonical UDP shape is a Go-style packet connection: create it once
for a routed `Session`, then support both `send_to` and `recv_from`. It is the
only listed shape that can express a SOCKS/QUIC UDP association and preserve
receive metadata without a side channel.

## 5. Object safety and boundary findings

1. O2/O3/O4/O6/O7/O8/O9 and I4 use `async_trait`; they are dyn-safe only because
   the macro boxes the returned future. O1/I1/I2 are explicitly dyn-safe via
   `BoxFuture`. The canonical port will use the latter, avoiding a Tokio/
   `async_trait` dependency in `sb-types`.
2. O11/O12 have an associated `IO` type; a trait object would have to bind it,
   so they are not suitable as the one erased common stream port. The canonical
   port returns one erased stream type instead.
3. O3/O4/O7/O8 expose `tokio::net::TcpStream`, while O2/O6/O9 use different
   Tokio-bound aliases. This is the direct adapter-wrapper cause, not a
   protocol semantic distinction.
4. Current `sb-types::AsyncStream` is a `Send + Sync + 'static` marker, not an
   `AsyncRead + AsyncWrite` contract. WP02 must make the trait functional using
   `futures::io` and use `tokio_util::compat` only at adapter/runtime seams;
   neither Tokio nor tokio-util belongs in `sb-types`.
5. D15 requires deletion of `sb-proto`, but O9 has one generic Trojan
   implementation. This is a **WP03 planned migration input**, not a D18
   conflict: move the genuinely needed helper/types before deletion.

## 6. Findings handed to dependent packages

| Finding | Evidence | Owner / required action |
|---|---|---|
| `register.rs` wrappers are caused by O3’s concrete TCP return. | O3 `connect` and O3 `connect_io`, plus O2’s `BoxedStream`. | WP02: adapters implement canonical `Outbound` directly; remove wrappers rather than adding a new one. |
| A dormant sb-types port cannot be a safe transition layer. | O1/I1/I2 have zero adopters. | WP02/WP03: replace/delete directly under D8. |
| `Session` already owns `TargetAddr`. | `sb-types/src/session.rs:164`; O1 redundantly receives both. | WP02: canonical `dial/listen_packet` accepts one `&Session`; callers set the routed target in the session. |
| UDP route controls affect runtime behavior. | `router/conn.rs:289-295,717-757` consumes `udp_timeout`, `udp_connect`, and `udp_disable_domain_unmapping`; SOCKS resolves timeout as route → inbound → protocol/port → `UDP_TIMEOUT` at `inbound/socks/udp.rs:181-194`; route IR declares the override at `sb-config/src/ir/route.rs:540-548`. | WP02: finalize `Session.packet` with `udp_connect`, `udp_disable_domain_unmapping`, and the resolved effective idle timeout before `listen_packet`; `PacketConn` snapshots it. |
| Selector control is GUI-visible; health is not. | O3 has `now/all/group_type/members_health/select_outbound`; `sb-api` calls `select_outbound`, while `rg -n '\.members_health\(' crates app labs` finds only the declaration and `SelectorGroup` implementation. | WP02/WP03: canonical `OutboundGroup` preserves only Go-common `now/all`; migrate selection to optional `SelectorControl` and delete unconsumed `members_health` with the legacy core trait. |
| Core inbound `serve` is not Go’s staged lifecycle. | I3 compared with Go `adapter/inbound.go` and `adapter/lifecycle.go`. | WP03: fold listener spawn/readiness into canonical `start(StartStage)` and retain observable status methods. |
| Trojan inbound feature gates are inconsistent. | `cargo check -p sb-adapters --no-default-features --features adapter-trojan,router` fails because `register.rs` references `inbound::trojan` although `adapter-trojan` does not enable `trojan`. | Record for the relevant feature-matrix/WP02 implementation sweep; do not repair in this documentation-only package. |
| No unapproved decision conflict was found. | D1–D8 and this census agree on placement, error, metadata, UDP, group, inbound, dependency, and direct-switch strategy. | WP01 can close; no D18 escalation is required. |
