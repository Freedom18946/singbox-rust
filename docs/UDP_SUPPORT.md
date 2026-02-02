UDP Support Overview

Scope
- SOCKS5 inbound: UDP ASSOCIATE minimal path
- Outbound UDP sessions: Shadowsocks AEAD, TUIC (udp_over_stream), Hysteria2 (QUIC datagram)
- Direct UDP fallback with NAT (per association, per target)

Behavior
- SOCKS5 UDP:
  - Client establishes UDP ASSOCIATE over TCP; server replies with relay address (bound locally)
  - Client sends datagrams with SOCKS5 UDP header to relay; relay routes per packet
  - Routing:
    - If selected outbound registers a UDP session factory (SS/TUIC/Hysteria2), open a per‑association session and forward both directions via that session
    - Otherwise fallback to direct UDP with per‑(client,target) NAT entries

NAT (direct fallback)
- Map key: (client_endpoint, target)
- TTL: default 60s; capacity: default 1024
- Eviction: periodic, earliest expiry first; capacity pre‑evict
- Env tuning:
  - `SOCKS_UDP_NAT_TTL_SECS` (default 60)
  - `SOCKS_UDP_NAT_CAP` (default 1024)

Supported Outbounds (UDP)
- Shadowsocks AEAD UDP
  - Uses AEAD UDP encapsulation with per‑packet salt + HKDF subkey
- TUIC
  - UDP over QUIC unidirectional streams (udp_over_stream)
- Hysteria2
  - QUIC datagrams with session id and basic bandwidth limiting hooks

Notes
- WS/H2 conflict in transport hints resolves to WS with a warning
- 0‑RTT (TUIC) field is accepted and stored; enabling early data will be evaluated with quinn behavior
- DNS outbound is exposed as type `dns` in IR (feature-gated via `adapter-dns`); use it for DNS resolution only, and keep routing rule `protocol: dns` → direct/selected outbound as the primary path

Testing
- A minimal SOCKS5 UDP → direct NAT echo test is provided: `app/tests/socks_udp_direct_e2e.rs`
- UDP session e2e (SS/TUIC/Hysteria2) rely on local servers and are planned to be expanded in follow‑ups
