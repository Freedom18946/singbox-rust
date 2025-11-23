# DERP Service - Usage Guide

## Overview

DERP (Designated Encrypted Relay for Packets) is a server-to-server mesh relay service, similar to Tailscale's DERP infrastructure. It provides NAT traversal and packet relay functionality for clients that cannot establish direct connections.

## Features

✅ **Complete mesh networking** - Automatic cross-server packet forwarding  
✅ **TLS support** - Optional TLS termination with rustls  
✅ **PSK authentication** - Mesh peer authentication via pre-shared keys  
✅ **Rate limiting** - Per-IP sliding window rate limiter (120 conn/10sec)  
✅ **Comprehensive metrics** - Connections, packets, bytes, lifetimes, STUN, HTTP  
✅ **STUN server** - Built-in STUN for connectivity checks  
✅ **HTTP health endpoint** - `/` and `/health` for monitoring  

## Quick Start

### Single Server (Standalone)

```json
{
  "services": [{
    "type": "derp",
    "tag": "derp-standalone",
    "derp_listen": "0.0.0.0",
    "derp_listen_port": 3478,
    "derp_stun_enabled": true
  }]
}
```

### Mesh Network (2+ Servers)

**Server A** (Region: US-East):
```json
{
  "services": [{
    "type": "derp",
    "tag": "derp-us-east",
    "derp_listen": "0.0.0.0",
    "derp_listen_port": 3478,
    "derp_mesh_psk": "your-secret-mesh-key",
    "derp_stun_enabled": true
  }]
}
```

**Server B** (Region: EU-West):
```json
{
  "services": [{
    "type": "derp",
    "tag": "derp-eu-west",
    "derp_listen": "0.0.0.0",
    "derp_listen_port": 3478,
    "derp_mesh_psk": "your-secret-mesh-key",
    "derp_mesh_with": ["us-east.example.com:3478"],
    "derp_stun_enabled": true
  }]
}
```

### With TLS

```json
{
  "services": [{
    "type": "derp",
    "tag": "derp-tls",
    "derp_listen": "0.0.0.0",
    "derp_listen_port": 443,
    "derp_tls_cert_path": "/etc/certs/derp.crt",
    "derp_tls_key_path": "/etc/certs/derp.key",
    "derp_mesh_psk": "your-secret-mesh-key",
    "derp_stun_enabled": true
  }]
}
```

## Configuration Reference

### Basic Options

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `derp_listen` | string | `"127.0.0.1"` | Listen address |
| `derp_listen_port` | integer | `3478` | Listen port |
| `derp_stun_enabled` | boolean | `true` | Enable STUN server |
| `derp_stun_listen_port` | integer | `derp_listen_port` | STUN port (usually same as DERP) |

### Mesh Networking

| Field | Type | Description |
|-------|------|-------------|
| `derp_mesh_psk` | string | Pre-shared key for mesh authentication |
| `derp_mesh_with` | array[string] | List of peer server addresses (e.g., `["peer1.example.com:3478"]`) |

### TLS Options

| Field | Type | Description |
|-------|------|-------------|
| `derp_tls_cert_path` | string | Path to TLS certificate file |
| `derp_tls_key_path` | string | Path to TLS private key file |

### Advanced Options

| Field | Type | Description |
|-------|------|-------------|
| `derp_server_key_path` | string | Path to persistent server key (auto-generated if not provided) |

## How It Works

### Client Connection Flow

1. **Client connects** to DERP server via TCP
2. **ServerKey frame** sent to client
3. **ClientInfo frame** sent by client (registration)
4. **Peer presence** broadcast to other clients
5. **SendPacket/RecvPacket** frames relay data between clients

### Mesh Forwarding

When Client A (on Server A) sends to Client B (on Server B):

1. Client A → Server A: `SendPacket(dst=ClientB, data=...)`
2. Server A checks local registry (Client B not found)
3. Server A checks remote registry (Client B on Server B)
4. Server A → Server B: `ForwardPacket(src=ClientA, dst=ClientB, data=...)`
5. Server B → Client B: `RecvPacket(src=ClientA, data=...)`

## Metrics

DERP exposes Prometheus metrics:

```
sb_derp_connection_total{tag, result}     # Connections (ok/rate_limited/unauthorized)
sb_derp_clients{tag}                       # Active clients
sb_derp_relay_total{tag, result, bytes}    # Packets relayed
sb_derp_client_lifetime_seconds{tag}       # Client connection duration
sb_derp_stun_total{tag, result}           # STUN requests
sb_derp_http_total{tag, code}             # HTTP requests
```

## Monitoring

### Health Check

```bash
curl http://localhost:3478/health
# Returns: 200 OK
```

### Metrics Endpoint

```bash
curl http://localhost:3478/metrics
# Or use separate metrics port if configured
```

### Logs

Enable debug logging for DERP:

```bash
RUST_LOG=sb_core::services::derp=debug cargo run -p app -- run config.json
```

## Testing

### Unit Tests

```bash
# Protocol tests (12 tests)
cargo test --package sb-core --lib services::derp::protocol::tests --features service_derp

# Client registry tests (7 tests)
cargo test --package sb-core --lib services::derp::client_registry::tests --features service_derp
```

### Mesh E2E Test

```bash
cargo test --package sb-core --lib services::derp::mesh_test --features service_derp
```

## Production Tips

1. **Use TLS** in production for security
2. **Set strong PSK** for mesh networking (32+ random characters)
3. **Monitor metrics** for connection failures and rate limiting
4. **Enable health checks** in your load balancer
5. **Use persistent server keys** (`derp_server_key_path`) for stable client reconnections
6. **Rate limits** protect against DoS (current: 120 conn/10sec per IP)

## Comparison with Tailscale DERP

| Feature | singbox-rust DERP | Tailscale DERP |
|---------|-------------------|----------------|
| Mesh networking | ✅ Complete | ✅ |
| TLS support | ✅ rustls | ✅ |
| STUN server | ✅ | ✅ |
| HTTP fallback | ✅ | ✅ |
| PSK auth | ✅ | ✅ (mesh) |
| Rate limiting | ✅ (per-IP) | ✅ |
| Metrics | ✅ Prometheus | ✅ |
| ACLs | ⚠️ PSK only | ✅ Advanced |

## Implementation Details

- **Protocol**: Frame-based binary protocol (10 frame types)
- **Transport**: TCP with optional TLS (rustls)
- **Mesh**: HTTP upgrade handshake with PSK validation
- **Rate limiting**: Sliding window per IP (configurable)
- **Tests**: 21 total (protocol 12, client_registry 7, server 8, mesh 1)

## References

- Protocol implementation: `crates/sb-core/src/services/derp/protocol.rs` (732 lines)
- Client registry: `crates/sb-core/src/services/derp/client_registry.rs` (636 lines)
- Server: `crates/sb-core/src/services/derp/server.rs` (2207 lines)
- Mesh E2E test: `crates/sb-core/src/services/derp/mesh_test.rs`

## Troubleshooting

**Mesh nodes not connecting:**
- Verify `derp_mesh_psk` matches on both servers
- Check firewall allows TCP connections on mesh ports
- Review logs: `RUST_LOG=sb_core::services::derp=debug`

**Clients getting rate limited:**
- Increase rate limit (currently hardcoded: 120/10sec)
- Check `sb_derp_connection_total{result="rate_limited"}` metric

**Packets not relaying:**
- Verify both clients are registered (`sb_derp_clients` metric)
- Check `sb_derp_relay_total{result="dst_missing"}` for routing failures
- Ensure mesh peers are connected (look for "Mesh peer registered" logs)
