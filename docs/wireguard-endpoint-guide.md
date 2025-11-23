# WireGuard Endpoint Configuration Guide

## Overview

The WireGuard endpoint feature allows singbox-rust to create and manage WireGuard VPN tunnels using a userspace implementation based on Cloudflare's `boringtun` library. This provides cross-platform VPN functionality without requiring kernel modules.

## Prerequisites

### System Requirements

- **Linux**: Root privileges or `CAP_NET_ADMIN` capability
- **macOS**: Administrator access for TUN device creation
- **Windows**: Administrator access and wintun driver

### Compilation

Enable the WireGuard endpoint feature:

```toml
# Cargo.toml
[dependencies]
app = { features = ["adapters"] }
```

Or build with specific feature:

```bash
cargo build --release --features adapter-wireguard-endpoint
```

## Basic Configuration

### Minimal Example

```json
{
  "endpoints": [
    {
      "type": "wireguard",
      "tag": "wg0",
      "wireguard_name": "wg0",
      "wireguard_address": ["10.0.0.2/24"],
      "wireguard_private_key": "YOUR_PRIVATE_KEY_HERE",
      "wireguard_listen_port": 51820,
      "wireguard_peers": [
        {
          "public_key": "PEER_PUBLIC_KEY_HERE",
          "address": "203.0.113.1",
          "port": 51820,
          "allowed_ips": ["0.0.0.0/0"]
        }
      ]
    }
  ]
}
```

### Complete Example

```json
{
  "log": {
    "level": "info"
  },
  "endpoints": [
    {
      "type": "wireguard",
      "tag": "vpn-tunnel",
      "wireguard_system": false,
      "wireguard_name": "wg-singbox",
      "wireguard_mtu": 1420,
      "wireguard_address": [
        "10.66.66.2/24",
        "fd00:1234:5678::2/64"
      ],
      "wireguard_private_key": "YAnz5TF+lXXJte14tji3zlbzbm+JFHYa74LLQDzOjG0=",
      "wireguard_listen_port": 51820,
      "wireguard_udp_timeout": "5m",
      "wireguard_workers": 4,
      "wireguard_peers": [
        {
          "public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
          "pre_shared_key": "MzUwNDU3MDc2NTU5NDYzMjI4NjM4MjA1NjkxODY0MjQ=",
          "address": "vpn.example.com",
          "port": 51820,
          "allowed_ips": [
            "0.0.0.0/0",
            "::/0"
          ],
          "persistent_keepalive_interval": 25
        }
      ]
    }
  ],
  "inbounds": [
    {
      "type": "mixed",
      "tag": "mixed-in",
      "listen": "127.0.0.1",
      "listen_port": 1080
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ]
}
```

## Configuration Reference

### Endpoint Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | Must be `"wireguard"` |
| `tag` | string | Yes | Unique identifier for the endpoint |
| `wireguard_system` | boolean | No | Use system WireGuard (not yet implemented) |
| `wireguard_name` | string | No | TUN device name (e.g., "wg0") |
| `wireguard_mtu` | integer | No | MTU size (default: 1420) |
| `wireguard_address` | array[string] | Yes | CIDR addresses (IPv4 and/or IPv6) |
| `wireguard_private_key` | string | Yes | Base64-encoded private key |
| `wireguard_listen_port` | integer | No | UDP listen port (0 = random) |
| `wireguard_udp_timeout` | string | No | UDP timeout duration (e.g., "5m") |
| `wireguard_workers` | integer | No | Number of worker threads |
| `wireguard_peers` | array[peer] | Yes | List of peers (see below) |

### Peer Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `public_key` | string | Yes | Base64-encoded peer public key |
| `pre_shared_key` | string | No | Base64-encoded PSK for extra security |
| `address` | string | Yes | Peer IP or hostname |
| `port` | integer | Yes | Peer port |
| `allowed_ips` | array[string] | Yes | CIDR ranges  allowed through tunnel |
| `persistent_keepalive_interval` | integer | No | Keepalive interval in seconds |

## Key Generation

Generate WireGuard keys using the standard `wg` command:

```bash
# Generate private key
wg genkey

# Generate public key from private key
echo "YOUR_PRIVATE_KEY" | wg pubkey

# Generate pre-shared key (optional)
wg genpsk
```

Or use online tools (for testing only):
- https://www.wireguardconfig.com/

## Common Configurations

### 1. Point-to-Point VPN

Connect two machines securely:

**Server (203.0.113.1)**:
```json
{
  "endpoints": [{
    "type": "wireguard",
    "tag": "wg-server",
    "wireguard_address": ["10.0.0.1/24"],
    "wireguard_private_key": "SERVER_PRIVATE_KEY",
    "wireguard_listen_port": 51820,
    "wireguard_peers": [{
      "public_key": "CLIENT_PUBLIC_KEY",
      "allowed_ips": ["10.0.0.2/32"],
      "persistent_keepalive_interval": 25
    }]
  }]
}
```

**Client**:
```json
{
  "endpoints": [{
    "type": "wireguard",
    "tag": "wg-client",
    "wireguard_address": ["10.0.0.2/24"],
    "wireguard_private_key": "CLIENT_PRIVATE_KEY",
    "wireguard_listen_port": 0,
    "wireguard_peers": [{
      "public_key": "SERVER_PUBLIC_KEY",
      "address": "203.0.113.1",
      "port": 51820,
      "allowed_ips": ["10.0.0.1/32"],
      "persistent_keepalive_interval": 25
    }]
  }]
}
```

### 2. Full Tunnel VPN (All Traffic)

Route all traffic through VPN:

```json
{
  "endpoints": [{
    "type": "wireguard",
    "tag": "wg-full",
    "wireguard_address": ["10.8.0.2/24"],
    "wireguard_private_key": "YOUR_PRIVATE_KEY",
    "wireguard_peers": [{
      "public_key": "VPN_SERVER_PUBLIC_KEY",
      "address": "vpn.example.com",
      "port": 51820,
      "allowed_ips": ["0.0.0.0/0", "::/0"],
      "persistent_keepalive_interval": 25
    }]
  }]
}
```

### 3. Split Tunnel (Specific Routes)

Route only specific traffic through VPN:

```json
{
  "endpoints": [{
    "type": "wireguard",
    "tag": "wg-split",
    "wireguard_address": ["10.8.0.2/24"],
    "wireguard_private_key": "YOUR_PRIVATE_KEY",
    "wireguard_peers": [{
      "public_key": "VPN_SERVER_PUBLIC_KEY",
      "address": "vpn.example.com",
      "port": 51820,
      "allowed_ips": [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16"
      ],
      "persistent_keepalive_interval": 25
    }]
  }]
}
```

### 4. Dual-Stack (IPv4 + IPv6)

```json
{
  "endpoints": [{
    "type": "wireguard",
    "tag": "wg-dualstack",
    "wireguard_address": [
      "10.0.0.2/24",
      "fd00:1234:5678::2/64"
    ],
    "wireguard_private_key": "YOUR_PRIVATE_KEY",
    "wireguard_peers": [{
      "public_key": "PEER_PUBLIC_KEY",
      "address": "2001:db8::1",
      "port": 51820,
      "allowed_ips": ["0.0.0.0/0", "::/0"],
      "persistent_keepalive_interval": 25
    }]
  }]
}
```

### 5. With Pre-Shared Key (Enhanced Security)

```json
{
  "endpoints": [{
    "type": "wireguard",
    "tag": "wg-psk",
    "wireguard_address": ["10.0.0.2/24"],
    "wireguard_private_key": "YOUR_PRIVATE_KEY",
    "wireguard_peers": [{
      "public_key": "PEER_PUBLIC_KEY",
      "pre_shared_key": "YOUR_PSK_HERE",
      "address": "vpn.example.com",
      "port": 51820,
      "allowed_ips": ["0.0.0.0/0"],
      "persistent_keepalive_interval": 25
    }]
  }]
}
```

### 6. Low MTU for PPPoE Connections

```json
{
  "endpoints": [{
    "type": "wireguard",
    "tag": "wg-low-mtu",
    "wireguard_mtu": 1380,
    "wireguard_address": ["10.0.0.2/24"],
    "wireguard_private_key": "YOUR_PRIVATE_KEY",
    "wireguard_peers": [{
      "public_key": "PEER_PUBLIC_KEY",
      "address": "vpn.example.com",
      "port": 51820,
      "allowed_ips": ["0.0.0.0/0"]
    }]
  }]
}
```

## Usage

### Starting the Endpoint

```bash
# Run with configuration file
./singbox-rust run -c config.json

# With specific log level
./singbox-rust run -c config.json --log-level debug
```

### Verifying Connection

```bash
# Check if TUN device is created (Linux/macOS)
ip addr show wg0
# or
ifconfig wg0

# Test connectivity through tunnel
ping 10.0.0.1

# Check routing table
ip route show
# or
netstat -rn
```

### Monitoring

Watch logs for WireGuard activity:

```bash
# In the singbox-rust output
[INFO] Starting WireGuard userspace endpoint: wg0
[INFO] Created TUN device
[INFO] WireGuard listening on 0.0.0.0:51820
```

## Troubleshooting

### Common Issues

#### 1. Permission Denied on TUN Device

**Error**: `Failed to create TUN device: Permission denied`

**Solution**:
```bash
# Linux: Run with sudo
sudo ./singbox-rust run -c config.json

# Or set capabilities (Linux only)
sudo setcap cap_net_admin+eip singbox-rust
./singbox-rust run -c config.json
```

#### 2. Invalid Private Key

**Error**: `Invalid private key base64` or `Invalid private key length`

**Solution**:
- Ensure key is exactly 44 characters (32 bytes base64-encoded)
- Verify no extra whitespace or newlines
- Use `wg genkey` to generate valid key

#### 3. Peer Connection Fails

**Symptoms**: No traffic flowing, timeout errors

**Debug steps**:
1. Verify peer public key matches
2. Check firewall allows UDP on specified port
3. Verify `allowed_ips` includes destination
4. Enable persistent keepalive for NAT traversal
5. Check network connectivity to peer address

#### 4. DNS Resolution Issues

**Solution**: Add DNS configuration:

```json
{
  "dns": {
    "servers": [
      {
        "address": "1.1.1.1",
        "tag": "cloudflare"
      }
    ]
  }
}
```

#### 5. MTU Issues

**Symptoms**: Some websites load partially or not at all

**Solution**: Lower MTU (try 1380, 1360, or 1280):

```json
{
  "wireguard_mtu": 1380
}
```

## Performance Tuning

### Optimal Settings

```json
{
  "endpoints": [{
    "wireguard_mtu": 1420,
    "wireguard_workers": 4,
    "wireguard_udp_timeout": "5m",
    "wireguard_peers": [{
      "persistent_keepalive_interval": 25
    }]
  }]
}
```

### High-Throughput Scenarios

- Increase `wireguard_workers` (4-8 recommended)
- Use wired connection for peer
- Consider kernel WireGuard for production (when available)

### Low-Power/Mobile Scenarios

- Reduce `wireguard_workers` (1-2)
- Increase `persistent_keepalive_interval` (30-60s) to save battery
- Use lower MTU if on cellular connection

## Security Best Practices

1. **Use Strong Keys**: Always generate keys securely with `wg genkey`
2. **Enable PSK**: Add pre-shared key for quantum-resistant security
3. **Restrict allowed_ips**: Only allow necessary IP ranges
4. **Rotate Keys**: Periodically generate new keys
5. **Secure Storage**: Protect private keys in configuration files
6. **Use Firewall**: Limit WireGuard port access

## Limitations

### Current Implementation

- **Single Peer MVP**: Only the first configured peer is active
  - Multi-peer support planned for future release
- **Userspace Only**: No kernel WireGuard integration yet
  - ~20-30% lower throughput vs kernel module
  - Higher CPU usage
- **Requires Privileges**: Must run as root or with capabilities
- **No NAT Traversal**: Relies on peer having public endpoint
  - Use `persistent_keepalive_interval` for NAT hole-punching

### Platform Support

| Platform | Status | Notes |
|----------|--------|-------|
| Linux | ✅ Full | Requires CAP_NET_ADMIN |
| macOS | ✅ Full | Requires admin access |
| Windows | ✅ Full | Requires admin + wintun |
| Android | ⚠️ Partial | Needs VPN service integration |
| iOS | ⚠️ Partial | Needs Network Extension |

## Migration from Standard WireGuard

To migrate from standard WireGuard:

1. Export configuration:
```bash
wg showconf wg0 > wg0.conf
```

2. Convert to singbox-rust format:
```bash
# Use the keys and peer info from wg0.conf
# Map to JSON structure shown in examples
```

3. Stop standard WireGuard:
```bash
sudo wg-quick down wg0
```

4. Start singbox-rust endpoint:
```bash
sudo ./singbox-rust run -c config.json
```

## Future Enhancements

Planned features:
- [ ] Multi-peer support with routing table
- [ ] Kernel WireGuard integration
- [ ] STUN/TURN NAT traversal
- [ ] Dynamic peer discovery
- [ ] Metrics and observability
- [ ] Configuration hot-reload

## References

- [WireGuard Protocol](https://www.wireguard.com/)
- [Cloudflare boringtun](https://github.com/cloudflare/boringtun)
- [singbox-rust Documentation](../README.md)
- [WireGuard Configuration Guide](https://www.wireguard.com/quickstart/)

## Support

For issues or questions:
- Check [Troubleshooting](#troubleshooting) section
- Review test files for configuration examples
- Open an issue on GitHub
