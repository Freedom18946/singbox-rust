# TLS Configuration

Configure TLS (Transport Layer Security) for secure, encrypted connections.

---

## Overview

singbox-rust supports multiple TLS modes:

1. **Standard TLS** - Production-ready TLS 1.2/1.3 using rustls
2. **REALITY** - Anti-censorship protocol that disguises as legitimate TLS
3. **ECH** - Encrypted Client Hello for enhanced SNI privacy

Most proxy protocols (Trojan, VMess, VLESS, Shadowsocks) can use TLS for encryption and anti-detection.

---

## Basic TLS Configuration

### Standard TLS

Used with protocols like Trojan, VMess over TLS, VLESS over TLS:

```yaml
outbounds:
  - type: trojan
    tag: trojan-out
    server: trojan.example.com
    port: 443
    password: your-password

    # TLS configuration
    tls:
      enabled: true
      sni: trojan.example.com # Server Name Indication
      alpn: [h2, http/1.1] # Application-Layer Protocol Negotiation
      skip_cert_verify: false # Certificate verification (DO NOT disable in production!)
```

**Key fields**:

- `enabled`: Enable TLS (required for Trojan, optional for VMess/VLESS)
- `sni`: Server Name Indication - must match server certificate
- `alpn`: Protocol negotiation (e.g., HTTP/2, HTTP/1.1)
- `skip_cert_verify`: Skip certificate validation (TESTING ONLY!)

### TLS for VMess

```yaml
outbounds:
  - type: vmess
    tag: vmess-tls
    server: vmess.example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000

    tls:
      enabled: true
      sni: vmess.example.com
```

### TLS for Shadowsocks

```yaml
outbounds:
  - type: shadowsocks
    tag: ss-tls
    server: ss.example.com
    port: 443
    method: aes-256-gcm
    password: your-password

    # Optional TLS layer
    tls:
      enabled: true
      sni: ss.example.com
```

---

## REALITY Protocol

[REALITY](../protocols/reality.md) is an anti-censorship protocol that makes proxy traffic indistinguishable from legitimate TLS connections.

### How REALITY Works

1. **Camouflage**: Traffic appears as connections to legitimate sites (e.g., microsoft.com)
2. **Authentication**: Client proves identity using X25519 key exchange
3. **Fallback**: Failed auth connects to real target site (undetectable probing)

### REALITY Client Configuration

```yaml
outbounds:
  - type: vless
    tag: vless-reality
    server: reality.example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000

    tls:
      enabled: true
      reality:
        enabled: true
        public_key: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        short_id: "0123456789abcdef"
      sni: www.microsoft.com # Target site for camouflage
```

**Required fields**:

- `public_key`: Server's X25519 public key (64 hex characters)
- `short_id`: Authentication identifier (0-16 hex characters)
- `sni`: Target domain that server will imitate

### Generate REALITY Keypair

```bash
singbox-rust generate reality-keypair
```

**Output**:

```json
{
  "private_key": "xxxxxxxx...",
  "public_key": "yyyyyyyy..."
}
```

- Use `private_key` on server
- Use `public_key` on client

### REALITY Server Configuration

```yaml
inbounds:
  - type: vless
    tag: vless-reality-in
    listen: 0.0.0.0
    port: 443
    users:
      - uuid: 00000000-0000-0000-0000-000000000000
        name: user1

    tls:
      enabled: true
      reality:
        enabled: true
        private_key: "your-private-key-hex"
        short_ids: ["0123456789abcdef", "fedcba9876543210"]
        fallback_server: "www.microsoft.com"
        fallback_port: 443
      sni: www.microsoft.com
```

**Security considerations**:

- **Never share `private_key`** - Only share `public_key` with clients
- **Use real target domains** - Choose stable, popular sites
- **Multiple `short_ids`** - Allow different auth identifiers

See [REALITY Protocol Guide](../protocols/reality.md) for details.

---

## ECH (Encrypted Client Hello)

[ECH](../protocols/ech.md) encrypts the SNI (Server Name Indication) in TLS ClientHello, preventing observers from seeing which domain you're connecting to.

### ECH Client Configuration

```yaml
outbounds:
  - type: trojan
    tag: trojan-ech
    server: trojan.example.com
    port: 443
    password: your-password

    tls:
      enabled: true
      ech:
        enabled: true
        config: "base64-encoded-ech-config" # From server
      sni: trojan.example.com
```

### Generate ECH Config

On server:

```bash
singbox-rust generate ech-keypair
```

**Output**:

```json
{
  "private_key": "...",
  "config": "base64-encoded-config"
}
```

- Server uses `private_key`
- Clients use `config` (base64-encoded ECHConfigList)

See [ECH Protocol Guide](../protocols/ech.md) for details.

---

## Advanced TLS Settings

### Custom CA Certificates

Use custom Certificate Authority for certificate validation:

```yaml
outbounds:
  - type: trojan
    tag: trojan-custom-ca
    server: trojan.example.com
    port: 443
    password: your-password

    tls:
      enabled: true
      sni: trojan.example.com
      ca_cert: /path/to/ca.crt # Custom CA certificate
```

### Client Certificate Authentication

Some servers require client certificates:

```yaml
outbounds:
  - type: trojan
    tag: trojan-mtls
    server: trojan.example.com
    port: 443
    password: your-password

    tls:
      enabled: true
      sni: trojan.example.com
      client_cert: /path/to/client.crt
      client_key: /path/to/client.key
```

### ALPN Negotiation

Specify application protocols:

```yaml
outbounds:
  - type: trojan
    tag: trojan-h2
    server: trojan.example.com
    port: 443
    password: your-password

    tls:
      enabled: true
      sni: trojan.example.com
      alpn: [h2] # Force HTTP/2

  - type: trojan
    tag: trojan-http11
    server: trojan.example.com
    port: 443
    password: your-password

    tls:
      enabled: true
      sni: trojan.example.com
      alpn: [http/1.1] # Force HTTP/1.1
```

**Common ALPN values**:

- `h2` - HTTP/2
- `http/1.1` - HTTP/1.1
- `h3` - HTTP/3 (QUIC)

---

## TLS with Transport Layers

Combine TLS with WebSocket, HTTP/2, gRPC:

### TLS + WebSocket

```yaml
outbounds:
  - type: vmess
    tag: vmess-tls-ws
    server: vmess.example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000

    # TLS first
    tls:
      enabled: true
      sni: vmess.example.com

    # Then WebSocket
    transport:
      type: ws
      path: /vmess
      headers:
        Host: vmess.example.com
```

### TLS + HTTP/2

```yaml
outbounds:
  - type: vmess
    tag: vmess-tls-h2
    server: vmess.example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000

    tls:
      enabled: true
      sni: vmess.example.com
      alpn: [h2] # Required for HTTP/2

    transport:
      type: h2
      path: /vmess
```

### TLS + gRPC

```yaml
outbounds:
  - type: vmess
    tag: vmess-tls-grpc
    server: vmess.example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000

    tls:
      enabled: true
      sni: vmess.example.com
      alpn: [h2] # gRPC requires HTTP/2

    transport:
      type: grpc
      service_name: VMessService
```

See [Transport Configuration](../features/transports.md) for details.

---

## Validation and Testing

### Validate TLS Configuration

```bash
singbox-rust check -c config.yaml
```

### Test TLS Handshake

Enable debug logging to see TLS handshake details:

```bash
RUST_LOG=sb_tls=debug singbox-rust run -c config.yaml
```

**Expected logs**:

```
[DEBUG sb_tls] TLS handshake started: sni=example.com
[DEBUG sb_tls] ALPN selected: h2
[INFO sb_tls] TLS handshake successful
```

### Verify Certificate

```bash
# Check server certificate
openssl s_client -connect trojan.example.com:443 -servername trojan.example.com

# Verify certificate dates
openssl s_client -connect trojan.example.com:443 -servername trojan.example.com 2>/dev/null | openssl x509 -noout -dates
```

---

## Troubleshooting

### Certificate Verification Failed

**Symptoms**:

```
[ERROR] TLS handshake failed: certificate verify failed
```

**Solutions**:

1. **Check SNI**: Ensure `sni` matches server certificate CN/SAN
2. **System time**: TLS requires accurate clock (±5 minutes)
3. **CA certificates**: Update system root certificates:

   ```bash
   # macOS
   brew install ca-certificates

   # Linux (Debian/Ubuntu)
   sudo apt-get update && sudo apt-get install ca-certificates
   ```

4. **Custom CA**: Use `ca_cert` if server uses self-signed cert
5. **Testing only**: Use `skip_cert_verify: true` (INSECURE!)

### ALPN Negotiation Failed

**Symptoms**:

```
[ERROR] ALPN protocol not negotiated
```

**Solutions**:

1. Server must support requested ALPN protocols
2. Try different ALPN values: `[h2, http/1.1]`
3. Some protocols require specific ALPN (gRPC needs `h2`)

### REALITY Authentication Failed

**Symptoms**:

```
[ERROR] REALITY auth failed
```

**Solutions**:

1. **Verify `public_key`**: Must match server's `private_key`
2. **Check `short_id`**: Must be in server's `short_ids` list
3. **SNI mismatch**: `sni` must match server config
4. **Generate new keypair**:
   ```bash
   singbox-rust generate reality-keypair
   ```

### ECH Config Invalid

**Symptoms**:

```
[ERROR] ECH config parse failed
```

**Solutions**:

1. Ensure `config` is valid base64
2. Regenerate ECH config on server
3. Check config expiration (some ECH configs have TTL)

### Connection Slow with TLS

**Possible causes**:

1. **TLS handshake overhead**: ~1-2 RTT for initial connection
2. **Certificate validation**: First connection may be slower
3. **ALPN negotiation**: Try different protocols

**Optimizations**:

- Use TLS session resumption (automatic)
- Enable connection pooling ([Multiplex](../features/multiplex.md))
- Use QUIC-based protocols (Hysteria, TUIC) for better handshake

---

## Security Best Practices

### ✅ DO

1. **Always verify certificates in production**

   ```yaml
   tls:
     skip_cert_verify: false # Default, but be explicit
   ```

2. **Use strong ciphers** (automatic with rustls)

   - TLS 1.2 minimum (1.3 preferred)
   - Modern cipher suites only

3. **Keep certificates updated**

   - Monitor expiration dates
   - Automate renewal (Let's Encrypt)

4. **Use REALITY for censorship resistance**

   - Choose stable, popular target domains
   - Rotate `short_ids` periodically

5. **Protect private keys**
   - Never commit keys to version control
   - Use environment variables or secure vaults

### ❌ DON'T

1. **Don't skip certificate verification** unless testing

   ```yaml
   # INSECURE - Only for local testing!
   tls:
     skip_cert_verify: true
   ```

2. **Don't reuse REALITY keys** across environments

   - Generate separate keys for each server

3. **Don't use weak SNI** for REALITY

   - Avoid: `example.com`, `test.com`
   - Prefer: `www.microsoft.com`, `www.apple.com`

4. **Don't ignore TLS errors** in logs
   - Certificate errors indicate MITM attacks or misconfiguration

---

## Configuration Examples

### Complete Example: Multi-Protocol with TLS

```yaml
schema_version: 2

inbounds:
  - type: socks
    tag: socks-in
    listen: 127.0.0.1
    port: 1080

outbounds:
  # Direct
  - type: direct
    tag: direct

  # Trojan with standard TLS
  - type: trojan
    tag: trojan-std
    server: trojan.example.com
    port: 443
    password: trojan-pass
    tls:
      enabled: true
      sni: trojan.example.com

  # VLESS with REALITY
  - type: vless
    tag: vless-reality
    server: reality.example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
    tls:
      enabled: true
      reality:
        enabled: true
        public_key: "your-public-key"
        short_id: "0123456789abcdef"
      sni: www.microsoft.com

  # VMess with TLS + WebSocket
  - type: vmess
    tag: vmess-tls-ws
    server: vmess.example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
    tls:
      enabled: true
      sni: vmess.example.com
      alpn: [http/1.1]
    transport:
      type: ws
      path: /vmess

route:
  rules:
    - domain: [trojan.example.com]
      outbound: trojan-std
    - domain: [reality.example.com]
      outbound: vless-reality
    - domain_suffix: [google.com, youtube.com]
      outbound: vmess-tls-ws
  default: direct
```

---

## Related Documentation

- **[REALITY Protocol](../protocols/reality.md)** - Detailed REALITY guide
- **[ECH Protocol](../protocols/ech.md)** - ECH configuration and usage
- **[Transport Layers](../features/transports.md)** - WebSocket, HTTP/2, gRPC
- **[Developer: TLS Infrastructure](../../04-development/architecture/tls-infrastructure.md)** - Technical implementation details

---

**See Also**:

- [Trojan Protocol](../protocols/trojan.md)
- [VMess Protocol](../protocols/vmess.md)
- [VLESS Protocol](../protocols/vless.md)
- [Troubleshooting Guide](../troubleshooting.md)
