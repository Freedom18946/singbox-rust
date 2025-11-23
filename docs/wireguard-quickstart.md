# WireGuard Endpoint Quick Start

Get up and running with WireGuard endpoint in 5 minutes!

## Step 1: Generate Keys

```bash
# Generate your private key
export PRIVATE_KEY=$(wg genkey)
echo "Your private key: $PRIVATE_KEY"

# Generate your public key
export PUBLIC_KEY=$(echo $PRIVATE_KEY | wg pubkey)
echo "Your public key: $PUBLIC_KEY"

# (Optional) Generate a pre-shared key for extra security
export PSK=$(wg genpsk)
echo "Your PSK: $PSK"
```

## Step 2: Get Peer Information

You need from your VPN provider or peer:
- Peer's public key
- Peer's endpoint address (IP or hostname)
- Peer's port (usually 51820)
- Your assigned IP address in the VPN network

Example values (replace with real ones):
```
Peer Public Key: bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
Peer Address: vpn.example.com
Peer Port: 51820
Your VPN IP: 10.0.0.2/24
```

## Step 3: Create Configuration

Create `config.json`:

```json
{
  "log": {
    "level": "info"
  },
  "endpoints": [
    {
      "type": "wireguard",
      "tag": "wg0",
      "wireguard_name": "wg0",
      "wireguard_address": ["10.0.0.2/24"],
      "wireguard_private_key": "YOUR_PRIVATE_KEY_HERE",
      "wireguard_listen_port": 0,
      "wireguard_peers": [
        {
          "public_key": "PEER_PUBLIC_KEY_HERE",
          "address": "vpn.example.com",
          "port": 51820,
          "allowed_ips": ["0.0.0.0/0"],
          "persistent_keepalive_interval": 25
        }
      ]
    }
  ],
  "inbounds": [
    {
      "type": "mixed",
      "tag": "proxy",
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

Replace placeholders:
- `YOUR_PRIVATE_KEY_HERE`: Your generated private key
- `PEER_PUBLIC_KEY_HERE`: Peer's public key
- `vpn.example.com`: Peer's address
- `10.0.0.2/24`: Your assigned VPN IP

## Step 4: Build with WireGuard Support

```bash
cd singbox-rust
cargo build --release --features adapters
```

## Step 5: Run

```bash
# Linux/macOS: Requires root/sudo
sudo ./target/release/app run -c config.json

# Or set capabilities (Linux only)
sudo setcap cap_net_admin+eip ./target/release/app
./target/release/app run -c config.json
```

## Step 6: Verify

In another terminal:

```bash
# Check TUN device created
ip addr show wg0

# Test VPN connectivity
ping 10.0.0.1

# Check your public IP (should show VPN server's IP)
curl ifconfig.me
```

## Step 7: Use the Proxy

Configure your applications to use the SOCKS5/HTTP proxy:

- **SOCKS5**: `127.0.0.1:1080`
- **HTTP**: `127.0.0.1:1080` (mixed mode supports both)

Example with curl:
```bash
curl --proxy socks5://127.0.0.1:1080 https://ifconfig.me
```

## Common Quick Fixes

### Can't Create TUN Device

```bash
# Run with sudo
sudo ./target/release/app run -c config.json
```

### No Connection to Peer

1. Check peer address is reachable:
   ```bash
   ping vpn.example.com
   ```

2. Check firewall allows UDP:
   ```bash
   # Linux
   sudo ufw allow 51820/udp
   ```

3. Verify keys are correct (no spaces, 44 characters)

### Slow Connection

Lower MTU in config:
```json
{
  "wireguard_mtu": 1380
}
```

## Next Steps

- Read the [full configuration guide](wireguard-endpoint-guide.md)
- Check [example configurations](../examples/)
- Enable logging: `"log": {"level": "debug"}`
- Add routing rules for split tunneling

## Getting Help

If you encounter issues:

1. Check logs for error messages
2. Verify all configuration values
3. Test with minimal configuration first
4. Review [troubleshooting guide](wireguard-endpoint-guide.md#troubleshooting)

## Security Reminder

🔒 **Protect your private key!**
- Never share your private key
- Use file permissions: `chmod 600 config.json`
- Consider using a secrets manager for production

---

**Success!** You now have a working WireGuard VPN tunnel through singbox-rust! 🎉
