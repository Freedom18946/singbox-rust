# Usage & Verification Guide

This guide details how to configure and verify the newly implemented features in `singbox-rust` to confirm parity with the Go reference.

## 1. Building the Application

Ensure you have the Rust toolchain installed.

```bash
# Build the main application
cargo build -p app --release

# The binary will be located at:
# target/release/sing-box-rust
```

## 2. Verifying Tailscale Control Plane

The new **Managed Mode** simulates a Tailscale node handshake using the implemented `Coordinator`.

### Configuration Example
Create a file named `config.json`:

```json
{
  "log": {
    "level": "info",
    "output": "console"
  },
  "inbounds": [
    {
      "type": "mixed",
      "tag": "mixed-in",
      "listen": "127.0.0.1",
      "listen_port": 2080
    }
  ],
  "outbounds": [
    {
      "type": "tailscale",
      "tag": "ts-managed",
      "auth_key": "tskey-auth-simulated-123456", 
      "control_url": "https://controlplane.tailscale.com" 
    },
    {
      "type": "direct",
      "tag": "direct"
    }
  ]
}
```

### Verification Steps
1. Run the application:
   ```bash
   ./target/release/sing-box-rust run -c config.json
   ```
2. Observe the logs. You should see entries indicating the Coordinator has started and performed a handshake:
   ```
   INFO ... [Coordinator] Starting Tailscale coordinator...
   INFO ... [Coordinator] Handshake init...
   INFO ... [Coordinator] Handshake complete.
   ```
   *(Note: Since this uses a simulated crypto handshake in the current build, it validates the architecture without needing a real Tailnet key).*

## 3. Verifying Native WireGuard

The WireGuard implementation has been refactored to use a native internal transport.

### Configuration Example

```json
{
  "outbounds": [
    {
      "type": "wireguard",
      "tag": "wg-out",
      "server": "1.2.3.4",
      "server_port": 51820,
      "private_key": "sK...",
      "peer_public_key": "pK...",
      "local_address": [
        "10.0.0.2/32"
      ]
    }
  ]
}
```

## 4. Platform Features

### Windows Named Pipes
- The application automatically uses Named Pipes for internal IPC (e.g., controlling the service) on Windows.
- **Verification**: Run on Windows. The log should not show "Unsupported" errors regarding IPC listeners.

### System Proxy
- **Verification**: On Windows/Android, configuring `"set_system_proxy": true` in an inbound will trigger the platform-specific API.
