//! Endpoint IR types (WireGuard, Tailscale).

use serde::{Deserialize, Serialize};

/// Endpoint type enumeration (WireGuard, Tailscale).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EndpointType {
    /// WireGuard VPN endpoint
    Wireguard,
    /// Tailscale VPN endpoint
    Tailscale,
}

/// Endpoint configuration IR.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EndpointIR {
    /// Endpoint type.
    #[serde(rename = "type")]
    pub ty: EndpointType,
    /// Unique tag identifier.
    #[serde(default)]
    pub tag: Option<String>,
    /// Network protocols supported (e.g., ["tcp", "udp"]).
    #[serde(default)]
    pub network: Option<Vec<String>>,

    // WireGuard-specific fields
    /// WireGuard: Use system WireGuard interface
    #[serde(default)]
    pub wireguard_system: Option<bool>,
    /// WireGuard: Interface name
    #[serde(default)]
    pub wireguard_name: Option<String>,
    /// WireGuard: MTU size
    #[serde(default)]
    pub wireguard_mtu: Option<u32>,
    /// WireGuard: Local addresses (CIDR format)
    #[serde(default)]
    pub wireguard_address: Option<Vec<String>>,
    /// WireGuard: Private key (base64)
    #[serde(default)]
    pub wireguard_private_key: Option<String>,
    /// WireGuard: Listen port
    #[serde(default)]
    pub wireguard_listen_port: Option<u16>,
    /// WireGuard: Peer configurations
    #[serde(default)]
    pub wireguard_peers: Option<Vec<WireGuardPeerIR>>,
    /// WireGuard: UDP timeout (e.g., "30s")
    #[serde(default)]
    pub wireguard_udp_timeout: Option<String>,
    /// WireGuard: Number of worker threads
    #[serde(default)]
    pub wireguard_workers: Option<i32>,

    // Tailscale-specific fields
    /// Tailscale: State directory path
    #[serde(default)]
    pub tailscale_state_directory: Option<String>,
    /// Tailscale: Authentication key
    #[serde(default)]
    pub tailscale_auth_key: Option<String>,
    /// Tailscale: Control server URL
    #[serde(default)]
    pub tailscale_control_url: Option<String>,
    /// Tailscale: Ephemeral mode
    #[serde(default)]
    pub tailscale_ephemeral: Option<bool>,
    /// Tailscale: Hostname
    #[serde(default)]
    pub tailscale_hostname: Option<String>,
    /// Tailscale: Accept routes from network
    #[serde(default)]
    pub tailscale_accept_routes: Option<bool>,
    /// Tailscale: Exit node address
    #[serde(default)]
    pub tailscale_exit_node: Option<String>,
    /// Tailscale: Allow LAN access when using exit node
    #[serde(default)]
    pub tailscale_exit_node_allow_lan_access: Option<bool>,
    /// Tailscale: Routes to advertise (CIDR format)
    #[serde(default)]
    pub tailscale_advertise_routes: Option<Vec<String>>,
    /// Tailscale: Advertise as exit node
    #[serde(default)]
    pub tailscale_advertise_exit_node: Option<bool>,
    /// Tailscale: UDP timeout (e.g., "30s")
    #[serde(default)]
    pub tailscale_udp_timeout: Option<String>,
}

/// WireGuard peer configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireGuardPeerIR {
    /// Peer endpoint address
    #[serde(default)]
    pub address: Option<String>,
    /// Peer endpoint port
    #[serde(default)]
    pub port: Option<u16>,
    /// Peer public key (base64)
    #[serde(default)]
    pub public_key: Option<String>,
    /// Pre-shared key (base64)
    #[serde(default)]
    pub pre_shared_key: Option<String>,
    /// Allowed IPs (CIDR format)
    #[serde(default)]
    pub allowed_ips: Option<Vec<String>>,
    /// Persistent keepalive interval (seconds)
    #[serde(default)]
    pub persistent_keepalive_interval: Option<u16>,
    /// Reserved bytes for connection ID
    #[serde(default)]
    pub reserved: Option<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn endpoint_type_serialization() {
        // Test WireGuard endpoint
        let data = json!({
            "type": "wireguard",
            "tag": "wg0",
            "wireguard_private_key": "ABCD1234",
            "wireguard_address": ["10.0.0.1/24"]
        });
        let ir: EndpointIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.ty, EndpointType::Wireguard);
        assert_eq!(ir.tag, Some("wg0".to_string()));
        assert_eq!(ir.wireguard_private_key, Some("ABCD1234".to_string()));

        let serialized = serde_json::to_value(&ir).unwrap();
        assert_eq!(serialized.get("type").unwrap(), "wireguard");
    }

    #[test]
    fn tailscale_endpoint_serialization() {
        let data = json!({
            "type": "tailscale",
            "tag": "ts0",
            "tailscale_auth_key": "tskey-xyz",
            "tailscale_hostname": "my-node"
        });
        let ir: EndpointIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.ty, EndpointType::Tailscale);
        assert_eq!(ir.tag, Some("ts0".to_string()));
        assert_eq!(ir.tailscale_auth_key, Some("tskey-xyz".to_string()));
        assert_eq!(ir.tailscale_hostname, Some("my-node".to_string()));

        let serialized = serde_json::to_value(&ir).unwrap();
        assert_eq!(serialized.get("type").unwrap(), "tailscale");
    }

    #[test]
    fn wireguard_peer_serialization() {
        let data = json!({
            "address": "192.168.1.1",
            "port": 51820,
            "public_key": "peer-pubkey",
            "allowed_ips": ["0.0.0.0/0"]
        });
        let peer: WireGuardPeerIR = serde_json::from_value(data).unwrap();
        assert_eq!(peer.address, Some("192.168.1.1".to_string()));
        assert_eq!(peer.port, Some(51820));
        assert_eq!(peer.public_key, Some("peer-pubkey".to_string()));
        assert_eq!(peer.allowed_ips, Some(vec!["0.0.0.0/0".to_string()]));
    }
}
