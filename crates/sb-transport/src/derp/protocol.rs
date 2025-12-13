//! DERP protocol wire format implementation.
//!
//! This module implements the binary protocol used for DERP (Designated Encrypted Relay for Packets).
//! The protocol uses length-prefixed frames where each frame starts with a frame type byte
//! followed by frame-specific data.
//!
//! Protocol v2 aligned with Tailscale DERP specification.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Client info payload (JSON encoded inside encrypted_info).
/// This is the decrypted content of the ClientInfo encrypted blob.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientInfoPayload {
    /// Client version string (e.g., "singbox-rust 0.1.0").
    pub version: String,
    /// Mesh key for mesh peer authorization.
    /// Only set if client is requesting to join mesh network.
    /// Must match server's configured mesh key to be treated as mesh peer.
    pub mesh_key: Option<[u8; 32]>,
}

impl ClientInfoPayload {
    /// Create a new client info payload.
    pub fn new(version: impl Into<String>) -> Self {
        Self {
            version: version.into(),
            mesh_key: None,
        }
    }

    /// Set mesh key for mesh peer authentication.
    pub fn with_mesh_key(mut self, key: [u8; 32]) -> Self {
        self.mesh_key = Some(key);
        self
    }

    /// Encode payload to JSON bytes (plaintext, for use before encryption).
    pub fn to_json(&self) -> Vec<u8> {
        // Simple JSON encoding without serde dependency
        let mesh_key_str = self.mesh_key.map(|k| {
            // Inline hex encoding
            const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
            let mut s = String::with_capacity(64);
            for byte in k {
                s.push(HEX_CHARS[(byte >> 4) as usize] as char);
                s.push(HEX_CHARS[(byte & 0xf) as usize] as char);
            }
            s
        });
        let json = if let Some(mk) = mesh_key_str {
            format!(r#"{{"version":"{}","meshKey":"{}"}}"#, self.version, mk)
        } else {
            format!(r#"{{"version":"{}"}}"#, self.version)
        };
        json.into_bytes()
    }

    /// Decode payload from JSON bytes.
    pub fn from_json(data: &[u8]) -> Result<Self, ProtocolError> {
        let s = std::str::from_utf8(data)
            .map_err(|_| ProtocolError::InvalidClientInfo("invalid UTF-8".to_string()))?;
        
        // Simple JSON parsing without serde dependency
        let mut version = String::new();
        let mut mesh_key = None;

        // Parse version field
        if let Some(start) = s.find("\"version\":") {
            let rest = &s[start + 10..];
            if let Some(val_start) = rest.find('"') {
                let val_rest = &rest[val_start + 1..];
                if let Some(val_end) = val_rest.find('"') {
                    version = val_rest[..val_end].to_string();
                }
            }
        }

        // Parse meshKey field
        if let Some(start) = s.find("\"meshKey\":") {
            let rest = &s[start + 10..];
            if let Some(val_start) = rest.find('"') {
                let val_rest = &rest[val_start + 1..];
                if let Some(val_end) = val_rest.find('"') {
                    let hex_str = &val_rest[..val_end];
                    if hex_str.len() == 64 {
                        // Inline hex decoding
                        let mut key = [0u8; 32];
                        let mut valid = true;
                        for (i, chunk) in hex_str.as_bytes().chunks(2).enumerate() {
                            if chunk.len() != 2 {
                                valid = false;
                                break;
                            }
                            let high = match chunk[0] {
                                b'0'..=b'9' => chunk[0] - b'0',
                                b'a'..=b'f' => chunk[0] - b'a' + 10,
                                b'A'..=b'F' => chunk[0] - b'A' + 10,
                                _ => { valid = false; break; }
                            };
                            let low = match chunk[1] {
                                b'0'..=b'9' => chunk[1] - b'0',
                                b'a'..=b'f' => chunk[1] - b'a' + 10,
                                b'A'..=b'F' => chunk[1] - b'A' + 10,
                                _ => { valid = false; break; }
                            };
                            key[i] = (high << 4) | low;
                        }
                        if valid {
                            mesh_key = Some(key);
                        }
                    }
                }
            }
        }

        Ok(Self { version, mesh_key })
    }
}

/// DERP protocol version.
/// - version 1: original protocol
/// - version 2: received packets have src addrs in frameRecvPacket at beginning
pub const PROTOCOL_VERSION: u8 = 2;

/// Magic header for ServerKey frame: "DERP🔑" (8 bytes)
pub const MAGIC: &[u8; 8] = b"DERP\xf0\x9f\x94\x91";

/// Maximum packet size (64 KB, same as Tailscale).
pub const MAX_PACKET_SIZE: usize = 64 << 10;

/// Maximum info length for ClientInfo/ServerInfo JSON (1 MB).
pub const MAX_INFO_LEN: usize = 1 << 20;

/// NaCl nonce length.
pub const NONCE_LEN: usize = 24;

/// Frame header length (1 byte type + 4 bytes length).
pub const FRAME_HEADER_LEN: usize = 5;

/// Public key size (32 bytes for Curve25519).
pub const KEY_LEN: usize = 32;
pub type PublicKey = [u8; KEY_LEN];

/// DERP protocol frame types (aligned with Tailscale DERP v2).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    /// Server sends magic + public key to client.
    ServerKey = 0x01,
    /// Client sends encrypted info (32B key + 24B nonce + naclbox(json)).
    ClientInfo = 0x02,
    /// Server sends encrypted info (24B nonce + naclbox(json)).
    ServerInfo = 0x03,
    /// Client sends packet to another client (32B dst key + packet).
    SendPacket = 0x04,
    /// Server delivers packet from another client (v2: 32B src key + packet).
    RecvPacket = 0x05,
    /// Keep connection alive (no payload).
    KeepAlive = 0x06,
    /// Note whether this is client's preferred/home node (1B payload: 0x01 or 0x00).
    NotePreferred = 0x07,
    /// Notify client that peer has disconnected (32B key + 1B reason).
    PeerGone = 0x08,
    /// Notify client that peer has connected (32B+ payload).
    PeerPresent = 0x09,
    /// Forward packet between mesh peers (32B src + 32B dst + packet).
    ForwardPacket = 0x0A,
    /// Subscribe to peer presence updates (mesh only, no payload).
    WatchConns = 0x10,
    /// Close a peer connection (mesh only, 32B key).
    ClosePeer = 0x11,
    /// Ping with 8-byte payload.
    Ping = 0x12,
    /// Pong with 8-byte payload (echo of ping).
    Pong = 0x13,
    /// Health status message (variable length text).
    Health = 0x14,
    /// Server restarting (two BE uint32 durations in ms).
    Restarting = 0x15,
}

impl FrameType {
    pub fn from_u8(byte: u8) -> Result<Self, ProtocolError> {
        match byte {
            0x01 => Ok(FrameType::ServerKey),
            0x02 => Ok(FrameType::ClientInfo),
            0x03 => Ok(FrameType::ServerInfo),
            0x04 => Ok(FrameType::SendPacket),
            0x05 => Ok(FrameType::RecvPacket),
            0x06 => Ok(FrameType::KeepAlive),
            0x07 => Ok(FrameType::NotePreferred),
            0x08 => Ok(FrameType::PeerGone),
            0x09 => Ok(FrameType::PeerPresent),
            0x0A => Ok(FrameType::ForwardPacket),
            0x10 => Ok(FrameType::WatchConns),
            0x11 => Ok(FrameType::ClosePeer),
            0x12 => Ok(FrameType::Ping),
            0x13 => Ok(FrameType::Pong),
            0x14 => Ok(FrameType::Health),
            0x15 => Ok(FrameType::Restarting),
            _ => Err(ProtocolError::InvalidFrameType(byte)),
        }
    }
}

/// Reason why a peer is gone.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PeerGoneReason {
    /// Peer disconnected from this server.
    #[default]
    Disconnected = 0x00,
    /// Server doesn't know about this peer.
    NotHere = 0x01,
}

impl PeerGoneReason {
    pub fn from_u8(byte: u8) -> Self {
        match byte {
            0x00 => PeerGoneReason::Disconnected,
            0x01 => PeerGoneReason::NotHere,
            _ => PeerGoneReason::Disconnected, // Default for unknown
        }
    }
}

/// Flags for PeerPresent frame.
pub mod peer_present_flags {
    pub const IS_REGULAR: u8 = 1 << 0;
    pub const IS_MESH_PEER: u8 = 1 << 1;
    pub const IS_PROBER: u8 = 1 << 2;
    pub const NOT_IDEAL: u8 = 1 << 3;
}

/// DERP protocol frames (v2 Tailscale-compatible).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DerpFrame {
    /// Server's public key with magic header.
    /// Format: 8B magic + 32B public key + optional future bytes.
    ServerKey { key: PublicKey },
    /// Client identifies itself with encrypted info.
    /// Format: 32B public key + 24B nonce + naclbox(json).
    /// For backward compatibility, also supports plain 32B key.
    ClientInfo {
        key: PublicKey,
        /// Encrypted client info (nonce + ciphertext). Empty for legacy plain key.
        encrypted_info: Vec<u8>,
    },
    /// Server sends encrypted info after successful auth.
    /// Format: 24B nonce + naclbox(json).
    ServerInfo { encrypted_info: Vec<u8> },
    /// Send packet to a peer.
    SendPacket { dst_key: PublicKey, packet: Vec<u8> },
    /// Receive packet from a peer (v2: always includes src_key).
    RecvPacket { src_key: PublicKey, packet: Vec<u8> },
    /// Keep connection alive.
    KeepAlive,
    /// Note whether this is client's preferred/home node.
    NotePreferred { preferred: bool },
    /// Peer has disconnected with reason.
    PeerGone {
        key: PublicKey,
        reason: PeerGoneReason,
    },
    /// Peer has connected, optionally with endpoint info.
    PeerPresent {
        key: PublicKey,
        /// Optional endpoint address (IP:port).
        endpoint: Option<SocketAddr>,
        /// Peer presence flags.
        flags: u8,
    },
    /// Forward packet from another mesh node.
    ForwardPacket {
        src_key: PublicKey,
        dst_key: PublicKey,
        packet: Vec<u8>,
    },
    /// Subscribe to peer presence updates (mesh only).
    WatchConns,
    /// Close a peer connection (mesh only).
    ClosePeer { key: PublicKey },
    /// Ping request.
    Ping { data: [u8; 8] },
    /// Pong response.
    Pong { data: [u8; 8] },
    /// Health status message.
    Health { message: String },
    /// Server restarting notification.
    Restarting {
        /// Milliseconds to wait before reconnecting.
        reconnect_in_ms: u32,
        /// Milliseconds to keep trying.
        try_for_ms: u32,
    },
}

/// Protocol errors.
#[derive(Error, Debug)]
pub enum ProtocolError {
    #[error("Invalid frame type: {0}")]
    InvalidFrameType(u8),

    #[error("Frame too large: {0} bytes (max {MAX_PACKET_SIZE})")]
    FrameTooLarge(usize),

    #[error("Incomplete frame: expected {expected} bytes, got {actual}")]
    IncompleteFrame { expected: usize, actual: usize },

    #[error("Invalid public key size: {0}")]
    InvalidKeySize(usize),

    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Protocol version mismatch: got {0}, expected {PROTOCOL_VERSION}")]
    VersionMismatch(u8),

    #[error("Invalid client info: {0}")]
    InvalidClientInfo(String),
}

impl DerpFrame {
    /// Get the frame type.
    pub fn frame_type(&self) -> FrameType {
        match self {
            DerpFrame::ServerKey { .. } => FrameType::ServerKey,
            DerpFrame::ClientInfo { .. } => FrameType::ClientInfo,
            DerpFrame::ServerInfo { .. } => FrameType::ServerInfo,
            DerpFrame::SendPacket { .. } => FrameType::SendPacket,
            DerpFrame::RecvPacket { .. } => FrameType::RecvPacket,
            DerpFrame::KeepAlive => FrameType::KeepAlive,
            DerpFrame::NotePreferred { .. } => FrameType::NotePreferred,
            DerpFrame::PeerGone { .. } => FrameType::PeerGone,
            DerpFrame::PeerPresent { .. } => FrameType::PeerPresent,
            DerpFrame::ForwardPacket { .. } => FrameType::ForwardPacket,
            DerpFrame::WatchConns => FrameType::WatchConns,
            DerpFrame::ClosePeer { .. } => FrameType::ClosePeer,
            DerpFrame::Ping { .. } => FrameType::Ping,
            DerpFrame::Pong { .. } => FrameType::Pong,
            DerpFrame::Health { .. } => FrameType::Health,
            DerpFrame::Restarting { .. } => FrameType::Restarting,
        }
    }

    /// Serialize frame to writer.
    ///
    /// Frame format (v2 Tailscale-compatible):
    /// - Frame type (1 byte)
    /// - Frame length (4 bytes, big-endian, excluding type and length fields)
    /// - Frame data (variable)
    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), ProtocolError> {
        let frame_type = self.frame_type() as u8;
        writer.write_all(&[frame_type])?;

        match self {
            DerpFrame::ServerKey { key } => {
                // v2: 8B magic + 32B key
                let len = 8 + KEY_LEN;
                writer.write_all(&(len as u32).to_be_bytes())?;
                writer.write_all(MAGIC)?;
                writer.write_all(key)?;
            }
            DerpFrame::ClientInfo { key, encrypted_info } => {
                // 32B key + encrypted info (nonce + ciphertext)
                let len = KEY_LEN + encrypted_info.len();
                if len > MAX_INFO_LEN {
                    return Err(ProtocolError::FrameTooLarge(len));
                }
                writer.write_all(&(len as u32).to_be_bytes())?;
                writer.write_all(key)?;
                writer.write_all(encrypted_info)?;
            }
            DerpFrame::ServerInfo { encrypted_info } => {
                // encrypted info (nonce + ciphertext)
                if encrypted_info.len() > MAX_INFO_LEN {
                    return Err(ProtocolError::FrameTooLarge(encrypted_info.len()));
                }
                writer.write_all(&(encrypted_info.len() as u32).to_be_bytes())?;
                writer.write_all(encrypted_info)?;
            }
            DerpFrame::SendPacket { dst_key, packet } => {
                let len = KEY_LEN + packet.len();
                if len > MAX_PACKET_SIZE {
                    return Err(ProtocolError::FrameTooLarge(len));
                }
                writer.write_all(&(len as u32).to_be_bytes())?;
                writer.write_all(dst_key)?;
                writer.write_all(packet)?;
            }
            DerpFrame::RecvPacket { src_key, packet } => {
                // v2: always include src_key
                let len = KEY_LEN + packet.len();
                if len > MAX_PACKET_SIZE {
                    return Err(ProtocolError::FrameTooLarge(len));
                }
                writer.write_all(&(len as u32).to_be_bytes())?;
                writer.write_all(src_key)?;
                writer.write_all(packet)?;
            }
            DerpFrame::KeepAlive => {
                writer.write_all(&0u32.to_be_bytes())?;
            }
            DerpFrame::NotePreferred { preferred } => {
                writer.write_all(&1u32.to_be_bytes())?;
                writer.write_all(&[if *preferred { 0x01 } else { 0x00 }])?;
            }
            DerpFrame::PeerGone { key, reason } => {
                // 32B key + 1B reason
                writer.write_all(&(33u32.to_be_bytes()))?;
                writer.write_all(key)?;
                writer.write_all(&[*reason as u8])?;
            }
            DerpFrame::PeerPresent { key, endpoint, flags } => {
                // 32B key + optional 18B (16B IP + 2B port) + optional 1B flags
                let (ip_bytes, port_bytes): (Option<[u8; 16]>, Option<[u8; 2]>) = match endpoint {
                    Some(SocketAddr::V4(addr)) => {
                        let mut ip = [0u8; 16];
                        ip[..4].copy_from_slice(&addr.ip().octets());
                        (Some(ip), Some(addr.port().to_be_bytes()))
                    }
                    Some(SocketAddr::V6(addr)) => {
                        (Some(addr.ip().octets()), Some(addr.port().to_be_bytes()))
                    }
                    None => (None, None),
                };

                let len = KEY_LEN + if endpoint.is_some() { 18 + 1 } else { 0 };
                writer.write_all(&(len as u32).to_be_bytes())?;
                writer.write_all(key)?;
                if let (Some(ip), Some(port)) = (ip_bytes, port_bytes) {
                    writer.write_all(&ip)?;
                    writer.write_all(&port)?;
                    writer.write_all(&[*flags])?;
                }
            }
            DerpFrame::ForwardPacket {
                src_key,
                dst_key,
                packet,
            } => {
                let len = KEY_LEN + KEY_LEN + packet.len();
                if len > MAX_PACKET_SIZE {
                    return Err(ProtocolError::FrameTooLarge(len));
                }
                writer.write_all(&(len as u32).to_be_bytes())?;
                writer.write_all(src_key)?;
                writer.write_all(dst_key)?;
                writer.write_all(packet)?;
            }
            DerpFrame::WatchConns => {
                writer.write_all(&0u32.to_be_bytes())?;
            }
            DerpFrame::ClosePeer { key } => {
                writer.write_all(&(KEY_LEN as u32).to_be_bytes())?;
                writer.write_all(key)?;
            }
            DerpFrame::Ping { data } => {
                writer.write_all(&8u32.to_be_bytes())?;
                writer.write_all(data)?;
            }
            DerpFrame::Pong { data } => {
                writer.write_all(&8u32.to_be_bytes())?;
                writer.write_all(data)?;
            }
            DerpFrame::Health { message } => {
                let bytes = message.as_bytes();
                writer.write_all(&(bytes.len() as u32).to_be_bytes())?;
                writer.write_all(bytes)?;
            }
            DerpFrame::Restarting {
                reconnect_in_ms,
                try_for_ms,
            } => {
                writer.write_all(&8u32.to_be_bytes())?;
                writer.write_all(&reconnect_in_ms.to_be_bytes())?;
                writer.write_all(&try_for_ms.to_be_bytes())?;
            }
        }

        Ok(())
    }

    /// Deserialize frame from reader (v2 Tailscale-compatible).
    pub fn read_from<R: Read>(reader: &mut R) -> Result<Self, ProtocolError> {
        // Read frame type (1 byte)
        let mut type_buf = [0u8; 1];
        reader.read_exact(&mut type_buf)?;
        let frame_type = FrameType::from_u8(type_buf[0])?;

        // Read frame length (4 bytes, big-endian)
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf)?;
        let frame_len = u32::from_be_bytes(len_buf) as usize;

        // Check size limits based on frame type
        let max_len = match frame_type {
            FrameType::ClientInfo | FrameType::ServerInfo => MAX_INFO_LEN,
            _ => MAX_PACKET_SIZE,
        };
        if frame_len > max_len {
            return Err(ProtocolError::FrameTooLarge(frame_len));
        }

        // Read frame data based on type
        match frame_type {
            FrameType::ServerKey => {
                // v2: 8B magic + 32B key + optional future bytes
                if frame_len < 8 + KEY_LEN {
                    return Err(ProtocolError::IncompleteFrame {
                        expected: 8 + KEY_LEN,
                        actual: frame_len,
                    });
                }
                let mut magic = [0u8; 8];
                reader.read_exact(&mut magic)?;
                // Verify magic (optional - just skip if invalid for compatibility)
                let mut key = [0u8; KEY_LEN];
                reader.read_exact(&mut key)?;
                // Discard any future bytes
                if frame_len > 8 + KEY_LEN {
                    let mut discard = vec![0u8; frame_len - 8 - KEY_LEN];
                    reader.read_exact(&mut discard)?;
                }
                Ok(DerpFrame::ServerKey { key })
            }
            FrameType::ClientInfo => {
                // 32B key + optional encrypted info
                if frame_len < KEY_LEN {
                    return Err(ProtocolError::IncompleteFrame {
                        expected: KEY_LEN,
                        actual: frame_len,
                    });
                }
                let mut key = [0u8; KEY_LEN];
                reader.read_exact(&mut key)?;
                let encrypted_len = frame_len - KEY_LEN;
                let mut encrypted_info = vec![0u8; encrypted_len];
                if encrypted_len > 0 {
                    reader.read_exact(&mut encrypted_info)?;
                }
                Ok(DerpFrame::ClientInfo { key, encrypted_info })
            }
            FrameType::ServerInfo => {
                // Encrypted info (nonce + ciphertext)
                let mut encrypted_info = vec![0u8; frame_len];
                reader.read_exact(&mut encrypted_info)?;
                Ok(DerpFrame::ServerInfo { encrypted_info })
            }
            FrameType::SendPacket => {
                if frame_len < KEY_LEN {
                    return Err(ProtocolError::IncompleteFrame {
                        expected: KEY_LEN,
                        actual: frame_len,
                    });
                }
                let mut dst_key = [0u8; KEY_LEN];
                reader.read_exact(&mut dst_key)?;

                let packet_len = frame_len - KEY_LEN;
                let mut packet = vec![0u8; packet_len];
                reader.read_exact(&mut packet)?;

                Ok(DerpFrame::SendPacket { dst_key, packet })
            }
            FrameType::RecvPacket => {
                // v2: always includes src_key
                if frame_len < KEY_LEN {
                    return Err(ProtocolError::IncompleteFrame {
                        expected: KEY_LEN,
                        actual: frame_len,
                    });
                }
                let mut src_key = [0u8; KEY_LEN];
                reader.read_exact(&mut src_key)?;

                let packet_len = frame_len - KEY_LEN;
                let mut packet = vec![0u8; packet_len];
                reader.read_exact(&mut packet)?;

                Ok(DerpFrame::RecvPacket { src_key, packet })
            }
            FrameType::KeepAlive => {
                // Discard any payload (though should be 0)
                if frame_len > 0 {
                    let mut discard = vec![0u8; frame_len];
                    reader.read_exact(&mut discard)?;
                }
                Ok(DerpFrame::KeepAlive)
            }
            FrameType::NotePreferred => {
                if frame_len < 1 {
                    return Err(ProtocolError::IncompleteFrame {
                        expected: 1,
                        actual: frame_len,
                    });
                }
                let mut byte = [0u8; 1];
                reader.read_exact(&mut byte)?;
                // Discard any extra bytes
                if frame_len > 1 {
                    let mut discard = vec![0u8; frame_len - 1];
                    reader.read_exact(&mut discard)?;
                }
                Ok(DerpFrame::NotePreferred { preferred: byte[0] != 0 })
            }
            FrameType::PeerGone => {
                // 32B key + optional 1B reason
                if frame_len < KEY_LEN {
                    return Err(ProtocolError::IncompleteFrame {
                        expected: KEY_LEN,
                        actual: frame_len,
                    });
                }
                let mut key = [0u8; KEY_LEN];
                reader.read_exact(&mut key)?;
                let reason = if frame_len > KEY_LEN {
                    let mut reason_byte = [0u8; 1];
                    reader.read_exact(&mut reason_byte)?;
                    // Discard any extra bytes
                    if frame_len > KEY_LEN + 1 {
                        let mut discard = vec![0u8; frame_len - KEY_LEN - 1];
                        reader.read_exact(&mut discard)?;
                    }
                    PeerGoneReason::from_u8(reason_byte[0])
                } else {
                    PeerGoneReason::Disconnected
                };
                Ok(DerpFrame::PeerGone { key, reason })
            }
            FrameType::PeerPresent => {
                // 32B key + optional 18B (16B IP + 2B port) + optional 1B flags
                if frame_len < KEY_LEN {
                    return Err(ProtocolError::IncompleteFrame {
                        expected: KEY_LEN,
                        actual: frame_len,
                    });
                }
                let mut key = [0u8; KEY_LEN];
                reader.read_exact(&mut key)?;

                let remaining = frame_len - KEY_LEN;
                let (endpoint, flags) = if remaining >= 18 {
                    let mut ip_bytes = [0u8; 16];
                    reader.read_exact(&mut ip_bytes)?;
                    let mut port_bytes = [0u8; 2];
                    reader.read_exact(&mut port_bytes)?;
                    let port = u16::from_be_bytes(port_bytes);

                    // Determine if IPv4 (first 12 bytes are 0) or IPv6
                    let addr = if ip_bytes[4..16].iter().all(|&b| b == 0) {
                        // IPv4: first 4 bytes
                        let ipv4 = Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
                        SocketAddr::new(IpAddr::V4(ipv4), port)
                    } else {
                        let ipv6 = Ipv6Addr::from(ip_bytes);
                        SocketAddr::new(IpAddr::V6(ipv6), port)
                    };

                    let flags = if remaining >= 19 {
                        let mut flags_byte = [0u8; 1];
                        reader.read_exact(&mut flags_byte)?;
                        // Discard any extra bytes
                        if remaining > 19 {
                            let mut discard = vec![0u8; remaining - 19];
                            reader.read_exact(&mut discard)?;
                        }
                        flags_byte[0]
                    } else {
                        0
                    };
                    (Some(addr), flags)
                } else {
                    // Discard remaining bytes
                    if remaining > 0 {
                        let mut discard = vec![0u8; remaining];
                        reader.read_exact(&mut discard)?;
                    }
                    (None, 0)
                };

                Ok(DerpFrame::PeerPresent { key, endpoint, flags })
            }
            FrameType::ForwardPacket => {
                if frame_len < KEY_LEN * 2 {
                    return Err(ProtocolError::IncompleteFrame {
                        expected: KEY_LEN * 2,
                        actual: frame_len,
                    });
                }
                let mut src_key = [0u8; KEY_LEN];
                reader.read_exact(&mut src_key)?;
                let mut dst_key = [0u8; KEY_LEN];
                reader.read_exact(&mut dst_key)?;

                let packet_len = frame_len - KEY_LEN * 2;
                let mut packet = vec![0u8; packet_len];
                reader.read_exact(&mut packet)?;

                Ok(DerpFrame::ForwardPacket {
                    src_key,
                    dst_key,
                    packet,
                })
            }
            FrameType::WatchConns => {
                // Discard any payload (should be 0)
                if frame_len > 0 {
                    let mut discard = vec![0u8; frame_len];
                    reader.read_exact(&mut discard)?;
                }
                Ok(DerpFrame::WatchConns)
            }
            FrameType::ClosePeer => {
                if frame_len < KEY_LEN {
                    return Err(ProtocolError::IncompleteFrame {
                        expected: KEY_LEN,
                        actual: frame_len,
                    });
                }
                let mut key = [0u8; KEY_LEN];
                reader.read_exact(&mut key)?;
                // Discard extra bytes
                if frame_len > KEY_LEN {
                    let mut discard = vec![0u8; frame_len - KEY_LEN];
                    reader.read_exact(&mut discard)?;
                }
                Ok(DerpFrame::ClosePeer { key })
            }
            FrameType::Ping => {
                if frame_len < 8 {
                    return Err(ProtocolError::IncompleteFrame {
                        expected: 8,
                        actual: frame_len,
                    });
                }
                let mut data = [0u8; 8];
                reader.read_exact(&mut data)?;
                // Discard extra bytes
                if frame_len > 8 {
                    let mut discard = vec![0u8; frame_len - 8];
                    reader.read_exact(&mut discard)?;
                }
                Ok(DerpFrame::Ping { data })
            }
            FrameType::Pong => {
                if frame_len < 8 {
                    return Err(ProtocolError::IncompleteFrame {
                        expected: 8,
                        actual: frame_len,
                    });
                }
                let mut data = [0u8; 8];
                reader.read_exact(&mut data)?;
                // Discard extra bytes
                if frame_len > 8 {
                    let mut discard = vec![0u8; frame_len - 8];
                    reader.read_exact(&mut discard)?;
                }
                Ok(DerpFrame::Pong { data })
            }
            FrameType::Health => {
                let mut bytes = vec![0u8; frame_len];
                reader.read_exact(&mut bytes)?;
                let message = String::from_utf8_lossy(&bytes).to_string();
                Ok(DerpFrame::Health { message })
            }
            FrameType::Restarting => {
                if frame_len < 8 {
                    return Err(ProtocolError::IncompleteFrame {
                        expected: 8,
                        actual: frame_len,
                    });
                }
                let mut reconnect_bytes = [0u8; 4];
                reader.read_exact(&mut reconnect_bytes)?;
                let mut try_for_bytes = [0u8; 4];
                reader.read_exact(&mut try_for_bytes)?;
                // Discard extra bytes
                if frame_len > 8 {
                    let mut discard = vec![0u8; frame_len - 8];
                    reader.read_exact(&mut discard)?;
                }
                Ok(DerpFrame::Restarting {
                    reconnect_in_ms: u32::from_be_bytes(reconnect_bytes),
                    try_for_ms: u32::from_be_bytes(try_for_bytes),
                })
            }
        }
    }


    /// Encode frame to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut buffer = Vec::new();
        self.write_to(&mut buffer)?;
        Ok(buffer)
    }

    /// Decode frame from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let mut cursor = std::io::Cursor::new(bytes);
        Self::read_from(&mut cursor)
    }

    /// Async write frame to tokio writer.
    pub async fn write_to_async<W>(&self, writer: &mut W) -> Result<(), ProtocolError>
    where
        W: AsyncWriteExt + Unpin,
    {
        // Serialize to bytes first (simple approach)
        let bytes = self.to_bytes()?;
        writer.write_all(&bytes).await.map_err(ProtocolError::Io)?;
        Ok(())
    }

    /// Async read frame from tokio reader (v2 Tailscale-compatible).
    ///
    /// This implementation reads the frame header, then the body,
    /// and delegates to the sync `read_from` for parsing.
    pub async fn read_from_async<R>(reader: &mut R) -> Result<Self, ProtocolError>
    where
        R: AsyncReadExt + Unpin,
    {
        // Read frame type (1 byte)
        let mut type_buf = [0u8; 1];
        reader
            .read_exact(&mut type_buf)
            .await
            .map_err(ProtocolError::Io)?;

        // Read frame length (4 bytes, big-endian)
        let mut len_buf = [0u8; 4];
        reader
            .read_exact(&mut len_buf)
            .await
            .map_err(ProtocolError::Io)?;
        let frame_len = u32::from_be_bytes(len_buf) as usize;

        // Check max size
        let max_len = match type_buf[0] {
            0x02 | 0x03 => MAX_INFO_LEN, // ClientInfo, ServerInfo
            _ => MAX_PACKET_SIZE,
        };
        if frame_len > max_len {
            return Err(ProtocolError::FrameTooLarge(frame_len));
        }

        // Read the entire frame body
        let mut body = vec![0u8; frame_len];
        if frame_len > 0 {
            reader
                .read_exact(&mut body)
                .await
                .map_err(ProtocolError::Io)?;
        }

        // Reconstruct the full frame bytes and parse with sync read_from
        let mut full_frame = Vec::with_capacity(FRAME_HEADER_LEN + frame_len);
        full_frame.push(type_buf[0]);
        full_frame.extend_from_slice(&len_buf);
        full_frame.extend_from_slice(&body);

        Self::from_bytes(&full_frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_type_conversion() {
        assert_eq!(FrameType::from_u8(0x01).unwrap(), FrameType::ServerKey);
        assert_eq!(FrameType::from_u8(0x06).unwrap(), FrameType::KeepAlive); // v2: 0x06
        assert_eq!(FrameType::from_u8(0x09).unwrap(), FrameType::PeerPresent);
        assert_eq!(FrameType::from_u8(0x12).unwrap(), FrameType::Ping); // v2: 0x12
        assert!(FrameType::from_u8(0xFF).is_err());
    }

    #[test]
    fn test_keepalive_roundtrip() {
        let frame = DerpFrame::KeepAlive;
        let bytes = frame.to_bytes().unwrap();

        // Should be: type (1) + length (4) = 5 bytes
        assert_eq!(bytes.len(), 5);
        assert_eq!(bytes[0], FrameType::KeepAlive as u8);

        let decoded = DerpFrame::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn test_server_key_roundtrip() {
        let key = [42u8; 32];
        let frame = DerpFrame::ServerKey { key };

        let bytes = frame.to_bytes().unwrap();
        // v2: type (1) + len (4) + magic (8) + key (32) = 45
        assert_eq!(bytes.len(), 45);

        let decoded = DerpFrame::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn test_client_info_roundtrip() {
        let key = [123u8; 32];
        let frame = DerpFrame::ClientInfo { key, encrypted_info: vec![] };

        let bytes = frame.to_bytes().unwrap();
        let decoded = DerpFrame::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, frame);

        // Also test with encrypted info
        let frame_enc = DerpFrame::ClientInfo { 
            key, 
            encrypted_info: vec![1, 2, 3, 4, 5] 
        };
        let bytes_enc = frame_enc.to_bytes().unwrap();
        let decoded_enc = DerpFrame::from_bytes(&bytes_enc).unwrap();
        assert_eq!(decoded_enc, frame_enc);
    }

    #[test]
    fn test_ping_pong_roundtrip() {
        let data = [1, 2, 3, 4, 5, 6, 7, 8];

        let ping = DerpFrame::Ping { data };
        let ping_bytes = ping.to_bytes().unwrap();
        assert_eq!(DerpFrame::from_bytes(&ping_bytes).unwrap(), ping);

        let pong = DerpFrame::Pong { data };
        let pong_bytes = pong.to_bytes().unwrap();
        assert_eq!(DerpFrame::from_bytes(&pong_bytes).unwrap(), pong);
    }

    #[test]
    fn test_send_packet_roundtrip() {
        let dst_key = [55u8; 32];
        let packet = vec![1, 2, 3, 4, 5];
        let frame = DerpFrame::SendPacket {
            dst_key,
            packet: packet.clone(),
        };

        let bytes = frame.to_bytes().unwrap();
        // type (1) + len (4) + dst_key (32) + packet (5) = 42
        assert_eq!(bytes.len(), 42);

        let decoded = DerpFrame::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn test_recv_packet_roundtrip() {
        let src_key = [77u8; 32];
        let packet = vec![0xAA, 0xBB, 0xCC];
        let frame = DerpFrame::RecvPacket {
            src_key,
            packet: packet.clone(),
        };

        let bytes = frame.to_bytes().unwrap();
        let decoded = DerpFrame::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn test_peer_notifications_roundtrip() {
        let key = [99u8; 32];

        // PeerGone with reason
        let gone = DerpFrame::PeerGone { key, reason: PeerGoneReason::Disconnected };
        let gone_bytes = gone.to_bytes().unwrap();
        assert_eq!(DerpFrame::from_bytes(&gone_bytes).unwrap(), gone);

        let gone_not_here = DerpFrame::PeerGone { key, reason: PeerGoneReason::NotHere };
        let gone_not_here_bytes = gone_not_here.to_bytes().unwrap();
        assert_eq!(DerpFrame::from_bytes(&gone_not_here_bytes).unwrap(), gone_not_here);

        // PeerPresent with no endpoint
        let present = DerpFrame::PeerPresent { key, endpoint: None, flags: 0 };
        let present_bytes = present.to_bytes().unwrap();
        assert_eq!(DerpFrame::from_bytes(&present_bytes).unwrap(), present);

        // PeerPresent with endpoint
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 12345);
        let present_with_ep = DerpFrame::PeerPresent { key, endpoint: Some(addr), flags: 0x01 };
        let present_with_ep_bytes = present_with_ep.to_bytes().unwrap();
        let decoded = DerpFrame::from_bytes(&present_with_ep_bytes).unwrap();
        assert_eq!(decoded, present_with_ep);
    }

    #[test]
    fn test_new_frame_types_roundtrip() {
        // NotePreferred
        let note = DerpFrame::NotePreferred { preferred: true };
        let note_bytes = note.to_bytes().unwrap();
        assert_eq!(DerpFrame::from_bytes(&note_bytes).unwrap(), note);

        // WatchConns
        let watch = DerpFrame::WatchConns;
        let watch_bytes = watch.to_bytes().unwrap();
        assert_eq!(DerpFrame::from_bytes(&watch_bytes).unwrap(), watch);

        // ClosePeer
        let key = [88u8; 32];
        let close = DerpFrame::ClosePeer { key };
        let close_bytes = close.to_bytes().unwrap();
        assert_eq!(DerpFrame::from_bytes(&close_bytes).unwrap(), close);

        // Health
        let health = DerpFrame::Health { message: "ok".to_string() };
        let health_bytes = health.to_bytes().unwrap();
        assert_eq!(DerpFrame::from_bytes(&health_bytes).unwrap(), health);

        // Restarting
        let restart = DerpFrame::Restarting { reconnect_in_ms: 1000, try_for_ms: 30000 };
        let restart_bytes = restart.to_bytes().unwrap();
        assert_eq!(DerpFrame::from_bytes(&restart_bytes).unwrap(), restart);

        // ServerInfo
        let info = DerpFrame::ServerInfo { encrypted_info: vec![10, 20, 30] };
        let info_bytes = info.to_bytes().unwrap();
        assert_eq!(DerpFrame::from_bytes(&info_bytes).unwrap(), info);
    }

    #[test]
    fn test_client_info_payload_json() {
        // Without mesh key
        let payload = ClientInfoPayload::new("singbox-rust 0.1.0");
        let json = payload.to_json();
        let decoded = ClientInfoPayload::from_json(&json).unwrap();
        assert_eq!(decoded.version, "singbox-rust 0.1.0");
        assert!(decoded.mesh_key.is_none());

        // With mesh key
        let mesh_key = [0xab_u8; 32];
        let payload_mesh = ClientInfoPayload::new("singbox-rust 0.1.0")
            .with_mesh_key(mesh_key);
        let json_mesh = payload_mesh.to_json();
        let decoded_mesh = ClientInfoPayload::from_json(&json_mesh).unwrap();
        assert_eq!(decoded_mesh.version, "singbox-rust 0.1.0");
        assert_eq!(decoded_mesh.mesh_key, Some(mesh_key));

        // Verify JSON format
        let json_str = String::from_utf8(json_mesh).unwrap();
        assert!(json_str.contains("\"version\":"));
        assert!(json_str.contains("\"meshKey\":"));
        assert!(json_str.contains("abababab")); // hex encoded 0xab
    }
}
