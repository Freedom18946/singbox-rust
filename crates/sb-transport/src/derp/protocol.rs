//! DERP protocol wire format implementation.
//!
//! This module implements the binary protocol used for DERP (Designated Encrypted Relay for Packets).
//! The protocol uses length-prefixed frames where each frame starts with a frame type byte
//! followed by frame-specific data.

use std::io::{self, Read, Write};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// DERP protocol version.
pub const PROTOCOL_VERSION: u8 = 1;

/// Maximum packet size (16 MB).
pub const MAX_PACKET_SIZE: usize = 16 * 1024 * 1024;

/// Public key size (32 bytes for Ed25519/Curve25519).
pub type PublicKey = [u8; 32];

/// DERP protocol frame types.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    /// Server sends its public key to client.
    ServerKey = 0x01,
    /// Client sends its public key to register.
    ClientInfo = 0x02,
    /// Client sends packet to another client.
    SendPacket = 0x03,
    /// Server delivers packet from another client.
    RecvPacket = 0x04,
    /// Keep connection alive.
    KeepAlive = 0x05,
    /// Ping with random data.
    Ping = 0x06,
    /// Pong response with same data.
    Pong = 0x07,
    /// Notify client that peer has disconnected.
    PeerGone = 0x08,
    /// Notify client that peer has connected.
    PeerPresent = 0x09,
    /// Forward packet between mesh peers (preserves source).
    ForwardPacket = 0x0A,
}

impl FrameType {
    pub fn from_u8(byte: u8) -> Result<Self, ProtocolError> {
        match byte {
            0x01 => Ok(FrameType::ServerKey),
            0x02 => Ok(FrameType::ClientInfo),
            0x03 => Ok(FrameType::SendPacket),
            0x04 => Ok(FrameType::RecvPacket),
            0x05 => Ok(FrameType::KeepAlive),
            0x06 => Ok(FrameType::Ping),
            0x07 => Ok(FrameType::Pong),
            0x08 => Ok(FrameType::PeerGone),
            0x09 => Ok(FrameType::PeerPresent),
            0x0A => Ok(FrameType::ForwardPacket),
            _ => Err(ProtocolError::InvalidFrameType(byte)),
        }
    }
}

/// DERP protocol frames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DerpFrame {
    /// Server's public key.
    ServerKey { key: PublicKey },
    /// Client identifies itself with public key.
    ClientInfo { key: PublicKey },
    /// Send packet to a peer.
    SendPacket { dst_key: PublicKey, packet: Vec<u8> },
    /// Receive packet from a peer.
    RecvPacket { src_key: PublicKey, packet: Vec<u8> },
    /// Keep connection alive.
    KeepAlive,
    /// Ping request.
    Ping { data: [u8; 8] },
    /// Pong response.
    Pong { data: [u8; 8] },
    /// Peer has disconnected.
    PeerGone { key: PublicKey },
    /// Peer has connected.
    PeerPresent { key: PublicKey },
    /// Forward packet from another mesh node.
    ForwardPacket {
        src_key: PublicKey,
        dst_key: PublicKey,
        packet: Vec<u8>,
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
}

impl DerpFrame {
    /// Get the frame type.
    pub fn frame_type(&self) -> FrameType {
        match self {
            DerpFrame::ServerKey { .. } => FrameType::ServerKey,
            DerpFrame::ClientInfo { .. } => FrameType::ClientInfo,
            DerpFrame::SendPacket { .. } => FrameType::SendPacket,
            DerpFrame::RecvPacket { .. } => FrameType::RecvPacket,
            DerpFrame::KeepAlive => FrameType::KeepAlive,
            DerpFrame::Ping { .. } => FrameType::Ping,
            DerpFrame::Pong { .. } => FrameType::Pong,
            DerpFrame::PeerGone { .. } => FrameType::PeerGone,
            DerpFrame::PeerPresent { .. } => FrameType::PeerPresent,
            DerpFrame::ForwardPacket { .. } => FrameType::ForwardPacket,
        }
    }

    /// Serialize frame to writer.
    ///
    /// Frame format:
    /// - Frame type (1 byte)
    /// - Frame length (4 bytes, big-endian, excluding type and length fields)
    /// - Frame data (variable)
    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), ProtocolError> {
        let frame_type = self.frame_type() as u8;
        writer.write_all(&[frame_type])?;

        match self {
            DerpFrame::ServerKey { key } => {
                writer.write_all(&(32u32.to_be_bytes()))?;
                writer.write_all(key)?;
            }
            DerpFrame::ClientInfo { key } => {
                writer.write_all(&(32u32.to_be_bytes()))?;
                writer.write_all(key)?;
            }
            DerpFrame::SendPacket { dst_key, packet } => {
                let len = 32 + packet.len();
                if len > MAX_PACKET_SIZE {
                    return Err(ProtocolError::FrameTooLarge(len));
                }
                writer.write_all(&(len as u32).to_be_bytes())?;
                writer.write_all(dst_key)?;
                writer.write_all(packet)?;
            }
            DerpFrame::RecvPacket { src_key, packet } => {
                let len = 32 + packet.len();
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
            DerpFrame::Ping { data } => {
                writer.write_all(&(8u32.to_be_bytes()))?;
                writer.write_all(data)?;
            }
            DerpFrame::Pong { data } => {
                writer.write_all(&(8u32.to_be_bytes()))?;
                writer.write_all(data)?;
            }
            DerpFrame::PeerGone { key } => {
                writer.write_all(&(32u32.to_be_bytes()))?;
                writer.write_all(key)?;
            }
            DerpFrame::PeerPresent { key } => {
                writer.write_all(&(32u32.to_be_bytes()))?;
                writer.write_all(key)?;
            }
            DerpFrame::ForwardPacket {
                src_key,
                dst_key,
                packet,
            } => {
                let len = 32 + 32 + packet.len();
                if len > MAX_PACKET_SIZE {
                    return Err(ProtocolError::FrameTooLarge(len));
                }
                writer.write_all(&(len as u32).to_be_bytes())?;
                writer.write_all(src_key)?;
                writer.write_all(dst_key)?;
                writer.write_all(packet)?;
            }
        }

        Ok(())
    }

    /// Deserialize frame from reader.
    pub fn read_from<R: Read>(reader: &mut R) -> Result<Self, ProtocolError> {
        // Read frame type (1 byte)
        let mut type_buf = [0u8; 1];
        reader.read_exact(&mut type_buf)?;
        let frame_type = FrameType::from_u8(type_buf[0])?;

        // Read frame length (4 bytes, big-endian)
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf)?;
        let frame_len = u32::from_be_bytes(len_buf) as usize;

        if frame_len > MAX_PACKET_SIZE {
            return Err(ProtocolError::FrameTooLarge(frame_len));
        }

        // Read frame data based on type
        match frame_type {
            FrameType::ServerKey => {
                if frame_len != 32 {
                    return Err(ProtocolError::InvalidKeySize(frame_len));
                }
                let mut key = [0u8; 32];
                reader.read_exact(&mut key)?;
                Ok(DerpFrame::ServerKey { key })
            }
            FrameType::ClientInfo => {
                if frame_len != 32 {
                    return Err(ProtocolError::InvalidKeySize(frame_len));
                }
                let mut key = [0u8; 32];
                reader.read_exact(&mut key)?;
                Ok(DerpFrame::ClientInfo { key })
            }
            FrameType::SendPacket => {
                if frame_len < 32 {
                    return Err(ProtocolError::IncompleteFrame {
                        expected: 32,
                        actual: frame_len,
                    });
                }
                let mut dst_key = [0u8; 32];
                reader.read_exact(&mut dst_key)?;

                let packet_len = frame_len - 32;
                let mut packet = vec![0u8; packet_len];
                reader.read_exact(&mut packet)?;

                Ok(DerpFrame::SendPacket { dst_key, packet })
            }
            FrameType::RecvPacket => {
                if frame_len < 32 {
                    return Err(ProtocolError::IncompleteFrame {
                        expected: 32,
                        actual: frame_len,
                    });
                }
                let mut src_key = [0u8; 32];
                reader.read_exact(&mut src_key)?;

                let packet_len = frame_len - 32;
                let mut packet = vec![0u8; packet_len];
                reader.read_exact(&mut packet)?;

                Ok(DerpFrame::RecvPacket { src_key, packet })
            }
            FrameType::KeepAlive => {
                if frame_len != 0 {
                    return Err(ProtocolError::IncompleteFrame {
                        expected: 0,
                        actual: frame_len,
                    });
                }
                Ok(DerpFrame::KeepAlive)
            }
            FrameType::Ping => {
                if frame_len != 8 {
                    return Err(ProtocolError::IncompleteFrame {
                        expected: 8,
                        actual: frame_len,
                    });
                }
                let mut data = [0u8; 8];
                reader.read_exact(&mut data)?;
                Ok(DerpFrame::Ping { data })
            }
            FrameType::Pong => {
                if frame_len != 8 {
                    return Err(ProtocolError::IncompleteFrame {
                        expected: 8,
                        actual: frame_len,
                    });
                }
                let mut data = [0u8; 8];
                reader.read_exact(&mut data)?;
                Ok(DerpFrame::Pong { data })
            }
            FrameType::PeerGone => {
                if frame_len != 32 {
                    return Err(ProtocolError::InvalidKeySize(frame_len));
                }
                let mut key = [0u8; 32];
                reader.read_exact(&mut key)?;
                Ok(DerpFrame::PeerGone { key })
            }
            FrameType::PeerPresent => {
                if frame_len != 32 {
                    return Err(ProtocolError::InvalidKeySize(frame_len));
                }
                let mut key = [0u8; 32];
                reader.read_exact(&mut key)?;
                Ok(DerpFrame::PeerPresent { key })
            }
            FrameType::ForwardPacket => {
                if frame_len < 64 {
                    return Err(ProtocolError::IncompleteFrame {
                        expected: 64,
                        actual: frame_len,
                    });
                }
                let mut src_key = [0u8; 32];
                reader.read_exact(&mut src_key)?;
                let mut dst_key = [0u8; 32];
                reader.read_exact(&mut dst_key)?;

                let packet_len = frame_len - 64;
                let mut packet = vec![0u8; packet_len];
                reader.read_exact(&mut packet)?;

                Ok(DerpFrame::ForwardPacket {
                    src_key,
                    dst_key,
                    packet,
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

    /// Async read frame from tokio reader.
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
        let frame_type = FrameType::from_u8(type_buf[0])?;

        // Read frame length (4 bytes, big-endian)
        let mut len_buf = [0u8; 4];
        reader
            .read_exact(&mut len_buf)
            .await
            .map_err(ProtocolError::Io)?;
        let frame_len = u32::from_be_bytes(len_buf) as usize;

        if frame_len > MAX_PACKET_SIZE {
            return Err(ProtocolError::FrameTooLarge(frame_len));
        }

        // Read frame data based on type
        match frame_type {
            FrameType::ServerKey => {
                if frame_len != 32 {
                    return Err(ProtocolError::InvalidKeySize(frame_len));
                }
                let mut key = [0u8; 32];
                reader
                    .read_exact(&mut key)
                    .await
                    .map_err(ProtocolError::Io)?;
                Ok(DerpFrame::ServerKey { key })
            }
            FrameType::ClientInfo => {
                if frame_len != 32 {
                    return Err(ProtocolError::InvalidKeySize(frame_len));
                }
                let mut key = [0u8; 32];
                reader
                    .read_exact(&mut key)
                    .await
                    .map_err(ProtocolError::Io)?;
                Ok(DerpFrame::ClientInfo { key })
            }
            FrameType::SendPacket => {
                if frame_len < 32 {
                    return Err(ProtocolError::IncompleteFrame {
                        expected: 32,
                        actual: frame_len,
                    });
                }
                let mut dst_key = [0u8; 32];
                reader
                    .read_exact(&mut dst_key)
                    .await
                    .map_err(ProtocolError::Io)?;

                let packet_len = frame_len - 32;
                let mut packet = vec![0u8; packet_len];
                reader
                    .read_exact(&mut packet)
                    .await
                    .map_err(ProtocolError::Io)?;

                Ok(DerpFrame::SendPacket { dst_key, packet })
            }
            FrameType::RecvPacket => {
                if frame_len < 32 {
                    return Err(ProtocolError::IncompleteFrame {
                        expected: 32,
                        actual: frame_len,
                    });
                }
                let mut src_key = [0u8; 32];
                reader
                    .read_exact(&mut src_key)
                    .await
                    .map_err(ProtocolError::Io)?;

                let packet_len = frame_len - 32;
                let mut packet = vec![0u8; packet_len];
                reader
                    .read_exact(&mut packet)
                    .await
                    .map_err(ProtocolError::Io)?;

                Ok(DerpFrame::RecvPacket { src_key, packet })
            }
            FrameType::KeepAlive => {
                if frame_len != 0 {
                    return Err(ProtocolError::IncompleteFrame {
                        expected: 0,
                        actual: frame_len,
                    });
                }
                Ok(DerpFrame::KeepAlive)
            }
            FrameType::Ping => {
                if frame_len != 8 {
                    return Err(ProtocolError::IncompleteFrame {
                        expected: 8,
                        actual: frame_len,
                    });
                }
                let mut data = [0u8; 8];
                reader
                    .read_exact(&mut data)
                    .await
                    .map_err(ProtocolError::Io)?;
                Ok(DerpFrame::Ping { data })
            }
            FrameType::Pong => {
                if frame_len != 8 {
                    return Err(ProtocolError::IncompleteFrame {
                        expected: 8,
                        actual: frame_len,
                    });
                }
                let mut data = [0u8; 8];
                reader
                    .read_exact(&mut data)
                    .await
                    .map_err(ProtocolError::Io)?;
                Ok(DerpFrame::Pong { data })
            }
            FrameType::PeerGone => {
                if frame_len != 32 {
                    return Err(ProtocolError::InvalidKeySize(frame_len));
                }
                let mut key = [0u8; 32];
                reader
                    .read_exact(&mut key)
                    .await
                    .map_err(ProtocolError::Io)?;
                Ok(DerpFrame::PeerGone { key })
            }
            FrameType::PeerPresent => {
                if frame_len != 32 {
                    return Err(ProtocolError::InvalidKeySize(frame_len));
                }
                let mut key = [0u8; 32];
                reader
                    .read_exact(&mut key)
                    .await
                    .map_err(ProtocolError::Io)?;
                Ok(DerpFrame::PeerPresent { key })
            }
            FrameType::ForwardPacket => {
                if frame_len < 64 {
                    return Err(ProtocolError::IncompleteFrame {
                        expected: 64,
                        actual: frame_len,
                    });
                }
                let mut src_key = [0u8; 32];
                reader
                    .read_exact(&mut src_key)
                    .await
                    .map_err(ProtocolError::Io)?;
                let mut dst_key = [0u8; 32];
                reader
                    .read_exact(&mut dst_key)
                    .await
                    .map_err(ProtocolError::Io)?;

                let packet_len = frame_len - 64;
                let mut packet = vec![0u8; packet_len];
                reader
                    .read_exact(&mut packet)
                    .await
                    .map_err(ProtocolError::Io)?;

                Ok(DerpFrame::ForwardPacket {
                    src_key,
                    dst_key,
                    packet,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_type_conversion() {
        assert_eq!(FrameType::from_u8(0x01).unwrap(), FrameType::ServerKey);
        assert_eq!(FrameType::from_u8(0x05).unwrap(), FrameType::KeepAlive);
        assert_eq!(FrameType::from_u8(0x09).unwrap(), FrameType::PeerPresent);
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
        assert_eq!(bytes.len(), 1 + 4 + 32); // type + len + key

        let decoded = DerpFrame::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn test_client_info_roundtrip() {
        let key = [123u8; 32];
        let frame = DerpFrame::ClientInfo { key };

        let bytes = frame.to_bytes().unwrap();
        let decoded = DerpFrame::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, frame);
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

        let gone = DerpFrame::PeerGone { key };
        let gone_bytes = gone.to_bytes().unwrap();
        assert_eq!(DerpFrame::from_bytes(&gone_bytes).unwrap(), gone);

        let present = DerpFrame::PeerPresent { key };
        let present_bytes = present.to_bytes().unwrap();
        assert_eq!(DerpFrame::from_bytes(&present_bytes).unwrap(), present);
    }
}
