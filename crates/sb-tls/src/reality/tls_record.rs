//! TLS record layer utilities for REALITY protocol
//!
//! This module provides low-level TLS record manipulation required for REALITY:
//! - ClientHello parsing and modification
//! - ServerHello parsing
//! - TLS extension handling
//!
//! REALITY requires embedding custom data in TLS extensions, which standard
//! TLS libraries don't support. This module provides the necessary primitives.

use std::io::{self, Cursor, Read, Write};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// TLS content type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

impl TryFrom<u8> for ContentType {
    type Error = io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            20 => Ok(ContentType::ChangeCipherSpec),
            21 => Ok(ContentType::Alert),
            22 => Ok(ContentType::Handshake),
            23 => Ok(ContentType::ApplicationData),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid content type: {}", value),
            )),
        }
    }
}

/// TLS handshake type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HandshakeType {
    ClientHello = 1,
    ServerHello = 2,
    Certificate = 11,
    ServerKeyExchange = 12,
    CertificateRequest = 13,
    ServerHelloDone = 14,
    CertificateVerify = 15,
    ClientKeyExchange = 16,
    Finished = 20,
}

impl TryFrom<u8> for HandshakeType {
    type Error = io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(HandshakeType::ClientHello),
            2 => Ok(HandshakeType::ServerHello),
            11 => Ok(HandshakeType::Certificate),
            12 => Ok(HandshakeType::ServerKeyExchange),
            13 => Ok(HandshakeType::CertificateRequest),
            14 => Ok(HandshakeType::ServerHelloDone),
            15 => Ok(HandshakeType::CertificateVerify),
            16 => Ok(HandshakeType::ClientKeyExchange),
            20 => Ok(HandshakeType::Finished),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid handshake type: {}", value),
            )),
        }
    }
}

/// TLS extension type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ExtensionType {
    ServerName = 0,
    SupportedGroups = 10,
    SignatureAlgorithms = 13,
    ApplicationLayerProtocolNegotiation = 16,
    SupportedVersions = 43,
    KeyShare = 51,
    /// REALITY custom extension for authentication data
    RealityAuth = 0xFFCE, // Unofficial extension type for REALITY
}

impl From<ExtensionType> for u16 {
    fn from(value: ExtensionType) -> Self {
        value as u16
    }
}

/// TLS record header
#[derive(Debug, Clone)]
pub struct TlsRecordHeader {
    pub content_type: ContentType,
    pub version: u16,
    pub length: u16,
}

impl TlsRecordHeader {
    /// Read TLS record header from stream
    pub async fn read_from<R: AsyncRead + Unpin>(stream: &mut R) -> io::Result<Self> {
        let content_type = ContentType::try_from(stream.read_u8().await?)?;
        let version = stream.read_u16().await?;
        let length = stream.read_u16().await?;

        Ok(Self {
            content_type,
            version,
            length,
        })
    }

    /// Write TLS record header to stream
    pub async fn write_to<W: AsyncWrite + Unpin>(&self, stream: &mut W) -> io::Result<()> {
        stream.write_u8(self.content_type as u8).await?;
        stream.write_u16(self.version).await?;
        stream.write_u16(self.length).await?;
        Ok(())
    }
}

/// TLS ClientHello message
#[derive(Debug, Clone)]
pub struct ClientHello {
    pub version: u16,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suites: Vec<u16>,
    pub compression_methods: Vec<u8>,
    pub extensions: Vec<TlsExtension>,
}

impl ClientHello {
    /// Parse ClientHello from bytes
    pub fn parse(data: &[u8]) -> io::Result<Self> {
        let mut cursor = Cursor::new(data);

        // Handshake type (should be 1 for ClientHello)
        let handshake_type = read_u8(&mut cursor)?;
        if handshake_type != HandshakeType::ClientHello as u8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Not a ClientHello",
            ));
        }

        // Handshake length (3 bytes)
        let _handshake_len = read_u24(&mut cursor)?;

        // Client version
        let version = read_u16(&mut cursor)?;

        // Random (32 bytes)
        let mut random = [0u8; 32];
        Read::read_exact(&mut cursor, &mut random)?;

        // Session ID
        let session_id_len = read_u8(&mut cursor)? as usize;
        let mut session_id = vec![0u8; session_id_len];
        Read::read_exact(&mut cursor, &mut session_id)?;

        // Cipher suites
        let cipher_suites_len = read_u16(&mut cursor)? as usize;
        let mut cipher_suites = Vec::new();
        for _ in 0..(cipher_suites_len / 2) {
            cipher_suites.push(read_u16(&mut cursor)?);
        }

        // Compression methods
        let compression_len = read_u8(&mut cursor)? as usize;
        let mut compression_methods = vec![0u8; compression_len];
        Read::read_exact(&mut cursor, &mut compression_methods)?;

        // Extensions
        let extensions = if cursor.position() < data.len() as u64 {
            let extensions_len = read_u16(&mut cursor)? as usize;
            let extensions_start = cursor.position() as usize;
            let extensions_data = &data[extensions_start..extensions_start + extensions_len];
            Self::parse_extensions(extensions_data)?
        } else {
            Vec::new()
        };

        Ok(Self {
            version,
            random,
            session_id,
            cipher_suites,
            compression_methods,
            extensions,
        })
    }

    /// Parse TLS extensions
    fn parse_extensions(data: &[u8]) -> io::Result<Vec<TlsExtension>> {
        let mut cursor = Cursor::new(data);
        let mut extensions = Vec::new();

        while cursor.position() < data.len() as u64 {
            let ext_type = read_u16(&mut cursor)?;
            let ext_len = read_u16(&mut cursor)? as usize;
            let mut ext_data = vec![0u8; ext_len];
            Read::read_exact(&mut cursor, &mut ext_data)?;

            extensions.push(TlsExtension {
                extension_type: ext_type,
                data: ext_data,
            });
        }

        Ok(extensions)
    }

    /// Serialize ClientHello to bytes
    pub fn serialize(&self) -> io::Result<Vec<u8>> {
        let mut buffer = Vec::new();

        // Write version
        write_u16(&mut buffer, self.version)?;

        // Write random
        Write::write_all(&mut buffer, &self.random)?;

        // Write session ID
        write_u8(&mut buffer, self.session_id.len() as u8)?;
        Write::write_all(&mut buffer, &self.session_id)?;

        // Write cipher suites
        write_u16(&mut buffer, (self.cipher_suites.len() * 2) as u16)?;
        for suite in &self.cipher_suites {
            write_u16(&mut buffer, *suite)?;
        }

        // Write compression methods
        write_u8(&mut buffer, self.compression_methods.len() as u8)?;
        Write::write_all(&mut buffer, &self.compression_methods)?;

        // Write extensions
        let extensions_data = self.serialize_extensions()?;
        write_u16(&mut buffer, extensions_data.len() as u16)?;
        Write::write_all(&mut buffer, &extensions_data)?;

        // Prepend handshake header
        let mut result = Vec::new();
        write_u8(&mut result, HandshakeType::ClientHello as u8)?;
        write_u24(&mut result, buffer.len() as u32)?;
        Write::write_all(&mut result, &buffer)?;

        Ok(result)
    }

    /// Serialize extensions
    fn serialize_extensions(&self) -> io::Result<Vec<u8>> {
        let mut buffer = Vec::new();

        for ext in &self.extensions {
            write_u16(&mut buffer, ext.extension_type)?;
            write_u16(&mut buffer, ext.data.len() as u16)?;
            Write::write_all(&mut buffer, &ext.data)?;
        }

        Ok(buffer)
    }

    /// Find extension by type
    pub fn find_extension(&self, ext_type: u16) -> Option<&TlsExtension> {
        self.extensions
            .iter()
            .find(|ext| ext.extension_type == ext_type)
    }

    /// Add or replace extension
    pub fn set_extension(&mut self, ext_type: u16, data: Vec<u8>) {
        // Remove existing extension of this type
        self.extensions.retain(|ext| ext.extension_type != ext_type);

        // Add new extension
        self.extensions.push(TlsExtension {
            extension_type: ext_type,
            data,
        });
    }

    /// Extract SNI (Server Name Indication) from extensions
    pub fn get_sni(&self) -> Option<String> {
        let sni_ext = self.find_extension(ExtensionType::ServerName as u16)?;

        // SNI extension format:
        // - u16: server name list length
        // - u8: name type (0 = host_name)
        // - u16: name length
        // - bytes: name
        if sni_ext.data.len() < 5 {
            return None;
        }

        let mut cursor = Cursor::new(&sni_ext.data);
        let _list_len = read_u16(&mut cursor).ok()?;
        let name_type = read_u8(&mut cursor).ok()?;

        if name_type != 0 {
            return None; // Only support host_name type
        }

        let name_len = read_u16(&mut cursor).ok()? as usize;
        let mut name_bytes = vec![0u8; name_len];
        Read::read_exact(&mut cursor, &mut name_bytes).ok()?;

        String::from_utf8(name_bytes).ok()
    }
}

/// TLS extension
#[derive(Debug, Clone)]
pub struct TlsExtension {
    pub extension_type: u16,
    pub data: Vec<u8>,
}

impl TlsExtension {
    /// Create REALITY authentication extension
    ///
    /// Format:
    /// - 32 bytes: client public key
    /// - 2 bytes: short_id length
    /// - N bytes: short_id
    /// - 32 bytes: auth_hash
    pub fn reality_auth(client_public_key: &[u8; 32], short_id: &[u8], auth_hash: &[u8; 32]) -> Self {
        let mut data = Vec::new();
        data.extend_from_slice(client_public_key);
        data.extend_from_slice(&(short_id.len() as u16).to_be_bytes());
        data.extend_from_slice(short_id);
        data.extend_from_slice(auth_hash);

        Self {
            extension_type: ExtensionType::RealityAuth as u16,
            data,
        }
    }

    /// Parse REALITY authentication extension
    ///
    /// Returns: (client_public_key, short_id, auth_hash)
    pub fn parse_reality_auth(&self) -> io::Result<([u8; 32], Vec<u8>, [u8; 32])> {
        if self.extension_type != ExtensionType::RealityAuth as u16 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Not a REALITY auth extension",
            ));
        }

        let mut cursor = Cursor::new(&self.data);

        // Client public key (32 bytes)
        let mut client_public_key = [0u8; 32];
        Read::read_exact(&mut cursor, &mut client_public_key)?;

        // Short ID length
        let short_id_len = read_u16(&mut cursor)? as usize;
        let mut short_id = vec![0u8; short_id_len];
        Read::read_exact(&mut cursor, &mut short_id)?;

        // Auth hash (32 bytes)
        let mut auth_hash = [0u8; 32];
        Read::read_exact(&mut cursor, &mut auth_hash)?;

        Ok((client_public_key, short_id, auth_hash))
    }
}

/// Helper: Read u8
fn read_u8<R: Read>(reader: &mut R) -> io::Result<u8> {
    let mut buf = [0u8; 1];
    reader.read_exact(&mut buf)?;
    Ok(buf[0])
}

/// Helper: Read u16 (big-endian)
fn read_u16<R: Read>(reader: &mut R) -> io::Result<u16> {
    let mut buf = [0u8; 2];
    reader.read_exact(&mut buf)?;
    Ok(u16::from_be_bytes(buf))
}

/// Helper: Read u24 (big-endian, 3 bytes)
fn read_u24<R: Read>(reader: &mut R) -> io::Result<u32> {
    let mut buf = [0u8; 3];
    reader.read_exact(&mut buf)?;
    Ok(u32::from_be_bytes([0, buf[0], buf[1], buf[2]]))
}

/// Helper: Write u8
fn write_u8<W: Write>(writer: &mut W, value: u8) -> io::Result<()> {
    writer.write_all(&[value])
}

/// Helper: Write u16 (big-endian)
fn write_u16<W: Write>(writer: &mut W, value: u16) -> io::Result<()> {
    writer.write_all(&value.to_be_bytes())
}

/// Helper: Write u24 (big-endian, 3 bytes)
fn write_u24<W: Write>(writer: &mut W, value: u32) -> io::Result<()> {
    let bytes = value.to_be_bytes();
    writer.write_all(&bytes[1..4])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reality_auth_extension() {
        let client_public_key = [0x42u8; 32];
        let short_id = vec![0x01, 0xab];
        let auth_hash = [0x99u8; 32];

        let ext = TlsExtension::reality_auth(&client_public_key, &short_id, &auth_hash);

        assert_eq!(ext.extension_type, ExtensionType::RealityAuth as u16);
        assert_eq!(ext.data.len(), 32 + 2 + short_id.len() + 32);

        // Parse it back
        let (parsed_pk, parsed_sid, parsed_hash) = ext.parse_reality_auth().unwrap();
        assert_eq!(parsed_pk, client_public_key);
        assert_eq!(parsed_sid, short_id);
        assert_eq!(parsed_hash, auth_hash);
    }

    #[test]
    fn test_client_hello_serialization() {
        let mut hello = ClientHello {
            version: 0x0303, // TLS 1.2
            random: [0x42; 32],
            session_id: vec![],
            cipher_suites: vec![0xC02F, 0xC030],
            compression_methods: vec![0x00],
            extensions: vec![],
        };

        // Add SNI extension
        let sni_data = {
            let mut data = Vec::new();
            let hostname = b"example.com";
            write_u16(&mut data, (hostname.len() + 3) as u16).unwrap(); // list length
            write_u8(&mut data, 0).unwrap(); // name type = host_name
            write_u16(&mut data, hostname.len() as u16).unwrap();
            data.extend_from_slice(hostname);
            data
        };
        hello.set_extension(ExtensionType::ServerName as u16, sni_data);

        // Serialize
        let serialized = hello.serialize().unwrap();

        // Parse back
        let parsed = ClientHello::parse(&serialized).unwrap();

        assert_eq!(parsed.version, hello.version);
        assert_eq!(parsed.random, hello.random);
        assert_eq!(parsed.cipher_suites, hello.cipher_suites);
        assert_eq!(parsed.get_sni(), Some("example.com".to_string()));
    }
}
