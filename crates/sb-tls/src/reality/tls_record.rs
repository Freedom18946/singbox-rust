//! TLS record layer utilities for REALITY protocol
//! REALITY 协议的 TLS 记录层工具
//!
//! This module provides low-level TLS record manipulation required for REALITY:
//! 此模块提供 REALITY 所需的低级 TLS 记录操作：
//! - `ClientHello` parsing and modification
//! - `ClientHello` 解析和修改
//! - `ServerHello` parsing
//! - `ServerHello` 解析
//! - TLS extension handling
//! - TLS 扩展处理
//!
//! REALITY requires embedding custom data in TLS extensions, which standard
//! TLS libraries don't support. This module provides the necessary primitives.
//! REALITY 需要在 TLS 扩展中嵌入自定义数据，这是标准 TLS 库不支持的。此模块提供了必要的原语。

use std::io::{self, Cursor, Read, Write};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// TLS content type
/// TLS 内容类型
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
            20 => Ok(Self::ChangeCipherSpec),
            21 => Ok(Self::Alert),
            22 => Ok(Self::Handshake),
            23 => Ok(Self::ApplicationData),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid content type: {value}"),
            )),
        }
    }
}

/// TLS handshake type
/// TLS 握手类型
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
            1 => Ok(Self::ClientHello),
            2 => Ok(Self::ServerHello),
            11 => Ok(Self::Certificate),
            12 => Ok(Self::ServerKeyExchange),
            13 => Ok(Self::CertificateRequest),
            14 => Ok(Self::ServerHelloDone),
            15 => Ok(Self::CertificateVerify),
            16 => Ok(Self::ClientKeyExchange),
            20 => Ok(Self::Finished),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid handshake type: {value}"),
            )),
        }
    }
}

/// TLS extension type
/// TLS 扩展类型
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
    /// REALITY 认证数据的自定义扩展
    RealityAuth = 0xFFCE, // Unofficial extension type for REALITY
}

impl From<ExtensionType> for u16 {
    fn from(value: ExtensionType) -> Self {
        value as Self
    }
}

/// TLS record header
/// TLS 记录头
#[derive(Debug, Clone)]
pub struct TlsRecordHeader {
    pub content_type: ContentType,
    pub version: u16,
    pub length: u16,
}

impl TlsRecordHeader {
    /// Read TLS record header from stream
    /// 从流中读取 TLS 记录头
    ///
    /// # Errors
    /// # 错误
    /// Returns an error if reading from the stream fails or data is invalid.
    /// 如果从流中读取失败或数据无效，则返回错误。
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
    /// 将 TLS 记录头写入流
    ///
    /// # Errors
    /// # 错误
    /// Returns an error if writing to the stream fails.
    /// 如果写入流失败，则返回错误。
    pub async fn write_to<W: AsyncWrite + Unpin>(&self, stream: &mut W) -> io::Result<()> {
        stream.write_u8(self.content_type as u8).await?;
        stream.write_u16(self.version).await?;
        stream.write_u16(self.length).await?;
        Ok(())
    }
}

/// TLS `ClientHello` message
/// TLS `ClientHello` 消息
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
    /// Parse `ClientHello` from bytes
    /// 从字节解析 `ClientHello`
    ///
    /// # Errors
    /// # 错误
    /// Returns an error if the buffer is malformed or truncated.
    /// 如果缓冲区格式错误或被截断，则返回错误。
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
            let extensions_start = usize::try_from(cursor.position()).unwrap_or(0);
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
    /// 解析 TLS 扩展
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

    /// Serialize `ClientHello` to bytes
    /// 将 `ClientHello` 序列化为字节
    ///
    /// # Errors
    /// # 错误
    /// Returns an error if writing into the buffer fails.
    /// 如果写入缓冲区失败，则返回错误。
    pub fn serialize(&self) -> io::Result<Vec<u8>> {
        let mut buffer = Vec::new();

        // Write version
        write_u16(&mut buffer, self.version)?;

        // Write random
        Write::write_all(&mut buffer, &self.random)?;

        // Write session ID
        write_u8(
            &mut buffer,
            u8::try_from(self.session_id.len()).unwrap_or(u8::MAX),
        )?;
        Write::write_all(&mut buffer, &self.session_id)?;

        // Write cipher suites
        write_u16(
            &mut buffer,
            u16::try_from(self.cipher_suites.len() * 2).unwrap_or(u16::MAX),
        )?;
        for suite in &self.cipher_suites {
            write_u16(&mut buffer, *suite)?;
        }

        // Write compression methods
        write_u8(
            &mut buffer,
            u8::try_from(self.compression_methods.len()).unwrap_or(u8::MAX),
        )?;
        Write::write_all(&mut buffer, &self.compression_methods)?;

        // Write extensions
        let extensions_data = self.serialize_extensions()?;
        write_u16(
            &mut buffer,
            u16::try_from(extensions_data.len()).unwrap_or(u16::MAX),
        )?;
        Write::write_all(&mut buffer, &extensions_data)?;

        // Prepend handshake header
        let mut result = Vec::new();
        write_u8(&mut result, HandshakeType::ClientHello as u8)?;
        write_u24(&mut result, u32::try_from(buffer.len()).unwrap_or(u32::MAX))?;
        Write::write_all(&mut result, &buffer)?;

        Ok(result)
    }

    /// Serialize extensions
    /// 序列化扩展
    fn serialize_extensions(&self) -> io::Result<Vec<u8>> {
        let mut buffer = Vec::new();

        for ext in &self.extensions {
            write_u16(&mut buffer, ext.extension_type)?;
            write_u16(
                &mut buffer,
                u16::try_from(ext.data.len()).unwrap_or(u16::MAX),
            )?;
            Write::write_all(&mut buffer, &ext.data)?;
        }

        Ok(buffer)
    }

    /// Find extension by type
    /// 按类型查找扩展
    #[must_use]
    pub fn find_extension(&self, ext_type: u16) -> Option<&TlsExtension> {
        self.extensions
            .iter()
            .find(|ext| ext.extension_type == ext_type)
    }

    /// Add or replace extension
    /// 添加或替换扩展
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
    /// 从扩展中提取 SNI (服务器名称指示)
    #[must_use]
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
/// TLS 扩展
#[derive(Debug, Clone)]
pub struct TlsExtension {
    pub extension_type: u16,
    pub data: Vec<u8>,
}

impl TlsExtension {
    /// Create REALITY authentication extension
    /// 创建 REALITY 认证扩展
    ///
    /// Format:
    /// 格式：
    /// - 32 bytes: client public key
    /// - 32 字节：客户端公钥
    /// - 2 bytes: `short_id` length
    /// - 2 字节：`short_id` 长度
    /// - N bytes: `short_id`
    /// - N 字节：`short_id`
    /// - 32 bytes: `auth_hash`
    /// - 32 字节：`auth_hash`
    #[must_use]
    pub fn reality_auth(
        client_public_key: &[u8; 32],
        short_id: &[u8],
        auth_hash: &[u8; 32],
    ) -> Self {
        let mut data = Vec::new();
        data.extend_from_slice(client_public_key);
        data.extend_from_slice(
            &u16::try_from(short_id.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        data.extend_from_slice(short_id);
        data.extend_from_slice(auth_hash);

        Self {
            extension_type: ExtensionType::RealityAuth as u16,
            data,
        }
    }

    /// Parse REALITY authentication extension
    /// 解析 REALITY 认证扩展
    ///
    /// Returns: (`client_public_key`, `short_id`, `auth_hash`)
    /// 返回：(`client_public_key`, `short_id`, `auth_hash`)
    ///
    /// # Errors
    /// # 错误
    /// Returns an error if the extension type or buffer layout is invalid.
    /// 如果扩展类型或缓冲区布局无效，则返回错误。
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
#[allow(clippy::unwrap_used, clippy::identity_op)]
mod tests {
    use super::*;

    // ========== REALITY Auth Extension Tests ==========

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
    fn test_reality_auth_extension_empty_short_id() {
        let client_public_key = [0x11u8; 32];
        let short_id = vec![];
        let auth_hash = [0x22u8; 32];

        let ext = TlsExtension::reality_auth(&client_public_key, &short_id, &auth_hash);

        assert_eq!(ext.data.len(), 32 + 2 + 0 + 32); // 66 bytes

        let (parsed_pk, parsed_sid, parsed_hash) = ext.parse_reality_auth().unwrap();
        assert_eq!(parsed_pk, client_public_key);
        assert_eq!(parsed_sid, short_id);
        assert_eq!(parsed_hash, auth_hash);
    }

    #[test]
    fn test_reality_auth_extension_max_short_id() {
        let client_public_key = [0xAAu8; 32];
        let short_id = vec![0xBB; 8]; // Max 8 bytes
        let auth_hash = [0xCCu8; 32];

        let ext = TlsExtension::reality_auth(&client_public_key, &short_id, &auth_hash);

        let (parsed_pk, parsed_sid, parsed_hash) = ext.parse_reality_auth().unwrap();
        assert_eq!(parsed_pk, client_public_key);
        assert_eq!(parsed_sid, short_id);
        assert_eq!(parsed_hash, auth_hash);
    }

    #[test]
    fn test_reality_auth_extension_parse_invalid_type() {
        let ext = TlsExtension {
            extension_type: ExtensionType::ServerName as u16,
            data: vec![0; 66],
        };

        let result = ext.parse_reality_auth();
        assert!(result.is_err());
    }

    #[test]
    fn test_reality_auth_extension_parse_truncated() {
        let ext = TlsExtension {
            extension_type: ExtensionType::RealityAuth as u16,
            data: vec![0; 10], // Too short
        };

        let result = ext.parse_reality_auth();
        assert!(result.is_err());
    }

    #[test]
    fn test_reality_auth_extension_roundtrip() {
        // Test various combinations
        let test_cases = vec![
            ([0x00u8; 32], vec![], [0xFFu8; 32]),
            ([0x11u8; 32], vec![0x01], [0x22u8; 32]),
            ([0x33u8; 32], vec![0x01, 0x02, 0x03, 0x04], [0x44u8; 32]),
            ([0x55u8; 32], vec![0xAA; 8], [0x66u8; 32]),
        ];

        for (pk, sid, hash) in test_cases {
            let ext = TlsExtension::reality_auth(&pk, &sid, &hash);
            let (parsed_pk, parsed_sid, parsed_hash) = ext.parse_reality_auth().unwrap();
            assert_eq!(parsed_pk, pk);
            assert_eq!(parsed_sid, sid);
            assert_eq!(parsed_hash, hash);
        }
    }

    // ========== ClientHello Serialization Tests ==========

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

    #[test]
    fn test_client_hello_with_reality_extension() {
        let mut hello = ClientHello {
            version: 0x0303,
            random: [0x42; 32],
            session_id: vec![],
            cipher_suites: vec![0xC02F],
            compression_methods: vec![0x00],
            extensions: vec![],
        };

        // Add REALITY auth extension
        let client_pk = [0x11u8; 32];
        let short_id = vec![0x01, 0xab];
        let auth_hash = [0x22u8; 32];
        hello.extensions.push(TlsExtension::reality_auth(
            &client_pk, &short_id, &auth_hash,
        ));

        // Serialize and parse
        let serialized = hello.serialize().unwrap();
        let parsed = ClientHello::parse(&serialized).unwrap();

        // Verify REALITY extension is preserved
        let reality_ext = parsed
            .find_extension(ExtensionType::RealityAuth as u16)
            .unwrap();
        let (parsed_pk, parsed_sid, parsed_hash) = reality_ext.parse_reality_auth().unwrap();
        assert_eq!(parsed_pk, client_pk);
        assert_eq!(parsed_sid, short_id);
        assert_eq!(parsed_hash, auth_hash);
    }

    #[test]
    fn test_client_hello_multiple_extensions() {
        let mut hello = ClientHello {
            version: 0x0303,
            random: [0x42; 32],
            session_id: vec![],
            cipher_suites: vec![0xC02F, 0xC030],
            compression_methods: vec![0x00],
            extensions: vec![],
        };

        // Add SNI
        let sni_data = {
            let mut data = Vec::new();
            let hostname = b"test.com";
            write_u16(&mut data, (hostname.len() + 3) as u16).unwrap();
            write_u8(&mut data, 0).unwrap();
            write_u16(&mut data, hostname.len() as u16).unwrap();
            data.extend_from_slice(hostname);
            data
        };
        hello.set_extension(ExtensionType::ServerName as u16, sni_data);

        // Add REALITY
        hello.extensions.push(TlsExtension::reality_auth(
            &[0x33u8; 32],
            &[0xAB, 0xCD],
            &[0x44u8; 32],
        ));

        // Serialize and parse
        let serialized = hello.serialize().unwrap();
        let parsed = ClientHello::parse(&serialized).unwrap();

        assert_eq!(parsed.extensions.len(), 2);
        assert_eq!(parsed.get_sni(), Some("test.com".to_string()));
        assert!(
            parsed
                .find_extension(ExtensionType::RealityAuth as u16)
                .is_some()
        );
    }

    #[test]
    fn test_client_hello_set_extension_replaces() {
        let mut hello = ClientHello {
            version: 0x0303,
            random: [0x42; 32],
            session_id: vec![],
            cipher_suites: vec![0xC02F],
            compression_methods: vec![0x00],
            extensions: vec![],
        };

        // Add SNI
        hello.set_extension(ExtensionType::ServerName as u16, vec![1, 2, 3]);
        assert_eq!(hello.extensions.len(), 1);

        // Replace SNI
        hello.set_extension(ExtensionType::ServerName as u16, vec![4, 5, 6]);
        assert_eq!(hello.extensions.len(), 1);
        assert_eq!(
            hello
                .find_extension(ExtensionType::ServerName as u16)
                .unwrap()
                .data,
            vec![4, 5, 6]
        );
    }

    #[test]
    fn test_client_hello_find_extension() {
        let mut hello = ClientHello {
            version: 0x0303,
            random: [0x42; 32],
            session_id: vec![],
            cipher_suites: vec![0xC02F],
            compression_methods: vec![0x00],
            extensions: vec![],
        };

        // No extensions
        assert!(
            hello
                .find_extension(ExtensionType::ServerName as u16)
                .is_none()
        );

        // Add extension
        hello.set_extension(ExtensionType::ServerName as u16, vec![1, 2, 3]);
        assert!(
            hello
                .find_extension(ExtensionType::ServerName as u16)
                .is_some()
        );
        assert!(
            hello
                .find_extension(ExtensionType::RealityAuth as u16)
                .is_none()
        );
    }

    #[test]
    fn test_client_hello_get_sni_missing() {
        let hello = ClientHello {
            version: 0x0303,
            random: [0x42; 32],
            session_id: vec![],
            cipher_suites: vec![0xC02F],
            compression_methods: vec![0x00],
            extensions: vec![],
        };

        assert!(hello.get_sni().is_none());
    }

    #[test]
    fn test_client_hello_get_sni_invalid() {
        let mut hello = ClientHello {
            version: 0x0303,
            random: [0x42; 32],
            session_id: vec![],
            cipher_suites: vec![0xC02F],
            compression_methods: vec![0x00],
            extensions: vec![],
        };

        // Add invalid SNI extension (too short)
        hello.set_extension(ExtensionType::ServerName as u16, vec![0, 1]);
        assert!(hello.get_sni().is_none());
    }

    #[test]
    fn test_client_hello_with_session_id() {
        let hello = ClientHello {
            version: 0x0303,
            random: [0x42; 32],
            session_id: vec![0x01, 0x02, 0x03, 0x04],
            cipher_suites: vec![0xC02F],
            compression_methods: vec![0x00],
            extensions: vec![],
        };

        let serialized = hello.serialize().unwrap();
        let parsed = ClientHello::parse(&serialized).unwrap();

        assert_eq!(parsed.session_id, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_client_hello_multiple_cipher_suites() {
        let hello = ClientHello {
            version: 0x0303,
            random: [0x42; 32],
            session_id: vec![],
            cipher_suites: vec![0xC02F, 0xC030, 0x009C, 0x009D],
            compression_methods: vec![0x00],
            extensions: vec![],
        };

        let serialized = hello.serialize().unwrap();
        let parsed = ClientHello::parse(&serialized).unwrap();

        assert_eq!(parsed.cipher_suites, vec![0xC02F, 0xC030, 0x009C, 0x009D]);
    }

    #[test]
    fn test_client_hello_no_extensions() {
        let hello = ClientHello {
            version: 0x0303,
            random: [0x42; 32],
            session_id: vec![],
            cipher_suites: vec![0xC02F],
            compression_methods: vec![0x00],
            extensions: vec![],
        };

        let serialized = hello.serialize().unwrap();
        let parsed = ClientHello::parse(&serialized).unwrap();

        assert_eq!(parsed.extensions.len(), 0);
    }

    // ========== Content Type Tests ==========

    #[test]
    fn test_content_type_conversion() {
        assert_eq!(ContentType::try_from(22).unwrap(), ContentType::Handshake);
        assert_eq!(
            ContentType::try_from(23).unwrap(),
            ContentType::ApplicationData
        );
        assert!(ContentType::try_from(99).is_err());
    }

    #[test]
    fn test_handshake_type_conversion() {
        assert_eq!(
            HandshakeType::try_from(1).unwrap(),
            HandshakeType::ClientHello
        );
        assert_eq!(
            HandshakeType::try_from(2).unwrap(),
            HandshakeType::ServerHello
        );
        assert!(HandshakeType::try_from(99).is_err());
    }
}
