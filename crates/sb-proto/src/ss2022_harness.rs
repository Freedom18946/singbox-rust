//! R123: SS2022 最小连通 harness（结构对齐 Trojan）
use crate::connector::OutboundConnector; // 若无统一 trait，保留最小自洽实现
use sb_transport::{Dialer, TcpDialer};
use std::time::Instant;

#[cfg(feature = "proto_ss2022_tls_first")]
use sb_transport::tls::{smoke_empty_roots_config, TlsDialer};

pub struct ConnectReport {
    pub ok: bool,
    pub path: &'static str,
    pub elapsed_ms: u64,
}

pub async fn connect_env(
    host: &str,
    port: u16,
    timeout_ms: u64,
    tls: bool,
) -> Result<ConnectReport, String> {
    let start = Instant::now();
    // 这里只做最小 dial；真实握手后续扩展
    if tls {
        #[cfg(feature = "proto_ss2022_tls_first")]
        {
            let config = smoke_empty_roots_config();
            let tls_dialer = TlsDialer::from_env(TcpDialer, config);
            let _io = tokio::time::timeout(
                std::time::Duration::from_millis(timeout_ms),
                tls_dialer.connect(host, port),
            )
            .await
            .map_err(|_| "timeout".to_string())?
            .map_err(|e| e.to_string())?;
            Ok(ConnectReport {
                ok: true,
                path: "tls",
                elapsed_ms: start.elapsed().as_millis() as u64,
            })
        }
        #[cfg(not(feature = "proto_ss2022_tls_first"))]
        {
            Err("tls not implemented".into())
        }
    } else {
        let dialer = TcpDialer;
        let _io = tokio::time::timeout(
            std::time::Duration::from_millis(timeout_ms),
            dialer.connect(host, port),
        )
        .await
        .map_err(|_| "timeout".to_string())?
        .map_err(|e| e.to_string())?;
        Ok(ConnectReport {
            ok: true,
            path: "tcp",
            elapsed_ms: start.elapsed().as_millis() as u64,
        })
    }
}

/// R133: SS2022 TLS first packet builder (read-only preview)
#[cfg(feature = "proto_ss2022_tls_first")]
pub fn build_tls_first_packet(payload: &[u8], sni: Option<&str>) -> Vec<u8> {
    // 模拟 TLS Client Hello 第一包构造
    // 这是一个 read-only 预览实现，不进行实际网络连接
    let mut packet = Vec::new();

    // TLS Record Header (5 bytes)
    packet.push(0x16); // Content Type: Handshake
    packet.extend_from_slice(&[0x03, 0x03]); // Version: TLS 1.2

    // 计算 Client Hello 长度（占位，稍后填充）
    let length_pos = packet.len();
    packet.extend_from_slice(&[0x00, 0x00]); // Length placeholder

    let hello_start = packet.len();

    // Client Hello
    packet.push(0x01); // Handshake Type: Client Hello

    // Client Hello 长度占位
    let hello_length_pos = packet.len();
    packet.extend_from_slice(&[0x00, 0x00, 0x00]); // Length placeholder

    let hello_content_start = packet.len();

    // Version
    packet.extend_from_slice(&[0x03, 0x03]); // TLS 1.2

    // Random (32 bytes) - 使用 blake3 哈希 payload 作为伪随机
    let mut hasher = blake3::Hasher::new();
    hasher.update(payload);
    let hash = hasher.finalize();
    packet.extend_from_slice(&hash.as_bytes()[..32]);

    // Session ID Length
    packet.push(0x00); // No session ID

    // Cipher Suites Length
    packet.extend_from_slice(&[0x00, 0x04]); // 2 cipher suites

    // Cipher Suites
    packet.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
    packet.extend_from_slice(&[0x13, 0x02]); // TLS_AES_256_GCM_SHA384

    // Compression Methods Length
    packet.push(0x01);

    // Compression Methods
    packet.push(0x00); // No compression

    // Extensions Length (占位)
    let ext_length_pos = packet.len();
    packet.extend_from_slice(&[0x00, 0x00]);
    let ext_start = packet.len();

    // SNI Extension (if provided)
    if let Some(sni_name) = sni {
        // Server Name Indication Extension
        packet.extend_from_slice(&[0x00, 0x00]); // Extension Type: server_name

        let sni_ext_length_pos = packet.len();
        packet.extend_from_slice(&[0x00, 0x00]); // Extension Length placeholder
        let sni_ext_start = packet.len();

        // Server Name List Length
        let sni_list_length_pos = packet.len();
        packet.extend_from_slice(&[0x00, 0x00]);
        let sni_list_start = packet.len();

        // Server Name Type
        packet.push(0x00); // host_name

        // Server Name Length
        let name_bytes = sni_name.as_bytes();
        packet.extend_from_slice(&[0x00, name_bytes.len() as u8]);

        // Server Name
        packet.extend_from_slice(name_bytes);

        // 填充长度字段
        let sni_list_length = packet.len() - sni_list_start;
        packet[sni_list_length_pos..sni_list_length_pos + 2]
            .copy_from_slice(&(sni_list_length as u16).to_be_bytes());

        let sni_ext_length = packet.len() - sni_ext_start;
        packet[sni_ext_length_pos..sni_ext_length_pos + 2]
            .copy_from_slice(&(sni_ext_length as u16).to_be_bytes());
    }

    // 填充扩展总长度
    let ext_total_length = packet.len() - ext_start;
    packet[ext_length_pos..ext_length_pos + 2]
        .copy_from_slice(&(ext_total_length as u16).to_be_bytes());

    // 填充 Client Hello 长度
    let hello_content_length = packet.len() - hello_content_start;
    let hello_content_bytes = (hello_content_length as u32).to_be_bytes();
    packet[hello_length_pos..hello_length_pos + 3].copy_from_slice(&hello_content_bytes[1..]);

    // 填充 TLS Record 长度
    let record_length = packet.len() - hello_start;
    packet[length_pos..length_pos + 2].copy_from_slice(&(record_length as u16).to_be_bytes());

    packet
}

#[cfg(feature = "proto_ss2022_tls_first")]
pub fn preview_tls_first_packet(payload: &[u8]) -> String {
    use std::fmt::Write;
    let packet = build_tls_first_packet(payload, Some("example.com"));
    let mut hex_output = String::new();
    for (i, byte) in packet.iter().enumerate() {
        if i % 16 == 0 {
            if i > 0 {
                writeln!(&mut hex_output).unwrap();
            }
            write!(&mut hex_output, "{:04x}: ", i).unwrap();
        }
        write!(&mut hex_output, "{:02x} ", byte).unwrap();
    }
    if !packet.is_empty() {
        writeln!(&mut hex_output).unwrap();
    }
    hex_output
}
