#[cfg(feature = "proto_trojan_dry")]
pub mod trojan_dry {
    use serde::{Deserialize, Serialize};

    // 简单的 hex 编码实现
    fn hex_encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DryrunReport {
        pub bytes_len: usize,
        pub meta: ConnectMeta,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ConnectMeta {
        pub kind: String,     // "hello" | "tls_first"
        pub hashes: bool,     // false (占位)
        pub ordered: bool,    // false (占位)
        pub normalized: bool, // false (占位)
    }

    /// 构建 Trojan hello 字节序列
    /// 格式：hex(sha224(password)) + CRLF + SOCKS5-like target + CRLF + data
    pub fn build_hello(password: &str, host: &str, port: u16) -> Vec<u8> {
        use blake3::Hasher;

        // 使用 blake3 模拟 sha224 (占位实现)
        let mut hasher = Hasher::new();
        hasher.update(password.as_bytes());
        let hash = hasher.finalize();
        let hash_hex = hex_encode(&hash.as_bytes()[..28]); // 取前28字节模拟sha224

        let mut result = Vec::new();

        // 1. 密码哈希
        result.extend_from_slice(hash_hex.as_bytes());
        result.extend_from_slice(b"\r\n");

        // 2. 目标地址 (简化的 SOCKS5 格式)
        // ATYP(1) + ADDR + PORT(2)
        result.push(0x03); // Domain name
        result.push(host.len() as u8);
        result.extend_from_slice(host.as_bytes());
        result.extend_from_slice(&port.to_be_bytes());
        result.extend_from_slice(b"\r\n");

        result
    }

    /// 生成连接报告
    pub fn report_shape(bytes_len: usize, with_tls: bool) -> DryrunReport {
        DryrunReport {
            bytes_len,
            meta: ConnectMeta {
                kind: if with_tls {
                    "tls_first".to_string()
                } else {
                    "hello".to_string()
                },
                hashes: false,
                ordered: false,
                normalized: false,
            },
        }
    }

    /// 构建带 TLS 的首包（占位）
    pub fn build_tls_first(password: &str, host: &str, port: u16) -> Vec<u8> {
        let mut hello = build_hello(password, host, port);

        // 添加占位 TLS ClientHello 标识
        let tls_marker = b"TLS_CLIENT_HELLO_PLACEHOLDER";
        hello.extend_from_slice(tls_marker);

        hello
    }
}

#[cfg(feature = "proto_trojan_dry")]
pub use trojan_dry::*;
