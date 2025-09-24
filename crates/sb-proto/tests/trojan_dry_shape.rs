#[cfg(feature = "proto_trojan_dry")]
mod trojan_dry_tests {
    use sb_proto::trojan_dry::*;

    #[test]
    fn test_build_hello_basic() {
        let bytes = build_hello("testpass", "example.com", 443);
        assert!(!bytes.is_empty());

        // 验证包含CRLF
        let s = String::from_utf8_lossy(&bytes);
        assert!(s.contains("\r\n"));

        println!("Trojan hello bytes: {} bytes", bytes.len());
        println!("Content: {}", hex::encode(&bytes));
    }

    #[test]
    fn test_build_hello_different_inputs() {
        let bytes1 = build_hello("pass1", "host1.com", 80);
        let bytes2 = build_hello("pass2", "host2.com", 443);

        // 不同输入应产生不同输出
        assert_ne!(bytes1, bytes2);

        // 都应该有合理长度
        assert!(bytes1.len() > 20);
        assert!(bytes2.len() > 20);
    }

    #[test]
    fn test_build_tls_first() {
        let bytes = build_tls_first("testpass", "example.com", 443);
        let hello_bytes = build_hello("testpass", "example.com", 443);

        // TLS first 应该比普通 hello 更长
        assert!(bytes.len() > hello_bytes.len());

        // 应该包含 hello 的内容
        assert!(bytes.starts_with(&hello_bytes));

        println!("TLS first bytes: {} bytes", bytes.len());
    }

    #[test]
    fn test_report_shape() {
        let report1 = report_shape(100, false);
        assert_eq!(report1.bytes_len, 100);
        assert_eq!(report1.meta.kind, "hello");
        assert!(!report1.meta.hashes);
        assert!(!report1.meta.ordered);
        assert!(!report1.meta.normalized);

        let report2 = report_shape(200, true);
        assert_eq!(report2.bytes_len, 200);
        assert_eq!(report2.meta.kind, "tls_first");
        assert!(!report2.meta.hashes);
        assert!(!report2.meta.ordered);
        assert!(!report2.meta.normalized);
    }

    #[test]
    fn test_hello_structure() {
        let password = "mypassword";
        let host = "target.example.com";
        let port = 8080u16;

        let bytes = build_hello(password, host, port);
        let s = String::from_utf8_lossy(&bytes);

        // 验证基本结构: hash + \r\n + SOCKS5 addr + \r\n
        let parts: Vec<&str> = s.split("\r\n").collect();
        assert!(parts.len() >= 2);

        // 第一部分应该是56字符的hex (28字节 * 2)
        assert_eq!(parts[0].len(), 56);
        assert!(parts[0].chars().all(|c| c.is_ascii_hexdigit()));

        println!("Password hash: {}", parts[0]);
        println!(
            "Address part length: {}",
            parts.get(1).map(|s| s.len()).unwrap_or(0)
        );
    }

    #[test]
    fn test_socks5_address_format() {
        let bytes = build_hello("test", "example.com", 80);

        // 找到第一个 \r\n 后的内容
        let pos = bytes.windows(2).position(|w| w == b"\r\n").unwrap();
        let addr_part = &bytes[pos + 2..];

        // 验证 SOCKS5 格式: ATYP(1) + LEN(1) + DOMAIN + PORT(2)
        assert!(addr_part.len() >= 4); // 至少有 ATYP + LEN + 最短域名 + PORT
        assert_eq!(addr_part[0], 0x03); // Domain type
        assert_eq!(addr_part[1], b"example.com".len() as u8); // Domain length

        // 验证域名
        let domain_len = addr_part[1] as usize;
        let domain = &addr_part[2..2 + domain_len];
        assert_eq!(domain, b"example.com");

        // 验证端口
        let port_bytes = &addr_part[2 + domain_len..2 + domain_len + 2];
        let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
        assert_eq!(port, 80);
    }
}

#[cfg(not(feature = "proto_trojan_dry"))]
mod no_feature {
    #[test]
    fn test_feature_disabled() {
        println!("proto_trojan_dry feature is disabled");
    }
}
