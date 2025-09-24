#[cfg(feature = "proto_ss2022_core")]
mod ss2022_core_tests {
    use sb_proto::ss2022_core::*;

    #[test]
    fn test_aead_kind_str() {
        assert_eq!(aead_kind_str(AeadKind::Aes256Gcm), "aes-256-gcm");
        assert_eq!(
            aead_kind_str(AeadKind::Chacha20Poly1305),
            "chacha20-poly1305"
        );
    }

    #[test]
    fn test_parse_aead_kind() {
        assert_eq!(parse_aead_kind("aes-256-gcm"), Some(AeadKind::Aes256Gcm));
        assert_eq!(parse_aead_kind("aes256gcm"), Some(AeadKind::Aes256Gcm));
        assert_eq!(
            parse_aead_kind("chacha20-poly1305"),
            Some(AeadKind::Chacha20Poly1305)
        );
        assert_eq!(
            parse_aead_kind("chacha20poly1305"),
            Some(AeadKind::Chacha20Poly1305)
        );
        assert_eq!(parse_aead_kind("unknown"), None);
    }

    #[test]
    fn test_derive_subkey_b3() {
        let key1 = derive_subkey_b3("password123", b"salt1234");
        let key2 = derive_subkey_b3("password123", b"salt1234");
        let key3 = derive_subkey_b3("password456", b"salt1234");

        // 同样输入应产生同样输出
        assert_eq!(key1, key2);
        // 不同输入应产生不同输出
        assert_ne!(key1, key3);
        // 密钥长度正确
        assert_eq!(key1.len(), 32);
    }

    #[test]
    fn test_build_client_first_shape() {
        let result = build_client_first(
            "2022-blake3-aes-256-gcm",
            "testpass",
            "example.com",
            443,
            AeadKind::Aes256Gcm,
        )
        .unwrap();

        // 验证输出不为空
        assert!(!result.is_empty());

        // 验证基本结构：应该包含 header_len(2) + header + payload_len(2) + payload + salt(16) + tag(16)
        assert!(result.len() > 36); // 至少有基本的开销

        // 验证前两个字节是header长度
        let header_len = u16::from_be_bytes([result[0], result[1]]) as usize;
        assert!(header_len > 0);
        assert!(result.len() > 2 + header_len + 2); // header_len + header + payload_len + ...

        println!("Generated SS2022 first packet: {} bytes", result.len());
        println!("Header length: {} bytes", header_len);
    }

    #[test]
    fn test_build_client_first_different_inputs() {
        let result1 =
            build_client_first("method1", "pass1", "host1.com", 80, AeadKind::Aes256Gcm).unwrap();
        let result2 = build_client_first(
            "method2",
            "pass2",
            "host2.com",
            443,
            AeadKind::Chacha20Poly1305,
        )
        .unwrap();

        // 不同输入应产生不同输出
        assert_ne!(result1, result2);

        // 但两者都应该有合理的长度
        assert!(result1.len() > 36);
        assert!(result2.len() > 36);
    }

    #[test]
    fn test_build_client_first_sni_shadow() {
        // 测试包含 SNI 影子的情况
        let result = build_client_first(
            "2022-blake3-chacha20-poly1305",
            "longpassword",
            "very-long-hostname.example.com",
            8080,
            AeadKind::Chacha20Poly1305,
        )
        .unwrap();

        assert!(!result.is_empty());
        // 长 hostname 应该产生更大的包
        assert!(result.len() > 60);

        println!("Long hostname packet: {} bytes", result.len());
    }

    #[test]
    fn test_build_client_first_error_cases() {
        // 空密码
        let result = build_client_first("method", "", "host.com", 80, AeadKind::Aes256Gcm);
        assert!(result.is_err());

        // 空主机名
        let result = build_client_first("method", "pass", "", 80, AeadKind::Aes256Gcm);
        assert!(result.is_err());
    }
}

#[cfg(not(feature = "proto_ss2022_core"))]
mod no_feature {
    #[test]
    fn test_feature_disabled() {
        // 当特性未启用时，此测试确保编译通过
        println!("proto_ss2022_core feature is disabled");
    }
}
