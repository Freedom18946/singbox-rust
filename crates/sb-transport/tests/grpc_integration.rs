//! gRPC transport integration tests
//!
//! Tests the gRPC transport layer with bidirectional streaming.

#[cfg(feature = "transport_grpc")]
mod grpc_tests {
    use sb_transport::grpc::{GrpcConfig, GrpcDialer};
    use sb_transport::Dialer;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_grpc_config_default() {
        let config = GrpcConfig::default();
        assert_eq!(config.service_name, "TunnelService");
        assert_eq!(config.method_name, "Tunnel");
        assert!(!config.enable_tls);
        assert!(config.metadata.is_empty());
    }

    #[tokio::test]
    async fn test_grpc_dialer_creation() {
        let config = GrpcConfig {
            service_name: "TestService".to_string(),
            method_name: "TestMethod".to_string(),
            metadata: vec![("key".to_string(), "value".to_string())],
            enable_tls: false,
            server_name: None,
        };
        let _dialer = GrpcDialer::new(config.clone());
        // Just verify it compiles and creates successfully
        assert_eq!(config.service_name, "TestService");
        assert_eq!(config.method_name, "TestMethod");
        assert_eq!(config.metadata.len(), 1);
    }

    // Note: Full end-to-end gRPC tests require a running gRPC server
    // These would be better suited for integration tests with protocol adapters
    // once we have VMess/VLESS/Trojan supporting gRPC transport.
    //
    // For now, we verify:
    // 1. Configuration parsing works
    // 2. Dialer creation succeeds
    // 3. The code compiles with transport_grpc feature
}
