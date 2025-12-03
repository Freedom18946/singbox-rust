//! Unit tests for V2Ray transport layer
//!
//! Tests for WebSocket, HTTP/2, TLS, and transport chaining

#[cfg(all(test, feature = "transport_ws"))]
mod websocket_tests {
    #[test]
    fn test_websocket_config_default() {
        use sb_transport::websocket::WebSocketConfig;

        let config = WebSocketConfig::default();
        assert_eq!(config.path, "/");
        assert_eq!(config.headers.len(), 0);
        assert_eq!(config.max_message_size, Some(64 * 1024 * 1024));
        assert_eq!(config.max_frame_size, Some(16 * 1024 * 1024));
        assert!(!config.early_data);
    }

    #[test]
    fn test_websocket_config_custom() {
        use sb_transport::websocket::WebSocketConfig;

        let config = WebSocketConfig {
            path: "/ws".to_string(),
            headers: vec![
                ("Host".to_string(), "example.com".to_string()),
                ("User-Agent".to_string(), "test/1.0".to_string()),
            ],
            max_message_size: Some(32 * 1024 * 1024),
            max_frame_size: Some(8 * 1024 * 1024),
            early_data: true,
            ..Default::default()
        };

        assert_eq!(config.path, "/ws");
        assert_eq!(config.headers.len(), 2);
        assert_eq!(config.headers[0].0, "Host");
        assert_eq!(config.headers[0].1, "example.com");
        assert_eq!(config.max_message_size, Some(32 * 1024 * 1024));
        assert!(config.early_data);
    }
}

#[cfg(all(test, feature = "transport_h2"))]
mod http2_tests {
    #[test]
    fn test_http2_config_validation() {
        use sb_transport::http2::Http2Config;
        // Validate default config fields to avoid constant assertions
        let cfg = Http2Config::default();
        assert_eq!(cfg.path, "/");
        assert!(cfg.enable_pooling);
        assert_eq!(cfg.max_concurrent_streams, Some(100));
    }
}

#[cfg(all(test, feature = "transport_tls"))]
mod tls_tests {
    #[test]
    fn test_tls_config_validation() {
        // Creating a client config should succeed
        let cfg = sb_transport::tls::webpki_roots_config();
        // Ensure ALPN list is initialized (may be empty by default)
        assert!(cfg.alpn_protocols.is_empty());
    }
}

#[cfg(test)]
mod transport_basic_tests {
    use sb_transport::TcpDialer;

    #[test]
    fn test_dialer_trait_exists() {
        // Create a boxed dialer via the builder to exercise trait object path
        let d = sb_transport::TransportBuilder::tcp().build();
        // Ensure the object is created; drop immediately
        let _ = d;
    }

    #[test]
    fn test_transport_modules_available() {
        let dialer = TcpDialer::default(); // type is available and implements Debug name
        let _tcp = dialer;
    }
}

#[cfg(all(test, feature = "transport_mux"))]
mod multiplex_tests {
    #[test]
    fn test_multiplex_module_exists() {
        // Validate default config
        let cfg = sb_transport::multiplex::MultiplexConfig::default();
        assert!(cfg.max_num_streams >= 1);
    }
}

#[cfg(all(test, feature = "transport_grpc"))]
mod grpc_tests {
    #[test]
    fn test_grpc_module_exists() {
        let cfg = sb_transport::grpc::GrpcConfig::default();
        assert_eq!(cfg.service_name, "TunnelService");
    }
}

#[cfg(all(test, feature = "transport_httpupgrade"))]
mod httpupgrade_tests {
    #[test]
    fn test_httpupgrade_module_exists() {
        let cfg = sb_transport::httpupgrade::HttpUpgradeServerConfig::default();
        assert_eq!(cfg.upgrade_protocol, "websocket");
    }
}
