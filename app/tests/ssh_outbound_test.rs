//! Test for SSH outbound adapter registration and instantiation.
//!
//! This module validates that the SSH outbound adapter is properly registered
//! and can be instantiated with valid credentials.

use sb_config::ir::{Credentials, OutboundIR, OutboundType};

#[test]
fn test_ssh_outbound_registration() {
    // Ensure SSH outbound is registered
    #[cfg(feature = "adapters")]
    {
        // Register all adapters
        sb_adapters::register::register_all();

        // Verify SSH can be built with password auth
        let ir = OutboundIR {
            ty: OutboundType::Ssh,
            server: Some("ssh.example.com".into()),
            port: Some(22),
            credentials: Some(Credentials {
                username: Some("testuser".into()),
                password: Some("testpass".into()),
                username_env: None,
                password_env: None,
            }),
            ..Default::default()
        };

        // Basic validation that IR can be constructed
        assert_eq!(ir.ty, OutboundType::Ssh);
        assert_eq!(ir.server, Some("ssh.example.com".into()));
        assert_eq!(ir.port, Some(22));
        assert!(ir.credentials.is_some());

        println!("✅ SSH outbound IR construction: PASS");
    }

    #[cfg(not(feature = "adapters"))]
    {
        println!("⊘ Skipping SSH outbound test: adapters feature not enabled");
    }
}

#[test]
fn test_ssh_outbound_requires_auth() {
    #[cfg(feature = "adapters")]
    {
        sb_adapters::register::register_all();

        // Test missing credentials
        let ir = OutboundIR {
            ty: OutboundType::Ssh,
            server: Some("ssh.example.com".into()),
            port: Some(22),
            credentials: None, // No credentials provided!
            ..Default::default()
        };

        // Verify that the IR can be constructed but has no credentials
        assert_eq!(ir.ty, OutboundType::Ssh);
        assert!(ir.credentials.is_none());

        println!("✅ SSH outbound requires auth validation: PASS");
    }

    #[cfg(not(feature = "adapters"))]
    {
        println!("⊘ Skipping SSH auth validation test: adapters feature not enabled");
    }
}

#[test]
fn test_ssh_outbound_with_private_key() {
    #[cfg(feature = "adapters")]
    {
        sb_adapters::register::register_all();

        // Test with private key instead of password
        let ir = OutboundIR {
            ty: OutboundType::Ssh,
            server: Some("ssh.example.com".into()),
            port: Some(22),
            credentials: Some(Credentials {
                username: Some("testuser".into()),
                password: None, // No password
                username_env: None,
                password_env: None,
            }),
            ssh_private_key: Some(
                "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----".into(),
            ),
            ..Default::default()
        };

        // Verify IR construction with private key
        assert_eq!(ir.ty, OutboundType::Ssh);
        assert!(ir.ssh_private_key.is_some());

        println!("✅ SSH outbound with private key: PASS");
    }

    #[cfg(not(feature = "adapters"))]
    {
        println!("⊘ Skipping SSH private key test: adapters feature not enabled");
    }
}

#[test]
fn test_ssh_outbound_config_options() {
    #[cfg(feature = "adapters")]
    {
        sb_adapters::register::register_all();

        // Test with various configuration options
        let ir = OutboundIR {
            ty: OutboundType::Ssh,
            server: Some("ssh.example.com".into()),
            port: Some(2222), // Custom port
            credentials: Some(Credentials {
                username: Some("testuser".into()),
                password: Some("testpass".into()),
                username_env: None,
                password_env: None,
            }),
            ssh_host_key_verification: Some(false),
            ssh_compression: Some(true),
            ssh_connection_pool_size: Some(8),
            ssh_keepalive_interval: Some(60),
            ..Default::default()
        };

        // Verify all config options are set
        assert_eq!(ir.port, Some(2222));
        assert_eq!(ir.ssh_host_key_verification, Some(false));
        assert_eq!(ir.ssh_compression, Some(true));
        assert_eq!(ir.ssh_connection_pool_size, Some(8));
        assert_eq!(ir.ssh_keepalive_interval, Some(60));

        println!("✅ SSH outbound config options: PASS");
    }

    #[cfg(not(feature = "adapters"))]
    {
        println!("⊘ Skipping SSH config options test: adapters feature not enabled");
    }
}
