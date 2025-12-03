//! Test for SSH outbound adapter registration and instantiation.

#[test]
fn test_ssh_outbound_registration() {
    // Ensure SSH outbound is registered
    #[cfg(feature = "adapters")]
    {
        // Register all adapters
        sb_adapters::register::register_all();

        // Verify SSH can be built with password auth
        let mut ir = OutboundIR::default();
        ir.ty = OutboundType::Ssh;
        ir.server = Some("ssh.example.com".into());
        ir.port = Some(22);
        ir.credentials = Some(Credentials {
            username: Some("testuser".into()),
            password: Some("testpass".into()),
            ..Default::default()
        });

        let param = OutboundParam {
            kind: "ssh".into(),
            name: Some("ssh-test".into()),
            ..Default::default()
        };

        // Try to build SSH outbound via registry
        let registry = sb_core::adapter::registry::global_outbound_registry();
        let builder = registry.get("ssh");
        assert!(builder.is_some(), "SSH outbound should be registered");

        // Test that builder can create outbound
        if let Some(builder_fn) = builder {
            let result = builder_fn(&param, &ir);
            assert!(
                result.is_some(),
                "SSH outbound should build successfully with valid credentials"
            );
        }
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
        let mut ir = OutboundIR::default();
        ir.ty = OutboundType::Ssh;
        ir.server = Some("ssh.example.com".into());
        ir.port = Some(22);
        // No credentials provided!

        let param = OutboundParam {
            kind: "ssh".into(),
            name: Some("ssh-test".into()),
            ..Default::default()
        };

        let registry = sb_core::adapter::registry::global_outbound_registry();
        if let Some(builder_fn) = registry.get("ssh") {
            let result = builder_fn(&param, &ir);
            assert!(
                result.is_none(),
                "SSH outbound should fail without credentials"
            );
        }
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
        let mut ir = OutboundIR::default();
        ir.ty = OutboundType::Ssh;
        ir.server = Some("ssh.example.com".into());
        ir.port = Some(22);
        ir.credentials = Some(Credentials {
            username: Some("testuser".into()),
            password: None, // No password
            ..Default::default()
        });
        ir.ssh_private_key =
            Some("-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----".into());

        let param = OutboundParam {
            kind: "ssh".into(),
            name: Some("ssh-test".into()),
            ..Default::default()
        };

        let registry = sb_core::adapter::registry::global_outbound_registry();
        if let Some(builder_fn) = registry.get("ssh") {
            let result = builder_fn(&param, &ir);
            assert!(
                result.is_some(),
                "SSH outbound should build successfully with private key"
            );
        }
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
        let mut ir = OutboundIR::default();
        ir.ty = OutboundType::Ssh;
        ir.server = Some("ssh.example.com".into());
        ir.port = Some(2222); // Custom port
        ir.credentials = Some(Credentials {
            username: Some("testuser".into()),
            password: Some("testpass".into()),
            ..Default::default()
        });
        ir.ssh_host_key_verification = Some(false);
        ir.ssh_compression = Some(true);
        ir.ssh_connection_pool_size = Some(8);
        ir.ssh_keepalive_interval = Some(60);

        let param = OutboundParam {
            kind: "ssh".into(),
            name: Some("ssh-test".into()),
            ..Default::default()
        };

        let registry = sb_core::adapter::registry::global_outbound_registry();
        if let Some(builder_fn) = registry.get("ssh") {
            let result = builder_fn(&param, &ir);
            assert!(
                result.is_some(),
                "SSH outbound should build successfully with config options"
            );
        }
    }

    #[cfg(not(feature = "adapters"))]
    {
        println!("⊘ Skipping SSH config options test: adapters feature not enabled");
    }
}
