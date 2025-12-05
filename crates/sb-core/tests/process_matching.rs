use sb_core::context::Context;
use sb_platform::process::{ConnectionInfo, Protocol};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[tokio::test]
async fn test_process_matcher_integration() {
    // 1. Initialize Context
    let ctx = Context::new();

    // 2. Verify ProcessMatcher presence
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    {
        assert!(
            ctx.process_matcher.is_some(),
            "ProcessMatcher should be initialized on supported platforms"
        );
        let matcher = ctx.process_matcher.as_ref().unwrap();

        // 3. Attempt to match a dummy connection
        // This will likely return ProcessNotFound, but we verify the API call works and doesn't panic.
        let conn_info = ConnectionInfo {
            local_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345),
            remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80),
            protocol: Protocol::Tcp,
        };

        let result = matcher.match_connection(&conn_info).await;
        // We expect an error (ProcessNotFound) because this is a fake connection,
        // but getting an error means the matcher logic ran.
        assert!(result.is_err());
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        assert!(
            ctx.process_matcher.is_none(),
            "ProcessMatcher should be None on unsupported platforms"
        );
    }
}
