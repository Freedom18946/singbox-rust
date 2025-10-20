#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Try to interpret as JSON requests for v2ray simple API
    if let Ok(s) = std::str::from_utf8(data) {
        // Construct server instance
        let cfg = sb_api::types::ApiConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap_or_else(|_| "127.0.0.1:0".parse().unwrap()),
            enable_cors: false,
            cors_origins: None,
            auth_token: None,
            enable_traffic_ws: false,
            enable_logs_ws: false,
            traffic_broadcast_interval_ms: 1000,
            log_buffer_size: 16,
        };
        if let Ok(api) = sb_api::v2ray::simple::SimpleV2RayApiServer::new(cfg) {
            // Attempt to parse various request types
            let _ = serde_json::from_str::<sb_api::v2ray::simple::SimpleStatsRequest>(s)
                .ok().and_then(|req| {
                    futures::executor::block_on(api.get_stats(req)).ok()
                });
            let _ = serde_json::from_str::<sb_api::v2ray::simple::SimpleQueryStatsRequest>(s)
                .ok().and_then(|req| {
                    futures::executor::block_on(api.query_stats(req)).ok()
                });
            let _ = api.negotiate_version(s).ok();
        }
    }
});

