use std::time::Duration;

#[tokio::main]
async fn main() {
    if std::env::var("SB_METRICS_ADDR").is_err() {
        std::env::set_var("SB_METRICS_ADDR", "127.0.0.1:9090");
    }
    let _jh = sb_metrics::maybe_spawn_http_exporter_from_env();
    // Force-register a few common metric families
    sb_metrics::inc_router_match("default", "direct");
    sb_metrics::observe_outbound_connect_seconds("direct", 0.01);
    sb_metrics::inc_socks_udp_packet("in");
    sb_metrics::transfer::add_bytes("up", "tcp", 128);
    sb_metrics::inc_adapter_dial_total("socks5", "ok");
    sb_metrics::observe_adapter_dial_latency_ms("socks5", 3.2);
    sb_metrics::inc_udp_evict("ttl");
    // Emit unified inbound error counters for CI greps
    sb_metrics::inbound::record_error("http", "protocol");
    sb_metrics::inbound::record_error_display("http", &"timeout while waiting".to_string());
    // Touch HTTP families (sb-metrics http module)
    sb_metrics::http::inc_method("GET");
    sb_metrics::http::inc_status(405);
    {
        let _t = sb_metrics::http::start_req_timer();
        // simulate work
    }
    // Small wait for bind
    tokio::time::sleep(Duration::from_millis(200)).await;
    println!("READY");
    // Keep alive briefly for CI to curl
    tokio::time::sleep(Duration::from_secs(2)).await;
}
