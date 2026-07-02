#[tokio::main]
async fn main() {
    let addr = std::env::var("SB_METRICS_ADDR").unwrap_or_else(|_| "127.0.0.1:9090".to_owned());
    std::env::set_var("SB_METRICS_ADDR", addr);

    let registry_owner = sb_metrics::install_default_registry_owner();
    let Some(_exporter) = sb_metrics::spawn_http_exporter_from_env(registry_owner.handle()) else {
        return;
    };

    // Preload representative metric families for manual scraping.
    sb_metrics::inc_router_match("default", "direct");
    sb_metrics::observe_outbound_connect_seconds("direct", 0.01);
    sb_metrics::inc_socks_udp_packet("in");
    sb_metrics::transfer::add_bytes("up", "tcp", 128);
    sb_metrics::inc_adapter_dial_total("socks5", "ok");
    sb_metrics::observe_adapter_dial_latency_ms("socks5", 3.2);
    sb_metrics::inc_udp_evict("ttl");
    sb_metrics::inbound::record_error("http", "protocol");
    sb_metrics::inbound::record_error_display("http", &"timeout while waiting".to_string());
    sb_metrics::http::inc_method("GET");
    sb_metrics::http::inc_status(405);
    {
        let _t = sb_metrics::http::start_req_timer();
    }

    std::future::pending::<()>().await;
}
