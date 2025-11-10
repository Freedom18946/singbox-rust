fn main() {
    // Touch DNS and HTTP error metrics via unified helpers
    sb_core::metrics::dns::record_error_display(&"dns timeout".to_string());
    sb_core::metrics::http::record_error_display(&"http parse error".to_string());
    // Touch HTTP 405 respond counter
    sb_core::metrics::http::inc_405_responses();

    // Also touch outbound error mapping once
    sb_core::metrics::record_outbound_error(sb_core::metrics::outbound::OutboundKind::Direct, &"connection refused".to_string());

    // Export sb-core Prometheus registry
    #[cfg(feature = "metrics")]
    {
        use prometheus::Encoder;
        let reg = sb_core::metrics::registry();
        let mfs = reg.gather();
        let mut buf = Vec::new();
        let enc = prometheus::TextEncoder::new();
        enc.encode(&mfs, &mut buf).unwrap();
        println!("{}", String::from_utf8(buf).unwrap());
    }
}
