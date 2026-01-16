use sb_config::validator::v2::to_ir_v1;
use serde_json::json;

#[test]
fn test_dns_server_config_fields() {
    let config = json!({
        "dns": {
            "servers": [
                {
                    "tag": "remote-dns",
                    "address": "tls://1.1.1.1",
                    "address_resolver": "local-dns",
                    "address_strategy": "prefer_ipv4",
                    "address_fallback_delay": "300ms",
                    "strategy": "ipv4_only",
                    "detour": "proxy"
                },
                {
                    "tag": "local-dns",
                    "address": "system"
                }
            ],
            "final": "remote-dns",
            "disable_cache": true
        }
    });

    let ir = to_ir_v1(&config);
    let dns = ir.dns.expect("dns should be present");

    // Server fields
    let server = &dns.servers[0];
    assert_eq!(server.tag, "remote-dns");
    assert_eq!(server.address_resolver, Some("local-dns".to_string()));
    assert_eq!(server.address_strategy, Some("prefer_ipv4".to_string()));
    assert_eq!(server.address_fallback_delay, Some("300ms".to_string()));
    assert_eq!(server.strategy, Some("ipv4_only".to_string()));
    assert_eq!(server.detour, Some("proxy".to_string()));

    // DnsIR fields
    assert_eq!(dns.final_server, Some("remote-dns".to_string()));
    assert_eq!(dns.default, Some("remote-dns".to_string()));
    assert_eq!(dns.disable_cache, Some(true));
}

#[test]
fn test_dns_reverse_mapping_and_client_subnet() {
    let config = json!({
        "dns": {
            "servers": [
                {
                    "tag": "main",
                    "address": "8.8.8.8",
                    "client_subnet": "1.2.3.0/24"
                }
            ],
            "client_subnet": "4.5.6.0/24",
            "reverse_mapping": true,
            "strategy": "prefer_ipv6",
            "independent_cache": true
        }
    });

    let ir = to_ir_v1(&config);
    let dns = ir.dns.expect("dns should be present");

    // Server client_subnet
    assert_eq!(dns.servers[0].client_subnet, Some("1.2.3.0/24".to_string()));

    // Global fields
    assert_eq!(dns.client_subnet, Some("4.5.6.0/24".to_string()));
    assert_eq!(dns.reverse_mapping, Some(true));
    assert_eq!(dns.strategy, Some("prefer_ipv6".to_string()));
    assert_eq!(dns.independent_cache, Some(true));
}
