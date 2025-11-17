#![allow(clippy::manual_flatten)]
use sb_config::ir::{ConfigIR, InboundIR, InboundType, OutboundIR, OutboundType, RouteIR, RuleIR};
use sb_core::adapter::bridge::build_bridge;
use sb_core::routing::engine::Engine;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

#[test]
fn rule_selects_named_outbound() {
    // echo upstream（用来证明 direct 可连通）
    let l = match TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                eprintln!("skipping bridge_resolve_and_health due to sandbox PermissionDenied on bind: {}", e);
                return;
            } else {
                panic!("bind failed: {}", e);
            }
        }
    };
    let _echo_addr = l.local_addr().unwrap();
    thread::spawn(move || {
        for c in l.incoming() {
            if let Ok(mut s) = c {
                thread::spawn(move || {
                    let mut buf = [0u8; 1024];
                    loop {
                        match s.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                let _ = s.write_all(&buf[..n]);
                            }
                        }
                    }
                });
            }
        }
    });
    // ir：一个 socks 入站 + direct 出站（命名为 "direct"），规则 domain:* → outbound:"direct"
    let ir = ConfigIR {
        log: None,
        ntp: None,
        certificate: None,
        dns: None,
        endpoints: Vec::new(),
        services: Vec::new(),
        inbounds: vec![InboundIR {
            ty: InboundType::Socks,
            listen: "127.0.0.1".into(),
            port: 0,
            sniff: false,
            udp: false,
            basic_auth: None,
            override_host: None,
            override_port: None,
            method: None,
            password: None,
            users_shadowsocks: None,
            network: None,
            uuid: None,
            alter_id: None,
            users_vmess: None,
            flow: None,
            users_vless: None,
            users_trojan: None,
            users_hysteria2: None,
            congestion_control: None,
            salamander: None,
            obfs: None,
            brutal_up_mbps: None,
            brutal_down_mbps: None,
            users_tuic: None,
            users_hysteria: None,
            hysteria_protocol: None,
            hysteria_obfs: None,
            hysteria_up_mbps: None,
            hysteria_down_mbps: None,
            hysteria_recv_window_conn: None,
            hysteria_recv_window: None,
            transport: None,
            ws_path: None,
            ws_host: None,
            h2_path: None,
            h2_host: None,
            grpc_service: None,
            tls_enabled: None,
            tls_cert_path: None,
            tls_key_path: None,
            tls_cert_pem: None,
            tls_key_pem: None,
            tls_server_name: None,
            tls_alpn: None,
            multiplex: None,
        }],
        outbounds: vec![OutboundIR {
            ty: OutboundType::Direct,
            server: None,
            port: None,
            udp: None,
            name: Some("direct".into()),
            members: None,
            default_member: None,
            method: None,
            credentials: None,
            uuid: None,
            flow: None,
            encryption: None,
            security: None,
            alter_id: None,
            network: None,
            packet_encoding: None,
            transport: None,
            ws_path: None,
            ws_host: None,
            h2_path: None,
            h2_host: None,
            grpc_service: None,
            grpc_method: None,
            grpc_authority: None,
            grpc_metadata: Vec::new(),
            http_upgrade_path: None,
            http_upgrade_headers: Vec::new(),
            tls_sni: None,
            tls_alpn: None,
            dns_transport: None,
            dns_tls_server_name: None,
            dns_timeout_ms: None,
            dns_query_timeout_ms: None,
            dns_enable_edns0: None,
            dns_edns0_buffer_size: None,
            dns_doh_url: None,
            tls_ca_paths: Vec::new(),
            tls_ca_pem: Vec::new(),
            tls_client_cert_path: None,
            tls_client_key_path: None,
            tls_client_cert_pem: None,
            tls_client_key_pem: None,
            alpn: None,
            skip_cert_verify: None,
            udp_relay_mode: None,
            udp_over_stream: None,
            zero_rtt_handshake: None,
            up_mbps: None,
            down_mbps: None,
            obfs: None,
            salamander: None,
            brutal_up_mbps: None,
            brutal_down_mbps: None,
            hysteria_protocol: None,
            hysteria_auth: None,
            hysteria_recv_window_conn: None,
            hysteria_recv_window: None,
            reality_enabled: None,
            reality_public_key: None,
            reality_short_id: None,
            reality_server_name: None,
            password: None,
            plugin: None,
            plugin_opts: None,
            ssh_private_key: None,
            ssh_private_key_path: None,
            ssh_private_key_passphrase: None,
            ssh_host_key_verification: None,
            ssh_known_hosts_path: None,
            ssh_connection_pool_size: None,
            ssh_compression: None,
            ssh_keepalive_interval: None,
            connect_timeout_sec: None,
            tor_proxy_addr: None,
            tor_executable_path: None,
            tor_extra_args: None,
            tor_data_directory: None,
            tor_options: None,
            test_url: None,
            test_interval_ms: None,
            test_timeout_ms: None,
            test_tolerance_ms: None,
            interrupt_exist_connections: None,
        }],
        route: RouteIR {
            rules: vec![RuleIR {
                domain: vec!["*".into()],
                outbound: Some("direct".into()),
                ..Default::default()
            }],
            default: Some("direct".into()),
        },
    };
    let eng = Engine::new(&ir);
    let br = build_bridge(&ir, eng);
    // 桥里应该能找到 direct
    assert!(br.find_outbound("direct").is_some());
}
