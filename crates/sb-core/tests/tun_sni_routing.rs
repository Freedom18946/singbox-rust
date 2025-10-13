use sb_core::router::sniff::extract_sni_from_tls_client_hello;

// Use the routing engine over ConfigIR rules
use sb_config::ir::{ConfigIR, RouteIR, RuleIR};
use sb_core::routing::engine::{Engine, Input};

fn build_tls_client_hello_with_sni(host: &str) -> Vec<u8> {
    // Build minimal TLS 1.2 ClientHello with only server_name extension
    let mut hs: Vec<u8> = Vec::new();
    // Handshake header: type(1)=1, length(3)=placeholder
    hs.push(0x01);
    hs.extend_from_slice(&[0, 0, 0]);
    // client_version (2)
    hs.extend_from_slice(&[0x03, 0x03]);
    // random (32)
    hs.extend_from_slice(&[0u8; 32]);
    // session_id len (1) + session_id
    hs.push(0);
    // cipher_suites len (2) + one suite (2)
    hs.extend_from_slice(&[0x00, 0x02]);
    hs.extend_from_slice(&[0x00, 0x2f]); // TLS_RSA_WITH_AES_128_CBC_SHA
                                         // compression_methods len (1) + null (1)
    hs.push(1);
    hs.push(0);
    // extensions placeholder: length(2)
    let ext_len_pos = hs.len();
    hs.extend_from_slice(&[0x00, 0x00]);

    // ---- server_name extension ----
    let mut ext: Vec<u8> = Vec::new();
    // type(2)=0x0000 server_name
    ext.extend_from_slice(&[0x00, 0x00]);
    // extension data placeholder len(2)
    let ext_data_len_pos = ext.len();
    ext.extend_from_slice(&[0x00, 0x00]);
    // ServerNameList length(2) placeholder
    let list_len_pos = ext.len();
    ext.extend_from_slice(&[0x00, 0x00]);
    // NameType(1)=0 (host_name)
    ext.push(0);
    // HostName length(2) + bytes
    let hbytes = host.as_bytes();
    let hlen = hbytes.len() as u16;
    ext.extend_from_slice(&hlen.to_be_bytes());
    ext.extend_from_slice(hbytes);
    // Fill ServerNameList length
    let list_len = (1 + 2 + hbytes.len()) as u16;
    ext[list_len_pos..list_len_pos + 2].copy_from_slice(&list_len.to_be_bytes());
    // Fill extension data length
    let ext_data_len = (2 + list_len as usize) as u16; // list length field + list
    ext[ext_data_len_pos..ext_data_len_pos + 2].copy_from_slice(&ext_data_len.to_be_bytes());

    // Append extension to handshake and update extensions length
    hs.extend_from_slice(&ext);
    let final_ext_len = (ext.len()) as u16;
    hs[ext_len_pos..ext_len_pos + 2].copy_from_slice(&final_ext_len.to_be_bytes());

    // Fill handshake length (exclude the 4-byte handshake header itself)
    let hs_body_len = (hs.len() - 4) as u32;
    hs[1..4].copy_from_slice(&[
        (hs_body_len >> 16) as u8,
        (hs_body_len >> 8) as u8,
        hs_body_len as u8,
    ]);

    // TLS record: type(22)=handshake, version 03 03, length=hs.len()
    let mut rec = Vec::with_capacity(5 + hs.len());
    rec.push(0x16);
    rec.extend_from_slice(&[0x03, 0x03]);
    let rec_len = hs.len() as u16;
    rec.extend_from_slice(&rec_len.to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

#[test]
fn sni_drives_routing_decision() {
    let sni = "www.example.com";
    let pkt = build_tls_client_hello_with_sni(sni);
    let got = extract_sni_from_tls_client_hello(&pkt).expect("SNI should be parsed");
    assert_eq!(got, sni);

    // Build routing rules: domain suffix example.com -> proxy
    let mut cfg = ConfigIR::default();
    cfg.route = RouteIR {
        rules: vec![RuleIR {
            domain: vec!["example.com".into()],
            outbound: Some("proxy".into()),
            ..Default::default()
        }],
        default: Some("direct".into()),
    };

    let eng = Engine::new(&cfg);
    let dec = eng.decide(
        &Input {
            host: &got,
            port: 443,
            network: "tcp",
            protocol: "tun",
            sniff_host: None,
            sniff_alpn: None,
        },
        false,
    );
    assert_eq!(dec.outbound, "proxy");
}
