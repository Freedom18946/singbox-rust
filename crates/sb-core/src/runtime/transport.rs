//! Transport IR mapping helpers
//!
//! Provides a unified function to apply transport layers (TLS/WS/H2/HTTPUpgrade/GRPC/mux)
//! to an `sb_transport::TransportBuilder` based on IR-like fields.

#[cfg(feature = "v2ray_transport")]
pub mod map {
    use sb_config::ir::OutboundIR;
    use sb_transport::TransportBuilder;

    /// Apply transport layers to the given `TransportBuilder` based on IR-like fields.
    ///
    /// Parameters mirror common OutboundIR fields; when `transport_chain` is `None`,
    /// this function derives a sensible chain from the presence of fields.
    /// Defaults:
    /// - If `h2` is present and ALPN is not supplied, ALPN defaults to `h2`.
    /// - gRPC enables TLS when `tls_sni`/ALPN indicates TLS or when chain contains `tls`.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn apply_layers(
        mut builder: TransportBuilder,
        transport_chain: Option<&[String]>,
        tls_sni: Option<&str>,
        tls_alpn_csv: Option<&str>,
        ws_path: Option<&str>,
        ws_host: Option<&str>,
        h2_path: Option<&str>,
        h2_host: Option<&str>,
        // HTTP Upgrade extras
        http_upgrade_path: Option<&str>,
        http_upgrade_headers: &[(String, String)],
        // gRPC extras
        grpc_service: Option<&str>,
        grpc_method: Option<&str>,
        grpc_authority: Option<&str>,
        grpc_metadata: &[(String, String)],
        // Optional TLS config override
        tls_cfg_override: Option<std::sync::Arc<rustls::ClientConfig>>,
        // Multiplex config
        multiplex: Option<&sb_config::ir::MultiplexOptionsIR>,
    ) -> TransportBuilder {
        let chain_buf = derive_chain(
            transport_chain,
            tls_sni,
            tls_alpn_csv,
            ws_path,
            ws_host,
            h2_path,
            h2_host,
            http_upgrade_path,
            http_upgrade_headers,
            grpc_service,
            grpc_method,
            grpc_authority,
            grpc_metadata,
        );

        let want_h2 = chain_buf.iter().any(|s| {
            let v = s.to_ascii_lowercase();
            v == "h2" || v == "http2" || v == "grpc"
        });

        let alpn_from_ir: Option<Vec<Vec<u8>>> = tls_alpn_csv.map(|s| {
            s.split(',')
                .map(|p| p.trim().as_bytes().to_vec())
                .collect::<Vec<_>>()
        });

        let mut saw_tls = false;
        // Log the final chain for diagnostics
        tracing::debug!(
            target: "sb_core::transport",
            chain = %chain_buf.join("->"),
            sni = tls_sni.unwrap_or(""),
            alpn = tls_alpn_csv.unwrap_or(""),
            "applying transport layers"
        );
        for layer in &chain_buf {
            match layer.to_ascii_lowercase().as_str() {
                "tls" => {
                    // Prefer provided TLS config override, otherwise global effective
                    let cfg = tls_cfg_override
                        .clone()
                        .unwrap_or_else(crate::tls::global::get_effective);
                    let alpn = alpn_from_ir.clone().or_else(|| {
                        if want_h2 {
                            Some(vec![b"h2".to_vec()])
                        } else {
                            None
                        }
                    });
                    builder = builder.tls(cfg, tls_sni.map(ToOwned::to_owned), alpn);
                    saw_tls = true;
                }
                "ws" => {
                    let mut ws_cfg = sb_transport::websocket::WebSocketConfig::default();
                    if let Some(p) = ws_path {
                        ws_cfg.path = p.to_string();
                    }
                    if let Some(h) = ws_host {
                        ws_cfg.headers.push(("Host".into(), h.to_string()));
                    }
                    builder = builder.websocket(ws_cfg);
                }
                "h2" | "http2" => {
                    let mut h2_cfg = sb_transport::http2::Http2Config::default();
                    if let Some(p) = h2_path {
                        h2_cfg.path = p.to_string();
                    }
                    if let Some(h) = h2_host {
                        h2_cfg.host = h.to_string();
                    }
                    builder = builder.http2(h2_cfg);
                }
                "httpupgrade" | "http_upgrade" => {
                    let mut cfg = sb_transport::httpupgrade::HttpUpgradeConfig::default();
                    if let Some(p) = http_upgrade_path {
                        cfg.path = p.to_string();
                    }
                    if !http_upgrade_headers.is_empty() {
                        cfg.headers = http_upgrade_headers.to_vec();
                    }
                    builder = builder.http_upgrade(cfg);
                }
                "grpc" => {
                    let mut cfg = sb_transport::grpc::GrpcConfig::default();
                    if let Some(s) = grpc_service {
                        cfg.service_name = s.to_string();
                    }
                    if let Some(m) = grpc_method {
                        cfg.method_name = m.to_string();
                    }
                    if let Some(a) = grpc_authority {
                        cfg.server_name = Some(a.to_string());
                    }
                    if !grpc_metadata.is_empty() {
                        cfg.metadata = grpc_metadata.to_vec();
                    }
                    // Enable TLS when TLS appears explicitly or SNI/ALPN suggests TLS
                    cfg.enable_tls = saw_tls || tls_sni.is_some() || tls_alpn_csv.is_some();
                    builder = builder.grpc(cfg);
                }
                "mux" | "multiplex" => {
                    let mut cfg = sb_transport::multiplex::MultiplexConfig::default();
                    if let Some(m) = multiplex {
                        // if let Some(n) = m.max_connections {
                        //     cfg.max_connections = n;
                        // }
                        if let Some(n) = m.max_streams {
                            cfg.max_streams_per_connection = n;
                        }
                        if let Some(p) = m.padding {
                            cfg.enable_padding = p;
                        }
                        if let Some(w) = m.initial_stream_window {
                            cfg.initial_stream_window = w;
                        }
                        if let Some(w) = m.max_stream_window {
                            cfg.max_stream_window = w;
                        }
                        if let Some(k) = m.enable_keepalive {
                            cfg.enable_keepalive = k;
                        }
                        if let Some(i) = m.keepalive_interval {
                            cfg.keepalive_interval = i;
                        }
                        if let Some(b) = &m.brutal {
                            cfg.brutal = Some(sb_transport::multiplex::BrutalConfig {
                                up_mbps: b.up,
                                down_mbps: b.down,
                            });
                        }
                    }
                    builder = builder.multiplex(cfg);
                }
                _ => {}
            }
        }

        builder
    }

    /// Derive a normalized transport chain from IR-like hint fields.
    /// When `transport_chain` is provided, it is returned verbatim.
    /// Otherwise, this function infers a sensible chain with the following rules:
    /// - Prefer `ws` over `h2` when both hints are present (warn).
    /// - Include `httpupgrade` when upgrade path/headers are set.
    /// - Append `grpc` when any gRPC hint present.
    /// - Insert `tls` at the beginning when SNI or ALPN are present.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn derive_chain(
        transport_chain: Option<&[String]>,
        tls_sni: Option<&str>,
        tls_alpn_csv: Option<&str>,
        ws_path: Option<&str>,
        ws_host: Option<&str>,
        h2_path: Option<&str>,
        h2_host: Option<&str>,
        http_upgrade_path: Option<&str>,
        http_upgrade_headers: &[(String, String)],
        grpc_service: Option<&str>,
        grpc_method: Option<&str>,
        _grpc_authority: Option<&str>,
        _grpc_metadata: &[(String, String)],
    ) -> Vec<String> {
        if let Some(chain) = transport_chain {
            return chain.to_vec();
        }
        let mut chain_buf: Vec<String> = Vec::new();
        let ws_present = ws_path.is_some() || ws_host.is_some();
        let h2_present = h2_path.is_some() || h2_host.is_some();
        if ws_present && h2_present {
            tracing::warn!(
                target: "sb_core::transport",
                "conflicting transport hints (ws + h2) in IR; preferring WebSocket"
            );
        }
        if ws_present {
            chain_buf.push("ws".into());
        } else if h2_present {
            chain_buf.push("h2".into());
        } else if http_upgrade_path.is_some() || !http_upgrade_headers.is_empty() {
            chain_buf.push("httpupgrade".into());
        }
        if grpc_service.is_some() || grpc_method.is_some() {
            chain_buf.push("grpc".into());
        }
        if tls_sni.is_some() || tls_alpn_csv.is_some() {
            chain_buf.insert(0, "tls".into());
        }
        chain_buf
    }

    /// Convenience: build a `TransportBuilder` from OutboundIR directly.
    #[must_use]
    pub fn builder_from_ir(ob: &OutboundIR) -> TransportBuilder {
        // Build per-outbound TLS config override if needed (skip verify, client auth, custom CA)
        let tls_cfg_override = tls_override_from_ob(ob);

        // Best-effort SNI fallback: if not explicitly set, and hints imply TLS (h2/grpc),
        // use server host as SNI when it looks like a domain name. Controlled by
        // SB_TRANSPORT_SNI_FALLBACK (default: enabled).
        fn looks_like_domain(s: &str) -> bool {
            // A minimal heuristic: has a dot and not a valid IPv4/IPv6 literal
            s.contains('.') && s.parse::<std::net::IpAddr>().is_err()
        }
        let sni_fallback_enabled = std::env::var("SB_TRANSPORT_SNI_FALLBACK")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(true);
        let h2_hint = ob.h2_path.is_some() || ob.h2_host.is_some();
        let grpc_hint = ob.grpc_service.is_some() || ob.grpc_method.is_some();
        let computed_tls_sni: Option<&str> =
            if ob.tls_sni.is_none() && sni_fallback_enabled && (h2_hint || grpc_hint) {
                ob.server.as_deref().filter(|s| looks_like_domain(s))
            } else {
                ob.tls_sni.as_deref()
            };
        let alpn_csv = ob.tls_alpn.as_ref().map(|v| v.join(","));
        let mut builder = TransportBuilder::tcp();

        if let Some(iface) = &ob.bind_interface {
            builder = builder.bind_interface(iface.clone());
        }
        if let Some(addr) = &ob.inet4_bind_address {
            if let Ok(ip) = addr.parse() {
                builder = builder.bind_v4(ip);
            }
        }
        if let Some(addr) = &ob.inet6_bind_address {
            if let Ok(ip) = addr.parse() {
                builder = builder.bind_v6(ip);
            }
        }
        if let Some(mark) = ob.routing_mark {
            builder = builder.routing_mark(mark);
        }
        if let Some(reuse) = ob.reuse_addr {
            builder = builder.reuse_addr(reuse);
        }
        if let Some(timeout) = &ob.connect_timeout {
            if let Ok(d) = humantime::parse_duration(timeout) {
                builder = builder.connect_timeout(d);
            }
        }
        if let Some(tfo) = ob.tcp_fast_open {
            builder = builder.tcp_fast_open(tfo);
        }
        if let Some(mptcp) = ob.tcp_multi_path {
            builder = builder.tcp_multi_path(mptcp);
        }
        if let Some(frag) = ob.udp_fragment {
            builder = builder.udp_fragment(frag);
        }

        let builder = apply_layers(
            builder,
            ob.transport.as_deref(),
            computed_tls_sni,
            alpn_csv.as_deref(),
            ob.ws_path.as_deref(),
            ob.ws_host.as_deref(),
            ob.h2_path.as_deref(),
            ob.h2_host.as_deref(),
            ob.http_upgrade_path.as_deref(),
            &ob.http_upgrade_headers
                .iter()
                .map(|h| (h.key.clone(), h.value.clone()))
                .collect::<Vec<_>>(),
            ob.grpc_service.as_deref(),
            ob.grpc_method.as_deref(),
            ob.grpc_authority.as_deref(),
            &ob.grpc_metadata
                .iter()
                .map(|h| (h.key.clone(), h.value.clone()))
                .collect::<Vec<_>>(),
            tls_cfg_override,
            ob.multiplex.as_ref(),
        );

        builder
    }

    /// Expose derived chain for diagnostics and tooling.
    pub fn chain_from_ir(ob: &OutboundIR) -> Vec<String> {
        let alpn_csv = ob.tls_alpn.as_ref().map(|v| v.join(","));
        derive_chain(
            ob.transport.as_deref(),
            ob.tls_sni.as_deref(),
            alpn_csv.as_deref(),
            ob.ws_path.as_deref(),
            ob.ws_host.as_deref(),
            ob.h2_path.as_deref(),
            ob.h2_host.as_deref(),
            ob.http_upgrade_path.as_deref(),
            &ob.http_upgrade_headers
                .iter()
                .map(|h| (h.key.clone(), h.value.clone()))
                .collect::<Vec<_>>(),
            ob.grpc_service.as_deref(),
            ob.grpc_method.as_deref(),
            ob.grpc_authority.as_deref(),
            &ob.grpc_metadata
                .iter()
                .map(|h| (h.key.clone(), h.value.clone()))
                .collect::<Vec<_>>(),
        )
    }

    /// Derive fallback chains for connection attempts (planning helper; no I/O here).
    pub fn fallback_chains_from_ir(ob: &OutboundIR) -> Vec<Vec<String>> {
        let primary = chain_from_ir(ob);
        let mut plans = vec![primary.clone()];

        let ws_hint = ob.ws_path.is_some() || ob.ws_host.is_some();
        let h2_hint = ob.h2_path.is_some() || ob.h2_host.is_some();

        let starts = |pfx: &[&str]| {
            primary
                .iter()
                .map(|s| s.as_str())
                .take(pfx.len())
                .eq(pfx.iter().copied())
        };

        if starts(&["tls", "ws"]) && h2_hint {
            plans.push(vec!["tls".into(), "h2".into()]);
        }
        if starts(&["tls", "h2"]) && ws_hint {
            plans.push(vec!["tls".into(), "ws".into()]);
        }
        if primary.contains(&"httpupgrade".to_string()) && ws_hint {
            if ob.tls_sni.is_some() || ob.tls_alpn.is_some() {
                plans.push(vec!["tls".into(), "ws".into()]);
            } else {
                plans.push(vec!["ws".into()]);
            }
        }

        plans
    }

    /// Build a TLS config override for an outbound if it specifies skip-verify,
    /// client cert, or custom CA; otherwise return None and use the global config.
    pub fn tls_override_from_ob(ob: &OutboundIR) -> Option<std::sync::Arc<rustls::ClientConfig>> {
        use rustls::{ClientConfig, RootCertStore};
        use rustls_pki_types::{CertificateDer, PrivateKeyDer};

        let want_skip = ob.skip_cert_verify.unwrap_or(false);
        let has_ca = !ob.tls_ca_paths.is_empty() || !ob.tls_ca_pem.is_empty();
        let has_client = ob.tls_client_cert_path.is_some()
            || ob.tls_client_key_path.is_some()
            || ob.tls_client_cert_pem.is_some()
            || ob.tls_client_key_pem.is_some();
        if !(want_skip || has_ca || has_client) {
            return None;
        }

        // Base roots: webpki + top-level IR CAs
        let mut roots: RootCertStore = crate::tls::global::base_root_store();
        // Extend with per-outbound CA paths
        for path in &ob.tls_ca_paths {
            if let Ok(bytes) = std::fs::read(path) {
                let mut rd = std::io::BufReader::new(&bytes[..]);
                for der in rustls_pemfile::certs(&mut rd).flatten() {
                    let _ = roots.add(der);
                }
            }
        }
        // Extend with inline per-outbound CAs
        for pem in &ob.tls_ca_pem {
            let mut rd = std::io::BufReader::new(pem.as_bytes());
            for der in rustls_pemfile::certs(&mut rd).flatten() {
                let _ = roots.add(der);
            }
        }

        // Build base client config (no client auth yet)
        let config = ClientConfig::builder().with_root_certificates(roots);

        // Client cert (optional)
        let certs: Option<Vec<CertificateDer<'static>>> =
            if let Some(pem) = ob.tls_client_cert_pem.as_ref() {
                let mut rd = std::io::BufReader::new(pem.as_bytes());
                let v = rustls_pemfile::certs(&mut rd)
                    .collect::<Result<Vec<_>, _>>()
                    .ok();
                v
            } else if let Some(path) = ob.tls_client_cert_path.as_ref() {
                if let Ok(bytes) = std::fs::read(path) {
                    let mut rd = std::io::BufReader::new(&bytes[..]);
                    let v = rustls_pemfile::certs(&mut rd)
                        .collect::<Result<Vec<_>, _>>()
                        .ok();
                    v
                } else {
                    None
                }
            } else {
                None
            };

        let key: Option<PrivateKeyDer<'static>> = if let Some(pem) = ob.tls_client_key_pem.as_ref()
        {
            // Parse from owned buffer and collect to break any borrow ties
            let bytes = pem.as_bytes();
            let mut rd = std::io::BufReader::new(bytes);
            let mut pkcs8 = rustls_pemfile::pkcs8_private_keys(&mut rd)
                .filter_map(|r| r.ok())
                .collect::<Vec<_>>();
            if let Some(k) = pkcs8.pop() {
                Some(PrivateKeyDer::Pkcs8(k))
            } else {
                let mut rd2 = std::io::BufReader::new(bytes);
                let mut rsa = rustls_pemfile::rsa_private_keys(&mut rd2)
                    .filter_map(|r| r.ok())
                    .collect::<Vec<_>>();
                rsa.pop().map(PrivateKeyDer::Pkcs1)
            }
        } else if let Some(path) = ob.tls_client_key_path.as_ref() {
            // Read key file once and parse from an owned buffer
            if let Ok(bytes) = std::fs::read(path) {
                use std::io::BufReader;
                let mut reader = BufReader::new(&bytes[..]);
                let mut pkcs8 = rustls_pemfile::pkcs8_private_keys(&mut reader)
                    .filter_map(|r| r.ok())
                    .collect::<Vec<_>>();
                if let Some(k) = pkcs8.pop() {
                    Some(PrivateKeyDer::Pkcs8(k))
                } else {
                    let mut r2 = BufReader::new(&bytes[..]);
                    let mut rsa = rustls_pemfile::rsa_private_keys(&mut r2)
                        .filter_map(|r| r.ok())
                        .collect::<Vec<_>>();
                    rsa.pop().map(PrivateKeyDer::Pkcs1)
                }
            } else {
                None
            }
        } else {
            None
        };

        let mut client = if let (Some(chain), Some(k)) = (certs, key) {
            ClientConfig::builder()
                .with_root_certificates(crate::tls::global::base_root_store())
                .with_client_auth_cert(chain, k)
                .expect("invalid client auth cert/key")
        } else {
            config.with_no_client_auth()
        };

        if want_skip {
            let v = crate::tls::danger::NoVerify::new();
            client
                .dangerous()
                .set_certificate_verifier(std::sync::Arc::new(v));
        }

        Some(std::sync::Arc::new(client))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn override_none_when_no_tls_extras() {
            let ob = sb_config::ir::OutboundIR::default();
            let ov = tls_override_from_ob(&ob);
            assert!(ov.is_none());
        }

        #[test]
        fn override_when_skip_verify() {
            let ob = sb_config::ir::OutboundIR {
                skip_cert_verify: Some(true),
                ..Default::default()
            };
            let ov = tls_override_from_ob(&ob);
            assert!(ov.is_some());
        }

        #[test]
        fn override_when_ca_inline_present() {
            let ob = sb_config::ir::OutboundIR {
                tls_ca_pem: vec![
                    "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----".into(),
                ],
                ..Default::default()
            };
            let ov = tls_override_from_ob(&ob);
            assert!(ov.is_some());
        }

        #[test]
        fn override_when_client_inline_present() {
            let ob = sb_config::ir::OutboundIR {
                tls_client_cert_pem: Some(
                    "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----".into(),
                ),
                tls_client_key_pem: Some(
                    "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----".into(),
                ),
                ..Default::default()
            };
            let ov = tls_override_from_ob(&ob);
            assert!(ov.is_some());
        }

        #[test]
        fn derive_chain_ws_prefers_over_h2_with_tls() {
            let chain = derive_chain(
                None,
                Some("example.com"),
                Some("h2"),
                Some("/ws"),
                None,
                Some("/h2"),
                Some("h.example"),
                None,
                &[],
                None,
                None,
                None,
                &[],
            );
            // Expect TLS outermost, then ws; h2 suppressed by preference
            assert_eq!(chain, vec!["tls", "ws"]);
        }

        #[test]
        fn derive_chain_httpupgrade_with_tls() {
            let chain = derive_chain(
                None,
                Some("sni"),
                None,
                None,
                None,
                None,
                None,
                Some("/up"),
                &[("X-Test".into(), "1".into())],
                None,
                None,
                None,
                &[],
            );
            assert_eq!(chain, vec!["tls", "httpupgrade"]);
        }

        #[test]
        fn derive_chain_grpc_only() {
            let chain = derive_chain(
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                &[],
                Some("svc"),
                Some("m"),
                None,
                &[("k".into(), "v".into())],
            );
            assert_eq!(chain, vec!["grpc".to_string()]);
        }

        #[test]
        fn derive_chain_respects_explicit_chain() {
            let chain = derive_chain(
                Some(&["ws".into(), "grpc".into()]),
                Some("sni"),
                None,
                Some("/ws"),
                None,
                Some("/h2"),
                None,
                None,
                &[],
                None,
                None,
                None,
                &[],
            );
            assert_eq!(chain, vec!["ws".to_string(), "grpc".to_string()]);
        }

        #[test]
        fn derive_chain_tls_only_when_only_tls_hints() {
            let chain = derive_chain(
                None,
                Some("example.com"),
                None,
                None,
                None,
                None,
                None,
                None,
                &[],
                None,
                None,
                None,
                &[],
            );
            assert_eq!(chain, vec!["tls".to_string()]);
        }

        #[test]
        fn derive_chain_ws_and_grpc_with_tls() {
            let chain = derive_chain(
                None,
                Some("sni"),
                None,
                Some("/ws"),
                None,
                None,
                None,
                None,
                &[],
                Some("svc"),
                Some("m"),
                None,
                &[],
            );
            assert_eq!(
                chain,
                vec!["tls".to_string(), "ws".to_string(), "grpc".to_string()]
            );
        }

        #[test]
        fn derive_chain_h2_defaults_tls_with_sni() {
            // When H2 hints are present and SNI indicates TLS, chain should include tls+h2
            let chain = derive_chain(
                None,
                Some("example.com"), // sni present implies TLS
                None,                // no explicit ALPN
                None,
                None,
                Some("/h2"),
                Some("h.example"),
                None,
                &[],
                None,
                None,
                None,
                &[],
            );
            assert_eq!(chain, vec!["tls".to_string(), "h2".to_string()]);
        }

        #[test]
        fn fallback_from_ws_to_h2_when_hints_present() {
            let ob = OutboundIR {
                tls_sni: Some("example.com".into()),
                ws_path: Some("/ws".into()),
                h2_path: Some("/h2".into()),
                ..Default::default()
            };
            let plans = fallback_chains_from_ir(&ob);
            assert_eq!(plans[0], vec!["tls", "ws"]);
            assert!(plans.contains(&vec!["tls".into(), "h2".into()]));
        }

        #[test]
        fn fallback_from_h2_to_ws_when_hints_present() {
            let ob = OutboundIR {
                tls_sni: Some("example.com".into()),
                h2_path: Some("/h2".into()),
                ws_path: Some("/ws".into()),
                // Force explicit chain to simulate h2 primary
                transport: Some(vec!["tls".into(), "h2".into()]),
                ..Default::default()
            };
            let plans = fallback_chains_from_ir(&ob);
            assert_eq!(plans[0], vec!["tls", "h2"]);
            assert!(plans.contains(&vec!["tls".into(), "ws".into()]));
        }

        #[test]
        fn fallback_from_httpupgrade_to_ws_when_ws_hint() {
            let ob = OutboundIR {
                http_upgrade_path: Some("/up".into()),
                ws_path: Some("/ws".into()),
                // Force explicit chain to simulate httpupgrade primary
                transport: Some(vec!["httpupgrade".into()]),
                ..Default::default()
            };
            let plans = fallback_chains_from_ir(&ob);
            assert_eq!(plans[0], vec!["httpupgrade"]);
            assert!(plans.contains(&vec!["ws".into()]));
        }

        #[test]
        fn fallback_no_hints_only_primary() {
            let ob = OutboundIR::default();
            let plans = fallback_chains_from_ir(&ob);
            assert_eq!(plans.len(), 1);
            assert_eq!(plans[0], Vec::<String>::new());
        }

        #[test]
        fn fallback_only_h2_hint() {
            let ob = OutboundIR {
                tls_sni: Some("example.com".into()),
                h2_path: Some("/h2".into()),
                ..Default::default()
            };
            let plans = fallback_chains_from_ir(&ob);
            // primary uses tls,h2; no ws hints so no alt added
            assert_eq!(plans[0], vec!["tls", "h2"]);
            assert_eq!(plans.len(), 1);
        }
    }
}
