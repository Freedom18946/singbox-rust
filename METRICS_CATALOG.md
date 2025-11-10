Singbox‑Rust Metrics Catalog (WS7)

Purpose
- Provide a stable catalog of metric families, label keys and accepted value sets.
- Guard label proliferation via a centralized whitelist enforced at registration.
- Document noise‑reduction defaults and sensitive data redaction guidance.

Exporters
- Prometheus (prometheus crate): `sb-metrics` exposes `/metrics` when `SB_METRICS_ADDR=host:port`.
- metrics crate (metrics macros): optionally used by modules; when a recorder is installed, these names will appear under that exporter.

Label Whitelist
- method, status, class
- kind, result
- protocol, cipher, operation
- outbound, reason, mode, place
- shard, state, dir
- qtype, from_cache
- adapter, category, chan, proxy

Guardrails
- Enforcement: `crates/sb-core/src/metrics/label_guard.rs` and `crates/sb-metrics/src/labels.rs` validate label keys during metric registration. New label keys must be added deliberately to these lists.
- CI intent: any unregistered label key causes a panic during tests/startup, surfacing changes early.

Families (selected)
- http_method_total {method}
- http_status_class_total {class}
- http_req_duration_ms
- outbound_connect_attempt_total {kind}
- outbound_connect_error_total {kind,class}
- outbound_connect_seconds {kind}
- outbound_handshake_duration_ms {protocol}
- outbound_aead_encrypt_total {protocol,cipher,result}
- outbound_aead_decrypt_total {protocol,cipher,result}
- ss_connect_total {cipher,result}
- ss_encrypt_bytes_total {cipher}
- ss_decrypt_bytes_total {cipher}
- ss_udp_send_total {cipher}
- ss_udp_recv_total {cipher}
- ss_aead_op_duration_ms {cipher,operation}
- ss_stream_error_total {cipher,reason}
- transport_fallback_total {reason,mode,result}
- transport_fallback_ms {mode}
- shadowtls_connect_total {result}
- tuic_connect_total {result}
- tuic_pool_reuse_total
- hysteria2_connect_total {result}
- hysteria2_handshake_ms
- hysteria2_cc_total {algorithm}
- udp_session_open_total {proto,stage|result}
- udp_quic_send_total {proto}
- udp_quic_recv_total {proto}
- udp_quic_send_bytes_total {proto}
- udp_quic_recv_bytes_total {proto}
- dns_query_total {qtype}
- dns_error_total {kind}
- dns_success_total {qtype,from_cache}
- dns_rtt_ms
- udp_upstream_fail_total {class}
- udp_nat_evicted_total {reason}
- inbound_socks_udp_packets_total {dir}
- inbound_error_total {protocol,class}
- inbound_active_connections {protocol}
- router_rule_match_total {category,outbound}
- proxy_select_score {proxy}
- proxy_select_total {proxy}
- outbound_circuit_state {outbound}
- prom_http_fail_total {class}
- bytes_total {dir,chan}

Notes
- inbound_error_total supersedes ad-hoc metrics::counter! usages with label "proto"; prefer label key "protocol" going forward. Legacy emitters may still produce "proto" under the metrics crate; both can coexist during migration.
 - inbound_active_connections is a gauge: HTTP-specific connections are also exported via http_active_connections. For SOCKS and other inbounds, prefer inbound_active_connections with protocol label.
- outbound_circuit_state is a gauge with numeric mapping: 0=closed, 1=half-open, 2=open.
 - transport_fallback_total: reason fixed to primary_failed; mode is the alt chain (e.g., "tls->h2"). Intended for coarse visibility rather than high-cardinality tracing.
- udp_quic_* families are emitted by TUIC/Hysteria2 UDP paths and represent datagram send/recv counters and bytes.
 - transport_fallback_ms: per-attempt duration in milliseconds; labeled by `mode` (e.g., `tls->h2`).

Noise Reduction
- Logging sampling: `SB_LOG_SAMPLE=<N>` enables per‑target rate limiting (per second) in `app/src/logging.rs`.
- Exporter error suppression: `/metrics` HTTP accept/serve errors are rate‑limited (max once/30s per class) in `sb-metrics`.
- Cardinality monitor: `sb-metrics::cardinality` tracks unique label combinations and warns when thresholds are exceeded.
- Unified error classification: use `sb_core::metrics::ErrorClass` helpers to map errors to a stable `{timeout|dns|tls|io|auth|protocol|other}` set. Convenience wrappers:
  - `sb_core::metrics::record_outbound_error(kind, &err)`
  - `sb_core::metrics::dns::record_error_display(&err)` and `http::record_error_display(&err)`
  - Typical mappings (heuristic, stable labels):
    - Timeout: io::ErrorKind::TimedOut, messages containing "deadline"/"timeout"
    - DNS: errors from resolver/backends (NXDOMAIN, NoRecords), `dns_error_total`
    - TLS: rustls/quic handshakes, cert validation failures, ALPN mismatch
    - IO: connection refused/reset/closed, broken pipe, network unreachable
    - Auth: invalid credentials/UUID/token, access denied, handshake auth fail
    - Protocol: parse errors, unsupported version/command/address type
    - Other: anything not matched above (kept small on purpose)

Sensitive Data Redaction
- Do not log secrets. Treat the following as sensitive by default: password, token, secret, key, authorization, cookie.
- Use helper utilities from `app/src/redact.rs` (added by WS7) to sanitize strings when you must include user‑provided content in logs.
- Avoid dumping full configs. If necessary, prefer structured logs with redacted fields.

Operational Notes
- Enable Prometheus exporter: set `SB_METRICS_ADDR=127.0.0.1:9090` and call `sb_metrics::maybe_spawn_http_exporter_from_env()` during startup.
- Build info and uptime gauges are emitted automatically once metrics are initialized.
- Build with metrics enabled:
  - Recommended: app with `--features observe` or `--features acceptance` (includes `sb-metrics`).
  - Run example exporter: `cargo run -p app --features observe --bin metrics-serve` then curl `http://127.0.0.1:9090/metrics`.
  - Or run main: set `SB_METRICS_ADDR=127.0.0.1:9090` and run any `app` binary; exporter spawns automatically (see app/src/tracing_init.rs).
