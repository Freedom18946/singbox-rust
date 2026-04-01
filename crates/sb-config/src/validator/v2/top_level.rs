use serde_json::Value;

use crate::ir::ConfigIR;

/// Lower top-level blocks (experimental, log, ntp, certificate) from raw JSON into IR.
///
/// This is the actual owner of top-level block lowering. `to_ir_v1()` delegates here.
/// Shared helpers (`parse_seconds_field_to_millis`, `parse_millis_field`) remain in the
/// parent module since they are also used by outbound lowering.
pub(crate) fn lower_top_level_blocks(doc: &Value, ir: &mut ConfigIR) {
    lower_experimental(doc, ir);
    lower_log(doc, ir);
    lower_ntp(doc, ir);
    lower_certificate(doc, ir);
}

/// Preserve optional experimental block (schema v2 passthrough).
fn lower_experimental(doc: &Value, ir: &mut ConfigIR) {
    if let Some(exp) = doc.get("experimental") {
        ir.experimental = serde_json::from_value(exp.clone()).ok();
    }
}

/// Parse optional log block (top-level).
fn lower_log(doc: &Value, ir: &mut ConfigIR) {
    if let Some(log) = doc.get("log").and_then(|v| v.as_object()) {
        let l = crate::ir::LogIR {
            level: log
                .get("level")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            timestamp: log.get("timestamp").and_then(|v| v.as_bool()),
            // Non-standard extension for rust build: allow format override
            format: log
                .get("format")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            // Go parity: log.disabled
            disabled: log.get("disabled").and_then(|v| v.as_bool()),
            // Go parity: log.output (stdout/stderr/path)
            output: log
                .get("output")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
        };
        ir.log = Some(l);
    }
}

/// Parse optional NTP block (top-level).
fn lower_ntp(doc: &Value, ir: &mut ConfigIR) {
    if let Some(ntp) = doc.get("ntp").and_then(|v| v.as_object()) {
        let n = crate::ir::NtpIR {
            enabled: ntp
                .get("enabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            server: ntp
                .get("server")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            server_port: ntp
                .get("server_port")
                .and_then(|v| v.as_u64())
                .and_then(|x| u16::try_from(x).ok()),
            // Support either interval (string like "30m") or interval_ms (number)
            interval_ms: super::parse_seconds_field_to_millis(ntp.get("interval"))
                .or_else(|| ntp.get("interval_ms").and_then(|v| v.as_u64())),
            // Optional timeout_ms (number or duration string)
            timeout_ms: super::parse_millis_field(ntp.get("timeout_ms"))
                .or_else(|| super::parse_seconds_field_to_millis(ntp.get("timeout"))),
        };
        ir.ntp = Some(n);
    }
}

/// Parse optional certificate block (top-level).
fn lower_certificate(doc: &Value, ir: &mut ConfigIR) {
    if let Some(cert) = doc.get("certificate").and_then(|v| v.as_object()) {
        // Parse store mode ("system", "mozilla", or "none")
        let mut c = crate::ir::CertificateIR {
            store: cert
                .get("store")
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            ..Default::default()
        };
        if let Some(arr) = cert.get("ca_paths").and_then(|v| v.as_array()) {
            for p in arr {
                if let Some(s) = p.as_str() {
                    let s = s.trim();
                    if !s.is_empty() {
                        c.ca_paths.push(s.to_string());
                    }
                }
            }
        }
        // Support both array and single-string for ca_pem
        match cert.get("ca_pem") {
            Some(v) if v.is_array() => {
                if let Some(arr) = v.as_array() {
                    for it in arr {
                        if let Some(s) = it.as_str() {
                            let s = s.trim();
                            if !s.is_empty() {
                                c.ca_pem.push(s.to_string());
                            }
                        }
                    }
                }
            }
            Some(v) if v.is_string() => {
                if let Some(s) = v.as_str() {
                    let s = s.trim();
                    if !s.is_empty() {
                        c.ca_pem.push(s.to_string());
                    }
                }
            }
            _ => {}
        }
        // Parse certificate directory path
        c.certificate_directory_path = cert
            .get("certificate_directory_path")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        ir.certificate = Some(c);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator::v2::to_ir_v1;

    // ───── Migrated from mod.rs ─────

    #[test]
    fn test_parse_experimental_block() {
        let json = serde_json::json!({
            "schema_version": 2,
            "experimental": {
                "quic_ech_mode": "experimental"
            }
        });

        let ir = to_ir_v1(&json);
        let exp = ir
            .experimental
            .expect("experimental block should be present");
        assert_eq!(exp.quic_ech_mode.as_deref(), Some("experimental"));
    }

    #[test]
    fn test_parse_ntp_block() {
        let json = serde_json::json!({
            "schema_version": 2,
            "ntp": {
                "enabled": true,
                "server": "time.apple.com",
                "server_port": 123,
                "interval": "30m",
                "timeout_ms": 2500
            }
        });
        let ir = to_ir_v1(&json);
        let ntp = ir.ntp.expect("ntp should be present");
        assert!(ntp.enabled);
        assert_eq!(ntp.server.as_deref(), Some("time.apple.com"));
        assert_eq!(ntp.server_port, Some(123));
        assert_eq!(ntp.interval_ms, Some(30 * 60 * 1000));
        assert_eq!(ntp.timeout_ms, Some(2500));
    }

    #[test]
    fn test_parse_top_level_certificate_block() {
        let json = serde_json::json!({
            "schema_version": 2,
            "certificate": {
                "ca_paths": ["/etc/custom/root.pem"],
                "ca_pem": ["-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"]
            }
        });
        let ir = to_ir_v1(&json);
        let cert = ir.certificate.expect("certificate should be parsed");
        assert_eq!(cert.ca_paths, vec!["/etc/custom/root.pem".to_string()]);
        assert_eq!(cert.ca_pem.len(), 1);
    }

    // ───── New: log block lowering test ─────

    #[test]
    fn test_parse_log_block() {
        let json = serde_json::json!({
            "schema_version": 2,
            "log": {
                "level": "debug",
                "timestamp": true,
                "format": "json",
                "disabled": false,
                "output": "stderr"
            }
        });
        let ir = to_ir_v1(&json);
        let log = ir.log.expect("log block should be present");
        assert_eq!(log.level.as_deref(), Some("debug"));
        assert_eq!(log.timestamp, Some(true));
        assert_eq!(log.format.as_deref(), Some("json"));
        assert_eq!(log.disabled, Some(false));
        assert_eq!(log.output.as_deref(), Some("stderr"));
    }

    #[test]
    fn test_log_block_absent_gives_none() {
        let json = serde_json::json!({ "schema_version": 2 });
        let ir = to_ir_v1(&json);
        assert!(ir.log.is_none(), "absent log block should give None");
    }

    // ───── New: ntp interval_ms direct field ─────

    #[test]
    fn test_ntp_interval_ms_direct() {
        let json = serde_json::json!({
            "ntp": {
                "enabled": true,
                "interval_ms": 60000
            }
        });
        let ir = to_ir_v1(&json);
        let ntp = ir.ntp.expect("ntp should be present");
        assert_eq!(ntp.interval_ms, Some(60000));
    }

    // ───── New: ntp timeout via seconds string ─────

    #[test]
    fn test_ntp_timeout_seconds_string() {
        let json = serde_json::json!({
            "ntp": {
                "enabled": false,
                "timeout": "5s"
            }
        });
        let ir = to_ir_v1(&json);
        let ntp = ir.ntp.expect("ntp should be present");
        assert_eq!(ntp.timeout_ms, Some(5000));
    }

    // ───── New: certificate store + directory_path ─────

    #[test]
    fn test_certificate_store_and_directory_path() {
        let json = serde_json::json!({
            "certificate": {
                "store": "mozilla",
                "certificate_directory_path": "/etc/ssl/custom"
            }
        });
        let ir = to_ir_v1(&json);
        let cert = ir.certificate.expect("certificate should be parsed");
        assert_eq!(cert.store.as_deref(), Some("mozilla"));
        assert_eq!(
            cert.certificate_directory_path.as_deref(),
            Some("/etc/ssl/custom")
        );
    }

    // ───── New: certificate ca_pem single string ─────

    #[test]
    fn test_certificate_ca_pem_single_string() {
        let json = serde_json::json!({
            "certificate": {
                "ca_pem": "-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----"
            }
        });
        let ir = to_ir_v1(&json);
        let cert = ir.certificate.expect("certificate should be parsed");
        assert_eq!(cert.ca_pem.len(), 1);
        assert!(cert.ca_pem[0].contains("ABC"));
    }

    // ───── Pins ─────

    #[test]
    fn wp30ac_pin_top_level_lowering_owner_is_top_level_rs() {
        // Pin: top-level block lowering (experimental/log/ntp/certificate) is owned
        // by validator/v2/top_level.rs, not mod.rs.
        let json = serde_json::json!({
            "experimental": { "quic_ech_mode": "experimental" },
            "log": { "level": "info" },
            "ntp": { "enabled": true, "server": "pool.ntp.org" },
            "certificate": { "store": "system" }
        });
        let mut ir = ConfigIR::default();
        lower_top_level_blocks(&json, &mut ir);
        assert!(ir.experimental.is_some(), "experimental should be lowered by top_level.rs");
        assert!(ir.log.is_some(), "log should be lowered by top_level.rs");
        assert!(ir.ntp.is_some(), "ntp should be lowered by top_level.rs");
        assert!(ir.certificate.is_some(), "certificate should be lowered by top_level.rs");
    }

    #[test]
    fn wp30ac_pin_to_ir_v1_delegates_top_level_lowering() {
        // Pin: to_ir_v1() delegates top-level lowering to top_level::lower_top_level_blocks(),
        // it does not contain inline lowering for experimental/log/ntp/certificate.
        //
        // Verification: to_ir_v1() produces the same result as calling lower_top_level_blocks()
        // directly for the top-level fields.
        let json = serde_json::json!({
            "experimental": { "quic_ech_mode": "experimental" },
            "log": { "level": "warn", "timestamp": false },
            "ntp": { "enabled": true, "server": "time.google.com", "server_port": 123 },
            "certificate": { "store": "mozilla", "ca_paths": ["/ca.pem"] }
        });

        let ir_full = to_ir_v1(&json);

        let mut ir_direct = ConfigIR::default();
        lower_top_level_blocks(&json, &mut ir_direct);

        // Compare top-level fields
        assert_eq!(
            ir_full.experimental.as_ref().and_then(|e| e.quic_ech_mode.as_deref()),
            ir_direct.experimental.as_ref().and_then(|e| e.quic_ech_mode.as_deref()),
            "experimental mismatch"
        );
        assert_eq!(
            ir_full.log.as_ref().and_then(|l| l.level.as_deref()),
            ir_direct.log.as_ref().and_then(|l| l.level.as_deref()),
            "log.level mismatch"
        );
        assert_eq!(
            ir_full.ntp.as_ref().map(|n| n.enabled),
            ir_direct.ntp.as_ref().map(|n| n.enabled),
            "ntp.enabled mismatch"
        );
        assert_eq!(
            ir_full.certificate.as_ref().and_then(|c| c.store.as_deref()),
            ir_direct.certificate.as_ref().and_then(|c| c.store.as_deref()),
            "certificate.store mismatch"
        );
    }
}
