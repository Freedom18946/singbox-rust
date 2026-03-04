use anyhow::{Context, Result};
use chrono::Utc;
use sb_config::ir::{ConfigIR, InboundType, OutboundIR, OutboundType};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, HashSet};
use std::path::Path;

const PROBE_SCHEMA_VERSION: &str = "1.0.0";
const PROBE_MODE: &str = "startup-static";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityProbeReport {
    pub schema_version: String,
    pub generated_at: String,
    pub probe_mode: String,
    pub probes: Vec<CapabilityProbeEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityProbeEntry {
    pub capability_id: String,
    pub compile_state: String,
    pub runtime_state: String,
    pub requested: bool,
    pub summary: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub details: BTreeMap<String, String>,
}

#[must_use]
pub fn collect_report(raw: &Value, ir: &ConfigIR) -> CapabilityProbeReport {
    let utls_requested_profiles = collect_utls_requested_profiles(raw);
    let ech_requests = count_ech_requests(raw);
    let quic_requested = ir.outbounds.iter().any(outbound_uses_quic);

    CapabilityProbeReport {
        schema_version: PROBE_SCHEMA_VERSION.to_string(),
        generated_at: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        probe_mode: PROBE_MODE.to_string(),
        probes: vec![
            probe_tun(ir),
            probe_redirect(ir),
            probe_tproxy(ir),
            probe_utls(&utls_requested_profiles),
            probe_ech_tcp(ech_requests),
            probe_ech_quic(ech_requests, quic_requested),
        ],
    }
}

pub fn log_report(report: &CapabilityProbeReport) {
    for probe in &report.probes {
        tracing::info!(
            target: "app::capability_probe",
            capability_id = %probe.capability_id,
            compile_state = %probe.compile_state,
            runtime_state = %probe.runtime_state,
            requested = probe.requested,
            summary = %probe.summary,
            "capability-probe"
        );
    }
}

pub fn write_report(report: &CapabilityProbeReport, out_path: &Path) -> Result<()> {
    let parent = out_path
        .parent()
        .context("probe output path has no parent")?;
    std::fs::create_dir_all(parent).with_context(|| {
        format!(
            "failed to create capability probe output directory {}",
            parent.display()
        )
    })?;
    let payload = serde_json::to_string_pretty(report).context("serialize probe report failed")?;
    std::fs::write(out_path, format!("{payload}\n")).with_context(|| {
        format!(
            "failed to write capability probe report to {}",
            out_path.display()
        )
    })?;
    Ok(())
}

#[must_use]
pub fn probe_only_enabled() -> bool {
    env_flag("SB_CAPABILITY_PROBE_ONLY")
}

#[must_use]
pub fn probe_output_path_from_env() -> Option<String> {
    std::env::var("SB_CAPABILITY_PROBE_OUT")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

#[must_use]
pub fn default_probe_output_path() -> &'static str {
    "reports/runtime/capability_probe.json"
}

fn env_flag(name: &str) -> bool {
    std::env::var(name).ok().is_some_and(|v| {
        let v = v.trim();
        v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes")
    })
}

fn probe_tun(ir: &ConfigIR) -> CapabilityProbeEntry {
    let requested = ir.inbounds.iter().any(|ib| ib.ty == InboundType::Tun);
    let tun2socks_mode = if cfg!(feature = "tun2socks-real") {
        "real"
    } else if cfg!(feature = "tun2socks-stub") {
        "stub"
    } else {
        "absent"
    };

    let compile_state = match tun2socks_mode {
        "real" => "supported",
        "stub" => "stubbed",
        _ => "absent",
    };

    let (runtime_state, summary) = match (compile_state, requested) {
        ("supported", true) => (
            "unverified",
            "TUN inbound is configured; tun2socks real mode is compiled, but startup probe is static.",
        ),
        ("supported", false) => (
            "unverified",
            "tun2socks real mode is compiled; no TUN inbound is requested in current config.",
        ),
        ("stubbed", true) => (
            "unsupported",
            "TUN inbound is configured but tun2socks is compiled in stub mode.",
        ),
        ("stubbed", false) => ("unsupported", "tun2socks is compiled in stub mode."),
        ("absent", true) => (
            "blocked",
            "TUN inbound is configured but tun2socks capability is not compiled in this build.",
        ),
        _ => (
            "unsupported",
            "tun2socks capability is not compiled in this build.",
        ),
    };

    let mut details = BTreeMap::new();
    details.insert("tun2socks_mode".to_string(), tun2socks_mode.to_string());
    details.insert(
        "feature_tun2socks_real".to_string(),
        yes_no(cfg!(feature = "tun2socks-real")),
    );
    details.insert(
        "feature_tun2socks_stub".to_string(),
        yes_no(cfg!(feature = "tun2socks-stub")),
    );

    CapabilityProbeEntry {
        capability_id: "tun.macos.tun2socks".to_string(),
        compile_state: compile_state.to_string(),
        runtime_state: runtime_state.to_string(),
        requested,
        summary: summary.to_string(),
        details,
    }
}

fn probe_redirect(ir: &ConfigIR) -> CapabilityProbeEntry {
    let requested = ir.inbounds.iter().any(|ib| ib.ty == InboundType::Redirect);
    let summary = if requested {
        "redirect inbound is configured but this build does not wire redirect runtime path."
    } else {
        "redirect inbound runtime path is not wired in this build."
    };

    CapabilityProbeEntry {
        capability_id: "inbound.redirect".to_string(),
        compile_state: "gated_off".to_string(),
        runtime_state: "unsupported".to_string(),
        requested,
        summary: summary.to_string(),
        details: BTreeMap::new(),
    }
}

fn probe_tproxy(ir: &ConfigIR) -> CapabilityProbeEntry {
    let requested = ir.inbounds.iter().any(|ib| ib.ty == InboundType::Tproxy);
    let summary = if requested {
        "tproxy inbound is configured but this build does not wire tproxy runtime path."
    } else {
        "tproxy inbound runtime path is not wired in this build."
    };

    CapabilityProbeEntry {
        capability_id: "inbound.tproxy".to_string(),
        compile_state: "gated_off".to_string(),
        runtime_state: "unsupported".to_string(),
        requested,
        summary: summary.to_string(),
        details: BTreeMap::new(),
    }
}

#[derive(Debug, Clone)]
struct UtlsProfileObservation {
    requested_profile: String,
    effective_profile: String,
    fallback_reason: Option<String>,
}

fn probe_utls(utls_requested_profiles: &[String]) -> CapabilityProbeEntry {
    let requested = !utls_requested_profiles.is_empty();
    let compile_state = if cfg!(feature = "sb-tls") {
        "supported"
    } else {
        "absent"
    };

    let observations: Vec<UtlsProfileObservation> = utls_requested_profiles
        .iter()
        .map(|profile| resolve_utls_profile(profile))
        .collect();
    let effective_profiles = dedup_preserve(
        observations
            .iter()
            .map(|obs| obs.effective_profile.clone())
            .collect(),
    );
    let fallback_reasons = dedup_preserve(
        observations
            .iter()
            .filter_map(|obs| obs.fallback_reason.clone())
            .collect(),
    );

    let (runtime_state, summary) = match (compile_state, requested) {
        ("supported", true) => (
            "unverified",
            "uTLS fingerprint is requested in config; startup probe records requested/effective profile mapping without handshake verification.",
        ),
        ("supported", false) => (
            "unverified",
            "uTLS is compiled; no utls_fingerprint request detected in current config.",
        ),
        ("absent", true) => (
            "blocked",
            "uTLS fingerprint is requested but sb-tls is not compiled in this build.",
        ),
        _ => (
            "unsupported",
            "sb-tls is not compiled in this build, uTLS runtime is unavailable.",
        ),
    };

    let mut details = BTreeMap::new();
    details.insert(
        "utls_request_count".to_string(),
        utls_requested_profiles.len().to_string(),
    );
    details.insert(
        "requested_profile".to_string(),
        csv_or_dash(utls_requested_profiles),
    );
    details.insert(
        "effective_profile".to_string(),
        csv_or_dash(&effective_profiles),
    );
    details.insert(
        "fallback_reason".to_string(),
        csv_or_dash(&fallback_reasons),
    );
    details.insert(
        "feature_sb_tls".to_string(),
        yes_no(cfg!(feature = "sb-tls")),
    );

    CapabilityProbeEntry {
        capability_id: "tls.utls".to_string(),
        compile_state: compile_state.to_string(),
        runtime_state: runtime_state.to_string(),
        requested,
        summary: summary.to_string(),
        details,
    }
}

fn probe_ech_tcp(ech_requests: usize) -> CapabilityProbeEntry {
    let requested = ech_requests > 0;
    let compile_state = if cfg!(feature = "tls_ech") {
        "supported"
    } else if cfg!(feature = "sb-tls") {
        "gated_off"
    } else {
        "absent"
    };

    let (runtime_state, summary) = match (compile_state, requested) {
        ("supported", true) => (
            "unverified",
            "ECH is requested and tls_ech is compiled; startup probe does not perform live ECH handshake.",
        ),
        ("supported", false) => (
            "unverified",
            "tls_ech is compiled; no ECH request detected in current config.",
        ),
        (_, true) => (
            "blocked",
            "ECH is requested but tls_ech feature is disabled in this build.",
        ),
        _ => (
            "unsupported",
            "tls_ech feature is disabled in this build, ECH runtime is unavailable.",
        ),
    };

    let mut details = BTreeMap::new();
    details.insert("ech_request_count".to_string(), ech_requests.to_string());
    details.insert(
        "feature_tls_ech".to_string(),
        yes_no(cfg!(feature = "tls_ech")),
    );
    details.insert(
        "feature_sb_tls".to_string(),
        yes_no(cfg!(feature = "sb-tls")),
    );

    CapabilityProbeEntry {
        capability_id: "tls.ech.tcp".to_string(),
        compile_state: compile_state.to_string(),
        runtime_state: runtime_state.to_string(),
        requested,
        summary: summary.to_string(),
        details,
    }
}

fn probe_ech_quic(ech_requests: usize, quic_requested: bool) -> CapabilityProbeEntry {
    let requested = ech_requests > 0 && quic_requested;
    let compile_state = if cfg!(feature = "tls_ech") {
        "supported"
    } else if cfg!(feature = "sb-tls") {
        "gated_off"
    } else {
        "absent"
    };

    let summary = if requested {
        "ECH + QUIC request detected; QUIC-ECH runtime path remains unsupported in current implementation."
    } else if quic_requested {
        "QUIC transport is requested, but no ECH request is detected."
    } else {
        "No QUIC + ECH request detected in current config."
    };

    let mut details = BTreeMap::new();
    details.insert("ech_request_count".to_string(), ech_requests.to_string());
    details.insert("quic_requested".to_string(), yes_no(quic_requested));
    details.insert(
        "feature_tls_ech".to_string(),
        yes_no(cfg!(feature = "tls_ech")),
    );

    CapabilityProbeEntry {
        capability_id: "tls.ech.quic".to_string(),
        compile_state: compile_state.to_string(),
        runtime_state: "unsupported".to_string(),
        requested,
        summary: summary.to_string(),
        details,
    }
}

fn outbound_uses_quic(ob: &OutboundIR) -> bool {
    if matches!(
        ob.ty,
        OutboundType::Tuic | OutboundType::Hysteria | OutboundType::Hysteria2
    ) {
        return true;
    }

    if ob
        .transport
        .as_ref()
        .is_some_and(|chain| chain.iter().any(|v| v.eq_ignore_ascii_case("quic")))
    {
        return true;
    }

    if ob
        .network
        .as_deref()
        .is_some_and(|v| contains_token_ci(v, "quic"))
    {
        return true;
    }

    ob.udp_relay_mode
        .as_deref()
        .is_some_and(|v| v.eq_ignore_ascii_case("quic"))
}

fn contains_token_ci(value: &str, needle: &str) -> bool {
    value
        .split(',')
        .map(str::trim)
        .any(|token| token.eq_ignore_ascii_case(needle))
}

fn collect_utls_requested_profiles(root: &Value) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    walk_json(root, &mut |obj| {
        let Some(value) = obj.get("utls_fingerprint").and_then(Value::as_str) else {
            return;
        };
        let requested_profile = normalize_profile_token(value);
        if requested_profile.is_empty() {
            return;
        }
        if seen.insert(requested_profile.clone()) {
            out.push(requested_profile);
        }
    });
    out
}

fn resolve_utls_profile(requested_profile: &str) -> UtlsProfileObservation {
    let requested = normalize_profile_token(requested_profile);
    let requested = if requested.is_empty() {
        "chrome".to_string()
    } else {
        requested
    };

    let (effective_profile, fallback_reason) = match requested.as_str() {
        // Chrome aliases and versions are currently mapped to the chrome_110 template.
        "chrome110" => ("chrome110".to_string(), None),
        "chrome"
        | "chrome58"
        | "chrome62"
        | "chrome70"
        | "chrome72"
        | "chrome83"
        | "chrome87"
        | "chrome96"
        | "chrome100"
        | "chrome102"
        | "chrome106"
        | "chrome_psk"
        | "chrome_psk_shuffle"
        | "chrome_padding_psk_shuffle"
        | "chrome_pq"
        | "chrome_pq_psk"
        | "chromepsk"
        | "chromepq"
        | "android"
        | "android11"
        | "android_11" => (
            "chrome110".to_string(),
            Some(format!(
                "requested '{}' mapped to chrome110 template",
                requested
            )),
        ),

        // Firefox high versions map to firefox_105 template.
        "firefox105" => ("firefox105".to_string(), None),
        "firefox" | "firefox63" | "firefox65" | "firefox99" => (
            "firefox105".to_string(),
            Some(format!(
                "requested '{}' mapped to firefox105 template",
                requested
            )),
        ),

        // Legacy Firefox aliases currently fall back to chrome_110 in sb-tls mapping.
        "firefox55" | "firefox56" => (
            "chrome110".to_string(),
            Some(format!(
                "requested '{}' falls back to chrome110 template",
                requested
            )),
        ),

        // Safari/iOS aliases map to safari_ios16 template.
        "safari_ios16" => ("safari_ios16".to_string(), None),
        "safari" | "ios" | "ios14" | "safari_ios14" | "ios15" | "safari_ios15" | "ios16" => (
            "safari_ios16".to_string(),
            Some(format!(
                "requested '{}' mapped to safari_ios16 template",
                requested
            )),
        ),

        // Edge / browser-specific / randomized aliases are all mapped to chrome_110 template.
        "edge" | "edge85" | "edge106" | "random" | "randomized" | "randomchrome"
        | "random_chrome" | "randomfirefox" | "random_firefox" | "360" | "360browser" | "qq"
        | "qqbrowser" => (
            "chrome110".to_string(),
            Some(format!(
                "requested '{}' mapped to chrome110 template",
                requested
            )),
        ),

        other => (
            "chrome110".to_string(),
            Some(format!(
                "requested '{}' is unknown to startup probe mapping; assume chrome110 fallback",
                other
            )),
        ),
    };

    UtlsProfileObservation {
        requested_profile: requested,
        effective_profile,
        fallback_reason,
    }
}

fn normalize_profile_token(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace('-', "_")
}

fn dedup_preserve(values: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for value in values {
        if value.is_empty() {
            continue;
        }
        if seen.insert(value.clone()) {
            out.push(value);
        }
    }
    out
}

fn csv_or_dash(values: &[String]) -> String {
    if values.is_empty() {
        "-".to_string()
    } else {
        values.join(",")
    }
}

fn count_ech_requests(root: &Value) -> usize {
    let mut count = 0usize;
    walk_json(root, &mut |obj| {
        let Some(ech) = obj.get("ech") else {
            return;
        };
        if ech_enabled(ech) {
            count += 1;
        }
    });
    count
}

fn ech_enabled(v: &Value) -> bool {
    let Value::Object(map) = v else {
        return false;
    };

    if map.get("enabled").and_then(Value::as_bool).unwrap_or(false) {
        return true;
    }

    map.get("config")
        .and_then(Value::as_str)
        .is_some_and(|s| !s.trim().is_empty())
}

fn walk_json(v: &Value, visitor: &mut dyn FnMut(&Map<String, Value>)) {
    match v {
        Value::Object(map) => {
            visitor(map);
            for value in map.values() {
                walk_json(value, visitor);
            }
        }
        Value::Array(items) => {
            for value in items {
                walk_json(value, visitor);
            }
        }
        _ => {}
    }
}

fn yes_no(value: bool) -> String {
    if value {
        "yes".to_string()
    } else {
        "no".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn find<'a>(report: &'a CapabilityProbeReport, id: &str) -> &'a CapabilityProbeEntry {
        report
            .probes
            .iter()
            .find(|probe| probe.capability_id == id)
            .unwrap_or_else(|| panic!("missing probe id {id}"))
    }

    #[test]
    fn counts_utls_requests_recursively() {
        let raw = json!({
            "outbounds": [
                { "utls_fingerprint": "chrome" },
                { "utls_fingerprint": "" },
                { "nested": { "utls_fingerprint": "firefox" } }
            ]
        });
        assert_eq!(
            collect_utls_requested_profiles(&raw),
            vec!["chrome".to_string(), "firefox".to_string()]
        );
    }

    #[test]
    fn resolves_utls_profile_with_effective_and_fallback() {
        let resolved = resolve_utls_profile("randomized");
        assert_eq!(resolved.requested_profile, "randomized");
        assert_eq!(resolved.effective_profile, "chrome110");
        assert!(resolved
            .fallback_reason
            .as_deref()
            .is_some_and(|v| v.contains("mapped to chrome110")));
    }

    #[test]
    fn utls_probe_contains_profile_mapping_details() {
        let raw = json!({
            "outbounds": [
                { "utls_fingerprint": "chrome_psk" },
                { "utls_fingerprint": "firefox" },
                { "utls_fingerprint": "randomized" }
            ]
        });
        let ir = ConfigIR::default();
        let report = collect_report(&raw, &ir);
        let probe = find(&report, "tls.utls");

        assert_eq!(
            probe.details.get("utls_request_count"),
            Some(&"3".to_string())
        );
        assert_eq!(
            probe.details.get("requested_profile"),
            Some(&"chrome_psk,firefox,randomized".to_string())
        );
        assert_eq!(
            probe.details.get("effective_profile"),
            Some(&"chrome110,firefox105".to_string())
        );
        assert!(probe
            .details
            .get("fallback_reason")
            .is_some_and(|v| v.contains("chrome_psk")));
    }

    #[test]
    fn counts_ech_requests_when_enabled_or_config_present() {
        let raw = json!({
            "outbounds": [
                { "tls": { "ech": { "enabled": true } } },
                { "tls": { "ech": { "config": "BASE64" } } },
                { "tls": { "ech": { "enabled": false } } }
            ]
        });
        assert_eq!(count_ech_requests(&raw), 2);
    }

    #[test]
    fn marks_quic_ech_requested_when_quic_and_ech_coexist() {
        let raw = json!({
            "outbounds": [
                { "tls": { "ech": { "enabled": true } } }
            ]
        });
        let mut ir = ConfigIR::default();
        ir.outbounds.push(OutboundIR {
            ty: OutboundType::Tuic,
            ..Default::default()
        });

        let report = collect_report(&raw, &ir);
        let probe = find(&report, "tls.ech.quic");
        assert!(probe.requested);
        assert_eq!(probe.runtime_state, "unsupported");
    }
}
