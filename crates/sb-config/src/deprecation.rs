//! Centralized deprecation directory for singbox configuration.
//!
//! Catalogs all deprecated fields, patterns, and migration paths.
//! Used by the validator to emit IssueCode::Deprecated diagnostics.

use serde::{Deserialize, Serialize};

/// Severity level for deprecated items.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeprecationSeverity {
    /// Informational: field still works but has a better alternative
    Info,
    /// Warning: field will be removed in a future version
    Warning,
    /// Error: field is no longer functional
    Error,
}

/// Category of deprecation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeprecationCategory {
    /// Field has been renamed
    Renamed,
    /// Field has been moved to a different section
    Moved,
    /// Entire type/section replaced by newer approach
    Replaced,
    /// Feature removed entirely
    Removed,
}

/// A single deprecated field entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeprecatedField {
    /// JSON pointer pattern (RFC 6901) for the deprecated location.
    /// Use "*" as wildcard for array indices (e.g., "/outbounds/*/server_port")
    pub json_pointer: &'static str,
    /// Version since which this field is deprecated
    pub since_version: &'static str,
    /// Replacement field/approach (human-readable)
    pub replacement: &'static str,
    /// Severity level
    pub severity: DeprecationSeverity,
    /// Category of deprecation
    pub category: DeprecationCategory,
    /// Brief explanation
    pub description: &'static str,
}

/// Returns the full deprecation directory (all known deprecated fields/patterns).
pub fn deprecation_directory() -> &'static [DeprecatedField] {
    &DEPRECATION_ENTRIES
}

static DEPRECATION_ENTRIES: &[DeprecatedField] = &[
    // 1. WireGuard outbound → endpoint migration
    DeprecatedField {
        json_pointer: "/outbounds/*/type=wireguard",
        since_version: "1.11.0",
        replacement: "Use 'endpoints' with type 'wireguard' instead of outbound",
        severity: DeprecationSeverity::Warning,
        category: DeprecationCategory::Replaced,
        description: "WireGuard outbound is deprecated; use endpoint configuration",
    },
    // 2. Legacy 'tag' field on outbounds (migrated to 'name')
    DeprecatedField {
        json_pointer: "/outbounds/*/tag",
        since_version: "2.0.0",
        replacement: "Use 'name' instead of 'tag' for outbound identification",
        severity: DeprecationSeverity::Warning,
        category: DeprecationCategory::Renamed,
        description: "Outbound 'tag' field renamed to 'name' in schema v2",
    },
    // 3. Legacy 'listen_port' on inbounds (migrated to combined 'listen')
    DeprecatedField {
        json_pointer: "/inbounds/*/listen_port",
        since_version: "2.0.0",
        replacement: "Use combined 'listen' field (e.g., '127.0.0.1:8080') instead of separate listen + listen_port",
        severity: DeprecationSeverity::Info,
        category: DeprecationCategory::Moved,
        description: "Separate listen_port merged into listen field in schema v2",
    },
    // 4. Legacy 'server_port' on outbounds (migrated to 'port')
    DeprecatedField {
        json_pointer: "/outbounds/*/server_port",
        since_version: "2.0.0",
        replacement: "Use 'port' instead of 'server_port'",
        severity: DeprecationSeverity::Info,
        category: DeprecationCategory::Renamed,
        description: "Outbound 'server_port' renamed to 'port' in schema v2",
    },
    // 5. Legacy 'socks5' outbound type (normalized to 'socks')
    DeprecatedField {
        json_pointer: "/outbounds/*/type=socks5",
        since_version: "2.0.0",
        replacement: "Use type 'socks' instead of 'socks5'",
        severity: DeprecationSeverity::Info,
        category: DeprecationCategory::Renamed,
        description: "Outbound type 'socks5' normalized to 'socks'",
    },
    // 6. Legacy 'outbound' in route rules (migrated to 'to')
    DeprecatedField {
        json_pointer: "/route/rules/*/outbound",
        since_version: "2.0.0",
        replacement: "Use 'to' instead of 'outbound' in route rules",
        severity: DeprecationSeverity::Info,
        category: DeprecationCategory::Renamed,
        description: "Route rule 'outbound' field renamed to 'to' in schema v2",
    },
    // 7. Flat rule conditions (should be wrapped in 'when')
    DeprecatedField {
        json_pointer: "/route/rules/*/domain_suffix",
        since_version: "2.0.0",
        replacement: "Wrap condition fields in a 'when' object",
        severity: DeprecationSeverity::Info,
        category: DeprecationCategory::Moved,
        description: "V1 flat condition fields should be wrapped in 'when' object in v2",
    },
    // 8. model::Config legacy structure
    DeprecatedField {
        json_pointer: "/default_outbound",
        since_version: "2.0.0",
        replacement: "Use 'route.default' instead of root-level 'default_outbound'",
        severity: DeprecationSeverity::Warning,
        category: DeprecationCategory::Moved,
        description: "Root-level default_outbound moved to route.default in schema v2",
    },
    // 9. Legacy inbound 'tag' field (migrated to 'name')
    DeprecatedField {
        json_pointer: "/inbounds/*/tag",
        since_version: "2.0.0",
        replacement: "Use 'name' instead of 'tag' for inbound identification",
        severity: DeprecationSeverity::Warning,
        category: DeprecationCategory::Renamed,
        description: "Inbound 'tag' field renamed to 'name' in schema v2",
    },
    // 10. Deprecated inbound fields (Go upstream deprecation)
    DeprecatedField {
        json_pointer: "/inbounds/*/sniff",
        since_version: "1.11.0",
        replacement: "Configure sniffing in route rules instead",
        severity: DeprecationSeverity::Warning,
        category: DeprecationCategory::Moved,
        description: "Per-inbound sniff deprecated; use route-level sniff configuration",
    },
    // ========================================================================
    // TLS Capability Limitations (Info-level notices for Rust implementation)
    // TLS 能力限制（Rust 实现的 Info 级别通知）
    // ========================================================================
    // 11. uTLS non-chrome fingerprint limited support
    DeprecatedField {
        json_pointer: "/outbounds/*/utls_fingerprint",
        since_version: "0.1.0",
        replacement: "Use 'chrome' fingerprint for best compatibility, or omit for native TLS",
        severity: DeprecationSeverity::Info,
        category: DeprecationCategory::Replaced,
        description: "uTLS fingerprints other than 'chrome' have limited support in Rust; \
            some fingerprints may fall back to native TLS behavior",
    },
    // 12. ECH (Encrypted Client Hello) behind feature flag
    DeprecatedField {
        json_pointer: "/outbounds/*/encrypted_client_hello",
        since_version: "0.1.0",
        replacement: "Enable the 'tls_ech' feature flag at build time for ECH support",
        severity: DeprecationSeverity::Info,
        category: DeprecationCategory::Replaced,
        description: "Encrypted Client Hello (ECH) requires the 'tls_ech' feature flag; \
            without it, ECH configuration is silently ignored",
    },
    // 13. REALITY TLS status
    DeprecatedField {
        json_pointer: "/outbounds/*/reality_enabled",
        since_version: "0.1.0",
        replacement: "REALITY is supported; ensure reality_public_key and reality_short_id are set",
        severity: DeprecationSeverity::Info,
        category: DeprecationCategory::Replaced,
        description: "REALITY TLS is supported in Rust via rustls; \
            verify public_key and short_id are correctly configured",
    },
];

/// Check if a given JSON pointer matches a deprecation pattern.
/// Supports wildcard '*' for array indices.
pub fn matches_deprecation_pattern(pointer: &str, pattern: &str) -> bool {
    let pointer_parts: Vec<&str> = pointer.split('/').collect();
    let pattern_parts: Vec<&str> = pattern.split('/').collect();

    if pointer_parts.len() != pattern_parts.len() {
        return false;
    }

    for (pp, pat) in pointer_parts.iter().zip(pattern_parts.iter()) {
        if *pat == "*" {
            continue;
        }
        // Handle type= patterns (e.g., "type=wireguard")
        if pat.contains('=') {
            // This is a type-match pattern, skip for simple pointer matching
            continue;
        }
        if pp != pat {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_directory_not_empty() {
        let dir = deprecation_directory();
        assert!(
            dir.len() >= 13,
            "Expected at least 13 deprecation entries, got {}",
            dir.len()
        );
    }

    #[test]
    fn test_no_duplicate_pointers() {
        let dir = deprecation_directory();
        let mut seen = std::collections::HashSet::new();
        for entry in dir {
            assert!(
                seen.insert(entry.json_pointer),
                "Duplicate json_pointer: {}",
                entry.json_pointer
            );
        }
    }

    #[test]
    fn test_severity_coverage() {
        let dir = deprecation_directory();
        let has_info = dir.iter().any(|e| e.severity == DeprecationSeverity::Info);
        let has_warning = dir.iter().any(|e| e.severity == DeprecationSeverity::Warning);
        assert!(has_info, "Should have at least one Info severity entry");
        assert!(
            has_warning,
            "Should have at least one Warning severity entry"
        );
    }

    #[test]
    fn test_pattern_matching() {
        assert!(matches_deprecation_pattern(
            "/outbounds/0/tag",
            "/outbounds/*/tag"
        ));
        assert!(matches_deprecation_pattern(
            "/outbounds/5/tag",
            "/outbounds/*/tag"
        ));
        assert!(!matches_deprecation_pattern(
            "/inbounds/0/tag",
            "/outbounds/*/tag"
        ));
        assert!(matches_deprecation_pattern(
            "/route/rules/0/outbound",
            "/route/rules/*/outbound"
        ));
    }

    #[test]
    fn test_all_entries_have_replacement() {
        for entry in deprecation_directory() {
            assert!(
                !entry.replacement.is_empty(),
                "Entry {} missing replacement",
                entry.json_pointer
            );
            assert!(
                !entry.description.is_empty(),
                "Entry {} missing description",
                entry.json_pointer
            );
        }
    }
}
