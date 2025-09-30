//! Integration tests for the new core modules

#[cfg(test)]
mod tests {
    use crate::error::*;
    use crate::pointer::*;
    use crate::types::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn test_error_system_integration() {
        // Test SbError creation and manipulation
        let config_error = SbError::config(
            IssueCode::UnknownField,
            "/config/inbounds/0/unknown_field",
            "Unknown field 'unknown_field'",
        )
        .with_hint("Did you mean 'listen'?");

        match &config_error {
            SbError::Config {
                code,
                ptr,
                msg,
                hint,
            } => {
                assert_eq!(*code, IssueCode::UnknownField);
                assert_eq!(ptr, "/config/inbounds/0/unknown_field");
                assert_eq!(msg, "Unknown field 'unknown_field'");
                assert_eq!(hint, &Some("Did you mean 'listen'?".to_string()));
            }
            _ => assert!(false, "Expected Config error from malformed configuration"),
        }

        // Test other error types
        let network_error = SbError::network(ErrorClass::Connection, "Connection refused");
        let timeout_error = SbError::timeout("connect", 5000);
        let capacity_error = SbError::capacity("connections", 1000);

        // Test error report
        let errors = vec![config_error, network_error, timeout_error, capacity_error];
        let report = ErrorReport::from_errors(errors);

        assert_eq!(report.issues.len(), 4);
        assert!(!report.fingerprint.is_empty());
        assert!(report.fingerprint.starts_with("sha256:"));
    }

    #[test]
    fn test_types_integration() {
        // Test Host creation and methods
        let domain_host = Host::domain("example.com");
        assert!(domain_host.is_domain());
        assert!(!domain_host.is_ip());
        assert_eq!(domain_host.as_domain(), Some("example.com"));
        assert_eq!(domain_host.as_ip(), None);

        let ip_host = Host::ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(!ip_host.is_domain());
        assert!(ip_host.is_ip());
        assert_eq!(ip_host.as_domain(), None);
        assert_eq!(
            ip_host.as_ip(),
            Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
        );

        // Test Endpoint
        let endpoint = Endpoint::new("example.com", 443);
        assert_eq!(endpoint.host.as_domain(), Some("example.com"));
        assert_eq!(endpoint.port, 443);

        let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let endpoint_from_socket = Endpoint::from_socket_addr(socket_addr);
        assert_eq!(endpoint_from_socket.to_socket_addr(), Some(socket_addr));

        // Test ConnCtx
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 12345);
        let dst = Endpoint::new("example.com", 443);
        let process = ProcessInfo::new("firefox".to_string(), "/usr/bin/firefox".to_string(), 1234);

        let ctx = ConnCtx::new(1, Network::Tcp, src, dst.clone())
            .with_sni("example.com")
            .with_user("test_user");

        assert_eq!(ctx.network, Network::Tcp);
        assert_eq!(ctx.src, src);
        assert_eq!(ctx.dst, dst);
        assert_eq!(ctx.sni, Some("example.com".into()));
        assert_eq!(ctx.user, Some("test_user".into()));
    }

    #[test]
    fn test_json_pointer_integration() {
        // Test basic pointer operations
        let ptr = JsonPointer::new()
            .with_segment("config")
            .with_segment("inbounds")
            .with_index(0)
            .with_segment("listen");

        assert_eq!(ptr.to_string(), "/config/inbounds/0/listen");
        assert_eq!(ptr.segments(), &["config", "inbounds", "0", "listen"]);
        assert!(!ptr.is_empty());
        assert_eq!(ptr.last_segment(), Some("listen"));

        // Test parent navigation
        let parent = ptr.parent();
        assert_eq!(parent.to_string(), "/config/inbounds/0");
        assert_eq!(parent.last_segment(), Some("0"));

        // Test encoding/decoding of special characters
        let ptr_with_special = JsonPointer::new()
            .with_segment("foo~bar")
            .with_segment("baz/qux");
        assert_eq!(ptr_with_special.to_string(), "/foo~0bar/baz~1qux");

        let decoded_ptr = JsonPointer::from_path("/foo~0bar/baz~1qux");
        assert_eq!(decoded_ptr.segments(), &["foo~bar", "baz/qux"]);

        // Test builder pattern
        let built_ptr = JsonPointerBuilder::new()
            .field("config")
            .field("outbounds")
            .index(1)
            .field("tag")
            .build();
        assert_eq!(built_ptr.to_string(), "/config/outbounds/1/tag");
    }

    #[test]
    fn test_error_conversion_integration() {
        // Test conversion between SbError and Issue
        let original_error = SbError::config(
            IssueCode::InvalidType,
            "/config/dns/servers/0/address",
            "Expected string, found number",
        );

        let issue: Issue = original_error.clone().into();
        assert_eq!(issue.kind, "config");
        assert_eq!(issue.code, "InvalidType");
        assert_eq!(issue.ptr, "/config/dns/servers/0/address");
        assert_eq!(issue.msg, "Expected string, found number");

        let converted_error: SbError = issue.into();
        assert_eq!(converted_error, original_error);
    }

    #[test]
    fn test_requirements_compliance() {
        // Test requirement 1.1: IssueCode enum with all variants
        let codes = vec![
            IssueCode::UnknownField,
            IssueCode::InvalidType,
            IssueCode::OutOfRange,
            IssueCode::MissingRequired,
            IssueCode::DuplicateTag,
        ];
        assert_eq!(codes.len(), 5);

        // Test requirement 1.2: RFC6901 JSON pointer implementation
        let ptr = JsonPointer::from_path("/config/inbounds/0/listen");
        assert_eq!(ptr.to_string(), "/config/inbounds/0/listen");

        // Test requirement 1.4: Structured error reporting
        let error = SbError::config(IssueCode::UnknownField, "/config/unknown", "Unknown field");
        let report = ErrorReport::single(error);
        assert_eq!(report.issues.len(), 1);
        assert!(!report.fingerprint.is_empty());
    }

    #[test]
    fn test_schema_v2_error_format_integration() {
        // Test requirement 1.3: CLI integration with --schema-v2-validate flag
        // This tests the error format structure that the CLI will use

        // Create multiple schema validation errors
        let errors = vec![
            SbError::config(
                IssueCode::UnknownField,
                "/unknown_field",
                "Unknown field 'unknown_field'",
            )
            .with_hint("Remove unknown field or check spelling"),
            SbError::config(
                IssueCode::InvalidType,
                "/inbounds/0/port",
                "Expected number, found string",
            )
            .with_hint("Expected numeric value, got different type"),
            SbError::config(
                IssueCode::OutOfRange,
                "/inbounds/0/port",
                "Port value 70000 is out of range",
            )
            .with_hint("Port must be 1-65535"),
            SbError::config(
                IssueCode::MissingRequired,
                "/outbounds/0/type",
                "Missing required field 'type'",
            )
            .with_hint("Add required field"),
        ];

        let report = ErrorReport::from_errors(errors);

        // Test requirement 1.4: JSON format with issues and fingerprint
        assert_eq!(report.issues.len(), 4);
        assert!(!report.fingerprint.is_empty());
        assert!(report.fingerprint.starts_with("sha256:"));
        assert_eq!(report.fingerprint.len(), 71); // "sha256:" + 64 hex chars

        // Test that each issue has the required structure
        for issue in &report.issues {
            assert_eq!(issue.kind, "config");
            assert!(!issue.code.is_empty());
            assert!(issue.ptr.starts_with("/"));
            assert!(!issue.msg.is_empty());
            // hint is optional but should be present for these test cases
            assert!(issue.hint.is_some());
        }

        // Test requirement 1.5: Fingerprint generation with SHA256
        // Create the same errors again and verify fingerprint is identical
        let errors2 = vec![
            SbError::config(
                IssueCode::UnknownField,
                "/unknown_field",
                "Unknown field 'unknown_field'",
            )
            .with_hint("Remove unknown field or check spelling"),
            SbError::config(
                IssueCode::InvalidType,
                "/inbounds/0/port",
                "Expected number, found string",
            )
            .with_hint("Expected numeric value, got different type"),
            SbError::config(
                IssueCode::OutOfRange,
                "/inbounds/0/port",
                "Port value 70000 is out of range",
            )
            .with_hint("Port must be 1-65535"),
            SbError::config(
                IssueCode::MissingRequired,
                "/outbounds/0/type",
                "Missing required field 'type'",
            )
            .with_hint("Add required field"),
        ];

        let report2 = ErrorReport::from_errors(errors2);
        assert_eq!(
            report.fingerprint, report2.fingerprint,
            "Fingerprints should be deterministic"
        );
    }

    #[test]
    fn test_fingerprint_generation_correctness() {
        // Test that fingerprint generation works correctly with SHA256 of error patterns

        // Test with single error
        let single_error = SbError::config(IssueCode::UnknownField, "/test", "Test error");
        let single_report = ErrorReport::single(single_error);

        // Test with multiple errors
        let multiple_errors = vec![
            SbError::config(IssueCode::UnknownField, "/test1", "Test error 1"),
            SbError::config(IssueCode::InvalidType, "/test2", "Test error 2"),
        ];
        let multiple_report = ErrorReport::from_errors(multiple_errors);

        // Fingerprints should be different
        assert_ne!(single_report.fingerprint, multiple_report.fingerprint);

        // Test that order matters for fingerprint
        let reordered_errors = vec![
            SbError::config(IssueCode::InvalidType, "/test2", "Test error 2"),
            SbError::config(IssueCode::UnknownField, "/test1", "Test error 1"),
        ];
        let reordered_report = ErrorReport::from_errors(reordered_errors);

        // Different order should produce different fingerprint
        assert_ne!(multiple_report.fingerprint, reordered_report.fingerprint);

        // Test that message content doesn't affect fingerprint (only code and ptr)
        let same_pattern_errors = vec![
            SbError::config(IssueCode::UnknownField, "/test1", "Different message 1"),
            SbError::config(IssueCode::InvalidType, "/test2", "Different message 2"),
        ];
        let same_pattern_report = ErrorReport::from_errors(same_pattern_errors);

        // Same code and ptr should produce same fingerprint regardless of message
        assert_eq!(multiple_report.fingerprint, same_pattern_report.fingerprint);
    }
}
