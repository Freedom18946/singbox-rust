//! AdGuard DNS filter rule parser
//!
//! Converts AdGuard DNS filter rules into HeadlessRule JSON format compatible
//! with sing-box rule-set v2. Ported from the Go reference implementation at
//! `go_fork_source/sing-box-1.12.14/common/convertor/adguard/convertor.go`.
//!
//! # Supported syntax
//!
//! | Syntax                              | Meaning                         |
//! |-------------------------------------|---------------------------------|
//! | `! comment` / `# comment`           | Comment (skipped)               |
//! | `\|\|example.com^`                  | Domain suffix match             |
//! | `\|https://example.com`             | Domain match with start anchor  |
//! | `@@\|\|example.com^`                | Exception / exclude rule        |
//! | `/regex/`                           | Domain regex match              |
//! | `$important`                        | Important modifier              |
//! | `0.0.0.0 example.com`              | Hosts file format               |
//! | plain domain name                   | Domain exact match              |

use std::net::IpAddr;

/// Parsed intermediate representation of a single AdGuard rule line.
#[derive(Debug, Clone)]
struct AdGuardRuleLine {
    rule_line: String,
    is_raw_domain: bool,
    is_exclude: bool,
    is_suffix: bool,
    has_start: bool,
    has_end: bool,
    is_regexp: bool,
    is_important: bool,
}

/// Parse AdGuard DNS filter rules from text input into HeadlessRule JSON values.
///
/// Returns a `Vec<serde_json::Value>` where each element is a HeadlessRule object
/// suitable for inclusion in `{"version": 2, "rules": [...]}`.
pub fn parse_adguard_rules(input: &str) -> anyhow::Result<Vec<serde_json::Value>> {
    let mut rule_lines: Vec<AdGuardRuleLine> = Vec::new();
    let mut ignored_lines = 0usize;

    'parse_line: for line in input.lines() {
        let rule_line = line.trim();

        // Skip empty lines
        if rule_line.is_empty() {
            continue;
        }

        // Skip comments
        if rule_line.starts_with('!') || rule_line.starts_with('#') {
            continue;
        }

        let origin_rule_line = rule_line.to_string();

        // Check if it's a plain domain name (no special chars)
        if is_domain_name(rule_line) {
            rule_lines.push(AdGuardRuleLine {
                rule_line: rule_line.to_string(),
                is_raw_domain: true,
                is_exclude: false,
                is_suffix: false,
                has_start: false,
                has_end: false,
                is_regexp: false,
                is_important: false,
            });
            continue;
        }

        // Check for hosts file format (e.g., "0.0.0.0 example.com")
        if let Some(host_domain) = parse_host_line(rule_line) {
            if !host_domain.is_empty() {
                rule_lines.push(AdGuardRuleLine {
                    rule_line: host_domain,
                    is_raw_domain: true,
                    is_exclude: false,
                    is_suffix: false,
                    has_start: true,
                    has_end: true,
                    is_regexp: false,
                    is_important: false,
                });
            }
            continue;
        }

        // Working copy of the rule line
        let mut working = rule_line.to_string();

        // Strip trailing pipe
        if working.ends_with('|') {
            working = working[..working.len() - 1].to_string();
        }

        let mut is_exclude = false;
        let mut is_suffix = false;
        let mut has_start = false;
        let mut has_end = false;
        let mut is_regexp = false;
        let mut is_important = false;

        // Parse $ modifiers (but not for regex lines starting with /)
        if !working.starts_with('/') && working.contains('$') {
            let dollar_pos = working.find('$').unwrap();
            let params_str = &working[dollar_pos + 1..];
            let params: Vec<&str> = params_str.split(',').collect();

            for param in &params {
                let param_parts: Vec<&str> = param.split('=').collect();
                let mut ignored = false;

                if !param_parts.is_empty() && param_parts.len() <= 2 {
                    match param_parts[0] {
                        "app" | "network" => {
                            // maybe support by package_name/process_name - skip
                        }
                        "dnstype" => {
                            // maybe support by query_type - skip
                        }
                        "important" => {
                            ignored = true;
                            is_important = true;
                        }
                        "dnsrewrite" => {
                            if param_parts.len() == 2 {
                                if let Ok(addr) = param_parts[1].parse::<IpAddr>() {
                                    if addr.is_unspecified() {
                                        ignored = true;
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }

                if !ignored {
                    ignored_lines += 1;
                    tracing::debug!(
                        "ignored unsupported rule with modifier: {}: {}",
                        param_parts[0],
                        origin_rule_line
                    );
                    continue 'parse_line;
                }
            }
            working = working[..dollar_pos].to_string();
        }

        // Check for exclude prefix @@
        if working.starts_with("@@") {
            working = working[2..].to_string();
            is_exclude = true;
        }

        // Strip trailing pipe again (after @@ removal)
        if working.ends_with('|') {
            working = working[..working.len() - 1].to_string();
        }

        // Check for || (suffix) or | (start anchor)
        if working.starts_with("||") {
            working = working[2..].to_string();
            is_suffix = true;
        } else if working.starts_with('|') {
            working = working[1..].to_string();
            has_start = true;
        }

        // Check for ^ (end anchor)
        if working.ends_with('^') {
            working = working[..working.len() - 1].to_string();
            has_end = true;
        }

        // Check for regex: /pattern/
        if working.starts_with('/') && working.ends_with('/') && working.len() >= 2 {
            working = working[1..working.len() - 1].to_string();
            if ignore_ip_cidr_regexp(&working) {
                ignored_lines += 1;
                tracing::debug!(
                    "ignored unsupported rule with IPCIDR regexp: {}",
                    origin_rule_line
                );
                continue;
            }
            is_regexp = true;
        } else {
            // Non-regex domain processing

            // Strip protocol prefix
            if working.contains("://") {
                if let Some(pos) = working.find("://") {
                    working = working[pos + 3..].to_string();
                    is_suffix = true;
                }
            }

            // Reject rules with path
            if working.contains('/') {
                ignored_lines += 1;
                tracing::debug!("ignored unsupported rule with path: {}", origin_rule_line);
                continue;
            }

            // Reject rules with query
            if working.contains('?') || working.contains('&') {
                ignored_lines += 1;
                tracing::debug!("ignored unsupported rule with query: {}", origin_rule_line);
                continue;
            }

            // Reject cosmetic filters
            if working.contains('[')
                || working.contains(']')
                || working.contains('(')
                || working.contains(')')
                || working.contains('!')
                || working.contains('#')
            {
                ignored_lines += 1;
                tracing::debug!("ignored unsupported cosmetic filter: {}", origin_rule_line);
                continue;
            }

            // Reject tilde modifier
            if working.contains('~') {
                ignored_lines += 1;
                tracing::debug!("ignored unsupported rule modifier: {}", origin_rule_line);
                continue;
            }

            // Domain validation
            let domain_check = if working.starts_with('.') || working.starts_with('-') {
                format!("r{}", working)
            } else {
                working.clone()
            };

            if working.is_empty() {
                ignored_lines += 1;
                tracing::debug!(
                    "ignored unsupported rule with empty domain: {}",
                    origin_rule_line
                );
                continue;
            }

            // Replace wildcards for validation
            let domain_check = domain_check.replace('*', "x");
            if !is_domain_name(&domain_check) {
                // Check if it's an IP/CIDR line
                if parse_ip_cidr_line(&working).is_some() {
                    ignored_lines += 1;
                    tracing::debug!("ignored unsupported rule with IPCIDR: {}", origin_rule_line);
                    continue;
                }
                // Check if it contains a port
                if domain_check.contains(':') {
                    tracing::debug!("ignored unsupported rule with port: {}", origin_rule_line);
                } else {
                    tracing::debug!(
                        "ignored unsupported rule with invalid domain: {}",
                        origin_rule_line
                    );
                }
                ignored_lines += 1;
                continue;
            }
        }

        rule_lines.push(AdGuardRuleLine {
            rule_line: working,
            is_raw_domain: false,
            is_exclude,
            is_suffix,
            has_start,
            has_end,
            is_regexp,
            is_important,
        });
    }

    if rule_lines.is_empty() {
        anyhow::bail!("AdGuard rule-set is empty or all rules are unsupported");
    }

    // If all lines are raw domains, emit a single default rule with domain list
    if rule_lines.iter().all(|r| r.is_raw_domain) {
        let domains: Vec<String> = rule_lines.into_iter().map(|r| r.rule_line).collect();
        return Ok(vec![serde_json::json!({
            "domain": domains,
        })]);
    }

    // Build the adguard_domain representation:
    // Re-encode the parsed rule back into adguard_domain format for the JSON output.
    let map_domain = |r: &AdGuardRuleLine| -> String {
        let mut s = String::new();
        if r.is_suffix {
            s.push_str("||");
        } else if r.has_start {
            s.push('|');
        }
        s.push_str(&r.rule_line);
        if r.has_end {
            s.push('^');
        }
        s
    };

    // Partition rules into 8 categories following Go reference
    let important_domain: Vec<String> = rule_lines
        .iter()
        .filter(|r| r.is_important && !r.is_regexp && !r.is_exclude)
        .map(map_domain)
        .collect();

    let important_domain_regex: Vec<String> = rule_lines
        .iter()
        .filter(|r| r.is_important && r.is_regexp && !r.is_exclude)
        .map(|r| r.rule_line.clone())
        .collect();

    let important_exclude_domain: Vec<String> = rule_lines
        .iter()
        .filter(|r| r.is_important && !r.is_regexp && r.is_exclude)
        .map(map_domain)
        .collect();

    let important_exclude_domain_regex: Vec<String> = rule_lines
        .iter()
        .filter(|r| r.is_important && r.is_regexp && r.is_exclude)
        .map(|r| r.rule_line.clone())
        .collect();

    let domain: Vec<String> = rule_lines
        .iter()
        .filter(|r| !r.is_important && !r.is_regexp && !r.is_exclude)
        .map(map_domain)
        .collect();

    let domain_regex: Vec<String> = rule_lines
        .iter()
        .filter(|r| !r.is_important && r.is_regexp && !r.is_exclude)
        .map(|r| r.rule_line.clone())
        .collect();

    let exclude_domain: Vec<String> = rule_lines
        .iter()
        .filter(|r| !r.is_important && !r.is_regexp && r.is_exclude)
        .map(map_domain)
        .collect();

    let exclude_domain_regex: Vec<String> = rule_lines
        .iter()
        .filter(|r| !r.is_important && r.is_regexp && r.is_exclude)
        .map(|r| r.rule_line.clone())
        .collect();

    // Build current_rule following Go reference layering logic
    let mut current_rule = build_default_rule(&domain, &domain_regex, false);

    // If there are exclude rules, wrap in logical AND with inverted exclude
    if !exclude_domain.is_empty() || !exclude_domain_regex.is_empty() {
        let exclude_rule = build_default_rule(&exclude_domain, &exclude_domain_regex, true);
        current_rule = serde_json::json!({
            "type": "logical",
            "mode": "and",
            "rules": [exclude_rule, current_rule],
        });
    }

    // If there are important rules, wrap in logical OR
    if !important_domain.is_empty() || !important_domain_regex.is_empty() {
        let important_rule = build_default_rule(&important_domain, &important_domain_regex, false);
        current_rule = serde_json::json!({
            "type": "logical",
            "mode": "or",
            "rules": [important_rule, current_rule],
        });
    }

    // If there are important exclude rules, wrap in logical AND with inverted
    if !important_exclude_domain.is_empty() || !important_exclude_domain_regex.is_empty() {
        let important_exclude_rule = build_default_rule(
            &important_exclude_domain,
            &important_exclude_domain_regex,
            true,
        );
        current_rule = serde_json::json!({
            "type": "logical",
            "mode": "and",
            "rules": [important_exclude_rule, current_rule],
        });
    }

    if ignored_lines > 0 {
        tracing::info!(
            "parsed rules: {}/{}",
            rule_lines.len(),
            rule_lines.len() + ignored_lines
        );
    }

    Ok(vec![current_rule])
}

/// Build a default HeadlessRule JSON value from domain and domain_regex lists.
fn build_default_rule(
    domain: &[String],
    domain_regex: &[String],
    invert: bool,
) -> serde_json::Value {
    let mut obj = serde_json::json!({});
    if invert {
        obj["invert"] = serde_json::json!(true);
    }
    if !domain.is_empty() {
        obj["domain"] = serde_json::json!(domain);
    }
    if !domain_regex.is_empty() {
        obj["domain_regex"] = serde_json::json!(domain_regex);
    }
    obj
}

/// Check if a string looks like a valid domain name.
///
/// Simplified domain validation: labels separated by dots, each label is
/// alphanumeric (with hyphens allowed in the middle), length 1-63, total
/// length <= 253.
fn is_domain_name(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }

    // Must not contain characters that aren't part of a domain
    if s.contains(' ') || s.contains('\t') {
        return false;
    }

    let labels: Vec<&str> = s.split('.').collect();
    if labels.len() < 2 {
        return false;
    }

    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }

    // Last label (TLD) must have at least one letter
    if let Some(tld) = labels.last() {
        if !tld.chars().any(|c| c.is_ascii_alphabetic()) {
            return false;
        }
    }

    true
}

/// Parse a hosts file line like "0.0.0.0 example.com" or "127.0.0.1 example.com".
///
/// Returns `Some(domain)` if the line is a valid hosts entry with an unspecified
/// address (0.0.0.0, ::, etc.), `Some("")` if the address is not unspecified
/// (e.g., 127.0.0.1 pointing to a real address — skip), or `None` if not a hosts line.
fn parse_host_line(line: &str) -> Option<String> {
    // Split on first whitespace
    let parts: Vec<&str> = line.splitn(2, [' ', '\t']).collect();
    if parts.len() != 2 {
        return None;
    }

    let addr: IpAddr = parts[0].parse().ok()?;
    let domain = parts[1].trim();

    if !addr.is_unspecified() {
        // Not an unspecified address (0.0.0.0 or ::) — skip silently
        return Some(String::new());
    }

    if !is_domain_name(domain) {
        return None;
    }

    Some(domain.to_string())
}

/// Check if a regex pattern is an IP CIDR pattern that should be ignored.
fn ignore_ip_cidr_regexp(rule_line: &str) -> bool {
    let mut s = rule_line;

    if s.starts_with("(http?:\\/\\/)") {
        s = &s[12..];
    } else if s.starts_with("(https?:\\/\\/)") {
        s = &s[13..];
    } else if s.starts_with('^') {
        s = &s[1..];
    }

    // Check if the first part before \. or . is a valid u8 (IP octet)
    let before_escaped_dot = s.split("\\.").next().unwrap_or(s);
    if before_escaped_dot.parse::<u8>().is_ok() {
        return true;
    }

    let before_dot = s.split('.').next().unwrap_or(s);
    if before_dot.parse::<u8>().is_ok() {
        return true;
    }

    false
}

/// Try to parse a rule line as an IP CIDR notation (e.g., "192.168.1." or "10.0.0.0").
fn parse_ip_cidr_line(rule_line: &str) -> Option<()> {
    let mut s = rule_line.to_string();
    let is_prefix = s.ends_with('.');
    if is_prefix {
        s = s[..s.len() - 1].to_string();
    }

    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() > 4 || (parts.len() < 4 && !is_prefix) {
        return None;
    }

    for part in &parts {
        part.parse::<u8>().ok()?;
    }

    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_domain_suffix() {
        let input = "||example.com^\n";
        let rules = parse_adguard_rules(input).unwrap();
        assert_eq!(rules.len(), 1);
        let rule = &rules[0];
        let domain = rule["domain"].as_array().unwrap();
        assert_eq!(domain.len(), 1);
        assert_eq!(domain[0].as_str().unwrap(), "||example.com^");
    }

    #[test]
    fn test_parse_exclude_rule() {
        let input = "||blocked.com^\n@@||allowed.com^\n";
        let rules = parse_adguard_rules(input).unwrap();
        assert_eq!(rules.len(), 1);
        let rule = &rules[0];
        // Should be a logical AND rule with exclude
        assert_eq!(rule["type"].as_str().unwrap(), "logical");
        assert_eq!(rule["mode"].as_str().unwrap(), "and");
        let sub_rules = rule["rules"].as_array().unwrap();
        assert_eq!(sub_rules.len(), 2);
        // First sub-rule should be inverted (exclude)
        assert!(sub_rules[0]["invert"].as_bool().unwrap());
        let exclude_domains = sub_rules[0]["domain"].as_array().unwrap();
        assert!(exclude_domains
            .iter()
            .any(|d| d.as_str().unwrap() == "||allowed.com^"));
    }

    #[test]
    fn test_parse_domain_regex() {
        let input = "/ads[0-9]+\\.example\\.com/\n||fallback.com^\n";
        let rules = parse_adguard_rules(input).unwrap();
        assert_eq!(rules.len(), 1);
        let rule = &rules[0];
        // Should have both domain and domain_regex
        let domain_regex = rule["domain_regex"].as_array().unwrap();
        assert_eq!(domain_regex.len(), 1);
        assert_eq!(
            domain_regex[0].as_str().unwrap(),
            "ads[0-9]+\\.example\\.com"
        );
    }

    #[test]
    fn test_parse_hosts_line() {
        let input = "0.0.0.0 ads.example.com\n";
        let rules = parse_adguard_rules(input).unwrap();
        assert_eq!(rules.len(), 1);
        let rule = &rules[0];
        let domains = rule["domain"].as_array().unwrap();
        assert_eq!(domains.len(), 1);
        assert_eq!(domains[0].as_str().unwrap(), "ads.example.com");
    }

    #[test]
    fn test_skip_comment_lines() {
        let input = "! This is a comment\n# Another comment\n||example.com^\n";
        let rules = parse_adguard_rules(input).unwrap();
        assert_eq!(rules.len(), 1);
        // Only the non-comment line should produce a rule
        let rule = &rules[0];
        let domains = rule["domain"].as_array().unwrap();
        assert_eq!(domains.len(), 1);
        assert_eq!(domains[0].as_str().unwrap(), "||example.com^");
    }

    #[test]
    fn test_parse_plain_domain() {
        let input = "example.com\ntest.org\n";
        let rules = parse_adguard_rules(input).unwrap();
        assert_eq!(rules.len(), 1);
        // All raw domains -> single rule with domain list
        let rule = &rules[0];
        let domains = rule["domain"].as_array().unwrap();
        assert_eq!(domains.len(), 2);
        assert_eq!(domains[0].as_str().unwrap(), "example.com");
        assert_eq!(domains[1].as_str().unwrap(), "test.org");
    }

    #[test]
    fn test_parse_important_modifier() {
        let input = "||important.com^$important\n||normal.com^\n";
        let rules = parse_adguard_rules(input).unwrap();
        assert_eq!(rules.len(), 1);
        let rule = &rules[0];
        // Should be a logical OR rule with important
        assert_eq!(rule["type"].as_str().unwrap(), "logical");
        assert_eq!(rule["mode"].as_str().unwrap(), "or");
        let sub_rules = rule["rules"].as_array().unwrap();
        assert_eq!(sub_rules.len(), 2);
        // First sub-rule is the important domain
        let important_domains = sub_rules[0]["domain"].as_array().unwrap();
        assert!(important_domains
            .iter()
            .any(|d| d.as_str().unwrap() == "||important.com^"));
    }

    #[test]
    fn test_empty_input_returns_error() {
        let input = "! only comments\n# nothing else\n";
        let result = parse_adguard_rules(input);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("empty or all rules are unsupported"));
    }

    #[test]
    fn test_hosts_line_non_unspecified_skipped() {
        // 127.0.0.1 is not unspecified, should be skipped silently
        let input = "127.0.0.1 local.test\n||example.com^\n";
        let rules = parse_adguard_rules(input).unwrap();
        assert_eq!(rules.len(), 1);
        let rule = &rules[0];
        let domains = rule["domain"].as_array().unwrap();
        assert_eq!(domains.len(), 1);
        assert_eq!(domains[0].as_str().unwrap(), "||example.com^");
    }

    #[test]
    fn test_is_domain_name() {
        assert!(is_domain_name("example.com"));
        assert!(is_domain_name("sub.example.com"));
        assert!(is_domain_name("my-site.org"));
        assert!(!is_domain_name(""));
        assert!(!is_domain_name("localhost"));
        assert!(!is_domain_name("192.168.1.1"));
        assert!(!is_domain_name("has space.com"));
    }

    #[test]
    fn test_parse_host_line() {
        assert_eq!(
            parse_host_line("0.0.0.0 ads.example.com"),
            Some("ads.example.com".to_string())
        );
        assert_eq!(
            parse_host_line(":: ads.example.com"),
            Some("ads.example.com".to_string())
        );
        // 127.0.0.1 is not unspecified -> empty string
        assert_eq!(parse_host_line("127.0.0.1 local.test"), Some(String::new()));
        // Not a host line
        assert_eq!(parse_host_line("||example.com^"), None);
    }

    #[test]
    fn test_ignore_ip_cidr_regexp() {
        assert!(ignore_ip_cidr_regexp("^192\\.168\\.1\\."));
        assert!(ignore_ip_cidr_regexp("10.0.0.1"));
        assert!(!ignore_ip_cidr_regexp("ads[0-9]+\\.example\\.com"));
    }
}
