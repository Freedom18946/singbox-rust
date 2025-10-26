//! SRS binary format parser
//!
//! Implements parsing of the sing-box rule-set binary format (.srs files)

use super::*;
use crate::error::{SbError, SbResult};
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::{Cursor, Read};
use std::path::Path;

/// Load rule-set from a file
pub async fn load_from_file(path: &Path, format: RuleSetFormat) -> SbResult<RuleSet> {
    let data = tokio::fs::read(path).await.map_err(|e| SbError::Config {
        code: crate::error::IssueCode::MissingRequired,
        ptr: "/rule_set/path".to_string(),
        msg: format!("failed to read rule-set file: {}", e),
        hint: Some(format!("Ensure file exists: {}", path.display())),
    })?;

    match format {
        RuleSetFormat::Binary => parse_binary(&data, RuleSetSource::Local(path.to_path_buf())),
        RuleSetFormat::Source => parse_json(&data, RuleSetSource::Local(path.to_path_buf())),
    }
}

/// Parse binary .srs format
pub fn parse_binary(data: &[u8], source: RuleSetSource) -> SbResult<RuleSet> {
    if data.len() < 4 {
        return Err(SbError::Config {
            code: crate::error::IssueCode::InvalidType,
            ptr: "/rule_set/binary".to_string(),
            msg: "file too small to be valid SRS".to_string(),
            hint: Some("SRS files must be at least 4 bytes (magic + version)".to_string()),
        });
    }

    // Validate magic number
    if data[0..3] != SRS_MAGIC {
        return Err(SbError::Config {
            code: crate::error::IssueCode::InvalidType,
            ptr: "/rule_set/binary/magic".to_string(),
            msg: format!(
                "invalid magic number: expected {:?}, got {:?}",
                SRS_MAGIC,
                &data[0..3]
            ),
            hint: Some("This does not appear to be a valid .srs file".to_string()),
        });
    }

    // Read version
    let version = data[3];
    if version > RULESET_VERSION_CURRENT {
        return Err(SbError::Config {
            code: crate::error::IssueCode::InvalidType,
            ptr: "/rule_set/binary/version".to_string(),
            msg: format!(
                "unsupported version: {}, max supported: {}",
                version, RULESET_VERSION_CURRENT
            ),
            hint: Some("Update singbox-rust or use an older rule-set file".to_string()),
        });
    }

    // Decompress with zlib
    let mut decoder = ZlibDecoder::new(&data[4..]);
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .map_err(|e| SbError::Config {
            code: crate::error::IssueCode::InvalidType,
            ptr: "/rule_set/binary/compression".to_string(),
            msg: format!("failed to decompress rule-set: {}", e),
            hint: Some("File may be corrupted or not properly compressed with zlib".to_string()),
        })?;

    // Parse decompressed data
    let mut cursor = Cursor::new(decompressed);
    let rules = parse_rules(&mut cursor)?;

    // Build optimized data structures
    let (domain_index, ip_tree) = build_indices(&rules);

    Ok(RuleSet {
        source,
        format: RuleSetFormat::Binary,
        version,
        rules,
        #[cfg(feature = "suffix_trie")]
        domain_trie: Arc::new(domain_index),
        #[cfg(not(feature = "suffix_trie"))]
        domain_suffixes: Arc::new(domain_index),
        ip_tree: Arc::new(ip_tree),
        last_updated: SystemTime::now(),
        etag: None,
    })
}

/// Parse JSON source format
pub fn parse_json(data: &[u8], source: RuleSetSource) -> SbResult<RuleSet> {
    let json_str = std::str::from_utf8(data).map_err(|e| SbError::Config {
        code: crate::error::IssueCode::InvalidType,
        ptr: "/rule_set/source".to_string(),
        msg: format!("invalid UTF-8 in JSON file: {}", e),
        hint: None,
    })?;

    let json: serde_json::Value = serde_json::from_str(json_str).map_err(|e| SbError::Config {
        code: crate::error::IssueCode::InvalidType,
        ptr: "/rule_set/source/json".to_string(),
        msg: format!("invalid JSON: {}", e),
        hint: None,
    })?;

    // Parse version
    let version = json.get("version").and_then(|v| v.as_u64()).unwrap_or(1) as u8;

    // Parse rules array
    let rules_array = json
        .get("rules")
        .and_then(|v| v.as_array())
        .ok_or_else(|| SbError::Config {
            code: crate::error::IssueCode::MissingRequired,
            ptr: "/rule_set/source/rules".to_string(),
            msg: "missing 'rules' array".to_string(),
            hint: None,
        })?;

    let mut rules = Vec::new();
    for (i, rule_val) in rules_array.iter().enumerate() {
        let rule = parse_json_rule(rule_val, i)?;
        rules.push(rule);
    }

    // Build optimized data structures
    let (domain_index, ip_tree) = build_indices(&rules);

    Ok(RuleSet {
        source,
        format: RuleSetFormat::Source,
        version,
        rules,
        #[cfg(feature = "suffix_trie")]
        domain_trie: Arc::new(domain_index),
        #[cfg(not(feature = "suffix_trie"))]
        domain_suffixes: Arc::new(domain_index),
        ip_tree: Arc::new(ip_tree),
        last_updated: SystemTime::now(),
        etag: None,
    })
}

/// Parse rules from binary cursor
fn parse_rules(cursor: &mut Cursor<Vec<u8>>) -> SbResult<Vec<Rule>> {
    // Read rule count (varint)
    let rule_count = read_varint(cursor)?;

    let mut rules = Vec::with_capacity(rule_count as usize);
    for _ in 0..rule_count {
        let rule = parse_binary_rule(cursor)?;
        rules.push(rule);
    }

    Ok(rules)
}

/// Parse a single rule from binary format
fn parse_binary_rule(cursor: &mut Cursor<Vec<u8>>) -> SbResult<Rule> {
    // Read rule type (0 = default, 1 = logical)
    let rule_type = read_u8(cursor)?;

    match rule_type {
        0 => {
            // Initialize rule with invert in the initializer to avoid field reassign
            let invert_flag = read_u8(cursor)? != 0;
            let mut rule = DefaultRule { invert: invert_flag, ..Default::default() };

            // Read rule items count
            let item_count = read_varint(cursor)?;

            for _ in 0..item_count {
                let item_type = read_u8(cursor)?;
                parse_rule_item(cursor, item_type, &mut rule)?;
            }

            Ok(Rule::Default(rule))
        }
        1 => {
            let mode = match read_u8(cursor)? {
                0 => LogicalMode::And,
                1 => LogicalMode::Or,
                m => {
                    return Err(SbError::Config {
                        code: crate::error::IssueCode::InvalidType,
                        ptr: "/rule_set/logical/mode".to_string(),
                        msg: format!("invalid logical mode: {}", m),
                        hint: None,
                    })
                }
            };

            let invert = read_u8(cursor)? != 0;
            let sub_rule_count = read_varint(cursor)?;

            let mut sub_rules = Vec::new();
            for _ in 0..sub_rule_count {
                sub_rules.push(parse_binary_rule(cursor)?);
            }

            Ok(Rule::Logical(LogicalRule {
                mode,
                rules: sub_rules,
                invert,
            }))
        }
        _ => Err(SbError::Config {
            code: crate::error::IssueCode::InvalidType,
            ptr: "/rule_set/rule/type".to_string(),
            msg: format!("unknown rule type: {}", rule_type),
            hint: None,
        }),
    }
}

/// Parse a rule item based on type
fn parse_rule_item(
    cursor: &mut Cursor<Vec<u8>>,
    item_type: u8,
    rule: &mut DefaultRule,
) -> SbResult<()> {
    match item_type {
        // Domain (exact)
        0 => {
            let domain = read_string(cursor)?;
            rule.domain.push(DomainRule::Exact(domain));
        }
        // Domain suffix
        1 => {
            let domain = read_string(cursor)?;
            rule.domain_suffix.push(domain.clone());
            rule.domain.push(DomainRule::Suffix(domain));
        }
        // Domain keyword
        2 => {
            let keyword = read_string(cursor)?;
            rule.domain_keyword.push(keyword.clone());
            rule.domain.push(DomainRule::Keyword(keyword));
        }
        // Domain regex
        3 => {
            let regex = read_string(cursor)?;
            rule.domain_regex.push(regex.clone());
            rule.domain.push(DomainRule::Regex(regex));
        }
        // IP CIDR
        4 => {
            let cidr_str = read_string(cursor)?;
            let cidr = IpCidr::parse(&cidr_str)?;
            rule.ip_cidr.push(cidr);
        }
        // Port
        5 => {
            let port = read_u16(cursor)?;
            rule.port.push(port);
        }
        // Port range
        6 => {
            let start = read_u16(cursor)?;
            let end = read_u16(cursor)?;
            rule.port_range.push((start, end));
        }
        // Source IP CIDR
        7 => {
            let cidr_str = read_string(cursor)?;
            let cidr = IpCidr::parse(&cidr_str)?;
            rule.source_ip_cidr.push(cidr);
        }
        // Network (tcp/udp)
        8 => {
            let network = read_string(cursor)?;
            rule.network.push(network);
        }
        // Process name
        9 => {
            let name = read_string(cursor)?;
            rule.process_name.push(name);
        }
        // Process path
        10 => {
            let path = read_string(cursor)?;
            rule.process_path.push(path);
        }
        // Process path regex
        11 => {
            let pattern = read_string(cursor)?;
            rule.process_path_regex.push(pattern);
        }
        _ => {
            // Unknown item type, skip it
            tracing::warn!("unknown rule item type: {}, skipping", item_type);
        }
    }

    Ok(())
}

/// Parse JSON rule
fn parse_json_rule(value: &serde_json::Value, index: usize) -> SbResult<Rule> {
    let obj = value.as_object().ok_or_else(|| SbError::Config {
        code: crate::error::IssueCode::InvalidType,
        ptr: format!("/rule_set/rules/{}", index),
        msg: "rule must be an object".to_string(),
        hint: None,
    })?;

    // Check if it's a logical rule
    if obj.contains_key("type") && obj["type"].as_str() == Some("logical") {
        let mode = match obj.get("mode").and_then(|v| v.as_str()) {
            Some("and") => LogicalMode::And,
            Some("or") => LogicalMode::Or,
            _ => {
                return Err(SbError::Config {
                    code: crate::error::IssueCode::MissingRequired,
                    ptr: format!("/rule_set/rules/{}/mode", index),
                    msg: "logical rule must have mode (and/or)".to_string(),
                    hint: None,
                })
            }
        };

        let invert = obj.get("invert").and_then(|v| v.as_bool()).unwrap_or(false);

        let sub_rules_val = obj.get("rules").ok_or_else(|| SbError::Config {
            code: crate::error::IssueCode::MissingRequired,
            ptr: format!("/rule_set/rules/{}/rules", index),
            msg: "logical rule must have sub-rules".to_string(),
            hint: None,
        })?;

        let sub_rules_array = sub_rules_val.as_array().ok_or_else(|| SbError::Config {
            code: crate::error::IssueCode::InvalidType,
            ptr: format!("/rule_set/rules/{}/rules", index),
            msg: "logical rule sub-rules must be array".to_string(),
            hint: None,
        })?;

        let mut sub_rules = Vec::new();
        for (i, sub_val) in sub_rules_array.iter().enumerate() {
            sub_rules.push(parse_json_rule(sub_val, i)?);
        }

        return Ok(Rule::Logical(LogicalRule {
            mode,
            rules: sub_rules,
            invert,
        }));
    }

    // Default rule
    let mut rule = DefaultRule { invert: obj.get("invert").and_then(|v| v.as_bool()).unwrap_or(false), ..Default::default() };

    // Parse domain rules
    if let Some(domains) = obj.get("domain").and_then(|v| v.as_array()) {
        for d in domains {
            if let Some(s) = d.as_str() {
                rule.domain.push(DomainRule::Exact(s.to_string()));
            }
        }
    }

    if let Some(domains) = obj.get("domain_suffix").and_then(|v| v.as_array()) {
        for d in domains {
            if let Some(s) = d.as_str() {
                rule.domain_suffix.push(s.to_string());
                rule.domain.push(DomainRule::Suffix(s.to_string()));
            }
        }
    }

    if let Some(keywords) = obj.get("domain_keyword").and_then(|v| v.as_array()) {
        for k in keywords {
            if let Some(s) = k.as_str() {
                rule.domain_keyword.push(s.to_string());
                rule.domain.push(DomainRule::Keyword(s.to_string()));
            }
        }
    }

    if let Some(regexes) = obj.get("domain_regex").and_then(|v| v.as_array()) {
        for r in regexes {
            if let Some(s) = r.as_str() {
                rule.domain_regex.push(s.to_string());
                rule.domain.push(DomainRule::Regex(s.to_string()));
            }
        }
    }

    // Parse IP CIDR
    if let Some(cidrs) = obj.get("ip_cidr").and_then(|v| v.as_array()) {
        for c in cidrs {
            if let Some(s) = c.as_str() {
                rule.ip_cidr.push(IpCidr::parse(s)?);
            }
        }
    }

    // Parse ports
    if let Some(ports) = obj.get("port").and_then(|v| v.as_array()) {
        for p in ports {
            if let Some(port) = p.as_u64() {
                rule.port.push(port as u16);
            }
        }
    }

    // Parse network
    if let Some(networks) = obj.get("network").and_then(|v| v.as_array()) {
        for n in networks {
            if let Some(s) = n.as_str() {
                rule.network.push(s.to_string());
            }
        }
    }

    if let Some(process_names) = obj.get("process_name").and_then(|v| v.as_array()) {
        for n in process_names {
            if let Some(s) = n.as_str() {
                rule.process_name.push(s.to_string());
            }
        }
    }

    if let Some(process_paths) = obj.get("process_path").and_then(|v| v.as_array()) {
        for p in process_paths {
            if let Some(s) = p.as_str() {
                rule.process_path.push(s.to_string());
            }
        }
    }

    if let Some(process_path_regex) = obj.get("process_path_regex").and_then(|v| v.as_array()) {
        for pattern in process_path_regex {
            if let Some(s) = pattern.as_str() {
                rule.process_path_regex.push(s.to_string());
            }
        }
    }

    Ok(Rule::Default(rule))
}

/// Build optimized indices from rules
#[cfg(feature = "suffix_trie")]
fn build_indices(rules: &[Rule]) -> (crate::router::suffix_trie::SuffixTrie, IpPrefixTree) {
    let mut domain_trie = crate::router::suffix_trie::SuffixTrie::new();
    let mut ip_tree = IpPrefixTree::new();

    for rule in rules {
        extract_and_index_rule(rule, &mut domain_trie, &mut ip_tree);
    }

    (domain_trie, ip_tree)
}

#[cfg(not(feature = "suffix_trie"))]
fn build_indices(rules: &[Rule]) -> (Vec<String>, IpPrefixTree) {
    let mut domain_suffixes = Vec::new();
    let mut ip_tree = IpPrefixTree::new();

    for rule in rules {
        extract_and_index_rule(rule, &mut domain_suffixes, &mut ip_tree);
    }

    (domain_suffixes, ip_tree)
}

#[cfg(feature = "suffix_trie")]
fn extract_and_index_rule(
    rule: &Rule,
    domain_trie: &mut crate::router::suffix_trie::SuffixTrie,
    ip_tree: &mut IpPrefixTree,
) {
    match rule {
        Rule::Default(r) => {
            // Index domain suffixes
            for suffix in &r.domain_suffix {
                domain_trie.insert(suffix);
            }

            // Index IP CIDRs
            for cidr in &r.ip_cidr {
                ip_tree.insert(cidr);
            }
        }
        Rule::Logical(r) => {
            // Recursively index sub-rules
            for sub_rule in &r.rules {
                extract_and_index_rule(sub_rule, domain_trie, ip_tree);
            }
        }
    }
}

#[cfg(not(feature = "suffix_trie"))]
fn extract_and_index_rule(
    rule: &Rule,
    domain_suffixes: &mut Vec<String>,
    ip_tree: &mut IpPrefixTree,
) {
    match rule {
        Rule::Default(r) => {
            // Collect domain suffixes
            domain_suffixes.extend(r.domain_suffix.iter().cloned());

            // Index IP CIDRs
            for cidr in &r.ip_cidr {
                ip_tree.insert(cidr);
            }
        }
        Rule::Logical(r) => {
            // Recursively index sub-rules
            for sub_rule in &r.rules {
                extract_and_index_rule(sub_rule, domain_suffixes, ip_tree);
            }
        }
    }
}

// Binary reading utilities

fn read_u8(cursor: &mut Cursor<Vec<u8>>) -> SbResult<u8> {
    let mut buf = [0u8; 1];
    cursor.read_exact(&mut buf).map_err(|e| SbError::Config {
        code: crate::error::IssueCode::InvalidType,
        ptr: "/rule_set/binary/read".to_string(),
        msg: format!("failed to read u8: {}", e),
        hint: None,
    })?;
    Ok(buf[0])
}

fn read_u16(cursor: &mut Cursor<Vec<u8>>) -> SbResult<u16> {
    let mut buf = [0u8; 2];
    cursor.read_exact(&mut buf).map_err(|e| SbError::Config {
        code: crate::error::IssueCode::InvalidType,
        ptr: "/rule_set/binary/read".to_string(),
        msg: format!("failed to read u16: {}", e),
        hint: None,
    })?;
    Ok(u16::from_be_bytes(buf))
}

fn read_varint(cursor: &mut Cursor<Vec<u8>>) -> SbResult<u64> {
    let mut result = 0u64;
    let mut shift = 0;

    loop {
        let byte = read_u8(cursor)?;
        result |= ((byte & 0x7F) as u64) << shift;

        if byte & 0x80 == 0 {
            break;
        }

        shift += 7;
        if shift >= 64 {
            return Err(SbError::Config {
                code: crate::error::IssueCode::InvalidType,
                ptr: "/rule_set/binary/varint".to_string(),
                msg: "varint overflow".to_string(),
                hint: None,
            });
        }
    }

    Ok(result)
}

fn read_string(cursor: &mut Cursor<Vec<u8>>) -> SbResult<String> {
    let len = read_varint(cursor)? as usize;
    let mut buf = vec![0u8; len];
    cursor.read_exact(&mut buf).map_err(|e| SbError::Config {
        code: crate::error::IssueCode::InvalidType,
        ptr: "/rule_set/binary/string".to_string(),
        msg: format!("failed to read string: {}", e),
        hint: None,
    })?;

    String::from_utf8(buf).map_err(|e| SbError::Config {
        code: crate::error::IssueCode::InvalidType,
        ptr: "/rule_set/binary/string/utf8".to_string(),
        msg: format!("invalid UTF-8 in string: {}", e),
        hint: None,
    })
}

// ----------------------------
// Binary writer (SRS compiler)
// ----------------------------

/// Write a rule-set to binary .srs file
pub async fn write_to_file(path: &Path, rules: &[Rule], version: u8) -> SbResult<()> {
    let mut payload = Vec::new();
    write_rules(&mut payload, rules)?;

    // Compress with zlib
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    use std::io::Write as _;
    encoder.write_all(&payload).map_err(|e| SbError::Config {
        code: crate::error::IssueCode::InvalidType,
        ptr: "/rule_set/binary/compression".to_string(),
        msg: format!("failed to compress rule-set: {}", e),
        hint: None,
    })?;
    let compressed = encoder.finish().map_err(|e| SbError::Config {
        code: crate::error::IssueCode::InvalidType,
        ptr: "/rule_set/binary/compression".to_string(),
        msg: format!("failed to finish compression: {}", e),
        hint: None,
    })?;

    // Build header + compressed body
    let mut out = Vec::with_capacity(4 + compressed.len());
    out.extend_from_slice(&SRS_MAGIC);
    out.push(version);
    out.extend_from_slice(&compressed);

    tokio::fs::write(path, out)
        .await
        .map_err(|e| SbError::Config {
            code: crate::error::IssueCode::MissingRequired,
            ptr: "/rule_set/output".to_string(),
            msg: format!("failed to write rule-set file: {}", e),
            hint: None,
        })
}

fn write_rules(buf: &mut Vec<u8>, rules: &[Rule]) -> SbResult<()> {
    write_varint(buf, rules.len() as u64);
    for r in rules {
        write_rule(buf, r)?;
    }
    Ok(())
}

fn write_rule(buf: &mut Vec<u8>, rule: &Rule) -> SbResult<()> {
    match rule {
        Rule::Default(r) => {
            buf.push(0); // rule_type default
            buf.push(if r.invert { 1 } else { 0 });

            // Compute item count
            let mut count = 0u64;
            // domain (derived from r.domain exact only)
            count += r
                .domain
                .iter()
                .filter(|d| matches!(d, super::DomainRule::Exact(_)))
                .count() as u64;
            count += r.domain_suffix.len() as u64;
            count += r.domain_keyword.len() as u64;
            count += r.domain_regex.len() as u64;
            count += r.ip_cidr.len() as u64;
            count += r.port.len() as u64;
            count += r.port_range.len() as u64;
            count += r.source_ip_cidr.len() as u64;
            count += r.network.len() as u64;
            count += r.process_name.len() as u64;
            count += r.process_path.len() as u64;
            count += r.process_path_regex.len() as u64;
            write_varint(buf, count);

            // Emit items in deterministic order
            for d in &r.domain {
                if let super::DomainRule::Exact(s) = d {
                    buf.push(0);
                    write_string(buf, s);
                }
            }
            for s in &r.domain_suffix {
                buf.push(1);
                write_string(buf, s);
            }
            for s in &r.domain_keyword {
                buf.push(2);
                write_string(buf, s);
            }
            for s in &r.domain_regex {
                buf.push(3);
                write_string(buf, s);
            }
            for c in &r.ip_cidr {
                buf.push(4);
                let s = match c.addr {
                    std::net::IpAddr::V4(v4) => format!("{}/{}", v4, c.prefix_len),
                    std::net::IpAddr::V6(v6) => format!("{}/{}", v6, c.prefix_len),
                };
                write_string(buf, &s);
            }
            for p in &r.port {
                buf.push(5);
                write_u16(buf, *p);
            }
            for (a, b) in &r.port_range {
                buf.push(6);
                write_u16(buf, *a);
                write_u16(buf, *b);
            }
            for c in &r.source_ip_cidr {
                buf.push(7);
                let s = match c.addr {
                    std::net::IpAddr::V4(v4) => format!("{}/{}", v4, c.prefix_len),
                    std::net::IpAddr::V6(v6) => format!("{}/{}", v6, c.prefix_len),
                };
                write_string(buf, &s);
            }
            for n in &r.network {
                buf.push(8);
                write_string(buf, n);
            }
            for s in &r.process_name {
                buf.push(9);
                write_string(buf, s);
            }
            for s in &r.process_path {
                buf.push(10);
                write_string(buf, s);
            }
            for s in &r.process_path_regex {
                buf.push(11);
                write_string(buf, s);
            }
        }
        Rule::Logical(r) => {
            buf.push(1); // logical
            buf.push(match r.mode {
                super::LogicalMode::And => 0,
                super::LogicalMode::Or => 1,
            });
            buf.push(if r.invert { 1 } else { 0 });
            write_varint(buf, r.rules.len() as u64);
            for sub in &r.rules {
                write_rule(buf, sub)?;
            }
        }
    }
    Ok(())
}

fn write_varint(buf: &mut Vec<u8>, mut v: u64) {
    loop {
        let mut b = (v & 0x7F) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        buf.push(b);
        if v == 0 {
            break;
        }
    }
}

fn write_string(buf: &mut Vec<u8>, s: &str) {
    write_varint(buf, s.len() as u64);
    buf.extend_from_slice(s.as_bytes());
}

fn write_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_srs_magic() {
        assert_eq!(SRS_MAGIC, [0x53, 0x52, 0x53]); // "SRS"
    }

    #[test]
    fn test_invalid_magic() {
        let data = vec![0x00, 0x00, 0x00, 0x01];
        let result = parse_binary(&data, RuleSetSource::Local(PathBuf::from("/test")));
        assert!(result.is_err());
    }

    #[test]
    fn test_file_too_small() {
        let data = vec![0x53, 0x52]; // Only 2 bytes
        let result = parse_binary(&data, RuleSetSource::Local(PathBuf::from("/test")));
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn roundtrip_json_to_srs_and_back() {
        // Build a simple JSON ruleset
        let json = serde_json::json!({
            "version": 3,
            "rules": [
                {
                    "domain": ["example.com"],
                    "domain_suffix": ["rust-lang.org"],
                    "port": [443],
                    "network": ["tcp"]
                }
            ]
        });
        let data = serde_json::to_vec(&json).unwrap();
        let rs = parse_json(&data, RuleSetSource::Local(PathBuf::from("/json"))).unwrap();

        // Write to temp .srs
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rt.srs");
        write_to_file(&path, &rs.rules, RULESET_VERSION_CURRENT)
            .await
            .unwrap();

        // Read back
        let rs2 = tokio::fs::read(&path).await.unwrap();
        let parsed = parse_binary(&rs2, RuleSetSource::Local(path.clone())).unwrap();
        assert_eq!(parsed.rules.len(), 1);
        match &parsed.rules[0] {
            Rule::Default(r) => {
                // Check domain exact present
                assert!(r
                    .domain
                    .iter()
                    .any(|d| matches!(d, DomainRule::Exact(s) if s == "example.com")));
                // Check suffix present
                assert!(r.domain_suffix.iter().any(|s| s == "rust-lang.org"));
                // Check port and network
                assert!(r.port.contains(&443));
                assert!(r.network.iter().any(|n| n == "tcp"));
            }
            _ => panic!("expected default rule"),
        }
    }
}
