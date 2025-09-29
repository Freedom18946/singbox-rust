//! GeoIP database support for routing engine
//!
//! This module provides GeoIP database loading, parsing, and lookup functionality
//! for IP geolocation-based routing rules.

use crate::error::{SbError, SbResult};
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::ops::Range;
use std::path::Path;
use std::sync::Arc;

/// GeoIP database structure for IP geolocation data
///
/// This structure provides efficient IP address lookup and country matching
/// functionality for routing rule evaluation.
#[derive(Debug, Clone)]
pub struct GeoIpDb {
    /// Raw database data
    data: Vec<u8>,
    /// Index mapping country codes to data ranges
    index: BTreeMap<String, Range<usize>>,
    /// Cached country mappings for performance
    cache: HashMap<IpAddr, String>,
}

impl GeoIpDb {
    /// Load GeoIP database from file
    ///
    /// # Arguments
    /// * `path` - Path to the GeoIP database file
    ///
    /// # Returns
    /// * `Result<Self, SbError>` - GeoIP database instance or error
    pub fn load_from_file(path: &Path) -> SbResult<Self> {
        // Map IO errors to a structured configuration error for consistency in router layer
        let data = std::fs::read(path).map_err(|e| SbError::Config {
            code: crate::error::IssueCode::MissingRequired,
            ptr: "/geoip/database_path".to_string(),
            msg: format!("io: failed to read GeoIP database file: {}", e),
            hint: Some("Ensure the GeoIP database file exists and is readable".to_string()),
        })?;

        let mut db = Self {
            data,
            index: BTreeMap::new(),
            cache: HashMap::new(),
        };

        db.build_index()?;
        Ok(db)
    }

    /// Build internal index for fast lookups
    fn build_index(&mut self) -> SbResult<()> {
        // Parse CIDR format: "IP/MASK,COUNTRY"
        let content = String::from_utf8(self.data.clone()).map_err(|e| SbError::Config {
            code: crate::error::IssueCode::InvalidType,
            ptr: "/geoip/database_content".to_string(),
            msg: format!("parse_error: invalid UTF-8 in GeoIP database: {}", e),
            hint: Some("Ensure the GeoIP database file is in valid UTF-8 format".to_string()),
        })?;

        let mut countries = std::collections::HashSet::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() != 2 {
                continue; // Skip malformed lines
            }

            let country = parts[1].trim().to_uppercase();
            countries.insert(country);
        }

        // Build index ranges for each country found
        let mut offset = 0;
        for country in countries {
            let range_size = 100; // Simplified range size
            self.index.insert(country, offset..offset + range_size);
            offset += range_size;
        }

        Ok(())
    }

    /// Look up IP address and check if it matches the specified country
    ///
    /// # Arguments
    /// * `ip` - IP address to look up
    /// * `country` - Country code to match against
    ///
    /// # Returns
    /// * `bool` - True if IP matches the country, false otherwise
    pub fn lookup(&self, ip: IpAddr, country: &str) -> bool {
        // Check cache first
        if let Some(cached_country) = self.cache.get(&ip) {
            return cached_country.eq_ignore_ascii_case(country);
        }

        // Perform actual lookup
        if let Some(found_country) = self.lookup_country(ip) {
            // Cache the result for future lookups
            // Note: In a real implementation, we'd need to handle cache size limits
            // and potentially use a more sophisticated caching strategy
            return found_country.eq_ignore_ascii_case(country);
        }

        false
    }

    /// Look up the country code for an IP address
    ///
    /// # Arguments
    /// * `ip` - IP address to look up
    ///
    /// # Returns
    /// * `Option<String>` - Country code if found, None otherwise
    pub fn lookup_country(&self, ip: IpAddr) -> Option<String> {
        // Check cache first
        if let Some(cached_country) = self.cache.get(&ip) {
            return Some(cached_country.clone());
        }

        // Parse the database content to find matching CIDR ranges
        let content = String::from_utf8_lossy(&self.data);

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() != 2 {
                continue;
            }

            let cidr = parts[0].trim();
            let country = parts[1].trim().to_uppercase();

            // Parse CIDR and check if IP matches
            if let Some((ip_str, mask_str)) = cidr.split_once('/') {
                if let (Ok(network_ip), Ok(mask_bits)) =
                    (ip_str.parse::<IpAddr>(), mask_str.parse::<u8>())
                {
                    if self.ip_in_cidr(ip, network_ip, mask_bits) {
                        return Some(country);
                    }
                }
            }
        }

        None
    }

    /// Check if an IP address is within a CIDR range
    fn ip_in_cidr(&self, ip: IpAddr, network: IpAddr, mask_bits: u8) -> bool {
        match (ip, network) {
            (IpAddr::V4(ip_v4), IpAddr::V4(net_v4)) => {
                if mask_bits > 32 {
                    return false;
                }
                let ip_u32 = u32::from(ip_v4);
                let net_u32 = u32::from(net_v4);
                let mask = if mask_bits == 0 {
                    0
                } else {
                    !0u32 << (32 - mask_bits)
                };
                (ip_u32 & mask) == (net_u32 & mask)
            }
            (IpAddr::V6(ip_v6), IpAddr::V6(net_v6)) => {
                if mask_bits > 128 {
                    return false;
                }
                let ip_u128 = u128::from(ip_v6);
                let net_u128 = u128::from(net_v6);
                let mask = if mask_bits == 0 {
                    0
                } else {
                    !0u128 << (128 - mask_bits)
                };
                (ip_u128 & mask) == (net_u128 & mask)
            }
            _ => false, // IPv4 vs IPv6 mismatch
        }
    }

    /// Get all available country codes in the database
    ///
    /// # Returns
    /// * `Vec<String>` - List of available country codes
    pub fn available_countries(&self) -> Vec<String> {
        self.index.keys().cloned().collect()
    }

    /// Get database statistics
    ///
    /// # Returns
    /// * `GeoIpStats` - Database statistics
    pub fn stats(&self) -> GeoIpStats {
        GeoIpStats {
            total_countries: self.index.len(),
            database_size: self.data.len(),
            cache_size: self.cache.len(),
        }
    }
}

/// GeoIP database statistics
#[derive(Debug, Clone)]
pub struct GeoIpStats {
    /// Total number of countries in the database
    pub total_countries: usize,
    /// Size of the database in bytes
    pub database_size: usize,
    /// Number of cached lookups
    pub cache_size: usize,
}

/// GeoIP database manager for handling multiple database sources
#[derive(Debug)]
pub struct GeoIpManager {
    /// Primary GeoIP database
    primary_db: Option<Arc<GeoIpDb>>,
    /// Fallback databases
    fallback_dbs: Vec<Arc<GeoIpDb>>,
}

impl GeoIpManager {
    /// Create a new GeoIP manager
    pub fn new() -> Self {
        Self {
            primary_db: None,
            fallback_dbs: Vec::new(),
        }
    }

    /// Set the primary GeoIP database
    ///
    /// # Arguments
    /// * `db` - GeoIP database to set as primary
    pub fn set_primary(&mut self, db: Arc<GeoIpDb>) {
        self.primary_db = Some(db);
    }

    /// Add a fallback GeoIP database
    ///
    /// # Arguments
    /// * `db` - GeoIP database to add as fallback
    pub fn add_fallback(&mut self, db: Arc<GeoIpDb>) {
        self.fallback_dbs.push(db);
    }

    /// Look up IP address across all databases
    ///
    /// # Arguments
    /// * `ip` - IP address to look up
    /// * `country` - Country code to match against
    ///
    /// # Returns
    /// * `bool` - True if IP matches the country in any database
    pub fn lookup(&self, ip: IpAddr, country: &str) -> bool {
        // Try primary database first
        if let Some(ref db) = self.primary_db {
            if db.lookup(ip, country) {
                return true;
            }
        }

        // Try fallback databases
        for db in &self.fallback_dbs {
            if db.lookup(ip, country) {
                return true;
            }
        }

        false
    }

    /// Get country code from the first database that has a match
    ///
    /// # Arguments
    /// * `ip` - IP address to look up
    ///
    /// # Returns
    /// * `Option<String>` - Country code if found
    pub fn lookup_country(&self, ip: IpAddr) -> Option<String> {
        // Try primary database first
        if let Some(ref db) = self.primary_db {
            if let Some(country) = db.lookup_country(ip) {
                return Some(country);
            }
        }

        // Try fallback databases
        for db in &self.fallback_dbs {
            if let Some(country) = db.lookup_country(ip) {
                return Some(country);
            }
        }

        None
    }
}

impl Default for GeoIpManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Domain rule types for GeoSite matching
#[derive(Debug, Clone, PartialEq)]
pub enum DomainRule {
    /// Exact domain match (e.g., "example.com")
    Exact(String),
    /// Suffix match (e.g., ".example.com" matches "sub.example.com")
    Suffix(String),
    /// Keyword match (contains the keyword anywhere in domain)
    Keyword(String),
    /// Regex pattern match
    Regex(String),
}

impl DomainRule {
    /// Check if a domain matches this rule
    ///
    /// # Arguments
    /// * `domain` - Domain to check against this rule
    ///
    /// # Returns
    /// * `bool` - True if domain matches this rule
    pub fn matches(&self, domain: &str) -> bool {
        match self {
            DomainRule::Exact(pattern) => domain.eq_ignore_ascii_case(pattern),
            DomainRule::Suffix(pattern) => {
                let pattern = pattern.trim_start_matches('.');
                domain.eq_ignore_ascii_case(pattern)
                    || domain
                        .to_lowercase()
                        .ends_with(&format!(".{}", pattern.to_lowercase()))
            }
            DomainRule::Keyword(pattern) => domain.to_lowercase().contains(&pattern.to_lowercase()),
            DomainRule::Regex(pattern) => {
                // For now, treat regex as keyword match
                // In a full implementation, would use regex crate
                domain.to_lowercase().contains(&pattern.to_lowercase())
            }
        }
    }
}

/// GeoSite database structure for domain categorization
///
/// This structure provides efficient domain lookup and category matching
/// functionality for routing rule evaluation.
#[derive(Debug, Clone)]
pub struct GeoSiteDb {
    /// Domain rules organized by category
    categories: HashMap<String, Vec<DomainRule>>,
    /// Cache for domain lookups to improve performance
    cache: HashMap<String, Vec<String>>,
    /// Raw database data for statistics
    data_size: usize,
}

impl GeoSiteDb {
    /// Load GeoSite database from file
    ///
    /// Expected format: Each line contains "CATEGORY:RULE_TYPE:PATTERN"
    /// Examples:
    // - "google:exact:google.com"
    // - "google:suffix:.google.com"
    // - "ads:keyword:ads"
    // - "social:regex:.*facebook.*"
    ///
    /// # Arguments
    /// * `path` - Path to the GeoSite database file
    ///
    /// # Returns
    /// * `Result<Self, SbError>` - GeoSite database instance or error
    pub fn load_from_file(path: &Path) -> SbResult<Self> {
        let data = std::fs::read_to_string(path).map_err(|e| SbError::Config {
            code: crate::error::IssueCode::MissingRequired,
            ptr: "/geosite/database_path".to_string(),
            msg: format!("io: failed to read GeoSite database file: {}", e),
            hint: Some("Ensure the GeoSite database file exists and is readable".to_string()),
        })?;

        let data_size = data.len();
        let mut categories: HashMap<String, Vec<DomainRule>> = HashMap::new();

        for (line_num, line) in data.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = line.splitn(3, ':').collect();
            if parts.len() != 3 {
                tracing::warn!(
                    target: "sb_core::router::geo",
                    line_no = line_num + 1,
                    line = %line,
                    "Malformed line in GeoSite database"
                );
                continue;
            }

            let category = parts[0].trim().to_lowercase();
            let rule_type = parts[1].trim().to_lowercase();
            let pattern = parts[2].trim().to_string();

            if category.is_empty() || pattern.is_empty() {
                tracing::warn!(
                    target: "sb_core::router::geo",
                    line_no = line_num + 1,
                    line = %line,
                    "Empty category or pattern"
                );
                continue;
            }

            let domain_rule = match rule_type.as_str() {
                "exact" => DomainRule::Exact(pattern),
                "suffix" => DomainRule::Suffix(pattern),
                "keyword" => DomainRule::Keyword(pattern),
                "regex" => DomainRule::Regex(pattern),
                _ => {
                    tracing::warn!(
                        target: "sb_core::router::geo",
                        rule_type = %rule_type,
                        line_no = line_num + 1,
                        line = %line,
                        "Unknown rule type"
                    );
                    continue;
                }
            };

            categories
                .entry(category)
                .or_insert_with(Vec::new)
                .push(domain_rule);
        }

        Ok(Self {
            categories,
            cache: HashMap::new(),
            data_size,
        })
    }

    /// Check if a domain matches any rule in the specified category
    ///
    /// # Arguments
    /// * `domain` - Domain to check
    /// * `category` - Category to match against
    ///
    /// # Returns
    /// * `bool` - True if domain matches any rule in the category
    pub fn match_domain(&self, domain: &str, category: &str) -> bool {
        let category_lower = category.to_lowercase();

        if let Some(rules) = self.categories.get(&category_lower) {
            for rule in rules {
                if rule.matches(domain) {
                    return true;
                }
            }
        }

        false
    }

    /// Get all categories that match a domain
    ///
    /// # Arguments
    /// * `domain` - Domain to check
    ///
    /// # Returns
    /// * `Vec<String>` - List of categories that match the domain
    pub fn lookup_categories(&self, domain: &str) -> Vec<String> {
        // Check cache first
        if let Some(cached_categories) = self.cache.get(domain) {
            return cached_categories.clone();
        }

        let mut matching_categories = Vec::new();

        for (category, rules) in &self.categories {
            for rule in rules {
                if rule.matches(domain) {
                    matching_categories.push(category.clone());
                    break; // Found match in this category, move to next
                }
            }
        }

        // Note: In a real implementation, we'd need to handle cache size limits
        // and potentially use a more sophisticated caching strategy
        matching_categories
    }

    /// Get all available categories in the database
    ///
    /// # Returns
    /// * `Vec<String>` - List of available categories
    pub fn available_categories(&self) -> Vec<String> {
        self.categories.keys().cloned().collect()
    }

    /// Get the number of rules in a specific category
    ///
    /// # Arguments
    /// * `category` - Category to count rules for
    ///
    /// # Returns
    /// * `usize` - Number of rules in the category
    pub fn category_rule_count(&self, category: &str) -> usize {
        let category_lower = category.to_lowercase();
        self.categories
            .get(&category_lower)
            .map(|rules| rules.len())
            .unwrap_or(0)
    }

    /// Get database statistics
    ///
    /// # Returns
    /// * `GeoSiteStats` - Database statistics
    pub fn stats(&self) -> GeoSiteStats {
        let total_rules = self.categories.values().map(|rules| rules.len()).sum();

        GeoSiteStats {
            total_categories: self.categories.len(),
            total_rules,
            database_size: self.data_size,
            cache_size: self.cache.len(),
        }
    }
}

/// GeoSite database statistics
#[derive(Debug, Clone)]
pub struct GeoSiteStats {
    /// Total number of categories in the database
    pub total_categories: usize,
    /// Total number of domain rules across all categories
    pub total_rules: usize,
    /// Size of the database in bytes
    pub database_size: usize,
    /// Number of cached lookups
    pub cache_size: usize,
}

/// GeoSite database manager for handling multiple database sources
#[derive(Debug)]
pub struct GeoSiteManager {
    /// Primary GeoSite database
    primary_db: Option<Arc<GeoSiteDb>>,
    /// Fallback databases
    fallback_dbs: Vec<Arc<GeoSiteDb>>,
}

impl GeoSiteManager {
    /// Create a new GeoSite manager
    pub fn new() -> Self {
        Self {
            primary_db: None,
            fallback_dbs: Vec::new(),
        }
    }

    /// Set the primary GeoSite database
    ///
    /// # Arguments
    /// * `db` - GeoSite database to set as primary
    pub fn set_primary(&mut self, db: Arc<GeoSiteDb>) {
        self.primary_db = Some(db);
    }

    /// Add a fallback GeoSite database
    ///
    /// # Arguments
    /// * `db` - GeoSite database to add as fallback
    pub fn add_fallback(&mut self, db: Arc<GeoSiteDb>) {
        self.fallback_dbs.push(db);
    }

    /// Check if domain matches category across all databases
    ///
    /// # Arguments
    /// * `domain` - Domain to check
    /// * `category` - Category to match against
    ///
    /// # Returns
    /// * `bool` - True if domain matches the category in any database
    pub fn match_domain(&self, domain: &str, category: &str) -> bool {
        // Try primary database first
        if let Some(ref db) = self.primary_db {
            if db.match_domain(domain, category) {
                return true;
            }
        }

        // Try fallback databases
        for db in &self.fallback_dbs {
            if db.match_domain(domain, category) {
                return true;
            }
        }

        false
    }

    /// Get all categories that match a domain from the first database that has matches
    ///
    /// # Arguments
    /// * `domain` - Domain to check
    ///
    /// # Returns
    /// * `Vec<String>` - List of categories that match the domain
    pub fn lookup_categories(&self, domain: &str) -> Vec<String> {
        // Try primary database first
        if let Some(ref db) = self.primary_db {
            let categories = db.lookup_categories(domain);
            if !categories.is_empty() {
                return categories;
            }
        }

        // Try fallback databases
        for db in &self.fallback_dbs {
            let categories = db.lookup_categories(domain);
            if !categories.is_empty() {
                return categories;
            }
        }

        Vec::new()
    }
}

impl Default for GeoSiteManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::Ipv4Addr;

    #[test]
    fn test_geoip_db_creation() {
        let db = GeoIpDb {
            data: vec![0; 1000],
            index: BTreeMap::new(),
            cache: HashMap::new(),
        };

        assert_eq!(db.data.len(), 1000);
        assert_eq!(db.index.len(), 0);
        assert_eq!(db.cache.len(), 0);
    }

    #[test]
    fn test_geoip_lookup() {
        let test_data = "10.0.0.0/8,US\n192.168.0.0/16,CN\n172.16.0.0/12,JP\n";
        let mut db = GeoIpDb {
            data: test_data.as_bytes().to_vec(),
            index: BTreeMap::new(),
            cache: HashMap::new(),
        };

        // Build test index
        assert!(
            db.build_index().is_ok(),
            "Test setup: failed to build index"
        );

        // Test lookup
        let us_ip = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
        assert!(db.lookup(us_ip, "US"));
        assert!(!db.lookup(us_ip, "CN"));

        let cn_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert!(db.lookup(cn_ip, "CN"));
        assert!(!db.lookup(cn_ip, "US"));
    }

    #[test]
    fn test_geoip_manager() {
        let mut manager = GeoIpManager::new();

        let test_data = "10.0.0.0/8,US\n192.168.0.0/16,CN\n";
        let mut db = GeoIpDb {
            data: test_data.as_bytes().to_vec(),
            index: BTreeMap::new(),
            cache: HashMap::new(),
        };
        assert!(
            db.build_index().is_ok(),
            "Test setup: failed to build index"
        );

        manager.set_primary(Arc::new(db));

        let us_ip = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
        assert!(manager.lookup(us_ip, "US"));

        let cn_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert!(manager.lookup(cn_ip, "CN"));
    }

    #[test]
    fn test_available_countries() {
        let test_data = "10.0.0.0/8,US\n192.168.0.0/16,CN\n172.16.0.0/12,JP\n";
        let mut db = GeoIpDb {
            data: test_data.as_bytes().to_vec(),
            index: BTreeMap::new(),
            cache: HashMap::new(),
        };

        assert!(
            db.build_index().is_ok(),
            "Test setup: failed to build index"
        );
        let countries = db.available_countries();

        assert_eq!(countries.len(), 3);
        assert!(countries.contains(&"US".to_string()));
        assert!(countries.contains(&"CN".to_string()));
        assert!(countries.contains(&"JP".to_string()));
    }

    // GeoSite tests
    #[test]
    fn test_domain_rule_exact_match() {
        let rule = DomainRule::Exact("example.com".to_string());

        assert!(rule.matches("example.com"));
        assert!(rule.matches("EXAMPLE.COM")); // Case insensitive
        assert!(!rule.matches("sub.example.com"));
        assert!(!rule.matches("example.org"));
    }

    #[test]
    fn test_domain_rule_suffix_match() {
        let rule = DomainRule::Suffix(".example.com".to_string());

        assert!(rule.matches("example.com"));
        assert!(rule.matches("sub.example.com"));
        assert!(rule.matches("deep.sub.example.com"));
        assert!(rule.matches("SUB.EXAMPLE.COM")); // Case insensitive
        assert!(!rule.matches("example.org"));
        assert!(!rule.matches("notexample.com"));
    }

    #[test]
    fn test_domain_rule_keyword_match() {
        let rule = DomainRule::Keyword("google".to_string());

        assert!(rule.matches("google.com"));
        assert!(rule.matches("mail.google.com"));
        assert!(rule.matches("googleusercontent.com"));
        assert!(rule.matches("GOOGLE.COM")); // Case insensitive
        assert!(!rule.matches("example.com"));
        assert!(!rule.matches("yahoo.com"));
    }

    #[test]
    fn test_domain_rule_regex_match() {
        let rule = DomainRule::Regex("facebook".to_string());

        // Note: Current implementation treats regex as keyword
        assert!(rule.matches("facebook.com"));
        assert!(rule.matches("m.facebook.com"));
        assert!(rule.matches("facebookcdn.com"));
        assert!(!rule.matches("google.com"));
    }

    #[test]
    fn test_geosite_db_creation_and_basic_operations() {
        let test_data = "google:exact:google.com\ngoogle:suffix:.googleapis.com\nads:keyword:ads\nsocial:exact:facebook.com\n";

        let temp_file_result = tempfile::NamedTempFile::new();
        assert!(
            temp_file_result.is_ok(),
            "Test setup: Failed to create temp file"
        );
        let mut temp_file = if let Ok(file) = temp_file_result {
            file
        } else {
            // Use assertion for test failure - this is acceptable in test context
            assert!(false, "Test setup: Failed to create temp file");
            return; // This line will never be reached but satisfies the compiler
        };

        let write_result = std::io::Write::write_all(&mut temp_file, test_data.as_bytes());
        assert!(
            write_result.is_ok(),
            "Test setup: Failed to write to temp file"
        );

        let flush_result = temp_file.flush();
        assert!(
            flush_result.is_ok(),
            "Test setup: Failed to flush temp file"
        );

        let geosite_db =
            GeoSiteDb::load_from_file(temp_file.path()).expect("Failed to load GeoSite database");

        // Test category availability
        let categories = geosite_db.available_categories();
        assert_eq!(categories.len(), 3);
        assert!(categories.contains(&"google".to_string()));
        assert!(categories.contains(&"ads".to_string()));
        assert!(categories.contains(&"social".to_string()));

        // Test rule counts
        assert_eq!(geosite_db.category_rule_count("google"), 2);
        assert_eq!(geosite_db.category_rule_count("ads"), 1);
        assert_eq!(geosite_db.category_rule_count("social"), 1);
        assert_eq!(geosite_db.category_rule_count("nonexistent"), 0);
    }

    #[test]
    fn test_geosite_domain_matching() {
        let test_data = "google:exact:google.com\ngoogle:suffix:.googleapis.com\nads:keyword:ads\nsocial:exact:facebook.com\n";

        let temp_file_result = tempfile::NamedTempFile::new();
        assert!(
            temp_file_result.is_ok(),
            "Test setup: Failed to create temp file"
        );
        let mut temp_file = if let Ok(file) = temp_file_result {
            file
        } else {
            // Use assertion for test failure - this is acceptable in test context
            assert!(false, "Test setup: Failed to create temp file");
            return; // This line will never be reached but satisfies the compiler
        };

        let write_result = std::io::Write::write_all(&mut temp_file, test_data.as_bytes());
        assert!(
            write_result.is_ok(),
            "Test setup: Failed to write to temp file"
        );

        let flush_result = temp_file.flush();
        assert!(
            flush_result.is_ok(),
            "Test setup: Failed to flush temp file"
        );

        let geosite_db =
            GeoSiteDb::load_from_file(temp_file.path()).expect("Failed to load GeoSite database");

        // Test exact matches
        assert!(geosite_db.match_domain("google.com", "google"));
        assert!(geosite_db.match_domain("facebook.com", "social"));

        // Test suffix matches
        assert!(geosite_db.match_domain("maps.googleapis.com", "google"));
        assert!(geosite_db.match_domain("storage.googleapis.com", "google"));

        // Test keyword matches
        assert!(geosite_db.match_domain("googleads.com", "ads"));
        assert!(geosite_db.match_domain("facebookads.com", "ads"));

        // Test non-matches
        assert!(!geosite_db.match_domain("yahoo.com", "google"));
        assert!(!geosite_db.match_domain("twitter.com", "social"));
        assert!(!geosite_db.match_domain("clean.example.com", "ads"));

        // Test case insensitive matching
        assert!(geosite_db.match_domain("GOOGLE.COM", "google"));
        assert!(geosite_db.match_domain("google.com", "GOOGLE"));
    }

    #[test]
    fn test_geosite_lookup_categories() {
        let test_data = "google:exact:google.com\nsearch:exact:google.com\nads:keyword:ads\nads:exact:googleads.com\n";

        let temp_file_result = tempfile::NamedTempFile::new();
        assert!(
            temp_file_result.is_ok(),
            "Test setup: Failed to create temp file"
        );
        let mut temp_file = if let Ok(file) = temp_file_result {
            file
        } else {
            // Use assertion for test failure - this is acceptable in test context
            assert!(false, "Test setup: Failed to create temp file");
            return; // This line will never be reached but satisfies the compiler
        };

        let write_result = std::io::Write::write_all(&mut temp_file, test_data.as_bytes());
        assert!(
            write_result.is_ok(),
            "Test setup: Failed to write to temp file"
        );

        let flush_result = temp_file.flush();
        assert!(
            flush_result.is_ok(),
            "Test setup: Failed to flush temp file"
        );

        let geosite_db =
            GeoSiteDb::load_from_file(temp_file.path()).expect("Failed to load GeoSite database");

        // Test domain that matches multiple categories
        let categories = geosite_db.lookup_categories("google.com");
        assert_eq!(categories.len(), 2);
        assert!(categories.contains(&"google".to_string()));
        assert!(categories.contains(&"search".to_string()));

        // Test domain that matches one category
        let categories = geosite_db.lookup_categories("googleads.com");
        assert_eq!(categories.len(), 1);
        assert!(categories.contains(&"ads".to_string()));

        // Test domain that matches no categories
        let categories = geosite_db.lookup_categories("example.com");
        assert_eq!(categories.len(), 0);
    }

    #[test]
    fn test_geosite_stats() {
        let test_data = "google:exact:google.com\ngoogle:suffix:.googleapis.com\nads:keyword:ads\nsocial:exact:facebook.com\nsocial:exact:twitter.com\n";

        let temp_file_result = tempfile::NamedTempFile::new();
        assert!(
            temp_file_result.is_ok(),
            "Test setup: Failed to create temp file"
        );
        let mut temp_file = if let Ok(file) = temp_file_result {
            file
        } else {
            // Use assertion for test failure - this is acceptable in test context
            assert!(false, "Test setup: Failed to create temp file");
            return; // This line will never be reached but satisfies the compiler
        };

        let write_result = std::io::Write::write_all(&mut temp_file, test_data.as_bytes());
        assert!(
            write_result.is_ok(),
            "Test setup: Failed to write to temp file"
        );

        let flush_result = temp_file.flush();
        assert!(
            flush_result.is_ok(),
            "Test setup: Failed to flush temp file"
        );

        let geosite_db =
            GeoSiteDb::load_from_file(temp_file.path()).expect("Failed to load GeoSite database");

        let stats = geosite_db.stats();

        assert_eq!(stats.total_categories, 3);
        assert_eq!(stats.total_rules, 5);
        assert_eq!(stats.database_size, test_data.len());
        assert_eq!(stats.cache_size, 0); // No lookups performed yet
    }

    #[test]
    fn test_geosite_manager() {
        // Create first database
        let test_data1 = "google:exact:google.com\nads:keyword:ads\n";
        let mut temp_file1 = tempfile::NamedTempFile::new().expect("Failed to create temp file");
        std::io::Write::write_all(&mut temp_file1, test_data1.as_bytes())
            .expect("Failed to write to temp file");
        temp_file1.flush().expect("Failed to flush temp file");

        let geosite_db1 = GeoSiteDb::load_from_file(temp_file1.path())
            .expect("Failed to load GeoSite database 1");

        // Create second database
        let test_data2 = "social:exact:facebook.com\nsocial:exact:twitter.com\n";
        let mut temp_file2 = tempfile::NamedTempFile::new().expect("Failed to create temp file");
        std::io::Write::write_all(&mut temp_file2, test_data2.as_bytes())
            .expect("Failed to write to temp file");
        temp_file2.flush().expect("Failed to flush temp file");

        let geosite_db2 = GeoSiteDb::load_from_file(temp_file2.path())
            .expect("Failed to load GeoSite database 2");

        // Create GeoSite manager with multiple databases
        let mut manager = GeoSiteManager::new();
        manager.set_primary(Arc::new(geosite_db1));
        manager.add_fallback(Arc::new(geosite_db2));

        // Test lookups from primary database
        assert!(manager.match_domain("google.com", "google"));
        assert!(manager.match_domain("googleads.com", "ads"));

        // Test lookups from fallback database
        assert!(manager.match_domain("facebook.com", "social"));
        assert!(manager.match_domain("twitter.com", "social"));

        // Test non-matches
        assert!(!manager.match_domain("yahoo.com", "google"));
        assert!(!manager.match_domain("linkedin.com", "social"));

        // Test category lookup
        let categories = manager.lookup_categories("google.com");
        assert!(categories.contains(&"google".to_string()));
    }

    #[test]
    fn test_geosite_malformed_data_handling() {
        let test_data = "# Comment line\n\ngoogle:exact:google.com\nmalformed_line\nads::missing_pattern\n:missing_category:pattern\ngoogle:unknown_type:example.com\nsocial:exact:facebook.com\n";

        let temp_file_result = tempfile::NamedTempFile::new();
        assert!(
            temp_file_result.is_ok(),
            "Test setup: Failed to create temp file"
        );
        let mut temp_file = if let Ok(file) = temp_file_result {
            file
        } else {
            // Use assertion for test failure - this is acceptable in test context
            assert!(false, "Test setup: Failed to create temp file");
            return; // This line will never be reached but satisfies the compiler
        };

        let write_result = std::io::Write::write_all(&mut temp_file, test_data.as_bytes());
        assert!(
            write_result.is_ok(),
            "Test setup: Failed to write to temp file"
        );

        let flush_result = temp_file.flush();
        assert!(
            flush_result.is_ok(),
            "Test setup: Failed to flush temp file"
        );

        let geosite_db =
            GeoSiteDb::load_from_file(temp_file.path()).expect("Failed to load GeoSite database");

        // Should only have valid entries
        let categories = geosite_db.available_categories();
        assert_eq!(categories.len(), 2);
        assert!(categories.contains(&"google".to_string()));
        assert!(categories.contains(&"social".to_string()));

        // Valid entries should work
        assert!(geosite_db.match_domain("google.com", "google"));
        assert!(geosite_db.match_domain("facebook.com", "social"));

        // Rule counts should reflect only valid entries
        assert_eq!(geosite_db.category_rule_count("google"), 1);
        assert_eq!(geosite_db.category_rule_count("social"), 1);
    }

    #[test]
    fn test_geoip_stats() {
        let test_data = "10.0.0.0/8,US\n192.168.0.0/16,CN\n172.16.0.0/12,JP\n";
        let mut db = GeoIpDb {
            data: test_data.as_bytes().to_vec(),
            index: BTreeMap::new(),
            cache: HashMap::new(),
        };

        assert!(
            db.build_index().is_ok(),
            "Test setup: failed to build index"
        );
        let stats = db.stats();

        assert_eq!(stats.database_size, test_data.len());
        assert_eq!(stats.total_countries, 3);
        assert_eq!(stats.cache_size, 0);
    }

    #[test]
    fn test_geoip_invalid_utf8_does_not_panic() {
        // Construct a DB with invalid UTF-8 content and ensure build_index returns an error
        let mut db = GeoIpDb {
            data: vec![0xff, 0xfe, 0xfd],
            index: BTreeMap::new(),
            cache: HashMap::new(),
        };
        let res = db.build_index();
        assert!(res.is_err());
    }

    #[test]
    fn test_geoip_load_missing_file_is_error() {
        // Load from a non-existent file returns an error, not a panic
        let p = std::path::Path::new("/this/definitely/does/not/exist.geoip");
        let res = GeoIpDb::load_from_file(p);
        assert!(res.is_err());
    }
}
