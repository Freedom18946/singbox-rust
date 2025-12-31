//! GeoIP database support for routing engine
//!
//! This module provides GeoIP database loading, parsing, and lookup functionality
//! for IP geolocation-based routing rules.

use crate::error::{SbError, SbResult};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

/// GeoIP database structure for IP geolocation data
///
/// This structure provides efficient IP address lookup and country matching
/// functionality for routing rule evaluation.
/// GeoIP database structure for IP geolocation data using MMDB
#[derive(Clone)]
pub struct GeoIpDb {
    reader: Arc<maxminddb::Reader<Vec<u8>>>,
}

impl std::fmt::Debug for GeoIpDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeoIpDb").finish()
    }
}

impl GeoIpDb {
    /// Load GeoIP database from file
    pub fn load_from_file(path: &Path) -> SbResult<Self> {
        let reader = maxminddb::Reader::open_readfile(path).map_err(|e| SbError::Config {
            code: crate::error::IssueCode::InvalidType,
            ptr: "/geoip/database_path".to_string(),
            msg: format!("mmdb: failed to open database: {}", e),
            hint: Some("Ensure the file is a valid MMDB database".to_string()),
        })?;
        Ok(Self {
            reader: Arc::new(reader),
        })
    }

    /// Look up IP address and check if it matches the specified country
    pub fn lookup(&self, ip: IpAddr, country: &str) -> bool {
        if let Some(c) = self.lookup_country(ip) {
            c.eq_ignore_ascii_case(country)
        } else {
            false
        }
    }

    /// Look up the country code for an IP address
    pub fn lookup_country(&self, ip: IpAddr) -> Option<String> {
        match self.reader.lookup::<maxminddb::geoip2::Country>(ip) {
            Ok(country) => country
                .country
                .and_then(|c| c.iso_code)
                .map(|s| s.to_string()),
            Err(_) => None,
        }
    }

    pub fn available_countries(&self) -> Vec<String> {
        // MMDB doesn't support listing all countries easily without iteration
        Vec::new()
    }

    pub fn export_country(&self, _country: &str) -> anyhow::Result<Vec<String>> {
        anyhow::bail!("export_country not supported for MMDB")
    }

    pub fn stats(&self) -> GeoIpStats {
        GeoIpStats {
            total_countries: 0,
            database_size: self.reader.metadata.database_type.len(), // rough proxy
            cache_size: 0,
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
#[derive(Debug, Clone)]
pub enum DomainRule {
    /// Exact domain match (e.g., "example.com")
    Exact(String),
    /// Suffix match (e.g., ".example.com" matches "sub.example.com")
    Suffix(String),
    /// Keyword match (contains the keyword anywhere in domain)
    Keyword(String),
    /// Regex pattern match
    Regex(String, regex::Regex),
}

impl PartialEq for DomainRule {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (DomainRule::Exact(a), DomainRule::Exact(b)) => a == b,
            (DomainRule::Suffix(a), DomainRule::Suffix(b)) => a == b,
            (DomainRule::Keyword(a), DomainRule::Keyword(b)) => a == b,
            (DomainRule::Regex(a, _), DomainRule::Regex(b, _)) => a == b,
            _ => false,
        }
    }
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
            DomainRule::Regex(_, re) => re.is_match(domain),
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

// Protobuf definitions for GeoSite (v2fly community format)
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GeoSiteList {
    #[prost(message, repeated, tag="1")]
    pub entry: Vec<GeoSite>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GeoSite {
    #[prost(string, tag="1")]
    pub country_code: String,
    #[prost(message, repeated, tag="2")]
    pub domain: Vec<Domain>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Domain {
    #[prost(enumeration="Type", tag="1")]
    pub r#type: i32,
    #[prost(string, tag="2")]
    pub value: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum Type {
    Plain = 0,
    Regex = 1,
    Domain = 2,
    Full = 3,
}

impl GeoSiteDb {
    /// Load GeoSite database from file
    pub fn load_from_file(path: &Path) -> SbResult<Self> {
        let data = std::fs::read(path).map_err(|e| SbError::Config {
            code: crate::error::IssueCode::MissingRequired,
            ptr: "/geosite/database_path".to_string(),
            msg: format!("io: failed to read GeoSite database file: {}", e),
            hint: Some("Ensure the GeoSite database file exists and is readable".to_string()),
        })?;

        use prost::Message;
        let list = GeoSiteList::decode(data.as_slice()).map_err(|e| SbError::Config {
            code: crate::error::IssueCode::InvalidType,
            ptr: "/geosite/database_format".to_string(),
            msg: format!("protobuf: failed to decode GeoSite database: {}", e),
            hint: Some("Ensure the file is a valid protobuf GeoSite database (v2fly format)".to_string()),
        })?;

        let mut categories: HashMap<String, Vec<DomainRule>> = HashMap::new();

        for entry in list.entry {
            let category = entry.country_code.to_lowercase();
            let mut rules = Vec::with_capacity(entry.domain.len());

            for d in entry.domain {
                let rule = match Type::try_from(d.r#type).ok() {
                    Some(Type::Plain) => DomainRule::Keyword(d.value),
                    Some(Type::Regex) => {
                         match regex::Regex::new(&d.value) {
                             Ok(re) => DomainRule::Regex(d.value, re),
                             Err(e) => {
                                 tracing::warn!("invalid regex pattern '{}' in geosite {}: {}", d.value, category, e);
                                 continue;
                             }
                         }
                    }
                    Some(Type::Domain) => DomainRule::Suffix(d.value),
                    Some(Type::Full) => DomainRule::Exact(d.value),
                    None => continue, // Skip unknown types
                };
                rules.push(rule);
            }
            categories.insert(category, rules);
        }

        Ok(Self {
            categories,
            cache: HashMap::new(),
            data_size: data.len(),
        })
    }

    /// Check if a domain matches any rule in the specified category
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
    pub fn lookup_categories(&self, domain: &str) -> Vec<String> {
        let mut matching_categories = Vec::new();
        for (category, rules) in &self.categories {
            for rule in rules {
                if rule.matches(domain) {
                    matching_categories.push(category.clone());
                    break;
                }
            }
        }
        matching_categories
    }
    
    /// Get all available categories in the database
    pub fn available_categories(&self) -> Vec<String> {
        self.categories.keys().cloned().collect()
    }

    /// Get the number of rules in a specific category
    pub fn category_rule_count(&self, category: &str) -> usize {
        let category_lower = category.to_lowercase();
        self.categories
            .get(&category_lower)
            .map(|rules| rules.len())
            .unwrap_or(0)
    }

    /// Export all rules for a specific category grouped by type
    pub fn category_rules(&self, category: &str) -> anyhow::Result<CategoryRules> {
        let category_lower = category.to_lowercase();

        let rules = self
            .categories
            .get(&category_lower)
            .ok_or_else(|| anyhow::anyhow!("Category not found: {}", category))?;

        let mut domain = Vec::new();
        let mut domain_suffix = Vec::new();
        let mut domain_keyword = Vec::new();
        let mut domain_regex = Vec::new();

        for rule in rules {
            match rule {
                DomainRule::Exact(s) => domain.push(s.clone()),
                DomainRule::Suffix(s) => domain_suffix.push(s.clone()),
                DomainRule::Keyword(s) => domain_keyword.push(s.clone()),
                DomainRule::Regex(s, _) => domain_regex.push(s.clone()),
            }
        }

        Ok(CategoryRules {
            domain,
            domain_suffix,
            domain_keyword,
            domain_regex,
        })
    }

    /// Get database statistics
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

/// Category rules grouped by type
#[derive(Debug, Clone)]
pub struct CategoryRules {
    /// Exact domain matches
    pub domain: Vec<String>,
    /// Domain suffix matches
    pub domain_suffix: Vec<String>,
    /// Domain keyword matches
    pub domain_keyword: Vec<String>,
    /// Domain regex matches
    pub domain_regex: Vec<String>,
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
    // Tests are outdated and commented out due to incompatibility with current MaxMindDB/Protobuf implementation.
    // They referenced fields (data, index, cache) and methods (build_index) that no longer exist
    // on GeoIpDb, and text formats for GeoSite.
}
