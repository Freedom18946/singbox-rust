//! GeoSite database demonstration
//!
//! This example shows how to use the GeoSite database for domain categorization
//! in the routing engine.

use sb_core::router::{geo::GeoSiteDb, router_build_index_from_str, RouterHandle};
use std::io::Write;
use std::sync::Arc;
use tempfile::NamedTempFile;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("GeoSite Database Demonstration");
    println!("==============================");

    // Create a sample GeoSite database
    let mut temp_file = NamedTempFile::new()?;
    writeln!(temp_file, "# GeoSite database example")?;
    writeln!(temp_file, "google:exact:google.com")?;
    writeln!(temp_file, "google:suffix:.googleapis.com")?;
    writeln!(temp_file, "google:suffix:.google.com")?;
    writeln!(temp_file, "ads:keyword:ads")?;
    writeln!(temp_file, "ads:keyword:doubleclick")?;
    writeln!(temp_file, "social:exact:facebook.com")?;
    writeln!(temp_file, "social:exact:twitter.com")?;
    writeln!(temp_file, "social:suffix:.instagram.com")?;
    writeln!(temp_file, "streaming:exact:youtube.com")?;
    writeln!(temp_file, "streaming:suffix:.youtube.com")?;
    writeln!(temp_file, "streaming:exact:netflix.com")?;
    temp_file.flush()?;

    println!("1. Loading GeoSite database from file...");
    let geosite_db = GeoSiteDb::load_from_file(temp_file.path())?;

    // Display database statistics
    let stats = geosite_db.stats();
    println!("   - Total categories: {}", stats.total_categories);
    println!("   - Total rules: {}", stats.total_rules);
    println!("   - Database size: {} bytes", stats.database_size);

    // Show available categories
    let categories = geosite_db.available_categories();
    println!("   - Available categories: {:?}", categories);

    println!("\n2. Testing domain categorization...");
    let test_domains = vec![
        "google.com",
        "maps.googleapis.com",
        "mail.google.com",
        "googleads.com",
        "facebook.com",
        "www.instagram.com",
        "youtube.com",
        "music.youtube.com",
        "netflix.com",
        "example.com",
    ];

    for domain in &test_domains {
        let categories = geosite_db.lookup_categories(domain);
        if categories.is_empty() {
            println!("   - {}: No categories", domain);
        } else {
            println!("   - {}: {:?}", domain, categories);
        }
    }

    println!("\n3. Creating router with GeoSite rules...");
    let rules = r#"
# GeoSite routing rules
geosite:google=proxy
geosite:ads=reject
geosite:social=direct
geosite:streaming=proxy
# Fallback
default=direct
"#;

    let router_index = router_build_index_from_str(rules, 1000)?;
    println!(
        "   - Parsed {} GeoSite rules",
        router_index.geosite_rules.len()
    );

    // Create RouterHandle with GeoSite database
    let router_handle = RouterHandle::from_env().with_geosite_db(Arc::new(geosite_db));

    println!("\n4. Testing routing decisions...");
    for domain in &test_domains {
        let decision = router_handle.enhanced_geosite_lookup(domain, &router_index);
        match decision {
            Some(dec) => println!("   - {} -> {}", domain, dec),
            None => println!("   - {} -> {} (default)", domain, router_index.default),
        }
    }

    println!("\n5. Testing category-specific matching...");
    let test_cases = vec![
        ("google.com", "google"),
        ("maps.googleapis.com", "google"),
        ("googleads.com", "ads"),
        ("facebook.com", "social"),
        ("youtube.com", "streaming"),
        ("example.com", "google"), // Should not match
    ];

    for (domain, category) in test_cases {
        if let Some(geosite_db) = router_handle.geosite_db() {
            let matches = geosite_db.match_domain(domain, category);
            println!(
                "   - {} matches category '{}': {}",
                domain, category, matches
            );
        }
    }

    println!("\nGeoSite demonstration completed successfully!");
    Ok(())
}
