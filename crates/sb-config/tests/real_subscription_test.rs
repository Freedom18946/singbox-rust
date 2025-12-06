//! Test subscription parsing on real data
use sb_config::subscribe::from_subscription;

#[test]
fn test_real_subscription() {
    let content = std::fs::read_to_string("/tmp/subscription_test.txt")
        .expect("Failed to read subscription file");
    
    println!("Content size: {} bytes", content.len());
    println!("First 300 chars:\n{}", &content[..content.len().min(300)]);
    
    match from_subscription(&content) {
        Ok(config) => {
            println!("\n✅ Parsing SUCCESS!");
            println!("Outbounds: {}", config.outbounds.len());
            println!("Rules: {}", config.rules.len());
            
            for (i, ob) in config.outbounds.iter().take(10).enumerate() {
                println!("  [{}] {:?}", i+1, ob);
            }
        }
        Err(e) => {
            println!("❌ Parsing FAILED: {}", e);
            panic!("Subscription parsing failed: {}", e);
        }
    }
}
