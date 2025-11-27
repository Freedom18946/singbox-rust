#![allow(
    clippy::doc_markdown,
    clippy::uninlined_format_args,
    clippy::unused_async
)]
//! `GeoIP` tooling subcommand (parity with sing-box `geoip`)
//! `GeoIP` 工具子命令（与 sing-box `geoip` 对齐）
//!
//! # Global Strategic Logic / 全局战略逻辑
//! This module manages **IP-based Location Data**.
//! 本模块管理 **基于 IP 的地理位置数据**。
//!
//! ## Strategic Features / 战略特性
//! - **Dual Format Support / 双格式支持**:
//!   - **MMDB**: Industry standard, fast binary lookups (MaxMind).
//!   - **Text**: Simple, human-readable fallback.
//! - **Rule Extraction / 规则提取**: Can "compile" country data into rule-sets for the router, enabling efficient country-based routing.
//!   可以将国家数据“编译”为路由器的规则集，从而实现高效的基于国家的路由。

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde_json::json;
use std::net::IpAddr;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "geoip")]
#[command(about = "GeoIP tools", long_about = None)]
pub struct GeoipArgs {
    /// `GeoIP` database file (text or MMDB)
    #[arg(short = 'f', long = "file", default_value = "geoip.db")]
    pub file: PathBuf,

    #[command(subcommand)]
    pub command: GeoipCmd,
}

#[derive(Subcommand, Debug)]
pub enum GeoipCmd {
    /// List country codes available in the database
    List,
    /// Lookup if an IP is contained in the `GeoIP` database
    Lookup { address: String },
    /// Export a country as rule-set JSON
    Export {
        /// Country code (e.g., US, CN)
        country: String,
        /// Output path (use "stdout" to print)
        #[arg(short = 'o', long = "output", default_value = "geoip-<country>.json")]
        output: String,
    },
}

pub async fn run(args: GeoipArgs) -> Result<()> {
    match args.command {
        GeoipCmd::List => geoip_list(&args.file).await,
        GeoipCmd::Lookup { address } => geoip_lookup(&args.file, &address).await,
        GeoipCmd::Export { country, output } => geoip_export(&args.file, &country, &output).await,
    }
}

async fn geoip_list(path: &PathBuf) -> Result<()> {
    if let Ok(reader) = maxminddb::Reader::open_readfile(path) {
        // MMDB path: print metadata languages (sing-geoip uses Languages to store codes)
        let mut langs = reader.metadata.languages.clone();
        langs.sort();
        for l in langs {
            println!("{l}");
        }
        return Ok(());
    }

    // Fallback: text DB
    let db = sb_core::router::geo::GeoIpDb::load_from_file(path)
        .with_context(|| format!("open geoip file: {}", path.display()))?;
    let mut countries = db.available_countries();
    countries.sort();
    for c in countries {
        println!("{c}");
    }
    Ok(())
}

async fn geoip_lookup(path: &PathBuf, address: &str) -> Result<()> {
    let ip: IpAddr = address
        .parse()
        .map_err(|e| anyhow::anyhow!("parse address: {}", e))?;
    if !is_public_addr(ip) {
        println!("private");
        return Ok(());
    }
    // Try MMDB (sing-geoip) first
    if let Ok(reader) = maxminddb::Reader::open_readfile(path) {
        // sing-geoip stores string code as value
        if let Ok(code) = reader.lookup::<String>(ip) {
            if !code.is_empty() {
                println!("{}", code);
                return Ok(());
            }
        }
        // Fallback: try country record decode for generic GeoLite2
        #[derive(serde::Deserialize, Debug)]
        struct CountryRecord {
            country: Option<CountryInfo>,
            registered_country: Option<CountryInfo>,
        }
        #[derive(serde::Deserialize, Debug)]
        struct CountryInfo {
            #[serde(rename = "iso_code")]
            iso: Option<String>,
        }
        if let Ok(rec) = reader.lookup::<CountryRecord>(ip) {
            let code = rec
                .country
                .and_then(|c| c.iso)
                .or_else(|| rec.registered_country.and_then(|c| c.iso));
            if let Some(code) = code {
                println!("{}", code);
                return Ok(());
            }
        }
        println!("unknown");
        return Ok(());
    }

    // Fallback: text DB
    let db = sb_core::router::geo::GeoIpDb::load_from_file(path)
        .with_context(|| format!("open geoip file: {}", path.display()))?;
    match db.lookup_country(ip) {
        Some(code) => println!("{}", code),
        None => println!("unknown"),
    }
    Ok(())
}

fn is_public_addr(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            // RFC1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
            if o[0] == 10
                || (o[0] == 172 && (16..=31).contains(&o[1]))
                || (o[0] == 192 && o[1] == 168)
            {
                return false;
            }
            // loopback 127.0.0.0/8
            if o[0] == 127 {
                return false;
            }
            // link-local 169.254.0.0/16
            if o[0] == 169 && o[1] == 254 {
                return false;
            }
            true
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() || v6.is_unique_local() || v6.is_multicast()
            {
                return false;
            }
            true
        }
    }
}

async fn geoip_export(path: &PathBuf, country: &str, output: &str) -> Result<()> {
    // MMDB path: iterate all networks for sing-geoip and extract CIDRs for given country code
    if let Ok(reader) = maxminddb::Reader::open_readfile(path) {
        let target = country.to_lowercase();
        let mut cidrs: Vec<String> = Vec::new();
        // Iterate both IPv4 and IPv6 spaces
        for net_str in ["0.0.0.0/0", "::/0"] {
            let net: ipnetwork::IpNetwork = net_str.parse().unwrap();
            let iter = reader
                .within::<String>(net)
                .map_err(|e| anyhow::anyhow!("mmdb within failed: {}", e))?;
            for next in iter {
                let item = next.map_err(|e| anyhow::anyhow!("mmdb iter error: {}", e))?;
                if item.info.to_lowercase() == target {
                    cidrs.push(item.ip_net.to_string());
                }
            }
        }
        if cidrs.is_empty() {
            anyhow::bail!("country code not found: {}", country);
        }
        cidrs.sort();
        cidrs.dedup();
        let headless = json!({ "ip_cidr": cidrs });
        let rules = json!([{ "type": "default", "default": headless }]);
        let out_json = json!({ "version": 2, "rules": rules });
        if output == "stdout" {
            println!("{}", serde_json::to_string_pretty(&out_json)?);
            return Ok(());
        }
        let out_path = if output == "geoip-<country>.json" {
            format!("geoip-{}.json", country)
        } else {
            output.to_string()
        };
        std::fs::write(
            &out_path,
            serde_json::to_string_pretty(&out_json)?.as_bytes(),
        )
        .with_context(|| format!("write {}", out_path))?;
        return Ok(());
    }

    // Fallback: text DB
    let db = sb_core::router::geo::GeoIpDb::load_from_file(path)
        .with_context(|| format!("open geoip file: {}", path.display()))?;
    let cidrs = db
        .export_country(country)
        .with_context(|| format!("export {}", country))?;
    if cidrs.is_empty() {
        anyhow::bail!("country code not found: {}", country);
    }
    let headless = json!({ "ip_cidr": cidrs });
    let rules = json!([{ "type": "default", "default": headless }]);
    let out_json = json!({ "version": 2, "rules": rules });
    if output == "stdout" {
        println!("{}", serde_json::to_string_pretty(&out_json)?);
        return Ok(());
    }
    let out_path = if output == "geoip-<country>.json" {
        format!("geoip-{}.json", country)
    } else {
        output.to_string()
    };
    std::fs::write(
        &out_path,
        serde_json::to_string_pretty(&out_json)?.as_bytes(),
    )
    .with_context(|| format!("write {}", out_path))?;
    Ok(())
}
