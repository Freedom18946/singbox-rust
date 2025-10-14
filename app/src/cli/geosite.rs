//! Geosite tooling subcommand (parity with sing-box `geosite`)

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde_json::json;
use std::io::Read as _;
use std::path::PathBuf;

// Type alias for compatibility with local code
type GeoRules = sb_core::router::geo::CategoryRules;

#[derive(Parser, Debug)]
#[command(name = "geosite")]
#[command(about = "Geosite tools", long_about = None)]
pub struct GeositeArgs {
    /// Geosite database file (text or binary)
    #[arg(short = 'f', long = "file", default_value = "geosite.db")]
    pub file: PathBuf,

    #[command(subcommand)]
    pub command: GeositeCmd,
}

#[derive(Subcommand, Debug)]
pub enum GeositeCmd {
    /// List geosite categories (sorted by rule count)
    List,
    /// Check if domain is in geosite (optional category)
    Lookup {
        /// Optional category
        category: Option<String>,
        /// Domain to check
        domain: String,
    },
    /// Export category as rule-set JSON (stdout or file)
    Export {
        /// Category to export
        category: String,
        /// Output path (use "stdout" for standard output)
        #[arg(
            short = 'o',
            long = "output",
            default_value = "geosite-<category>.json"
        )]
        output: String,
    },
    /// Test matcher: read domains from stdin and print first match per line
    Matcher {
        /// Category to match (use existing category name)
        category: String,
    },
}

pub async fn run(args: GeositeArgs) -> Result<()> {
    match args.command {
        GeositeCmd::List => geosite_list(&args.file).await,
        GeositeCmd::Lookup { category, domain } => {
            geosite_lookup(&args.file, category, domain).await
        }
        GeositeCmd::Export { category, output } => {
            geosite_export(&args.file, &category, &output).await
        }
        GeositeCmd::Matcher { category } => geosite_matcher(&args.file, &category).await,
    }
}

async fn geosite_list(path: &PathBuf) -> Result<()> {
    if let Ok(bin) = GeositeBin::parse(path) {
        let mut entries: Vec<(String, usize)> = bin
            .meta
            .iter()
            .map(|m| (m.code.clone(), m.length))
            .collect();
        entries.sort_by_key(|(_, n)| *n);
        for (cat, n) in entries {
            println!("{} ({})", cat, n);
        }
        return Ok(());
    }

    let db = sb_core::router::geo::GeoSiteDb::load_from_file(path)
        .with_context(|| format!("open geosite file: {}", path.display()))?;
    let mut entries: Vec<(String, usize)> = db
        .available_categories()
        .into_iter()
        .map(|c| (c.clone(), db.category_rule_count(&c)))
        .collect();
    entries.sort_by_key(|(_, n)| *n);
    for (cat, n) in entries {
        println!("{} ({})", cat, n);
    }
    Ok(())
}

async fn geosite_lookup(path: &PathBuf, category: Option<String>, domain: String) -> Result<()> {
    // Prefer binary parser if available
    if let Ok(bin) = GeositeBin::parse(path) {
        let mut cats: Vec<String> = match category {
            Some(c) => vec![c],
            None => bin.meta.iter().map(|m| m.code.clone()).collect(),
        };
        cats.sort();
        for cat in cats {
            if let Some(rule) = bin.first_match(&cat, &domain)? {
                use sb_core::router::geo::DomainRule;
                let desc = match rule {
                    DomainRule::Exact(_) => format!("domain={}", domain),
                    DomainRule::Suffix(s) => format!("domain_suffix={}", s),
                    DomainRule::Keyword(k) => format!("domain_keyword={}", k),
                    DomainRule::Regex(r) => format!("domain_regex={}", r),
                };
                println!("Match code ({}) {}", cat, desc);
            }
        }
        return Ok(());
    }

    use sb_core::router::geo::GeoSiteDb;
    let db = GeoSiteDb::load_from_file(path)
        .with_context(|| format!("open geosite file: {}", path.display()))?;
    let mut cats: Vec<String> = match category {
        Some(c) => vec![c],
        None => db.available_categories(),
    };
    cats.sort();
    for cat in cats {
        if let Some(rule) = first_match_rule_from_file(path, &cat, &domain)? {
            use sb_core::router::geo::DomainRule;
            let desc = match rule {
                DomainRule::Exact(_) => format!("domain={}", domain),
                DomainRule::Suffix(s) => format!("domain_suffix={}", s),
                DomainRule::Keyword(k) => format!("domain_keyword={}", k),
                DomainRule::Regex(r) => format!("domain_regex={}", r),
            };
            println!("Match code ({}) {}", cat, desc);
        }
    }
    Ok(())
}

fn first_match_rule_from_file(
    path: &PathBuf,
    category: &str,
    domain: &str,
) -> Result<Option<sb_core::router::geo::DomainRule>> {
    use sb_core::router::geo::DomainRule;
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    // Priority: exact -> suffix -> keyword -> regex
    let mut best: Option<DomainRule> = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.splitn(3, ':').collect();
        if parts.len() != 3 {
            continue;
        }
        let cat = parts[0].trim().to_lowercase();
        if cat != category.to_lowercase() {
            continue;
        }
        let rule_type = parts[1].trim().to_lowercase();
        let pattern = parts[2].trim();
        match rule_type.as_str() {
            "exact" => {
                if domain.eq_ignore_ascii_case(pattern) {
                    return Ok(Some(DomainRule::Exact(pattern.to_string())));
                }
            }
            "suffix" => {
                let pat = pattern.trim_start_matches('.');
                if domain.eq_ignore_ascii_case(pat)
                    || domain
                        .to_lowercase()
                        .ends_with(&format!(".{}", pat.to_lowercase()))
                {
                    if best.is_none() {
                        best = Some(DomainRule::Suffix(pattern.to_string()));
                    }
                }
            }
            "keyword" => {
                if domain.to_lowercase().contains(&pattern.to_lowercase()) {
                    // prefer longer keyword if multiple
                    match &best {
                        Some(DomainRule::Keyword(k)) if k.len() >= pattern.len() => {}
                        Some(DomainRule::Exact(_)) => {}
                        Some(DomainRule::Suffix(_)) => {}
                        _ => best = Some(DomainRule::Keyword(pattern.to_string())),
                    }
                }
            }
            "regex" => {
                // Treat regex as substring test for now
                if domain.to_lowercase().contains(&pattern.to_lowercase()) {
                    if best.is_none() {
                        best = Some(DomainRule::Regex(pattern.to_string()));
                    }
                }
            }
            _ => {}
        }
    }
    Ok(best)
}

async fn geosite_export(path: &PathBuf, category: &str, output: &str) -> Result<()> {
    if let Ok(bin) = GeositeBin::parse(path) {
        let rules = bin.read_category_rules(category)?;
        return write_ruleset_json(output, category, rules);
    }
    // Text fallback
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let mut domain: Vec<String> = Vec::new();
    let mut domain_suffix: Vec<String> = Vec::new();
    let mut domain_keyword: Vec<String> = Vec::new();
    let mut domain_regex: Vec<String> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.splitn(3, ':').collect();
        if parts.len() != 3 {
            continue;
        }
        let cat = parts[0].trim().to_lowercase();
        if cat != category.to_lowercase() {
            continue;
        }
        let rule_type = parts[1].trim().to_lowercase();
        let pattern = parts[2].trim().to_string();
        match rule_type.as_str() {
            "exact" => domain.push(pattern),
            "suffix" => domain_suffix.push(pattern),
            "keyword" => domain_keyword.push(pattern),
            "regex" => domain_regex.push(pattern),
            _ => {}
        }
    }
    let rules = GeoRules {
        domain,
        domain_suffix,
        domain_keyword,
        domain_regex,
    };
    write_ruleset_json(output, category, rules)
}

async fn geosite_matcher(path: &PathBuf, category: &str) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, BufReader};

    if let Ok(bin) = GeositeBin::parse(path) {
        let rules = bin.read_category_rules(category)?;
        let stdin = BufReader::new(tokio::io::stdin());
        tokio::pin!(stdin);
        let mut lines = stdin.lines();
        while let Some(line) = lines.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }
            match match_domain(&rules, &line) {
                Some(desc) => println!("{}\t{}", line, desc),
                None => println!("{}\t(no match)", line),
            }
        }
        return Ok(());
    }

    let db = sb_core::router::geo::GeoSiteDb::load_from_file(path)
        .with_context(|| format!("open geosite file: {}", path.display()))?;
    let rules = db
        .category_rules(category)
        .with_context(|| format!("category {}", category))?;
    let stdin = BufReader::new(tokio::io::stdin());
    tokio::pin!(stdin);
    let mut lines = stdin.lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        match match_domain(&rules, &line) {
            Some(desc) => println!("{}\t{}", line, desc),
            None => println!("{}\t(no match)", line),
        }
    }
    Ok(())
}

fn match_domain(rules: &GeoRules, domain: &str) -> Option<String> {
    for d in &rules.domain {
        if domain.eq_ignore_ascii_case(d) {
            return Some(format!("domain={}", d));
        }
    }
    for s in &rules.domain_suffix {
        let pat = s.trim_start_matches('.');
        if domain.eq_ignore_ascii_case(pat)
            || domain
                .to_lowercase()
                .ends_with(&format!(".{}", pat.to_lowercase()))
        {
            return Some(format!("domain_suffix={}", s));
        }
    }
    for k in &rules.domain_keyword {
        if domain.to_lowercase().contains(&k.to_lowercase()) {
            return Some(format!("domain_keyword={}", k));
        }
    }
    for r in &rules.domain_regex {
        if domain.to_lowercase().contains(&r.to_lowercase()) {
            return Some(format!("domain_regex={}", r));
        }
    }
    None
}

fn write_ruleset_json(output: &str, category: &str, rules: GeoRules) -> Result<()> {
    let rule_json = json!([{
        "type": "field",
        "domain": rules.domain,
        "domain_suffix": rules.domain_suffix,
        "domain_keyword": rules.domain_keyword,
        "domain_regex": rules.domain_regex,
        "outbound": format!("geosite-{}", category),
    }]);
    let out_json = json!({ "version": 2, "rules": rule_json });
    if output == "stdout" {
        println!("{}", serde_json::to_string_pretty(&out_json)?);
        return Ok(());
    }
    let out_path = if output == "geosite-<category>.json" {
        format!("geosite-{}.json", category)
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

// ---- Binary geosite (.db) minimal reader ----

struct GeositeBinMeta {
    code: String,
    index: usize,
    length: usize,
}
struct GeositeBin {
    data: Vec<u8>,
    content_start: usize,
    meta: Vec<GeositeBinMeta>,
}

impl GeositeBin {
    fn parse(path: &PathBuf) -> Result<Self> {
        let mut f =
            std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
        let mut data = Vec::new();
        f.read_to_end(&mut data).context("read geosite db")?;
        let mut cur = 0usize;
        // version
        if data.len() < 1 {
            anyhow::bail!("invalid geosite db: short");
        }
        let version = data[0];
        cur += 1;
        if version != 0 {
            anyhow::bail!("unsupported geosite version: {}", version);
        }
        // entry length
        let (entry_len, n) = read_uvarint(&data[cur..])?;
        cur += n;
        let mut meta = Vec::with_capacity(entry_len as usize);
        for _ in 0..entry_len {
            let (code, ncode) = read_varbin_string(&data[cur..])?;
            cur += ncode;
            let (idx, ni) = read_uvarint(&data[cur..])?;
            cur += ni;
            let (len, nl) = read_uvarint(&data[cur..])?;
            cur += nl;
            meta.push(GeositeBinMeta {
                code,
                index: idx as usize,
                length: len as usize,
            });
        }
        let content_start = cur;
        Ok(Self {
            data,
            content_start,
            meta,
        })
    }

    fn read_category_rules(&self, category: &str) -> Result<GeoRules> {
        let cat = category.to_lowercase();
        let meta = self
            .meta
            .iter()
            .find(|m| m.code == cat)
            .ok_or_else(|| anyhow::anyhow!("category not found: {}", category))?;
        let mut off = self.content_start + meta.index;
        let mut domain = Vec::new();
        let mut domain_suffix = Vec::new();
        let mut domain_keyword = Vec::new();
        let mut domain_regex = Vec::new();
        for _ in 0..meta.length {
            // item: u8 type + varbin string value
            if off >= self.data.len() {
                anyhow::bail!("truncated items");
            }
            let typ = self.data[off];
            off += 1;
            let (val, nv) = read_varbin_string(&self.data[off..])?;
            off += nv;
            match typ {
                0 => domain.push(val),
                1 => domain_suffix.push(val),
                2 => domain_keyword.push(val),
                3 => domain_regex.push(val),
                _ => {}
            }
        }
        Ok(GeoRules {
            domain,
            domain_suffix,
            domain_keyword,
            domain_regex,
        })
    }

    fn first_match(
        &self,
        category: &str,
        domain_name: &str,
    ) -> Result<Option<sb_core::router::geo::DomainRule>> {
        let rules = self.read_category_rules(category)?;
        use sb_core::router::geo::DomainRule;
        // exact
        if rules
            .domain
            .iter()
            .any(|d| domain_name.eq_ignore_ascii_case(d))
        {
            return Ok(Some(DomainRule::Exact(domain_name.to_string())));
        }
        // suffix
        for s in &rules.domain_suffix {
            let pat = s.trim_start_matches('.');
            if domain_name.eq_ignore_ascii_case(pat)
                || domain_name
                    .to_lowercase()
                    .ends_with(&format!(".{}", pat.to_lowercase()))
            {
                return Ok(Some(DomainRule::Suffix(s.clone())));
            }
        }
        // keyword
        for k in &rules.domain_keyword {
            if domain_name.to_lowercase().contains(&k.to_lowercase()) {
                return Ok(Some(DomainRule::Keyword(k.clone())));
            }
        }
        // regex (treated as substring)
        for r in &rules.domain_regex {
            if domain_name.to_lowercase().contains(&r.to_lowercase()) {
                return Ok(Some(DomainRule::Regex(r.clone())));
            }
        }
        Ok(None)
    }
}

fn read_uvarint(data: &[u8]) -> Result<(u64, usize)> {
    let mut x: u64 = 0;
    let mut s: u32 = 0;
    for (i, b) in data.iter().copied().enumerate() {
        if b < 0x80 {
            return Ok((x | ((b as u64) << s), i + 1));
        }
        x |= ((b & 0x7F) as u64) << s;
        s += 7;
        if s >= 64 {
            anyhow::bail!("uvarint overflow");
        }
    }
    anyhow::bail!("buffer too short for uvarint");
}

fn read_varbin_string(data: &[u8]) -> Result<(String, usize)> {
    let (len, n) = read_uvarint(data)?;
    let start = n;
    let end = start + len as usize;
    if end > data.len() {
        anyhow::bail!("string overflow");
    }
    let s = std::str::from_utf8(&data[start..end]).context("invalid utf8")?;
    Ok((s.to_string(), end))
}
