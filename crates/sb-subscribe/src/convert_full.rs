//! R100: Aggregates subscription into {dsl, view_json, bindings_json, hashes} (minijson).
//! [Chinese] R100: 将订阅文本聚合为 {dsl, view_json, bindings_json, hashes}（minijson）。
//!
//!   - Dependencies: subs_full (internally enables subs_view + subs_bindings), optional subs_hash for blake3.
//!   - [Chinese] 依赖：subs_full（内部启用 subs_view + subs_bindings），可选 subs_hash 计算 blake3。
use crate::model::Profile;
use sb_core::router::minijson::{obj, Val};

/// Average estimated line length for DSL generation
const ESTIMATED_LINE_LENGTH: usize = 50;

/// Hash result container
struct HashResult {
    hex: String,
    enabled: bool,
}

impl HashResult {
    fn new(hex: Option<String>) -> Self {
        match hex {
            Some(h) => Self {
                hex: h,
                enabled: true,
            },
            None => Self {
                hex: "disabled".to_string(),
                enabled: false,
            },
        }
    }

    fn as_str(&self) -> &str {
        &self.hex
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }
}

#[inline]
fn b3_hex_opt(s: &str) -> Option<String> {
    #[cfg(feature = "subs_hash")]
    {
        use blake3::Hasher;
        let mut h = Hasher::new();
        h.update(s.as_bytes());
        Some(h.finalize().to_hex().to_string())
    }
    #[cfg(not(feature = "subs_hash"))]
    {
        let _ = s; // Silence unused variable warning
        None
    }
}

/// Converts Profile to DSL text (line by line), optionally normalizing.
/// [Chinese] 将 Profile -> DSL 文本（逐行拼接），可选 normalize。
fn profile_to_dsl(p: &Profile, normalize: bool) -> String {
    let estimated_capacity = p.rules.len() * ESTIMATED_LINE_LENGTH;
    let mut s = String::with_capacity(estimated_capacity);
    for r in &p.rules {
        s.push_str(&r.line);
        s.push('\n');
    }
    if normalize {
        sb_core::router::rules_normalize(&s)
    } else {
        s
    }
}

/// Convert use_keyword flag to mode string
#[inline]
const fn mode_str(use_keyword: bool) -> &'static str {
    if use_keyword {
        "keyword"
    } else {
        "suffix"
    }
}

/// Parse profile from input based on format
fn parse_profile(input: &str, format: &str, use_keyword: bool) -> Result<Profile, String> {
    match format {
        "clash" => {
            #[cfg(feature = "subs_clash")]
            {
                crate::parse_clash::parse_with_mode(input, use_keyword)
                    .map_err(|e| format!("clash parse error: {e:?}"))
            }
            #[cfg(not(feature = "subs_clash"))]
            {
                let _ = (input, use_keyword); // Silence unused warnings
                Err("format clash disabled".to_string())
            }
        }
        "singbox" | "sing-box" => {
            #[cfg(feature = "subs_singbox")]
            {
                crate::parse_singbox::parse_with_mode(input, use_keyword)
                    .map_err(|e| format!("singbox parse error: {e:?}"))
            }
            #[cfg(not(feature = "subs_singbox"))]
            {
                let _ = (input, use_keyword); // Silence unused warnings
                Err("format singbox disabled".to_string())
            }
        }
        _ => Err(format!("unknown format: {format}")),
    }
}

/// Generate view JSON
#[inline]
fn generate_view(prof: &Profile) -> String {
    #[cfg(feature = "subs_view")]
    {
        crate::convert_view::view_minijson(prof)
    }
    #[cfg(not(feature = "subs_view"))]
    {
        let _ = prof; // Silence unused warning
        "{}".to_string()
    }
}

/// Generate bindings JSON
#[inline]
fn generate_bindings(prof: &Profile) -> String {
    #[cfg(feature = "subs_bindings")]
    {
        crate::bindings::bindings_minijson(prof)
    }
    #[cfg(not(feature = "subs_bindings"))]
    {
        let _ = prof; // Silence unused warning
        "{\"outbounds\":[]}".to_string()
    }
}

/// Core aggregation: returns a minijson object string.
/// [Chinese] 核心聚合：返回 minijson 对象字符串。
///
/// Pipeline: Parse -> DSL -> View -> Bindings -> Hash -> JSON.
/// [Chinese] 流程：解析 -> DSL -> 视图 -> 绑定 -> 哈希 -> JSON。
pub fn convert_full_minijson(
    input: &str,
    format: &str,
    use_keyword: bool,
    normalize: bool,
) -> Result<String, String> {
    // 1) Parse to Profile
    // [Chinese] 1) 解析为 Profile
    let prof = parse_profile(input, format, use_keyword)?;

    // 2) Generate DSL
    // [Chinese] 2) 生成 DSL
    let dsl = profile_to_dsl(&prof, normalize);

    // 3) View and Bindings
    // [Chinese] 3) 视图与绑定
    let view = generate_view(&prof);
    let bindings = generate_bindings(&prof);

    // 4) Hash (optional, cache result to avoid re-computation)
    // [Chinese] 4) 哈希（可选，缓存结果避免重复计算）
    let hash_result = HashResult::new(b3_hex_opt(&dsl));

    // 5) Assemble minijson
    // [Chinese] 5) 拼装 minijson
    Ok(obj([
        ("ok", Val::Bool(true)),
        ("format", Val::Str(format)),
        ("mode", Val::Str(mode_str(use_keyword))),
        ("normalized", Val::Bool(normalize)),
        ("dsl", Val::Str(&dsl)),
        ("dsl_hash", Val::Str(hash_result.as_str())),
        ("view", Val::Raw(&view)),
        ("bindings", Val::Raw(&bindings)),
        (
            "meta",
            Val::Raw(&obj([
                ("hashes", Val::Bool(hash_result.is_enabled())),
                ("ordered", Val::Bool(false)),
                ("normalized", Val::Bool(normalize)),
            ])),
        ),
    ]))
}
