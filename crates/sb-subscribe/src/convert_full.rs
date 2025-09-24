//! R100: 将订阅文本聚合为 {dsl, view_json, bindings_json, hashes}（minijson）
//! - 依赖：subs_full（内部启用 subs_view + subs_bindings），可选 subs_hash 计算 blake3
use crate::model::Profile;
use sb_core::router::minijson::{obj, Val};

#[inline]
fn b3_hex_opt(s: &str) -> Option<String> {
    #[cfg(feature = "subs_hash")]
    {
        use blake3::Hasher;
        let mut h = Hasher::new();
        h.update(s.as_bytes());
        return Some(h.finalize().to_hex().to_string());
    }
    #[allow(unreachable_code)]
    None
}

/// 将 Profile -> DSL 文本（逐行拼接），可选 normalize
fn profile_to_dsl(p: &Profile, normalize: bool) -> String {
    let mut s = String::new();
    for r in &p.rules {
        s.push_str(r.line.as_str());
        s.push('\n');
    }
    if normalize {
        return sb_core::router::rules_normalize(&s);
    }
    s
}

/// 核心聚合：返回 minijson 对象字符串
pub fn convert_full_minijson(
    input: &str,
    format: &str,
    use_keyword: bool,
    normalize: bool,
) -> Result<String, String> {
    // 1) 解析为 Profile
    let prof: Profile = match format {
        "clash" => {
            #[cfg(feature = "subs_clash")]
            {
                crate::parse_clash::parse_with_mode(input, use_keyword)
                    .map_err(|e| format!("{:?}", e))?
            }
            #[cfg(not(feature = "subs_clash"))]
            {
                return Err("format clash disabled".into());
            }
        }
        "singbox" | "sing-box" => {
            #[cfg(feature = "subs_singbox")]
            {
                crate::parse_singbox::parse_with_mode(input, use_keyword)
                    .map_err(|e| format!("{:?}", e))?
            }
            #[cfg(not(feature = "subs_singbox"))]
            {
                return Err("format singbox disabled".into());
            }
        }
        _ => return Err("unknown format".into()),
    };

    // 2) 生成 DSL
    let dsl = profile_to_dsl(&prof, normalize);

    // 3) 视图与绑定
    let view = {
        #[cfg(feature = "subs_view")]
        {
            crate::convert_view::view_minijson(&prof)
        }
        #[cfg(not(feature = "subs_view"))]
        {
            "{}".to_string()
        }
    };
    let bindings = {
        #[cfg(feature = "subs_bindings")]
        {
            crate::bindings::bindings_minijson(&prof)
        }
        #[cfg(not(feature = "subs_bindings"))]
        {
            "{\"outbounds\":[]}".to_string()
        }
    };

    // 4) 哈希（可选）
    let dsl_hash = b3_hex_opt(&dsl).unwrap_or_else(|| "disabled".into());

    // 5) 拼装 minijson
    Ok(obj([
        ("ok", Val::Bool(true)),
        ("format", Val::Str(format)),
        (
            "mode",
            Val::Str(if use_keyword { "keyword" } else { "suffix" }),
        ),
        ("normalized", Val::Bool(normalize)),
        ("dsl", Val::Str(&dsl)),
        ("dsl_hash", Val::Str(&dsl_hash)),
        ("view", Val::Raw(&view)),
        ("bindings", Val::Raw(&bindings)),
        (
            "meta",
            Val::Raw(&obj([
                ("hashes", Val::Bool(b3_hex_opt(&dsl).is_some())),
                ("ordered", Val::Bool(false)),
                ("normalized", Val::Bool(normalize)),
            ])),
        ),
    ]))
}
