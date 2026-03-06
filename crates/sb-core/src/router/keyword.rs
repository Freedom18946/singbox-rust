//! 关键词索引：normalize + 可选 Aho-Corasick 构建
#[inline]
pub(crate) fn normalize_keyword(s: &str) -> String {
    s.trim().to_lowercase()
}

#[cfg(feature = "router_keyword_ac")]
#[derive(Clone, Debug)]
pub struct AcMatcher(pub(crate) aho_corasick::AhoCorasick);

#[cfg(feature = "router_keyword_ac")]
impl AcMatcher {
    #[inline]
    pub fn find(&self, haystack: &str) -> Option<aho_corasick::Match> {
        self.0.find(haystack)
    }
}

#[derive(Debug, Clone)]
pub struct Index {
    pub pats: Vec<String>,
    pub decs: Vec<String>,
    #[cfg(feature = "router_keyword_ac")]
    pub ac: Option<aho_corasick::AhoCorasick>,
}

use std::sync::Arc;

/// 读取 ENV 决定是否启用 AC（在 router_keyword_ac 打开时才生效）
pub fn should_enable_ac(count: usize) -> bool {
    let th = keyword_ac_min_from_env();
    count >= th
}

fn parse_keyword_ac_min_env(value: Option<&str>) -> Result<usize, Arc<str>> {
    match value {
        Some(raw) => raw.parse::<usize>().map_err(|err| {
            format!(
                "router env 'SB_ROUTER_KEYWORD_AC_MIN' value '{raw}' is invalid; silent parse fallback is disabled; fix the config explicitly: {err}"
            )
            .into()
        }),
        None => Ok(64),
    }
}

fn keyword_ac_min_from_env() -> usize {
    let raw = std::env::var("SB_ROUTER_KEYWORD_AC_MIN").ok();
    match parse_keyword_ac_min_env(raw.as_deref()) {
        Ok(val) => val,
        Err(reason) => {
            tracing::warn!("{reason}; using default 64");
            64
        }
    }
}

impl Index {
    pub fn is_empty(&self) -> bool {
        self.pats.is_empty()
    }
    pub fn len(&self) -> usize {
        self.pats.len()
    }
    pub fn find_idx(&self, hay: &str) -> Option<usize> {
        #[cfg(feature = "router_keyword_ac")]
        if let Some(ac) = &self.ac {
            if let Some(m) = ac.find(hay) {
                return Some(m.pattern().as_usize());
            }
        }
        for (i, kw) in self.pats.iter().enumerate() {
            if hay.contains(kw) {
                return Some(i);
            }
        }
        None
    }
}

pub(crate) fn build_index<'a, I>(pairs: I) -> Option<Index>
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    let mut pats = Vec::new();
    let mut decs = Vec::new();
    for (k, v) in pairs {
        pats.push(normalize_keyword(k));
        decs.push(v.to_string());
    }
    if pats.is_empty() {
        return None;
    }
    #[cfg(feature = "router_keyword_ac")]
    {
        let ac = if should_enable_ac(pats.len()) {
            aho_corasick::AhoCorasick::new(&pats).ok()
        } else {
            None
        };
        Some(Index { pats, decs, ac })
    }
    #[cfg(not(feature = "router_keyword_ac"))]
    {
        return Some(Index { pats, decs });
    }
}

#[cfg(test)]
mod tests {
    use super::parse_keyword_ac_min_env;

    #[test]
    fn invalid_keyword_ac_min_env_reports_explicitly() {
        let err = parse_keyword_ac_min_env(Some("bad-min"))
            .expect_err("invalid keyword ac min env should be rejected explicitly");
        let msg = err.to_string();
        assert!(msg.contains("SB_ROUTER_KEYWORD_AC_MIN"));
        assert!(msg.contains("silent parse fallback is disabled"));
    }
}
