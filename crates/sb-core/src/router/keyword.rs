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

/// Return whether Aho-Corasick should be enabled for the default threshold.
pub fn should_enable_ac(count: usize) -> bool {
    count >= 64
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
    build_index_with_threshold(pairs, 64)
}

pub(crate) fn build_index_with_threshold<'a, I>(pairs: I, _threshold: usize) -> Option<Index>
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
        let ac = if pats.len() >= _threshold {
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
