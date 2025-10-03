#[derive(Default, Debug)]
pub struct SuffixTrie {
    nodes: Vec<Node>,
}

#[derive(Default, Clone, Debug)]
struct Node {
    next: std::collections::HashMap<u8, usize>,
    /// 命中时的决策
    decision: Option<&'static str>,
}

impl SuffixTrie {
    pub fn new() -> Self {
        Self {
            nodes: vec![Node::default()],
        }
    }
    fn add_bytes(&mut self, rev: &[u8], dec: &'static str) {
        let mut cur = 0usize;
        for &b in rev {
            let nxt = if let Some(&id) = self.nodes[cur].next.get(&b) {
                id
            } else {
                let id = self.nodes.len();
                self.nodes[cur].next.insert(b, id);
                self.nodes.push(Node::default());
                id
            };
            cur = nxt;
        }
        self.nodes[cur].decision = Some(dec);
    }
    pub fn insert_suffix(&mut self, dom: &str, dec: &'static str) {
        let mut v = dom.as_bytes().to_vec();
        v.reverse();
        self.add_bytes(&v, dec);
    }

    /// Insert a domain suffix with a default decision marker
    pub fn insert(&mut self, suffix: &str) {
        self.insert_suffix(suffix, "match");
    }

    /// Check if a domain matches any inserted suffix
    pub fn contains(&self, domain: &str) -> bool {
        self.query(domain).is_some()
    }

    pub fn query(&self, host: &str) -> Option<&'static str> {
        let mut best: Option<&'static str> = None;
        let mut cur = 0usize;
        for &b in host.as_bytes().iter().rev() {
            if let Some(&id) = self.nodes[cur].next.get(&b) {
                cur = id;
            } else {
                break;
            }
            if let Some(d) = self.nodes[cur].decision {
                best = Some(d);
            }
        }
        best
    }
}
