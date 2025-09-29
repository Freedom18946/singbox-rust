use anyhow::Result;
use sb_config::ir::{RouteIR, RuleIR};
use std::net::IpAddr;

/// Compiled port range [start, end]
#[derive(Clone, Copy, Debug)]
struct PortRange(u16, u16);

#[derive(Clone, Debug, Default)]
struct CompiledRule {
    outbound: Option<String>,
    domains: Vec<String>,
    ipcidr: Vec<ipnet::IpNet>,
    ports: Vec<PortRange>,
    networks: Vec<String>, // "tcp"/"udp"
}

impl CompiledRule {
    fn from_ir(r: &RuleIR) -> Self {
        let mut ports = Vec::new();
        for p in &r.port {
            if let Some(pr) = parse_port_expr(p) {
                ports.push(pr);
            }
        }
        let mut cidrs = Vec::new();
        for c in &r.ipcidr {
            if let Ok(net) = c.parse::<ipnet::IpNet>() {
                cidrs.push(net);
            }
        }
        Self {
            outbound: r.outbound.clone(),
            domains: r.domain.clone(),
            ipcidr: cidrs,
            ports,
            networks: r.network.clone(),
        }
    }

    fn matches(
        &self,
        host: Option<&str>,
        ip: Option<IpAddr>,
        port: Option<u16>,
        network: Option<&str>,
    ) -> bool {
        // Network filter
        if !self.networks.is_empty() {
            if let Some(n) = network {
                if !self.networks.iter().any(|x| x.eq_ignore_ascii_case(n)) {
                    return false;
                }
            } else {
                return false;
            }
        }
        // Port filter
        if !self.ports.is_empty() {
            if let Some(p) = port {
                if !self.ports.iter().any(|pr| p >= pr.0 && p <= pr.1) {
                    return false;
                }
            } else {
                return false;
            }
        }
        // IP/CIDR filter
        if !self.ipcidr.is_empty() {
            if let Some(ipaddr) = ip {
                if !self.ipcidr.iter().any(|n| n.contains(&ipaddr)) {
                    return false;
                }
            } else {
                return false;
            }
        }
        // Domain filter (exact or suffix)
        if !self.domains.is_empty() {
            if let Some(h) = host {
                let h_lc = h.to_ascii_lowercase();
                let mut ok = false;
                for d in &self.domains {
                    let d = d.to_ascii_lowercase();
                    if h_lc == d || h_lc.ends_with(&format!(".{d}")) {
                        ok = true;
                        break;
                    }
                }
                if !ok {
                    return false;
                }
            } else {
                return false;
            }
        }
        true
    }
}

#[derive(Default, Debug)]
pub struct Matcher {
    rules: Vec<CompiledRule>,
    default: Option<String>,
}

impl Matcher {
    pub fn new() -> Self {
        Self::default()
    }

    /// Compile RouteIR into an internal matcher structure
    pub fn update(&mut self, route: &RouteIR) -> Result<()> {
        self.rules.clear();
        self.default = route.default.clone();
        for r in &route.rules {
            self.rules.push(CompiledRule::from_ir(r));
        }
        tracing::info!(target = "sb_core::routing::matcher", default = ?self.default, rules = self.rules.len(), "matcher updated");
        Ok(())
    }

    /// Decide an outbound name by target attributes
    pub fn decide(
        &self,
        host: Option<&str>,
        ip: Option<IpAddr>,
        port: Option<u16>,
        network: Option<&str>,
    ) -> Option<&str> {
        for r in &self.rules {
            if r.matches(host, ip, port, network) {
                if let Some(out) = &r.outbound {
                    return Some(out.as_str());
                }
            }
        }
        self.default.as_deref()
    }
}

fn parse_port_expr(s: &str) -> Option<PortRange> {
    if let Some((a, b)) = s.split_once('-') {
        let a = a.trim().parse::<u16>().ok()?;
        let b = b.trim().parse::<u16>().ok()?;
        Some(PortRange(a.min(b), a.max(b)))
    } else {
        let p = s.trim().parse::<u16>().ok()?;
        Some(PortRange(p, p))
    }
}
