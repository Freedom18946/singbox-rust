use super::Provider;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;

#[derive(Clone, Debug)]
struct Net4 {
    net: u32,
    mask: u32,
}
#[derive(Clone, Debug)]
struct Net6 {
    net: u128,
    mask: u128,
}

pub struct CidrDb {
    v4: HashMap<String, Vec<Net4>>, // CC -> nets
    v6: HashMap<String, Vec<Net6>>, // CC -> nets
    // Map from country code to static decision
    cc_map: HashMap<String, &'static str>,
}

impl CidrDb {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let f = File::open(path)?;
        let r = BufReader::new(f);
        let mut v4: HashMap<String, Vec<Net4>> = HashMap::new();
        let mut v6: HashMap<String, Vec<Net6>> = HashMap::new();
        for line in r.lines() {
            let line = line.unwrap_or_default();
            let s = line.trim();
            if s.is_empty() || s.starts_with('#') {
                continue;
            }
            let Some((cidr, cc)) = s.split_once(',') else {
                continue;
            };
            let cc = cc.trim().to_ascii_uppercase();
            if let Some((ip, plen)) = cidr.trim().split_once('/') {
                if let Ok(bits) = plen.parse::<u32>() {
                    if let Ok(addr) = ip.parse::<IpAddr>() {
                        match addr {
                            IpAddr::V4(v4ip) => {
                                if bits <= 32 {
                                    let mask = if bits == 0 { 0 } else { (!0u32) << (32 - bits) };
                                    v4.entry(cc).or_default().push(Net4 {
                                        net: u32::from(v4ip) & mask,
                                        mask,
                                    });
                                }
                            }
                            IpAddr::V6(v6ip) => {
                                if bits <= 128 {
                                    let mask: u128 = if bits == 0 {
                                        0
                                    } else {
                                        (!0u128) << (128 - bits)
                                    };
                                    v6.entry(cc).or_default().push(Net6 {
                                        net: u128::from(v6ip) & mask,
                                        mask,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(Self {
            v4,
            v6,
            cc_map: HashMap::new(),
        })
    }

    pub fn with_cc_map(mut self, cc_map: HashMap<String, &'static str>) -> Self {
        self.cc_map = cc_map;
        self
    }

    fn lookup_cc(&self, ip: IpAddr) -> Option<String> {
        match ip {
            IpAddr::V4(v4ip) => {
                let x = u32::from(v4ip);
                for (cc, nets) in &self.v4 {
                    if nets.iter().any(|n| (x & n.mask) == n.net) {
                        return Some(cc.clone());
                    }
                }
                None
            }
            IpAddr::V6(v6ip) => {
                let x = u128::from(v6ip);
                for (cc, nets) in &self.v6 {
                    if nets.iter().any(|n| (x & n.mask) == n.net) {
                        return Some(cc.clone());
                    }
                }
                None
            }
        }
    }
}

impl Provider for CidrDb {
    fn lookup(&self, ip: IpAddr) -> Option<&'static str> {
        if let Some(cc) = self.lookup_cc(ip) {
            self.cc_map.get(&cc).copied()
        } else {
            None
        }
    }
}
