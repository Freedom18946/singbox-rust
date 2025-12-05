//! DNS rule actions for extended DNS routing.
//!
//! Provides additional DNS rule actions beyond simple upstream routing:
//! - Rewrite: Modify response records
//! - Reject: Return specific error codes
//! - Proxy: Route through specific outbound
//! - ClientSubnet: Add EDNS Client Subnet
//!
//! # Example
//! ```ignore
//! use sb_core::dns::rule_action::{DnsRuleAction, RewriteAction};
//!
//! let action = DnsRuleAction::Rewrite(RewriteAction {
//!     target: "example.com".to_string(),
//!     answer: Some("127.0.0.1".to_string()),
//! });
//! ```

use std::net::IpAddr;

/// DNS rule action types.
#[derive(Debug, Clone)]
pub enum DnsRuleAction {
    /// Route to specific upstream.
    Upstream(String),
    /// Rewrite the response.
    Rewrite(RewriteAction),
    /// Reject with specific code.
    Reject(RejectAction),
    /// Route DNS through proxy outbound.
    Proxy(ProxyAction),
    /// Add EDNS Client Subnet.
    ClientSubnet(ClientSubnetAction),
    /// Return cached/predefined answer.
    PredefineAnswer(PredefineAnswerAction),
}

/// Rewrite action configuration.
#[derive(Debug, Clone, Default)]
pub struct RewriteAction {
    /// Rewrite domain target (CNAME-like).
    pub target: Option<String>,
    /// Fixed A/AAAA answer.
    pub answer: Option<String>,
    /// Fixed CNAME answer.
    pub cname: Option<String>,
    /// TTL override.
    pub ttl: Option<u32>,
}

impl RewriteAction {
    /// Create a rewrite that returns a fixed IP.
    pub fn fixed_ip(ip: impl Into<String>) -> Self {
        Self {
            answer: Some(ip.into()),
            ..Default::default()
        }
    }

    /// Create a rewrite that returns a CNAME.
    pub fn cname(target: impl Into<String>) -> Self {
        Self {
            cname: Some(target.into()),
            ..Default::default()
        }
    }
}

/// Reject action configuration.
#[derive(Debug, Clone)]
pub struct RejectAction {
    /// DNS response code.
    pub rcode: DnsRcode,
}

impl Default for RejectAction {
    fn default() -> Self {
        Self {
            rcode: DnsRcode::Refused,
        }
    }
}

/// DNS response codes for reject action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DnsRcode {
    /// No Error (0).
    NoError = 0,
    /// Format Error (1).
    FormErr = 1,
    /// Server Failure (2).
    ServFail = 2,
    /// Non-Existent Domain (3).
    NxDomain = 3,
    /// Not Implemented (4).
    NotImp = 4,
    /// Query Refused (5).
    Refused = 5,
}

impl RejectAction {
    /// Create NXDOMAIN reject.
    pub fn nxdomain() -> Self {
        Self { rcode: DnsRcode::NxDomain }
    }

    /// Create REFUSED reject.
    pub fn refused() -> Self {
        Self { rcode: DnsRcode::Refused }
    }

    /// Create SERVFAIL reject.
    pub fn servfail() -> Self {
        Self { rcode: DnsRcode::ServFail }
    }
}

/// Proxy action configuration.
#[derive(Debug, Clone)]
pub struct ProxyAction {
    /// Outbound tag to route DNS through.
    pub outbound: String,
    /// Upstream server to query through the proxy.
    pub upstream: Option<String>,
}

/// EDNS Client Subnet action.
#[derive(Debug, Clone)]
pub struct ClientSubnetAction {
    /// Client IP to use.
    pub client_ip: IpAddr,
    /// Prefix length for IPv4 (default: 24).
    pub prefix_v4: u8,
    /// Prefix length for IPv6 (default: 56).
    pub prefix_v6: u8,
}

impl Default for ClientSubnetAction {
    fn default() -> Self {
        Self {
            client_ip: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            prefix_v4: 24,
            prefix_v6: 56,
        }
    }
}

/// Predefined answer action.
#[derive(Debug, Clone)]
pub struct PredefineAnswerAction {
    /// A record answers.
    pub ipv4: Vec<std::net::Ipv4Addr>,
    /// AAAA record answers.
    pub ipv6: Vec<std::net::Ipv6Addr>,
    /// TTL for the answers.
    pub ttl: u32,
}

impl Default for PredefineAnswerAction {
    fn default() -> Self {
        Self {
            ipv4: vec![],
            ipv6: vec![],
            ttl: 300,
        }
    }
}

impl PredefineAnswerAction {
    /// Create with single IPv4.
    pub fn ipv4(ip: std::net::Ipv4Addr) -> Self {
        Self {
            ipv4: vec![ip],
            ..Default::default()
        }
    }

    /// Create with single IPv6.
    pub fn ipv6(ip: std::net::Ipv6Addr) -> Self {
        Self {
            ipv6: vec![ip],
            ..Default::default()
        }
    }

    /// Set TTL.
    pub fn with_ttl(mut self, ttl: u32) -> Self {
        self.ttl = ttl;
        self
    }
}

/// Apply a DNS rule action to a query.
pub fn apply_action(
    action: &DnsRuleAction,
    _domain: &str,
    _record_type: u16,
) -> ActionResult {
    match action {
        DnsRuleAction::Upstream(tag) => ActionResult::RouteUpstream(tag.clone()),
        DnsRuleAction::Rewrite(rewrite) => {
            if let Some(ref ip) = rewrite.answer {
                if let Ok(addr) = ip.parse::<IpAddr>() {
                    return ActionResult::FixedAnswer(vec![addr], rewrite.ttl.unwrap_or(300));
                }
            }
            if let Some(ref cname) = rewrite.cname {
                return ActionResult::Cname(cname.clone());
            }
            ActionResult::Continue
        }
        DnsRuleAction::Reject(reject) => ActionResult::Reject(reject.rcode),
        DnsRuleAction::Proxy(proxy) => ActionResult::Proxy(proxy.outbound.clone()),
        DnsRuleAction::ClientSubnet(_ecs) => {
            // ECS is applied during query, not as a result
            ActionResult::Continue
        }
        DnsRuleAction::PredefineAnswer(predef) => {
            let mut addrs: Vec<IpAddr> = predef.ipv4.iter().map(|ip| IpAddr::V4(*ip)).collect();
            addrs.extend(predef.ipv6.iter().map(|ip| IpAddr::V6(*ip)));
            ActionResult::FixedAnswer(addrs, predef.ttl)
        }
    }
}

/// Result of applying a DNS rule action.
#[derive(Debug, Clone)]
pub enum ActionResult {
    /// Continue to next rule or default.
    Continue,
    /// Route to specific upstream.
    RouteUpstream(String),
    /// Return fixed IP answers.
    FixedAnswer(Vec<IpAddr>, u32),
    /// Return CNAME.
    Cname(String),
    /// Reject with rcode.
    Reject(DnsRcode),
    /// Route through proxy outbound.
    Proxy(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rewrite_action() {
        let action = DnsRuleAction::Rewrite(RewriteAction::fixed_ip("127.0.0.1"));
        let result = apply_action(&action, "example.com", 1);
        
        match result {
            ActionResult::FixedAnswer(addrs, ttl) => {
                assert_eq!(addrs.len(), 1);
                assert_eq!(ttl, 300);
            }
            _ => panic!("Expected FixedAnswer"),
        }
    }

    #[test]
    fn test_reject_action() {
        let action = DnsRuleAction::Reject(RejectAction::nxdomain());
        let result = apply_action(&action, "blocked.com", 1);
        
        match result {
            ActionResult::Reject(rcode) => {
                assert_eq!(rcode, DnsRcode::NxDomain);
            }
            _ => panic!("Expected Reject"),
        }
    }

    #[test]
    fn test_predefine_answer() {
        let action = DnsRuleAction::PredefineAnswer(
            PredefineAnswerAction::ipv4(std::net::Ipv4Addr::new(1, 2, 3, 4))
                .with_ttl(600)
        );
        let result = apply_action(&action, "static.test", 1);
        
        match result {
            ActionResult::FixedAnswer(addrs, ttl) => {
                assert_eq!(addrs.len(), 1);
                assert_eq!(ttl, 600);
            }
            _ => panic!("Expected FixedAnswer"),
        }
    }
}
