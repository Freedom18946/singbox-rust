//! Process-aware routing integration
//!
//! This module integrates process matching with the routing engine to enable
//! routing decisions based on the process that initiated the connection.

use crate::router::rules::{Decision, Engine, RouteCtx};
use sb_platform::process::{
    ConnectionInfo, ProcessInfo, ProcessMatchError, ProcessMatcher, Protocol,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Process-aware router that can make routing decisions based on process information
pub struct ProcessRouter {
    engine: Arc<RwLock<Engine>>,
    process_matcher: ProcessMatcher,
}

impl ProcessRouter {
    /// Create a new process-aware router
    pub fn new(engine: Engine) -> Result<Self, ProcessMatchError> {
        Ok(Self {
            engine: Arc::new(RwLock::new(engine)),
            process_matcher: ProcessMatcher::new()?,
        })
    }

    /// Make a routing decision with process information
    pub async fn decide_with_process(
        &self,
        domain: Option<&str>,
        ip: Option<std::net::IpAddr>,
        transport_udp: bool,
        port: Option<u16>,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Decision {
        // Try to get process information
        let (process_name, process_path) = match self
            .get_process_info(local_addr, remote_addr, transport_udp)
            .await
        {
            Ok(info) => (Some(info.name), Some(info.path)),
            Err(_) => (None, None), // Continue without process info if matching fails
        };

        // Create routing context with process information
        let ctx = RouteCtx {
            domain,
            ip,
            transport_udp,
            port,
            process_name: process_name.as_deref(),
            process_path: process_path.as_deref(),
        };

        // Make routing decision
        let engine = self.engine.read().await;
        engine.decide(&ctx)
    }

    /// Make a routing decision without process information (fallback)
    pub async fn decide_without_process(
        &self,
        domain: Option<&str>,
        ip: Option<std::net::IpAddr>,
        transport_udp: bool,
        port: Option<u16>,
    ) -> Decision {
        let ctx = RouteCtx {
            domain,
            ip,
            transport_udp,
            port,
            process_name: None,
            process_path: None,
        };

        let engine = self.engine.read().await;
        engine.decide(&ctx)
    }

    /// Update the routing engine
    pub async fn update_engine(&self, new_engine: Engine) {
        let mut engine = self.engine.write().await;
        *engine = new_engine;
    }

    /// Get process information for a connection
    async fn get_process_info(
        &self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        transport_udp: bool,
    ) -> Result<ProcessInfo, ProcessMatchError> {
        let protocol = if transport_udp {
            Protocol::Udp
        } else {
            Protocol::Tcp
        };

        let conn_info = ConnectionInfo {
            local_addr,
            remote_addr,
            protocol,
        };

        self.process_matcher.match_connection(&conn_info).await
    }

    /// Clean up expired process cache entries
    pub async fn cleanup_cache(&self) {
        self.process_matcher.cleanup_cache().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::router::rules::{Rule, RuleKind};
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_process_router_creation() {
        let engine = Engine::new();
        let result = ProcessRouter::new(engine);

        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        assert!(result.is_ok());

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_decide_without_process() {
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        {
            let engine = Engine::new();
            let router = ProcessRouter::new(engine).unwrap();

            let decision = router
                .decide_without_process(Some("example.com"), None, false, Some(443))
                .await;

            // Should return Direct as default
            assert!(matches!(decision, Decision::Direct));
        }
    }

    #[tokio::test]
    async fn test_process_rule_matching() {
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        {
            let rules = vec![
                Rule {
                    kind: RuleKind::ProcessName("firefox".to_string()),
                    decision: Decision::Proxy(None),
                },
                Rule {
                    kind: RuleKind::Default,
                    decision: Decision::Direct,
                },
            ];

            let engine = Engine::build(rules);
            let router = ProcessRouter::new(engine).unwrap();

            // Test with mock process info
            let ctx = RouteCtx {
                domain: Some("example.com"),
                ip: None,
                transport_udp: false,
                port: Some(443),
                process_name: Some("firefox"),
                process_path: Some("/usr/bin/firefox"),
            };

            let engine = router.engine.read().await;
            let decision = engine.decide(&ctx);

            assert!(matches!(decision, Decision::Proxy(None)));
        }
    }
}
