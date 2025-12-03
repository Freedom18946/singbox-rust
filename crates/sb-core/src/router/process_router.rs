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
            ..Default::default()
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
            ..Default::default()
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
                inbound_tag: None,
                outbound_tag: None,
                auth_user: None,
                query_type: None,
                ..Default::default()
            };

            let engine = router.engine.read().await;
            let decision = engine.decide(&ctx);

            assert!(matches!(decision, Decision::Proxy(None)));
        }
    }

    #[tokio::test]
    async fn test_process_path_rule_matching() {
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        {
            let rules = vec![
                Rule {
                    kind: RuleKind::ProcessPath("/usr/bin/curl".to_string()),
                    decision: Decision::Direct,
                },
                Rule {
                    kind: RuleKind::ProcessPath("/Applications/Telegram.app".to_string()),
                    decision: Decision::Proxy(Some("telegram_proxy".to_string())),
                },
                Rule {
                    kind: RuleKind::Default,
                    decision: Decision::Reject,
                },
            ];

            let engine = Engine::build(rules);
            let router = ProcessRouter::new(engine).unwrap();

            // Test curl path
            let ctx_curl = RouteCtx {
                domain: Some("example.com"),
                ip: None,
                transport_udp: false,
                port: Some(443),
                process_name: Some("curl"),
                process_path: Some("/usr/bin/curl"),
                inbound_tag: None,
                outbound_tag: None,
                auth_user: None,
                query_type: None,
                ..Default::default()
            };

            let eng = router.engine.read().await;
            let decision = eng.decide(&ctx_curl);
            assert!(matches!(decision, Decision::Direct));
            drop(eng);

            // Test telegram path
            let ctx_telegram = RouteCtx {
                domain: Some("example.com"),
                ip: None,
                transport_udp: false,
                port: Some(443),
                process_name: Some("Telegram"),
                process_path: Some("/Applications/Telegram.app"),
                inbound_tag: None,
                outbound_tag: None,
                auth_user: None,
                query_type: None,
                ..Default::default()
            };

            let eng = router.engine.read().await;
            let decision = eng.decide(&ctx_telegram);
            assert!(matches!(decision, Decision::Proxy(Some(_))));
        }
    }

    #[tokio::test]
    async fn test_rule_priority_domain_beats_process() {
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        {
            let rules = vec![
                Rule {
                    kind: RuleKind::Exact("blocked.example.com".to_string()),
                    decision: Decision::Reject,
                },
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

            // Domain rule should beat process rule
            let ctx = RouteCtx {
                domain: Some("blocked.example.com"),
                ip: None,
                transport_udp: false,
                port: Some(443),
                process_name: Some("firefox"),
                process_path: None,
                inbound_tag: None,
                outbound_tag: None,
                auth_user: None,
                query_type: None,
                ..Default::default()
            };

            let eng = router.engine.read().await;
            let decision = eng.decide(&ctx);
            assert!(matches!(decision, Decision::Reject));
        }
    }

    #[tokio::test]
    async fn test_update_engine() {
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        {
            let initial_rules = vec![Rule {
                kind: RuleKind::Default,
                decision: Decision::Direct,
            }];

            let engine = Engine::build(initial_rules);
            let router = ProcessRouter::new(engine).unwrap();

            // Initial decision
            let decision = router
                .decide_without_process(Some("example.com"), None, false, Some(443))
                .await;
            assert!(matches!(decision, Decision::Direct));

            // Update engine with new rules
            let new_rules = vec![
                Rule {
                    kind: RuleKind::Exact("example.com".to_string()),
                    decision: Decision::Reject,
                },
                Rule {
                    kind: RuleKind::Default,
                    decision: Decision::Direct,
                },
            ];

            let new_engine = Engine::build(new_rules);
            router.update_engine(new_engine).await;

            // Decision should reflect new rules
            let decision = router
                .decide_without_process(Some("example.com"), None, false, Some(443))
                .await;
            assert!(matches!(decision, Decision::Reject));
        }
    }

    #[tokio::test]
    async fn test_udp_tcp_transport_distinction() {
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        {
            let rules = vec![Rule {
                kind: RuleKind::Default,
                decision: Decision::Direct,
            }];

            let engine = Engine::build(rules);
            let router = ProcessRouter::new(engine).unwrap();

            // Test TCP
            let tcp_decision = router
                .decide_without_process(Some("example.com"), None, false, Some(443))
                .await;
            assert!(matches!(tcp_decision, Decision::Direct));

            // Test UDP
            let udp_decision = router
                .decide_without_process(Some("example.com"), None, true, Some(53))
                .await;
            assert!(matches!(udp_decision, Decision::Direct));
        }
    }

    #[tokio::test]
    async fn test_multiple_process_rules() {
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        {
            let rules = vec![
                Rule {
                    kind: RuleKind::ProcessName("firefox".to_string()),
                    decision: Decision::Proxy(Some("browser_proxy".to_string())),
                },
                Rule {
                    kind: RuleKind::ProcessName("chrome".to_string()),
                    decision: Decision::Proxy(Some("browser_proxy".to_string())),
                },
                Rule {
                    kind: RuleKind::ProcessName("curl".to_string()),
                    decision: Decision::Direct,
                },
                Rule {
                    kind: RuleKind::Default,
                    decision: Decision::Reject,
                },
            ];

            let engine = Engine::build(rules);
            let router = ProcessRouter::new(engine).unwrap();

            // Test firefox
            let ctx_firefox = RouteCtx {
                domain: Some("example.com"),
                ip: None,
                transport_udp: false,
                port: Some(443),
                process_name: Some("firefox"),
                process_path: None,
                inbound_tag: None,
                outbound_tag: None,
                auth_user: None,
                query_type: None,
                ..Default::default()
            };

            let eng = router.engine.read().await;
            let decision = eng.decide(&ctx_firefox);
            assert!(matches!(decision, Decision::Proxy(Some(name)) if name == "browser_proxy"));
            drop(eng);

            // Test chrome
            let ctx_chrome = RouteCtx {
                domain: Some("example.com"),
                ip: None,
                transport_udp: false,
                port: Some(443),
                process_name: Some("chrome"),
                process_path: None,
                inbound_tag: None,
                outbound_tag: None,
                auth_user: None,
                query_type: None,
                ..Default::default()
            };

            let eng = router.engine.read().await;
            let decision = eng.decide(&ctx_chrome);
            assert!(matches!(decision, Decision::Proxy(Some(name)) if name == "browser_proxy"));
            drop(eng);

            // Test curl
            let ctx_curl = RouteCtx {
                domain: Some("example.com"),
                ip: None,
                transport_udp: false,
                port: Some(443),
                process_name: Some("curl"),
                process_path: None,
                inbound_tag: None,
                outbound_tag: None,
                auth_user: None,
                query_type: None,
                ..Default::default()
            };

            let eng = router.engine.read().await;
            let decision = eng.decide(&ctx_curl);
            assert!(matches!(decision, Decision::Direct));
        }
    }
}
