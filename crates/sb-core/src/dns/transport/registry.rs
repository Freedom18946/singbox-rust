use super::{DnsStartStage, DnsTransport};
use anyhow::Result;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;

/// Type alias for transport constructor function
pub type TransportConstructor =
    Box<dyn Fn(&str, &serde_json::Value) -> Result<Arc<dyn DnsTransport>> + Send + Sync>;

/// Registry to manage DNS transport lifecycle, types, and dependencies (Go-parity)
///
/// Mirrors Go's `TransportRegistry` with:
/// - Type-based constructor registration
/// - Options creation per transport type
/// - Dependency tracking for startup order
/// - Lifecycle management (start/close)
#[derive(Default)]
pub struct TransportRegistry {
    /// Registered transports by tag
    transports: Arc<Mutex<HashMap<String, Arc<dyn DnsTransport>>>>,
    /// Constructor functions by transport type
    constructors: Arc<Mutex<HashMap<String, TransportConstructor>>>,
    /// Dependencies: tag -> list of tags it depends on
    dependencies: Arc<Mutex<HashMap<String, Vec<String>>>>,
}

impl Clone for TransportRegistry {
    fn clone(&self) -> Self {
        Self {
            transports: Arc::clone(&self.transports),
            constructors: Arc::clone(&self.constructors),
            dependencies: Arc::clone(&self.dependencies),
        }
    }
}

impl TransportRegistry {
    /// Create a new empty transport registry
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a transport type constructor (Go-parity: RegisterTransport)
    pub fn register_type<F>(&self, transport_type: &str, constructor: F)
    where
        F: Fn(&str, &serde_json::Value) -> Result<Arc<dyn DnsTransport>> + Send + Sync + 'static,
    {
        self.constructors
            .lock()
            .insert(transport_type.to_string(), Box::new(constructor));
    }

    /// Create a transport from registered type (Go-parity: CreateDNSTransport)
    pub fn create_transport(
        &self,
        tag: &str,
        transport_type: &str,
        options: &serde_json::Value,
    ) -> Result<Arc<dyn DnsTransport>> {
        let constructors = self.constructors.lock();
        let constructor = constructors
            .get(transport_type)
            .ok_or_else(|| anyhow::anyhow!("transport type not found: {}", transport_type))?;
        constructor(tag, options)
    }

    /// Check if a transport type is registered
    pub fn has_type(&self, transport_type: &str) -> bool {
        self.constructors.lock().contains_key(transport_type)
    }

    /// Register a transport with a unique tag
    pub fn register(&self, tag: String, transport: Arc<dyn DnsTransport>) {
        self.transports.lock().insert(tag, transport);
    }

    /// Register a transport with dependencies
    pub fn register_with_deps(
        &self,
        tag: String,
        transport: Arc<dyn DnsTransport>,
        deps: Vec<String>,
    ) {
        self.transports.lock().insert(tag.clone(), transport);
        if !deps.is_empty() {
            self.dependencies.lock().insert(tag, deps);
        }
    }

    /// Get a registered transport by tag
    pub fn get(&self, tag: &str) -> Option<Arc<dyn DnsTransport>> {
        self.transports.lock().get(tag).cloned()
    }

    /// Get all registered transport tags
    pub fn tags(&self) -> Vec<String> {
        self.transports.lock().keys().cloned().collect()
    }

    /// Get startup order respecting dependencies (topological sort)
    pub fn get_startup_order(&self) -> Result<Vec<String>> {
        let deps = self.dependencies.lock();
        let transports = self.transports.lock();

        let mut order = Vec::new();
        let mut visited = std::collections::HashSet::new();
        let mut in_progress = std::collections::HashSet::new();

        fn visit(
            tag: &str,
            deps: &HashMap<String, Vec<String>>,
            visited: &mut std::collections::HashSet<String>,
            in_progress: &mut std::collections::HashSet<String>,
            order: &mut Vec<String>,
        ) -> Result<()> {
            if in_progress.contains(tag) {
                return Err(anyhow::anyhow!("dependency cycle detected at: {}", tag));
            }
            if visited.contains(tag) {
                return Ok(());
            }

            in_progress.insert(tag.to_string());

            if let Some(tag_deps) = deps.get(tag) {
                for dep in tag_deps {
                    visit(dep, deps, visited, in_progress, order)?;
                }
            }

            in_progress.remove(tag);
            visited.insert(tag.to_string());
            order.push(tag.to_string());
            Ok(())
        }

        for tag in transports.keys() {
            visit(tag, &deps, &mut visited, &mut in_progress, &mut order)?;
        }

        Ok(order)
    }

    /// Start all registered transports in dependency order
    pub async fn start_all(&self, stage: DnsStartStage) -> Result<()> {
        let order = self.get_startup_order()?;
        let transports = self.transports.lock().clone();

        for tag in order {
            if let Some(t) = transports.get(&tag) {
                t.start(stage)
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to start transport {}: {}", tag, e))?;
            }
        }
        Ok(())
    }

    /// Close all registered transports (reverse order)
    pub async fn close_all(&self) -> Result<()> {
        let mut order = self.get_startup_order()?;
        order.reverse();
        let transports = self.transports.lock().clone();

        for tag in order {
            if let Some(t) = transports.get(&tag) {
                t.close()
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to close transport {}: {}", tag, e))?;
            }
        }
        Ok(())
    }

    /// Remove a transport by tag
    pub fn remove(&self, tag: &str) -> Option<Arc<dyn DnsTransport>> {
        self.dependencies.lock().remove(tag);
        self.transports.lock().remove(tag)
    }

    /// Clear all transports
    pub fn clear(&self) {
        self.transports.lock().clear();
        self.dependencies.lock().clear();
    }
}
