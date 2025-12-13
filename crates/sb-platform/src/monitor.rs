/// Network monitor for retrieving network status and tracking changes.
///
/// This module abstracts platform-specific network monitoring capabilities.
/// - Linux: Uses netlink sockets via rtnetlink
/// - macOS/Windows: Stub implementations (TODO)

use parking_lot::RwLock;
use std::sync::Arc;

/// Network event types for callback notification.
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    /// A network interface was added or came online.
    LinkUp { interface: String },
    /// A network interface was removed or went offline.
    LinkDown { interface: String },
    /// An IP address was added to an interface.
    AddressAdded { interface: String, address: String },
    /// An IP address was removed from an interface.
    AddressRemoved { interface: String, address: String },
    /// Network route changed.
    RouteChanged,
    /// General network change (unspecified).
    Changed,
}

/// Callback type for network change notifications.
pub type NetworkChangeCallback = Box<dyn Fn(NetworkEvent) + Send + Sync>;

/// Network monitor for retrieving network status and registering change callbacks.
#[derive(Default)]
pub struct NetworkMonitor {
    callbacks: Arc<RwLock<Vec<NetworkChangeCallback>>>,
    #[cfg(target_os = "linux")]
    running: Arc<std::sync::atomic::AtomicBool>,
}

impl std::fmt::Debug for NetworkMonitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkMonitor")
            .field("callbacks_count", &self.callbacks.read().len())
            .finish()
    }
}

impl Clone for NetworkMonitor {
    fn clone(&self) -> Self {
        Self {
            callbacks: self.callbacks.clone(),
            #[cfg(target_os = "linux")]
            running: self.running.clone(),
        }
    }
}

impl NetworkMonitor {
    /// Create a new network monitor instance.
    pub fn new() -> Self {
        Self {
            callbacks: Arc::new(RwLock::new(Vec::new())),
            #[cfg(target_os = "linux")]
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Register a callback to be notified of network changes.
    pub fn register_callback(&self, callback: NetworkChangeCallback) {
        self.callbacks.write().push(callback);
        tracing::debug!(
            callbacks = self.callbacks.read().len(),
            "Network change callback registered"
        );
    }

    /// Notify all registered callbacks of a network event.
    fn notify(&self, event: NetworkEvent) {
        let callbacks = self.callbacks.read();
        for callback in callbacks.iter() {
            callback(event.clone());
        }
    }

    /// Get the current network type (e.g., "wifi", "cellular", "ethernet").
    pub fn get_network_type(&self) -> &'static str {
        // TODO: Implement platform-specific logic
        "unknown"
    }

    /// Check if the current network is expensive (e.g., cellular data).
    pub fn is_expensive(&self) -> bool {
        // TODO: Implement platform-specific logic
        false
    }

    /// Check if the current network is constrained (e.g., low data mode).
    pub fn is_constrained(&self) -> bool {
        // TODO: Implement platform-specific logic
        false
    }

    /// Start listening for network changes.
    /// On Linux, this spawns a background task to listen to netlink events.
    #[cfg(target_os = "linux")]
    pub fn start(&self) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error + Send + Sync>> {
        use std::sync::atomic::Ordering;

        if self.running.load(Ordering::SeqCst) {
            return Err("NetworkMonitor already running".into());
        }
        self.running.store(true, Ordering::SeqCst);

        let monitor = self.clone();
        let handle = tokio::spawn(async move {
            if let Err(e) = monitor.listen_netlink().await {
                tracing::error!(error = %e, "NetworkMonitor netlink listener error");
            }
        });

        tracing::info!("NetworkMonitor started (Linux netlink)");
        Ok(handle)
    }

    /// Start listening for network changes (stub for non-Linux platforms).
    #[cfg(not(target_os = "linux"))]
    pub fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!("NetworkMonitor started (stub - no platform implementation)");
        Ok(())
    }

    /// Stop listening for network changes.
    #[cfg(target_os = "linux")]
    pub fn stop(&self) {
        use std::sync::atomic::Ordering;
        self.running.store(false, Ordering::SeqCst);
        tracing::info!("NetworkMonitor stopped");
    }

    #[cfg(not(target_os = "linux"))]
    pub fn stop(&self) {
        tracing::info!("NetworkMonitor stopped (stub)");
    }

    /// Listen to Linux netlink socket for network events.
    #[cfg(all(target_os = "linux", feature = "linux"))]
    async fn listen_netlink(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use futures::stream::StreamExt;
        use rtnetlink::new_connection;
        use std::sync::atomic::Ordering;

        let (mut connection, handle, mut messages) = new_connection()?;

        // Spawn the connection driver
        tokio::spawn(connection);

        tracing::debug!("NetworkMonitor: netlink connection established");

        // Subscribe to link and address notifications
        // Note: rtnetlink may not support subscription directly; this is a polling approach
        while self.running.load(Ordering::SeqCst) {
            // Poll for link changes periodically
            match handle.link().get().execute().try_next().await {
                Ok(Some(_link)) => {
                    // Link data received - could compare with previous state
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(error = %e, "NetworkMonitor: netlink poll error");
                }
            }

            // Small delay between polls
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        }

        Ok(())
    }

    /// Listen to Linux netlink socket (stub when linux feature disabled).
    #[cfg(all(target_os = "linux", not(feature = "linux")))]
    async fn listen_netlink(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::warn!("NetworkMonitor: netlink support disabled (linux feature not enabled)");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn test_callback_registration() {
        let monitor = NetworkMonitor::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();

        monitor.register_callback(Box::new(move |_event| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        }));

        // Trigger notification
        monitor.notify(NetworkEvent::Changed);
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        // Second notification
        monitor.notify(NetworkEvent::LinkUp { interface: "eth0".into() });
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_default_values() {
        let monitor = NetworkMonitor::new();
        assert_eq!(monitor.get_network_type(), "unknown");
        assert!(!monitor.is_expensive());
        assert!(!monitor.is_constrained());
    }
}
