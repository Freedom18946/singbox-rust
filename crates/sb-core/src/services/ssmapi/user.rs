//! User management for SSMAPI service.
//!
//! Go reference: `service/ssmapi/user.go`

use super::traffic::TrafficManager;
use super::ManagedSSMServer;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

/// User information with statistics.
#[derive(Debug, Clone, serde::Serialize)]
pub struct UserObject {
    #[serde(rename = "username")]
    pub user_name: String,
    #[serde(rename = "uPSK", skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(rename = "downlinkBytes")]
    pub downlink_bytes: i64,
    #[serde(rename = "uplinkBytes")]
    pub uplink_bytes: i64,
    #[serde(rename = "downlinkPackets")]
    pub downlink_packets: i64,
    #[serde(rename = "uplinkPackets")]
    pub uplink_packets: i64,
    #[serde(rename = "tcpSessions")]
    pub tcp_sessions: i64,
    #[serde(rename = "udpSessions")]
    pub udp_sessions: i64,
}

impl UserObject {
    /// Create a new user object with no traffic stats.
    pub fn new(user_name: String, password: Option<String>) -> Self {
        Self {
            user_name,
            password,
            downlink_bytes: 0,
            uplink_bytes: 0,
            downlink_packets: 0,
            uplink_packets: 0,
            tcp_sessions: 0,
            udp_sessions: 0,
        }
    }

    /// Clear password field (used when returning stats).
    pub fn without_password(mut self) -> Self {
        self.password = None;
        self
    }
}

/// User manager for storing user credentials.
///
/// Go reference: `type UserManager struct` in `service/ssmapi/user.go`
///
/// When bound to a managed SS server, user changes are automatically
/// pushed to the server via `update_users()`.
pub struct UserManager {
    users: RwLock<HashMap<String, String>>,
    /// Reference to the managed SS server (for pushing user updates).
    /// Go reference: `server adapter.ManagedSSMServer`
    server: Option<Arc<dyn ManagedSSMServer>>,
    /// Reference to the traffic manager (for updating user list on changes).
    /// Go reference: `trafficManager *TrafficManager`
    traffic_manager: Option<Arc<TrafficManager>>,
}

impl UserManager {
    /// Create a new empty user manager (standalone, no server binding).
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            users: RwLock::new(HashMap::new()),
            server: None,
            traffic_manager: None,
        })
    }

    /// Create a user manager bound to a managed SS server.
    ///
    /// Go reference: `NewUserManager(inbound adapter.ManagedSSMServer, trafficManager *TrafficManager)`
    ///
    /// When users are added/updated/deleted, changes are automatically
    /// pushed to the server via `ManagedSSMServer::update_users()`.
    pub fn with_server(
        server: Arc<dyn ManagedSSMServer>,
        traffic_manager: Arc<TrafficManager>,
    ) -> Arc<Self> {
        Arc::new(Self {
            users: RwLock::new(HashMap::new()),
            server: Some(server),
            traffic_manager: Some(traffic_manager),
        })
    }

    /// Create a user manager with initial users from configuration.
    ///
    /// # Arguments
    /// * `initial_users` - Map of username to password
    pub fn with_users(initial_users: HashMap<String, String>) -> Arc<Self> {
        Arc::new(Self {
            users: RwLock::new(initial_users),
            server: None,
            traffic_manager: None,
        })
    }

    /// Push user list to bound server if present.
    ///
    /// Go reference: `func (m *UserManager) postUpdate(updated bool) error`
    ///
    /// # Arguments
    /// * `updated` - If true, also update traffic manager's user list
    fn post_update(&self, updated: bool) -> Result<(), UserError> {
        // Push to server if bound
        if let Some(server) = &self.server {
            let users = self.users.read();
            let (usernames, passwords): (Vec<_>, Vec<_>) = users
                .iter()
                .map(|(u, p)| (u.clone(), p.clone()))
                .unzip();
            
            server.update_users(usernames, passwords).map_err(|e| {
                tracing::error!(error = %e, "Failed to push users to SS server");
                UserError::ServerError(e)
            })?;
        }

        // Update traffic manager's user list if requested
        if updated {
            if let Some(tm) = &self.traffic_manager {
                let users: Vec<_> = self.users.read().keys().cloned().collect();
                tm.update_users(&users);
            }
        }

        Ok(())
    }

    /// List all users with their passwords.
    pub fn list(&self) -> Vec<UserObject> {
        let users = self.users.read();
        users
            .iter()
            .map(|(name, password)| UserObject::new(name.clone(), Some(password.clone())))
            .collect()
    }

    /// Get a user's password.
    pub fn get(&self, username: &str) -> Option<String> {
        let users = self.users.read();
        users.get(username).cloned()
    }

    /// Add a new user.
    ///
    /// Go reference: `func (m *UserManager) Add(username string, password string) error`
    ///
    /// # Errors
    /// Returns an error if the user already exists or server update fails.
    pub fn add(&self, username: String, password: String) -> Result<(), UserError> {
        {
            let mut users = self.users.write();
            if users.contains_key(&username) {
                return Err(UserError::AlreadyExists(username));
            }
            users.insert(username, password);
        }
        self.post_update(true)
    }

    /// Update a user's password.
    ///
    /// Go reference: `func (m *UserManager) Update(username string, password string) error`
    ///
    /// # Errors
    /// Returns an error if the user doesn't exist or server update fails.
    pub fn update(&self, username: &str, password: String) -> Result<(), UserError> {
        {
            let mut users = self.users.write();
            if !users.contains_key(username) {
                return Err(UserError::NotFound(username.to_string()));
            }
            users.insert(username.to_string(), password);
        }
        self.post_update(true)
    }

    /// Delete a user.
    ///
    /// Go reference: `func (m *UserManager) Delete(username string) error`
    ///
    /// # Errors
    /// Returns an error if the user doesn't exist or server update fails.
    pub fn delete(&self, username: &str) -> Result<(), UserError> {
        {
            let mut users = self.users.write();
            if users.remove(username).is_none() {
                return Err(UserError::NotFound(username.to_string()));
            }
        }
        self.post_update(true)
    }

    /// Check if a user exists.
    pub fn contains(&self, username: &str) -> bool {
        let users = self.users.read();
        users.contains_key(username)
    }

    /// Get number of users.
    pub fn len(&self) -> usize {
        let users = self.users.read();
        users.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Set users directly (for cache loading).
    ///
    /// Used when loading cache to restore user list.
    /// Calls `post_update(false)` to push to server without updating traffic manager.
    pub fn set_users(&self, users_map: HashMap<String, String>) -> Result<(), UserError> {
        {
            let mut users = self.users.write();
            *users = users_map;
        }
        self.post_update(false)
    }

    /// Get all users as a map (for cache saving).
    pub fn users_map(&self) -> HashMap<String, String> {
        self.users.read().clone()
    }
}

impl Default for UserManager {
    fn default() -> Self {
        Self {
            users: RwLock::new(HashMap::new()),
            server: None,
            traffic_manager: None,
        }
    }
}

/// User management errors.
#[derive(Debug, thiserror::Error)]
pub enum UserError {
    #[error("user '{0}' already exists")]
    AlreadyExists(String),
    #[error("user '{0}' not found")]
    NotFound(String),
    #[error("server error: {0}")]
    ServerError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_management() {
        let manager = UserManager::new();

        // Add user
        assert!(manager
            .add("alice".to_string(), "pass123".to_string())
            .is_ok());
        assert!(manager
            .add("bob".to_string(), "pass456".to_string())
            .is_ok());

        // Duplicate add should fail
        assert!(matches!(
            manager.add("alice".to_string(), "pass789".to_string()),
            Err(UserError::AlreadyExists(_))
        ));

        // Get user
        assert_eq!(manager.get("alice"), Some("pass123".to_string()));
        assert_eq!(manager.get("unknown"), None);

        // Update user
        assert!(manager.update("alice", "newpass".to_string()).is_ok());
        assert_eq!(manager.get("alice"), Some("newpass".to_string()));
        assert!(matches!(
            manager.update("unknown", "pass".to_string()),
            Err(UserError::NotFound(_))
        ));

        // List users
        let users = manager.list();
        assert_eq!(users.len(), 2);

        // Delete user
        assert!(manager.delete("bob").is_ok());
        assert!(!manager.contains("bob"));
        assert!(matches!(manager.delete("bob"), Err(UserError::NotFound(_))));
    }

    #[test]
    fn test_set_users() {
        let manager = UserManager::new();

        let mut users = HashMap::new();
        users.insert("user1".to_string(), "pass1".to_string());
        users.insert("user2".to_string(), "pass2".to_string());

        assert!(manager.set_users(users).is_ok());
        assert_eq!(manager.len(), 2);
        assert_eq!(manager.get("user1"), Some("pass1".to_string()));
    }

    /// Mock ManagedSSMServer for testing post_update functionality
    struct MockSSMServer {
        updated_users: std::sync::Mutex<Vec<(Vec<String>, Vec<String>)>>,
        tag: String,
    }

    impl MockSSMServer {
        fn new(tag: &str) -> Arc<Self> {
            Arc::new(Self {
                updated_users: std::sync::Mutex::new(Vec::new()),
                tag: tag.to_string(),
            })
        }

        fn get_update_calls(&self) -> Vec<(Vec<String>, Vec<String>)> {
            self.updated_users.lock().unwrap().clone()
        }
    }

    impl super::ManagedSSMServer for MockSSMServer {
        fn set_tracker(&self, _tracker: Arc<dyn crate::services::ssmapi::TrafficTracker>) {}

        fn tag(&self) -> &str {
            &self.tag
        }

        fn inbound_type(&self) -> &str {
            "mock"
        }

        fn update_users(&self, users: Vec<String>, passwords: Vec<String>) -> Result<(), String> {
            self.updated_users.lock().unwrap().push((users, passwords));
            Ok(())
        }
    }

    #[test]
    fn test_with_server_calls_update_users() {
        let mock_server = MockSSMServer::new("test-ss");
        let traffic_manager = super::TrafficManager::new();
        let manager = UserManager::with_server(mock_server.clone(), traffic_manager);

        // Add user should trigger update_users
        assert!(manager.add("alice".to_string(), "pass1".to_string()).is_ok());
        
        let calls = mock_server.get_update_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, vec!["alice".to_string()]);
        assert_eq!(calls[0].1, vec!["pass1".to_string()]);

        // Update user should also trigger update_users
        assert!(manager.update("alice", "newpass".to_string()).is_ok());
        
        let calls = mock_server.get_update_calls();
        assert_eq!(calls.len(), 2);
        assert!(calls[1].0.contains(&"alice".to_string()));
        assert!(calls[1].1.contains(&"newpass".to_string()));
    }

    #[test]
    fn test_with_server_delete_triggers_update() {
        let mock_server = MockSSMServer::new("test-ss");
        let traffic_manager = super::TrafficManager::new();
        let manager = UserManager::with_server(mock_server.clone(), traffic_manager);

        // Add two users
        assert!(manager.add("alice".to_string(), "pass1".to_string()).is_ok());
        assert!(manager.add("bob".to_string(), "pass2".to_string()).is_ok());

        // Delete one user
        assert!(manager.delete("alice").is_ok());

        let calls = mock_server.get_update_calls();
        // 3 calls: add alice, add bob, delete alice
        assert_eq!(calls.len(), 3);
        
        // Last call should only have bob
        let last_call = calls.last().unwrap();
        assert_eq!(last_call.0.len(), 1);
        assert!(last_call.0.contains(&"bob".to_string()));
    }

    #[test]
    fn test_standalone_manager_no_server() {
        // Standalone manager should work without server binding
        let manager = UserManager::new();
        
        assert!(manager.add("alice".to_string(), "pass1".to_string()).is_ok());
        assert!(manager.update("alice", "newpass".to_string()).is_ok());
        assert!(manager.delete("alice").is_ok());
        
        // No panics, all operations succeed
        assert_eq!(manager.len(), 0);
    }
}

