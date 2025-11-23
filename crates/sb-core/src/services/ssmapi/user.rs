//! User management for SSMAPI service.

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
pub struct UserManager {
    users: RwLock<HashMap<String, String>>,
}

impl UserManager {
    /// Create a new empty user manager.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            users: RwLock::new(HashMap::new()),
        })
    }

    /// Create a user manager with initial users from configuration.
    ///
    /// # Arguments
    /// * `initial_users` - Map of username to "method:password" format strings
    pub fn with_users(initial_users: HashMap<String, String>) -> Arc<Self> {
        Arc::new(Self {
            users: RwLock::new(initial_users),
        })
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
    /// # Errors
    /// Returns an error if the user already exists.
    pub fn add(&self, username: String, password: String) -> Result<(), UserError> {
        let mut users = self.users.write();
        if users.contains_key(&username) {
            return Err(UserError::AlreadyExists(username));
        }
        users.insert(username, password);
        Ok(())
    }

    /// Update a user's password.
    ///
    /// # Errors
    /// Returns an error if the user doesn't exist.
    pub fn update(&self, username: &str, password: String) -> Result<(), UserError> {
        let mut users = self.users.write();
        if !users.contains_key(username) {
            return Err(UserError::NotFound(username.to_string()));
        }
        users.insert(username.to_string(), password);
        Ok(())
    }

    /// Delete a user.
    ///
    /// # Errors
    /// Returns an error if the user doesn't exist.
    pub fn delete(&self, username: &str) -> Result<(), UserError> {
        let mut users = self.users.write();
        if users.remove(username).is_none() {
            return Err(UserError::NotFound(username.to_string()));
        }
        Ok(())
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
}

impl Default for UserManager {
    fn default() -> Self {
        Self {
            users: RwLock::new(HashMap::new()),
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
}
