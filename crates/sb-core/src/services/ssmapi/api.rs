//! HTTP API handlers for SSMAPI service.

use super::{traffic::TrafficManager, user::UserManager};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// API server state shared across handlers.
#[derive(Clone)]
pub struct ApiState {
    pub user_manager: Arc<UserManager>,
    pub traffic_manager: Arc<TrafficManager>,
}

/// Server info response.
#[derive(Serialize)]
pub struct ServerInfo {
    server: String,
    #[serde(rename = "apiVersion")]
    api_version: String,
}

/// Add user request.
#[derive(Deserialize)]
pub struct AddUserRequest {
    username: String,
    #[serde(rename = "uPSK")]
    password: String,
}

/// Update user request.
#[derive(Deserialize)]
pub struct UpdateUserRequest {
    #[serde(rename = "uPSK")]
    password: String,
}

/// List users response.
#[derive(Serialize)]
pub struct ListUsersResponse {
    users: Vec<super::user::UserObject>,
}

/// Stats query parameters.
#[derive(Deserialize)]
pub struct StatsQuery {
    #[serde(default)]
    clear: bool,
}

/// Stats response.
#[derive(Serialize)]
pub struct StatsResponse {
    #[serde(rename = "uplinkBytes")]
    uplink_bytes: i64,
    #[serde(rename = "downlinkBytes")]
    downlink_bytes: i64,
    #[serde(rename = "uplinkPackets")]
    uplink_packets: i64,
    #[serde(rename = "downlinkPackets")]
    downlink_packets: i64,
    #[serde(rename = "tcpSessions")]
    tcp_sessions: i64,
    #[serde(rename = "udpSessions")]
    udp_sessions: i64,
    users: Vec<super::user::UserObject>,
}

/// Error response.
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    error: String,
}

impl IntoResponse for ErrorResponse {
    fn into_response(self) -> Response {
        (StatusCode::BAD_REQUEST, Json(self)).into_response()
    }
}

/// Create v1 API routes that can be nested under different prefixes.
/// Used for per-inbound routing like `/{server_tag}/v1/...`.
pub fn api_routes() -> axum::Router<ApiState> {
    use axum::routing::{get, post};

    axum::Router::new()
        .route("/v1", get(get_server_info))
        .route("/v1/users", get(list_users).post(add_user))
        .route(
            "/v1/users/:username",
            get(get_user).put(update_user).delete(delete_user),
        )
        .route("/v1/stats", get(get_stats))
}

/// GET /server/v1 - Server info.
pub async fn get_server_info() -> Json<ServerInfo> {
    Json(ServerInfo {
        server: format!("singbox-rust {}", env!("CARGO_PKG_VERSION")),
        api_version: "v1".to_string(),
    })
}

/// GET /server/v1/users - List all users.
pub async fn list_users(State(state): State<ApiState>) -> Json<ListUsersResponse> {
    let mut users = state.user_manager.list();
    state.traffic_manager.read_users(&mut users, false);
    // Remove passwords from response (Go parity: users contain stats but no password)
    let users: Vec<_> = users.into_iter().map(|u| u.without_password()).collect();
    Json(ListUsersResponse { users })
}

/// POST /server/v1/users - Add new user.
pub async fn add_user(
    State(state): State<ApiState>,
    Json(req): Json<AddUserRequest>,
) -> Result<StatusCode, ErrorResponse> {
    state
        .user_manager
        .add(req.username, req.password)
        .map_err(|e| ErrorResponse {
            error: e.to_string(),
        })?;
    Ok(StatusCode::CREATED)
}

/// GET /server/v1/users/{username} - Get user info with stats.
pub async fn get_user(
    State(state): State<ApiState>,
    Path(username): Path<String>,
) -> Result<Json<super::user::UserObject>, StatusCode> {
    let password = state
        .user_manager
        .get(&username)
        .ok_or(StatusCode::NOT_FOUND)?;

    let mut user = super::user::UserObject::new(username, Some(password));
    state.traffic_manager.read_user(&mut user, false);

    Ok(Json(user))
}

/// PUT /server/v1/users/{username} - Update user password.
pub async fn update_user(
    State(state): State<ApiState>,
    Path(username): Path<String>,
    Json(req): Json<UpdateUserRequest>,
) -> Result<StatusCode, ErrorResponse> {
    if !state.user_manager.contains(&username) {
        return Err(ErrorResponse {
            error: format!("user '{}' not found", username),
        });
    }

    state
        .user_manager
        .update(&username, req.password)
        .map_err(|e| ErrorResponse {
            error: e.to_string(),
        })?;

    Ok(StatusCode::NO_CONTENT)
}

/// DELETE /server/v1/users/{username} - Delete user.
pub async fn delete_user(
    State(state): State<ApiState>,
    Path(username): Path<String>,
) -> Result<StatusCode, ErrorResponse> {
    if !state.user_manager.contains(&username) {
        return Err(ErrorResponse {
            error: format!("user '{}' not found", username),
        });
    }

    state
        .user_manager
        .delete(&username)
        .map_err(|e| ErrorResponse {
            error: e.to_string(),
        })?;

    // Also clear traffic stats for this user
    state.traffic_manager.clear_user(&username);

    Ok(StatusCode::NO_CONTENT)
}

/// GET /server/v1/stats - Get global and per-user stats.
pub async fn get_stats(
    State(state): State<ApiState>,
    Query(query): Query<StatsQuery>,
) -> Json<StatsResponse> {
    let mut users = state.user_manager.list();
    state.traffic_manager.read_users(&mut users, query.clear);

    // Remove passwords from response
    let users: Vec<_> = users.into_iter().map(|u| u.without_password()).collect();

    let global = state.traffic_manager.read_global(query.clear);

    Json(StatsResponse {
        uplink_bytes: global.uplink_bytes,
        downlink_bytes: global.downlink_bytes,
        uplink_packets: global.uplink_packets,
        downlink_packets: global.downlink_packets,
        tcp_sessions: global.tcp_sessions,
        udp_sessions: global.udp_sessions,
        users,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_state() -> ApiState {
        let user_manager = UserManager::new();
        let traffic_manager = TrafficManager::new();
        ApiState {
            user_manager,
            traffic_manager,
        }
    }

    #[tokio::test]
    async fn test_server_info() {
        let info = get_server_info().await;
        assert!(info.0.server.starts_with("singbox-rust"));
        assert_eq!(info.0.api_version, "v1");
    }

    #[tokio::test]
    async fn test_user_lifecycle() {
        let state = create_test_state();

        // Add user
        let add_req = AddUserRequest {
            username: "alice".to_string(),
            password: "pass123".to_string(),
        };
        let result = add_user(State(state.clone()), Json(add_req)).await;
        assert!(result.is_ok());

        // List users
        let list_resp = list_users(State(state.clone())).await;
        assert_eq!(list_resp.0.users.len(), 1);
        assert_eq!(list_resp.0.users[0].user_name, "alice");
        assert!(list_resp.0.users[0].password.is_none()); // Password stripped in list

        // Get user
        let user_resp = get_user(State(state.clone()), Path("alice".to_string())).await;
        assert!(user_resp.is_ok());
        let user = user_resp.unwrap().0;
        assert_eq!(user.user_name, "alice");
        assert_eq!(user.password, Some("pass123".to_string()));

        // Update user
        let update_req = UpdateUserRequest {
            password: "newpass".to_string(),
        };
        let result = update_user(
            State(state.clone()),
            Path("alice".to_string()),
            Json(update_req),
        )
        .await;
        assert!(result.is_ok());

        // Verify update
        let user_resp = get_user(State(state.clone()), Path("alice".to_string())).await;
        assert_eq!(user_resp.unwrap().0.password, Some("newpass".to_string()));

        // Delete user
        let result = delete_user(State(state.clone()), Path("alice".to_string())).await;
        assert!(result.is_ok());

        // Verify deletion
        let list_resp = list_users(State(state.clone())).await;
        assert_eq!(list_resp.0.users.len(), 0);
    }

    #[tokio::test]
    async fn test_stats() {
        let state = create_test_state();

        // Add user and record traffic
        state
            .user_manager
            .add("alice".to_string(), "pass".to_string())
            .unwrap();
        state.traffic_manager.record_uplink("alice", 1000, 10);
        state.traffic_manager.record_downlink("alice", 2000, 20);

        // Get stats (non-clearing)
        let stats = get_stats(State(state.clone()), Query(StatsQuery { clear: false })).await;
        assert_eq!(stats.0.uplink_bytes, 1000);
        assert_eq!(stats.0.downlink_bytes, 2000);
        assert_eq!(stats.0.users.len(), 1);
        assert!(stats.0.users[0].password.is_none()); // Password should be removed

        // Get stats (clearing)
        let stats = get_stats(State(state.clone()), Query(StatsQuery { clear: true })).await;
        assert_eq!(stats.0.uplink_bytes, 1000);

        // Stats should be cleared now
        let stats = get_stats(State(state.clone()), Query(StatsQuery { clear: false })).await;
        assert_eq!(stats.0.uplink_bytes, 0);
    }
}
