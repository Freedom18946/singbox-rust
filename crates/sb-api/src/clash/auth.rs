//! Clash API authentication middleware (Go parity: clashapi/server.go L256-290)
//!
//! Behavior:
//! 1. token=None → skip auth (all requests pass through)
//! 2. WebSocket upgrade with ?token= query param → check token
//! 3. HTTP with Authorization: Bearer <token> header → check token
//! 4. Mismatch → 401 {"message": "Unauthorized"}

use axum::{
    extract::Request,
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde_json::json;

/// Authentication middleware function for axum.
///
/// If `secret` is None or empty, all requests are allowed (Go parity).
/// Otherwise, validates Bearer token or WebSocket ?token= query param.
pub async fn auth_middleware(secret: Option<String>, request: Request, next: Next) -> Response {
    // No secret configured → skip authentication
    let secret = match secret {
        Some(ref s) if !s.is_empty() => s.as_str(),
        _ => return next.run(request).await,
    };

    // Check if this is a WebSocket upgrade request
    let is_ws_upgrade = request
        .headers()
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);

    if is_ws_upgrade {
        // For WebSocket: check ?token= query parameter
        if let Some(query) = request.uri().query() {
            for pair in query.split('&') {
                if let Some(token) = pair.strip_prefix("token=") {
                    if token == secret {
                        return next.run(request).await;
                    } else {
                        return unauthorized_response();
                    }
                }
            }
        }
        // WebSocket without token param → fall through to header check
    }

    // Check Authorization: Bearer <token> header
    if let Some(auth_header) = request.headers().get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                if token == secret {
                    return next.run(request).await;
                }
            }
        }
    }

    unauthorized_response()
}

fn unauthorized_response() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::CONTENT_TYPE, "application/json")],
        json!({"message": "Unauthorized"}).to_string(),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request as HttpRequest, middleware, routing::get, Router};
    use tower::ServiceExt;

    async fn ok_handler() -> &'static str {
        "ok"
    }

    fn make_app(secret: Option<String>) -> Router {
        let secret_clone = secret.clone();
        Router::new()
            .route("/test", get(ok_handler))
            .route("/ws", get(ok_handler))
            .layer(middleware::from_fn(move |req, next| {
                let s = secret_clone.clone();
                auth_middleware(s, req, next)
            }))
    }

    #[tokio::test]
    async fn test_no_secret_allows_all() {
        let app = make_app(None);
        let req = HttpRequest::builder()
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_empty_secret_allows_all() {
        let app = make_app(Some(String::new()));
        let req = HttpRequest::builder()
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_correct_bearer_token() {
        let app = make_app(Some("test123".to_string()));
        let req = HttpRequest::builder()
            .uri("/test")
            .header("Authorization", "Bearer test123")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_wrong_bearer_token() {
        let app = make_app(Some("test123".to_string()));
        let req = HttpRequest::builder()
            .uri("/test")
            .header("Authorization", "Bearer wrong")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_missing_auth_with_secret() {
        let app = make_app(Some("test123".to_string()));
        let req = HttpRequest::builder()
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_ws_correct_token_query() {
        let app = make_app(Some("test123".to_string()));
        let req = HttpRequest::builder()
            .uri("/ws?token=test123")
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_ws_wrong_token_query() {
        let app = make_app(Some("test123".to_string()));
        let req = HttpRequest::builder()
            .uri("/ws?token=wrong")
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_ws_with_bearer_header_fallback() {
        let app = make_app(Some("test123".to_string()));
        // WS upgrade without ?token= but with Bearer header should work
        let req = HttpRequest::builder()
            .uri("/ws")
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .header("Authorization", "Bearer test123")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
