//! Error handling for API services

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;
use sb_core::error::SbError;

/// Result type for API operations
pub type ApiResult<T> = Result<T, ApiError>;

/// API error types
#[derive(Debug, Error)]
pub enum ApiError {
    /// Invalid request parameters
    #[error("Invalid request: {message}")]
    BadRequest { message: String },

    /// Resource not found
    #[error("Not found: {resource}")]
    NotFound { resource: String },

    /// Internal server error
    #[error("Internal error: {source}")]
    Internal {
        #[from]
        source: anyhow::Error,
    },

    /// Service unavailable
    #[error("Service unavailable: {message}")]
    ServiceUnavailable { message: String },

    /// Configuration error
    #[error("Configuration error: {message}")]
    Configuration { message: String },

    /// JSON serialization/deserialization error
    #[error("JSON error: {source}")]
    Json {
        #[from]
        source: serde_json::Error,
    },

    /// WebSocket error
    #[error("WebSocket error: {message}")]
    WebSocket { message: String },

    /// Input parse error (malformed or ambiguous input)
    #[error("Parse error: {message}")]
    Parse { message: String },

    /// A specific field is invalid
    #[error("Invalid field '{field}': {message}")]
    InvalidField { field: String, message: String },

    /// Unsupported API version requested
    #[error("Unsupported version: {version}")]
    UnsupportedVersion { version: String },
}

impl ApiError {
    /// Stable kind string for logging/assertions
    pub fn kind(&self) -> &'static str {
        match self {
            ApiError::BadRequest { .. } => "BadRequest",
            ApiError::NotFound { .. } => "NotFound",
            ApiError::Internal { .. } => "Internal",
            ApiError::ServiceUnavailable { .. } => "ServiceUnavailable",
            ApiError::Configuration { .. } => "Configuration",
            ApiError::Json { .. } => "Json",
            ApiError::WebSocket { .. } => "WebSocket",
            ApiError::Parse { .. } => "Parse",
            ApiError::InvalidField { .. } => "InvalidField",
            ApiError::UnsupportedVersion { .. } => "UnsupportedVersion",
        }
    }

    /// Example
    /// ```
    /// use sb_api::error::ApiError;
    /// let e = ApiError::bad_request("missing field");
    /// assert_eq!(e.status_code(), axum::http::StatusCode::BAD_REQUEST);
    /// ```
    /// Create a bad request error
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::BadRequest {
            message: message.into(),
        }
    }

    /// Create a not found error
    pub fn not_found(resource: impl Into<String>) -> Self {
        Self::NotFound {
            resource: resource.into(),
        }
    }

    /// Create a service unavailable error
    pub fn service_unavailable(message: impl Into<String>) -> Self {
        Self::ServiceUnavailable {
            message: message.into(),
        }
    }

    /// Create a configuration error
    pub fn configuration(message: impl Into<String>) -> Self {
        Self::Configuration {
            message: message.into(),
        }
    }

    /// Create a WebSocket error
    pub fn websocket(message: impl Into<String>) -> Self {
        Self::WebSocket {
            message: message.into(),
        }
    }

    /// Get the HTTP status code for this error
    pub fn status_code(&self) -> StatusCode {
        match self {
            ApiError::BadRequest { .. } => StatusCode::BAD_REQUEST,
            ApiError::NotFound { .. } => StatusCode::NOT_FOUND,
            ApiError::Internal { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::ServiceUnavailable { .. } => StatusCode::SERVICE_UNAVAILABLE,
            ApiError::Configuration { .. } => StatusCode::BAD_REQUEST,
            ApiError::Json { .. } => StatusCode::BAD_REQUEST,
            ApiError::WebSocket { .. } => StatusCode::BAD_REQUEST,
            ApiError::Parse { .. } => StatusCode::BAD_REQUEST,
            ApiError::InvalidField { .. } => StatusCode::BAD_REQUEST,
            ApiError::UnsupportedVersion { .. } => StatusCode::BAD_REQUEST,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status_code = self.status_code();
        let error_message = self.to_string();

        let body = Json(json!({
            "error": error_message,
            "code": status_code.as_u16()
        }));

        (status_code, body).into_response()
    }
}

impl From<SbError> for ApiError {
    fn from(e: SbError) -> Self {
        // Preserve source via anyhow wrapping, keep external signature intact
        ApiError::Internal { source: anyhow::Error::from(e) }
    }
}
